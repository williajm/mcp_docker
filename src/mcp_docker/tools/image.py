"""FastMCP image tools.

This module contains Docker image management tools using FastMCP 2.0.
Includes operations across all safety levels:
- SAFE: list, inspect, history (read-only)
- MODERATE: pull, build, push, tag (reversible)
- DESTRUCTIVE: remove, prune (permanent)

Long-running operations (pull, build, push) support background tasks
with real-time progress reporting.
"""

import asyncio
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from queue import Empty, Queue
from typing import Any

from docker.errors import APIError, DockerException, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from fastmcp.dependencies import Progress
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import (
    DESC_IMAGE_ID,
    DESC_TRUNCATION_INFO,
    FiltersInput,
    PaginatedListOutput,
    apply_list_pagination,
)
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound, ValidationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_IMAGE_NOT_FOUND
from mcp_docker.utils.validation import validate_image_name

logger = get_logger(__name__)

# Constants for progress message sanitization
MAX_PROGRESS_MESSAGE_LENGTH = 200
PROGRESS_THROTTLE_SECONDS = 0.1  # Max 10 updates per second
# Regex to strip ANSI escape sequences
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _check_chunk_for_error(chunk: dict[str, Any], operation: str) -> None:
    """Check if a chunk contains an error and raise if so.

    Args:
        chunk: Streaming chunk from Docker API
        operation: Operation name for error message (e.g., "pull", "push", "build")

    Raises:
        DockerOperationError: If chunk contains an error
    """
    if "error" in chunk and chunk["error"] is not None:
        error_msg = str(chunk["error"])
        logger.error(f"Failed to {operation} image: {error_msg}")
        raise DockerOperationError(f"Failed to {operation} image: {error_msg}")


def _sanitize_progress_message(message: str) -> str:
    """Sanitize a progress message for safe display.

    - Strips ANSI escape sequences
    - Truncates to MAX_PROGRESS_MESSAGE_LENGTH
    - Removes control characters

    Args:
        message: Raw progress message

    Returns:
        Sanitized message safe for display
    """
    # Strip ANSI escape sequences
    message = ANSI_ESCAPE_PATTERN.sub("", message)
    # Remove other control characters (except newline/tab)
    message = "".join(c for c in message if c.isprintable() or c in "\n\t")
    # Strip whitespace
    message = message.strip()
    # Truncate if too long
    if len(message) > MAX_PROGRESS_MESSAGE_LENGTH:
        message = message[: MAX_PROGRESS_MESSAGE_LENGTH - 3] + "..."
    return message


def _image_has_tag(image: str) -> bool:
    """Check if an image reference already contains a tag.

    Handles registry hosts with ports like localhost:5000/myimg correctly
    by only checking for ':' after the last '/'.

    Args:
        image: Image reference string

    Returns:
        True if the image contains a tag (colon after last slash)
    """
    # Get the part after the last slash (or the whole string if no slash)
    name_part = image.rsplit("/", 1)[-1]
    # Check if that part contains a colon (indicating a tag)
    return ":" in name_part


def _validate_build_context_path(path: str) -> Path:
    """Validate and resolve build context path for security.

    Args:
        path: Build context path string

    Returns:
        Resolved Path object

    Raises:
        ValidationError: If path is invalid or poses security risk
    """
    resolved_path = Path(path).resolve()

    if str(resolved_path) == "/":
        raise ValidationError("Cannot build from root directory '/'")
    if not resolved_path.exists():
        raise ValidationError(f"Build context path does not exist: {path}")
    if not resolved_path.is_dir():
        raise ValidationError(f"Build context path must be a directory: {path}")

    return resolved_path


class ProgressThrottler:
    """Throttle progress updates to avoid overwhelming clients."""

    def __init__(self, min_interval: float = PROGRESS_THROTTLE_SECONDS) -> None:
        """Initialize throttler.

        Args:
            min_interval: Minimum seconds between updates
        """
        self.min_interval = min_interval
        self.last_update_time: float = 0.0
        self.last_message: str = ""

    def should_update(self, message: str) -> bool:
        """Check if we should send this progress update.

        Args:
            message: The message to potentially send

        Returns:
            True if update should be sent
        """
        now = time.monotonic()
        # Always allow if message is different and enough time passed
        time_elapsed = now - self.last_update_time >= self.min_interval
        message_changed = message != self.last_message

        if time_elapsed or (message_changed and "complete" in message.lower()):
            self.last_update_time = now
            self.last_message = message
            return True
        return False


def _format_layer_message(chunk: dict[str, Any]) -> str | None:
    """Format a progress message from a Docker streaming chunk.

    Args:
        chunk: Streaming chunk from Docker API

    Returns:
        Formatted message string or None if no message to report
    """
    raw_id = chunk.get("id")
    layer_id = str(raw_id)[:12] if raw_id is not None else ""

    raw_status = chunk.get("status")
    status = str(raw_status) if raw_status is not None else ""

    # Check for detailed progress info
    detail = chunk.get("progressDetail")
    if detail:
        current = detail.get("current", 0) or 0
        total = detail.get("total", 0) or 0
        if total > 0:
            pct = int((current / total) * 100)
            cur_mb = current / 1024 / 1024
            tot_mb = total / 1024 / 1024
            return f"Layer {layer_id}: {status} {pct}% ({cur_mb:.1f}MB/{tot_mb:.1f}MB)"
        if layer_id:
            return f"Layer {layer_id}: {status}"
        return None

    # No detail, just format status
    if not status:
        return None
    return f"Layer {layer_id}: {status}" if layer_id else status


async def _report_layer_progress(
    progress: Progress,
    chunk: dict[str, Any],
    throttler: ProgressThrottler | None = None,
) -> str | None:
    """Report progress for a single layer chunk and return status if present.

    Args:
        progress: FastMCP Progress dependency
        chunk: Streaming chunk from Docker API
        throttler: Optional throttler to limit update frequency

    Returns:
        Status string if present, None otherwise
    """
    msg = _format_layer_message(chunk)

    if msg:
        msg = _sanitize_progress_message(msg)
        if throttler is None or throttler.should_update(msg):
            await progress.set_message(msg)

    raw_status = chunk.get("status")
    return str(raw_status) if raw_status is not None else None


async def _cleanup_worker_task(
    task: asyncio.Future[None],
    chunk_queue: Queue[Any],
) -> None:
    """Clean up a worker task by draining its queue and awaiting completion.

    This ensures the worker thread can terminate even if an error occurred
    during processing, preventing memory leaks and thread hangs.

    Args:
        task: The executor future running the worker
        chunk_queue: The queue the worker is writing to
    """
    # Drain the queue to unblock the worker if it's trying to put
    while True:
        try:
            chunk = chunk_queue.get_nowait()
            if chunk is None:
                break
        except Empty:
            break

    # Wait for the worker to finish (it should complete quickly now)
    try:
        await asyncio.wait_for(task, timeout=5.0)
    except TimeoutError:
        logger.warning("Worker thread did not complete within timeout")
    except Exception as e:
        # Worker may have already failed during streaming - log at debug level
        logger.debug(f"Worker task cleanup: {type(e).__name__}: {e}")


def _check_worker_error(
    error_list: list[Exception],
    error_event: threading.Event | None,
) -> None:
    """Check for errors from worker thread and raise if found.

    Args:
        error_list: List containing errors from worker thread
        error_event: Optional threading.Event signaling an error occurred

    Raises:
        Exception: Re-raises the first error from error_list if error detected
    """
    # Use thread-safe event if available
    if error_event is not None:
        if error_event.is_set() and error_list:
            raise error_list[0] from error_list[0]
        return

    # Fallback for backwards compatibility (no event provided)
    if error_list:
        raise error_list[0] from error_list[0]


async def _process_streaming_queue(  # noqa: PLR0913 - Streaming processor needs all parameters
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    progress: Progress,
    throttler: ProgressThrottler,
    operation: str,
    error_event: threading.Event | None = None,
) -> str | None:
    """Process chunks from a streaming queue with progress reporting.

    Args:
        chunk_queue: Queue containing streaming chunks (None signals completion)
        error_list: List to check for errors from worker thread
        progress: FastMCP Progress dependency
        throttler: Throttler for progress updates
        operation: Operation name for error messages (e.g., "pull", "push")
        error_event: Optional threading.Event signaling an error occurred

    Returns:
        Last status string or None

    Raises:
        DockerOperationError: If an error is found in a chunk

    Note:
        Thread safety: The error_list is written to by the worker thread (single
        append) and read by this async function. The error_event provides explicit
        signaling when an error occurs. The worker sets the event before appending
        to the list, ensuring the list is populated when the event is set.
    """
    last_status: str | None = None

    while True:
        try:
            chunk = await asyncio.to_thread(chunk_queue.get, True, 0.1)
        except Empty:
            _check_worker_error(error_list, error_event)
            continue

        if chunk is None:
            break

        if isinstance(chunk, dict):
            _check_chunk_for_error(chunk, operation)
            status = await _report_layer_progress(progress, chunk, throttler)
            if status:
                last_status = status

    return last_status


async def _report_build_progress(
    progress: Progress,
    chunk: dict[str, Any],
    throttler: ProgressThrottler,
) -> None:
    """Report progress for a build log chunk.

    Args:
        progress: FastMCP Progress dependency
        chunk: Build log chunk from Docker API
        throttler: Throttler for progress updates
    """
    stream_val = chunk.get("stream")
    if not isinstance(stream_val, str):
        return

    msg = stream_val.strip()
    if not msg:
        return

    sanitized_msg = _sanitize_progress_message(msg)
    is_important = msg.startswith("Step ") or "Successfully" in msg
    if is_important or throttler.should_update(sanitized_msg):
        await progress.set_message(f"Build: {sanitized_msg}")


async def _process_build_streaming_queue(
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    progress: Progress,
    throttler: ProgressThrottler,
    error_event: threading.Event | None = None,
) -> None:
    """Process build log chunks from a streaming queue with progress reporting.

    Args:
        chunk_queue: Queue containing build log chunks (None signals completion)
        error_list: List to check for errors from worker thread
        progress: FastMCP Progress dependency
        throttler: Throttler for progress updates
        error_event: Optional threading.Event signaling an error occurred

    Raises:
        DockerOperationError: If an error is found in a chunk

    Note:
        Thread safety: The error_list is written to by the worker thread (single
        append) and read by this async function. The error_event provides explicit
        signaling when an error occurs.
    """
    while True:
        try:
            chunk = await asyncio.to_thread(chunk_queue.get, True, 0.1)
        except Empty:
            _check_worker_error(error_list, error_event)
            continue

        if chunk is None:
            break

        if isinstance(chunk, dict):
            _check_chunk_for_error(chunk, "build")
            await _report_build_progress(progress, chunk, throttler)


def _create_pull_streaming_worker(  # noqa: PLR0913 - Factory needs all pull parameters
    docker_client: Any,
    image: str,
    tag: str | None,
    all_tags: bool,
    platform: str | None,
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    error_event: threading.Event | None = None,
) -> Callable[[], None]:
    """Create a worker function for streaming image pull.

    Args:
        docker_client: Docker client wrapper
        image: Image name
        tag: Optional tag
        all_tags: Pull all tags
        platform: Platform specification
        chunk_queue: Queue to put chunks on
        error_list: List to append errors to
        error_event: Optional threading.Event to signal errors

    Returns:
        Callable worker function
    """

    def _pull_with_streaming() -> None:
        try:
            stream = docker_client.client.api.pull(
                repository=image,
                tag=tag,
                stream=True,
                decode=True,
                all_tags=all_tags,
                platform=platform,
            )
            for chunk in stream:
                chunk_queue.put(chunk)
        except Exception as e:
            error_list.append(e)
            if error_event is not None:
                error_event.set()
        finally:
            chunk_queue.put(None)

    return _pull_with_streaming


async def _get_pulled_image(
    docker_client: Any,
    image: str,
    tag: str | None,
) -> Any:
    """Get the image object after a successful pull.

    Args:
        docker_client: Docker client wrapper
        image: Image name
        tag: Optional tag

    Returns:
        Docker image object

    Raises:
        ImageNotFound: If image not found after pull
    """
    full_name = f"{image}:{tag}" if tag else image

    def _get() -> Any:
        return docker_client.client.images.get(full_name)

    try:
        return await asyncio.to_thread(_get)
    except (DockerImageNotFound, NotFound) as e:
        logger.error(f"Image not found after pull: {image}")
        raise ImageNotFound(ERROR_IMAGE_NOT_FOUND.format(image)) from e


def _collect_build_log_message(log_entry: Any) -> str | None:
    """Extract a log message from a build log entry.

    Args:
        log_entry: Build log entry from Docker API

    Returns:
        Stripped message string or None
    """
    if not isinstance(log_entry, dict):
        return None
    stream_val = log_entry.get("stream")
    if not isinstance(stream_val, str):
        return None
    msg = stream_val.strip()
    return msg if msg else None


def _create_build_streaming_worker(  # noqa: PLR0913 - Factory needs all build parameters
    docker_client: Any,
    resolved_path: str,
    tag: str | None,
    dockerfile: str,
    nocache: bool,
    rm: bool,
    pull: bool,
    buildargs: dict[str, str] | None,
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    result_list: list[tuple[Any, list[str]]],
    error_event: threading.Event | None = None,
) -> Callable[[], None]:
    """Create a worker function for streaming image build.

    Args:
        docker_client: Docker client wrapper
        resolved_path: Resolved build context path
        tag: Optional image tag
        dockerfile: Dockerfile path
        nocache: No cache flag
        rm: Remove intermediate containers flag
        pull: Pull base images flag
        buildargs: Build arguments
        chunk_queue: Queue to put chunks on
        error_list: List to append errors to
        result_list: List to append (image, logs) result to
        error_event: Optional threading.Event to signal errors

    Returns:
        Callable worker function
    """

    def _build_with_streaming() -> None:
        try:
            kwargs: dict[str, Any] = {
                "path": resolved_path,
                "dockerfile": dockerfile,
                "nocache": nocache,
                "rm": rm,
                "pull": pull,
            }
            if tag:
                kwargs["tag"] = tag
            if buildargs:
                kwargs["buildargs"] = buildargs

            image_obj, build_logs_gen = docker_client.client.images.build(**kwargs)

            # Stream logs to queue while collecting them
            log_messages: list[str] = []
            for log_entry in build_logs_gen:
                chunk_queue.put(log_entry)
                msg = _collect_build_log_message(log_entry)
                if msg:
                    log_messages.append(msg)

            result_list.append((image_obj, log_messages))
        except Exception as e:
            error_list.append(e)
            if error_event is not None:
                error_event.set()
        finally:
            chunk_queue.put(None)

    return _build_with_streaming


def _create_push_streaming_worker(  # noqa: PLR0913 - Factory needs all push parameters
    docker_client: Any,
    image: str,
    tag: str | None,
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    error_event: threading.Event | None = None,
) -> Callable[[], None]:
    """Create a worker function for streaming image push.

    Args:
        docker_client: Docker client wrapper
        image: Image name
        tag: Optional tag
        chunk_queue: Queue to put chunks on
        error_list: List to append errors to
        error_event: Optional threading.Event to signal errors

    Returns:
        Callable worker function
    """

    def _push_with_streaming() -> None:
        try:
            stream = docker_client.client.api.push(
                repository=image,
                tag=tag,
                stream=True,
                decode=True,
            )
            for chunk in stream:
                chunk_queue.put(chunk)
        except Exception as e:
            error_list.append(e)
            if error_event is not None:
                error_event.set()
        finally:
            chunk_queue.put(None)

    return _push_with_streaming


def _force_remove_all_images(docker_client: Any) -> tuple[list[dict[str, Any]], int]:
    """Force remove ALL images (extremely destructive).

    Args:
        docker_client: Docker client instance

    Returns:
        Tuple of (deleted_images, space_reclaimed)
    """
    logger.warning("force_all=True: Removing ALL images (extremely destructive)")
    all_images = docker_client.images.list(all=True)

    deleted = []
    space_reclaimed = 0

    for image in all_images:
        if not image.id:
            continue

        try:
            size = image.attrs.get("Size", 0)
            docker_client.images.remove(image.id, force=True)
            deleted.append({"Deleted": image.id})
            space_reclaimed += size
            logger.debug(f"Force removed image {image.id[:12]}")
        except (APIError, DockerException) as e:
            logger.debug(f"Could not force remove image {image.id[:12]}: {e}")
            continue

    return deleted, space_reclaimed


def _prune_all_unused_images(
    docker_client: Any, filters: dict[str, str | list[str]] | None
) -> tuple[list[dict[str, Any]], int]:
    """Prune all unused images (equivalent to docker image prune -a).

    The Docker SDK's prune() method only removes dangling images by default.
    To remove ALL unused images (including tagged but unused), we must manually
    iterate and remove images not in use by any container.

    Args:
        docker_client: Docker client instance
        filters: Optional filters to apply

    Returns:
        Tuple of (deleted_images, space_reclaimed)
    """
    prune_filters = filters or {}
    all_images = docker_client.images.list(all=True, filters=prune_filters)
    containers = docker_client.containers.list(all=True)
    images_in_use = {c.image.id for c in containers if c.image}

    deleted = []
    space_reclaimed = 0

    for image in all_images:
        if image.id in images_in_use or not image.id:
            continue

        try:
            size = image.attrs.get("Size", 0)
            docker_client.images.remove(image.id, force=False)
            deleted.append({"Deleted": image.id})
            space_reclaimed += size
            logger.debug(f"Removed unused image {image.id[:12]}")
        except (APIError, DockerException) as e:
            logger.debug(f"Could not remove image {image.id[:12]}: {e}")
            continue

    return deleted, space_reclaimed


# Input/Output Models (reused from legacy tools)


class ListImagesInput(FiltersInput):
    """Input for listing images."""

    all: bool = Field(default=False, description="Show all images including intermediates")


class ListImagesOutput(PaginatedListOutput):
    """Output for listing images."""

    images: list[dict[str, Any]] = Field(description="List of images with basic info")


class InspectImageInput(BaseModel):
    """Input for inspecting an image."""

    image_name: str = Field(description=DESC_IMAGE_ID)


class InspectImageOutput(BaseModel):
    """Output for inspecting an image."""

    details: dict[str, Any] = Field(description="Detailed image information")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


class ImageHistoryInput(BaseModel):
    """Input for viewing image history."""

    image: str = Field(description=DESC_IMAGE_ID)


class ImageHistoryOutput(BaseModel):
    """Output for viewing image history."""

    history: list[dict[str, Any]] = Field(description="Image layer history")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


class PullImageInput(BaseModel):
    """Input for pulling an image."""

    image: str = Field(description="Image name (e.g., 'ubuntu:22.04')")
    tag: str | None = Field(default=None, description="Optional tag (if not in image name)")
    all_tags: bool = Field(default=False, description="Pull all tags")
    platform: str | None = Field(default=None, description="Platform (e.g., 'linux/amd64')")


class PullImageOutput(BaseModel):
    """Output for pulling an image."""

    image: str = Field(description="Pulled image name")
    id: str = Field(description="Image ID")
    tags: list[str] = Field(description="Image tags")


class BuildImageInput(BaseModel):
    """Input for building an image."""

    path: str = Field(description="Path to build context")
    tag: str | None = Field(default=None, description="Tag for the image")
    dockerfile: str = Field(default="Dockerfile", description="Path to Dockerfile")
    buildargs: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Build arguments as key-value pairs. "
            "Example: {'NODE_VERSION': '18', 'ENVIRONMENT': 'production'}"
        ),
    )
    nocache: bool = Field(default=False, description="Do not use cache")
    rm: bool = Field(default=True, description="Remove intermediate containers")
    pull: bool = Field(default=False, description="Always pull newer base images")

    @field_validator("buildargs", mode="before")
    @classmethod
    def _parse_json_fields(cls, v: Any, info: Any) -> Any:
        """Parse JSON string fields to dicts."""
        return parse_json_string_field(v, info.field_name)


class BuildImageOutput(BaseModel):
    """Output for building an image."""

    image_id: str = Field(description="Built image ID")
    tags: list[str] = Field(description="Image tags")
    logs: list[str] = Field(description="Build logs")


class PushImageInput(BaseModel):
    """Input for pushing an image."""

    image: str = Field(description="Image name to push")
    tag: str | None = Field(default=None, description="Optional tag")


class PushImageOutput(BaseModel):
    """Output for pushing an image."""

    image: str = Field(description="Pushed image name")
    status: str = Field(description="Push status")


class TagImageInput(BaseModel):
    """Input for tagging an image."""

    image: str = Field(description="Source image name or ID")
    repository: str = Field(description="Target repository")
    tag: str = Field(default="latest", description="Tag name")


class TagImageOutput(BaseModel):
    """Output for tagging an image."""

    source: str = Field(description="Source image")
    target: str = Field(description="Target repository:tag")


class RemoveImageInput(BaseModel):
    """Input for removing an image."""

    image: str = Field(description=DESC_IMAGE_ID)
    force: bool = Field(default=False, description="Force removal")
    noprune: bool = Field(default=False, description="Do not delete untagged parents")


class RemoveImageOutput(BaseModel):
    """Output for removing an image."""

    deleted: list[dict[str, Any]] = Field(description="List of deleted items")


class PruneImagesInput(BaseModel):
    """Input for pruning Docker images (unused by default, all with force_all=true)."""

    all: bool = Field(
        default=False,
        description=(
            "Remove all unused images, not just dangling ones. "
            "Equivalent to 'docker image prune -a'. "
            "When False (default), only removes dangling images (untagged intermediate layers). "
            "When True, removes all images not used by any container. "
            "NOTE: This still only removes UNUSED images. "
            "To remove ALL images including tagged ones, use force_all=true."
        ),
    )
    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'dangling': ['true']}, {'until': '24h'}, {'label': ['env=test']}"
        ),
    )
    force_all: bool = Field(
        default=False,
        description=(
            "Force remove ALL images, even if tagged or in use. "
            "USE THIS when user asks to 'remove all images', 'delete all images', "
            "or 'prune all images'. "
            "When True, removes EVERY image regardless of tags, names, or container usage. "
            "WARNING: This is extremely destructive and will delete all images. "
            "Requires user confirmation."
        ),
    )


class PruneImagesOutput(BaseModel):
    """Output for pruning images."""

    deleted: list[dict[str, Any]] = Field(description="List of deleted images")
    space_reclaimed: int = Field(description="Disk space reclaimed in bytes")


# FastMCP Tool Functions


def create_list_images_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the list_images FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    def list_images(
        all: bool = False,
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker images with optional filters.

        Args:
            all: Show all images including intermediates
            filters: Filters to apply (e.g., {'dangling': ['true']})

        Returns:
            Dictionary with images list, count, and truncation info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing images (all={all}, filters={filters})")
            images = docker_client.client.images.list(all=all, filters=filters)

            image_list = [
                {
                    "id": img.id,
                    "short_id": img.short_id,
                    "tags": img.tags,
                    "labels": img.labels,
                    "size": img.attrs.get("Size", 0),
                }
                for img in images
            ]

            image_list, truncation_info, original_count = apply_list_pagination(
                image_list,
                safety_config,
                "images",
            )

            logger.info(f"Found {len(image_list)} images (total: {original_count})")

            # Convert to output model for validation
            output = ListImagesOutput(
                images=image_list,
                count=original_count,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list images: {e}")
            raise DockerOperationError(f"Failed to list images: {e}") from e

    return (
        "docker_list_images",
        "List Docker images with optional filters",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        False,  # not supports_task
        list_images,
    )


def create_inspect_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the inspect_image FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    def inspect_image(
        image_name: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker image.

        Args:
            image_name: Image name or ID

        Returns:
            Dictionary with detailed image information

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting image: {image_name}")
            image = docker_client.client.images.get(image_name)
            details = image.attrs

            # Apply output limits (truncate large fields)
            truncation_info: dict[str, Any] = {}
            # Note: truncate_dict_fields would be imported if we use it
            # For now, returning full info

            logger.info(f"Successfully inspected image: {image_name}")

            # Convert to output model for validation
            output = InspectImageOutput(
                details=details,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image_name}")
            raise ImageNotFound(ERROR_IMAGE_NOT_FOUND.format(image_name)) from e
        except APIError as e:
            logger.error(f"Failed to inspect image: {e}")
            raise DockerOperationError(f"Failed to inspect image: {e}") from e

    return (
        "docker_inspect_image",
        "Get detailed information about a Docker image",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        False,  # not supports_task
        inspect_image,
    )


def create_image_history_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the image_history FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    def image_history(
        image: str,
    ) -> dict[str, Any]:
        """View the history of a Docker image.

        Args:
            image: Image name or ID

        Returns:
            Dictionary with image layer history

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If history retrieval fails
        """
        try:
            logger.info(f"Getting history for image: {image}")
            image_obj = docker_client.client.images.get(image)
            history = image_obj.history()

            history, truncation_info, _ = apply_list_pagination(history, safety_config, "layers")

            logger.info(f"Successfully retrieved history for image: {image}")

            # Convert to output model for validation
            output = ImageHistoryOutput(
                history=history,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image}")
            raise ImageNotFound(ERROR_IMAGE_NOT_FOUND.format(image)) from e
        except APIError as e:
            logger.error(f"Failed to get image history: {e}")
            raise DockerOperationError(f"Failed to get image history: {e}") from e

    return (
        "docker_image_history",
        "View the history of a Docker image",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        False,  # not supports_task
        image_history,
    )


def create_pull_image_tool(  # noqa: PLR0915 - Complex streaming logic requires many statements
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the pull_image FastMCP tool with background task support.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    async def pull_image(  # noqa: PLR0915 - Complex streaming logic
        image: str,
        tag: str | None = None,
        all_tags: bool = False,
        platform: str | None = None,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Pull a Docker image from a registry with real-time progress reporting.

        Args:
            image: Image name (e.g., 'ubuntu:22.04')
            tag: Optional tag (if not in image name)
            all_tags: Pull all tags (note: output will show only the primary image)
            platform: Platform (e.g., 'linux/amd64')
            progress: FastMCP Progress dependency for real-time updates

        Returns:
            Dictionary with image name, ID, and tags

        Raises:
            ValidationError: If image name is invalid
            ImageNotFound: If image cannot be found after pull
            DockerOperationError: If pull fails
        """
        # Validate tag consistency: reject if both image contains tag AND tag param provided
        if tag and _image_has_tag(image):
            raise ValidationError(
                f"Image '{image}' already contains a tag. "
                "Do not specify both a tagged image and a separate tag parameter."
            )

        validate_image_name(image)
        logger.info(f"Pulling image: {image}")

        await progress.set_message(f"Starting pull: {image}")

        # Use a queue for real-time progress streaming
        chunk_queue: Queue[dict[str, Any] | None] = Queue()
        pull_error: list[Exception] = []
        error_event = threading.Event()

        # Create and start the pull worker
        worker = _create_pull_streaming_worker(
            docker_client, image, tag, all_tags, platform, chunk_queue, pull_error, error_event
        )
        pull_task: asyncio.Future[None] = asyncio.get_running_loop().run_in_executor(None, worker)

        try:
            # Process chunks as they arrive (real-time progress)
            await _process_streaming_queue(
                chunk_queue, pull_error, progress, ProgressThrottler(), "pull", error_event
            )

            # Wait for pull thread to complete
            await pull_task

            # Check for any errors from the pull thread
            if pull_error:
                raise pull_error[0] from pull_error[0]

            # Get the final image object
            image_obj = await _get_pulled_image(docker_client, image, tag)

            logger.info(f"Successfully pulled image: {image}")
            await progress.set_message(f"Pull complete: {image}")

            output = PullImageOutput(image=image, id=str(image_obj.id), tags=image_obj.tags or [])
            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image}")
            raise ImageNotFound(ERROR_IMAGE_NOT_FOUND.format(image)) from e
        except APIError as e:
            logger.error(f"Failed to pull image: {e}")
            raise DockerOperationError(f"Failed to pull image: {e}") from e
        finally:
            # Ensure worker thread is cleaned up even on error
            await _cleanup_worker_task(pull_task, chunk_queue)

    return (
        "docker_pull_image",
        "Pull a Docker image from a registry",
        OperationSafety.MODERATE,
        True,  # idempotent
        True,  # open_world (pulls from registry)
        True,  # supports_task (background task with progress)
        pull_image,
    )


def create_build_image_tool(  # noqa: PLR0915 - Complex streaming logic requires many statements
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the build_image FastMCP tool with background task support.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    async def build_image(  # noqa: PLR0913, PLR0912, PLR0915 - Docker API requires these params
        path: str,
        tag: str | None = None,
        dockerfile: str = "Dockerfile",
        buildargs: dict[str, str] | None = None,
        nocache: bool = False,
        rm: bool = True,
        pull: bool = False,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Build a Docker image from a Dockerfile with real-time progress reporting.

        Args:
            path: Path to build context
            tag: Tag for the image
            dockerfile: Path to Dockerfile
            buildargs: Build arguments as key-value pairs
            nocache: Do not use cache
            rm: Remove intermediate containers
            pull: Always pull newer base images
            progress: FastMCP Progress dependency for real-time updates

        Returns:
            Dictionary with image_id, tags, and logs

        Raises:
            ValidationError: If path or tag is invalid
            DockerOperationError: If build fails
        """
        if tag:
            validate_image_name(tag)

        # Validate build context path for security
        resolved_path = _validate_build_context_path(path)

        logger.info(f"Building image from: {resolved_path}")
        await progress.set_message(f"Starting build from: {resolved_path}")

        # Use a queue for real-time progress streaming
        chunk_queue: Queue[Any] = Queue()
        build_error: list[Exception] = []
        build_result: list[tuple[Any, list[str]]] = []
        error_event = threading.Event()

        # Create and start the build worker
        worker = _create_build_streaming_worker(
            docker_client,
            str(resolved_path),
            tag,
            dockerfile,
            nocache,
            rm,
            pull,
            buildargs,
            chunk_queue,
            build_error,
            build_result,
            error_event,
        )
        build_task: asyncio.Future[None] = asyncio.get_running_loop().run_in_executor(None, worker)

        try:
            # Process chunks as they arrive (real-time progress)
            await _process_build_streaming_queue(
                chunk_queue, build_error, progress, ProgressThrottler(), error_event
            )

            # Wait for build thread to complete
            await build_task

            # Check for any errors from the build thread
            if build_error:
                raise build_error[0] from build_error[0]

            if not build_result:
                raise DockerOperationError("Build completed but no image was returned")

            image_obj, log_messages = build_result[0]

            logger.info(f"Successfully built image: {image_obj.id}")

            await progress.set_message(f"Build complete: {image_obj.id[:12]}")

            output = BuildImageOutput(
                image_id=str(image_obj.id), tags=image_obj.tags or [], logs=log_messages
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to build image: {e}")
            raise DockerOperationError(f"Failed to build image: {e}") from e
        finally:
            # Ensure worker thread is cleaned up even on error
            await _cleanup_worker_task(build_task, chunk_queue)

    return (
        "docker_build_image",
        "Build a Docker image from a Dockerfile",
        OperationSafety.MODERATE,
        False,  # not idempotent (creates different images)
        True,  # open_world (may pull base images)
        True,  # supports_task (background task with progress)
        build_image,
    )


def create_push_image_tool(  # noqa: PLR0915 - Complex streaming logic requires many statements
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the push_image FastMCP tool with background task support.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world,
                 supports_task, function)
    """

    async def push_image(  # noqa: PLR0915 - Complex streaming logic
        image: str,
        tag: str | None = None,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Push a Docker image to a registry with real-time progress reporting.

        Args:
            image: Image name to push
            tag: Optional tag
            progress: FastMCP Progress dependency for real-time updates

        Returns:
            Dictionary with image name and status

        Raises:
            ImageNotFound: If image doesn't exist locally
            DockerOperationError: If push fails
        """
        validate_image_name(image)
        logger.info(f"Pushing image: {image}")

        await progress.set_message(f"Starting push: {image}")

        # Use a queue for real-time progress streaming
        chunk_queue: Queue[dict[str, Any] | None] = Queue()
        push_error: list[Exception] = []
        error_event = threading.Event()

        # Create and start the push worker
        worker = _create_push_streaming_worker(
            docker_client, image, tag, chunk_queue, push_error, error_event
        )
        push_task = asyncio.get_running_loop().run_in_executor(None, worker)

        try:
            # Process chunks as they arrive (real-time progress)
            last_status = await _process_streaming_queue(
                chunk_queue, push_error, progress, ProgressThrottler(), "push", error_event
            )

            # Wait for push thread to complete
            await push_task

            # Check for any errors from the push thread
            if push_error:
                raise push_error[0] from push_error[0]

            status = last_status if last_status else "pushed"
            logger.info(f"Successfully pushed image: {image}")

            await progress.set_message(f"Push complete: {image}")

            output = PushImageOutput(image=image, status=status)
            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image}")
            raise ImageNotFound(f"Image not found: {image}") from e
        except APIError as e:
            logger.error(f"Failed to push image: {e}")
            raise DockerOperationError(f"Failed to push image: {e}") from e
        finally:
            # Ensure worker thread is cleaned up even on error
            await _cleanup_worker_task(push_task, chunk_queue)

    return (
        "docker_push_image",
        "Push a Docker image to a registry",
        OperationSafety.MODERATE,
        False,  # not idempotent (may push to different registries)
        True,  # open_world (pushes to registry)
        True,  # supports_task (background task with progress)
        push_image,
    )


def create_tag_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the tag_image FastMCP tool."""

    def tag_image(
        image: str,
        repository: str,
        tag: str = "latest",
    ) -> dict[str, Any]:
        """Tag a Docker image."""
        try:
            validate_image_name(f"{repository}:{tag}")
            logger.info(f"Tagging image: {image} as {repository}:{tag}")

            image_obj = docker_client.client.images.get(image)
            image_obj.tag(repository=repository, tag=tag)

            target = f"{repository}:{tag}"
            logger.info(f"Successfully tagged image: {target}")
            output = TagImageOutput(source=image, target=target)
            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image}")
            raise ImageNotFound(f"Image not found: {image}") from e
        except APIError as e:
            logger.error(f"Failed to tag image: {e}")
            raise DockerOperationError(f"Failed to tag image: {e}") from e

    return (
        "docker_tag_image",
        "Tag a Docker image",
        OperationSafety.MODERATE,
        True,  # idempotent (tagging with same tag overwrites)
        False,  # not open_world
        False,  # not supports_task
        tag_image,
    )


def create_remove_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the remove_image FastMCP tool."""

    def remove_image(
        image: str,
        force: bool = False,
        noprune: bool = False,
    ) -> dict[str, Any]:
        """Remove a Docker image."""
        try:
            logger.info(f"Removing image: {image} (force={force}, noprune={noprune})")
            docker_client.client.images.remove(image=image, force=force, noprune=noprune)

            logger.info(f"Successfully removed image: {image}")
            output = RemoveImageOutput(deleted=[{"Deleted": image}])
            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image}")
            raise ImageNotFound(f"Image not found: {image}") from e
        except APIError as e:
            logger.error(f"Failed to remove image: {e}")
            raise DockerOperationError(f"Failed to remove image: {e}") from e

    return (
        "docker_remove_image",
        "Remove a Docker image",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (image is gone after first removal)
        False,  # not open_world
        False,  # not supports_task
        remove_image,
    )


def create_prune_images_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the prune_images FastMCP tool."""

    def prune_images(
        all: bool = False,
        filters: dict[str, str | list[str]] | None = None,
        force_all: bool = False,
    ) -> dict[str, Any]:
        """Prune Docker images."""
        try:
            logger.info(f"Pruning images (all={all}, force_all={force_all}, filters={filters})")

            if force_all:
                deleted, space_reclaimed = _force_remove_all_images(docker_client.client)
                logger.info(
                    f"Successfully force-pruned {len(deleted)} images (force_all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            elif all:
                deleted, space_reclaimed = _prune_all_unused_images(docker_client.client, filters)
                logger.info(
                    f"Successfully pruned {len(deleted)} images (all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            else:
                # Standard prune (only dangling images) using SDK
                result = docker_client.client.images.prune(filters=filters)
                deleted = result.get("ImagesDeleted") or []
                space_reclaimed = result.get("SpaceReclaimed", 0)
                logger.info(
                    f"Successfully pruned {len(deleted)} images, reclaimed {space_reclaimed} bytes"
                )

            output = PruneImagesOutput(deleted=deleted, space_reclaimed=space_reclaimed)
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to prune images: {e}")
            raise DockerOperationError(f"Failed to prune images: {e}") from e

    return (
        "docker_prune_images",
        "Prune Docker images (unused by default, all with force_all=true)",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (different images may be pruned each time)
        False,  # not open_world
        False,  # not supports_task
        prune_images,
    )


def register_image_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all image tools with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        List of registered tool names
    """
    tools = [
        # SAFE tools
        create_list_images_tool(docker_client, safety_config),
        create_inspect_image_tool(docker_client),
        create_image_history_tool(docker_client, safety_config),
        # MODERATE tools
        create_pull_image_tool(docker_client),
        create_build_image_tool(docker_client),
        create_push_image_tool(docker_client),
        create_tag_image_tool(docker_client),
        # DESTRUCTIVE tools
        create_remove_image_tool(docker_client),
        create_prune_images_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
