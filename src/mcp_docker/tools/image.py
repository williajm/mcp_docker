"""FastMCP image tools (SAFE operations).

This module contains read-only image tools migrated to FastMCP 2.0.
"""

import asyncio
from pathlib import Path
from typing import Any

from docker.errors import APIError, DockerException, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from docker.utils.json_stream import json_stream
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


def _parse_build_logs_from_stream(build_logs: Any) -> list[str]:
    """Parse build logs using Docker SDK's json_stream utility.

    Args:
        build_logs: Raw build logs from Docker API

    Returns:
        List of log message strings
    """
    log_messages = []
    for log_entry in json_stream(build_logs):
        if isinstance(log_entry, dict) and "stream" in log_entry:
            stream_val = log_entry.get("stream")
            if isinstance(stream_val, str):
                log_messages.append(stream_val.strip())
    return log_messages


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


def _parse_push_stream_for_status(push_stream: Any) -> tuple[str | None, str | None]:
    """Parse push stream using Docker SDK's json_stream utility.

    Args:
        push_stream: Raw push stream from Docker API

    Returns:
        Tuple of (last_status, error_message)
    """
    last_status: str | None = None
    error_message: str | None = None

    for status_entry in json_stream(push_stream):
        if not isinstance(status_entry, dict):
            continue

        # Check for errors first (errors terminate the loop)
        if "error" in status_entry:
            error_val = status_entry["error"]
            if error_val is not None:
                error_message = str(error_val)
            break

        # Track last status
        if "status" in status_entry:
            status_val = status_entry["status"]
            if status_val is not None:
                last_status = str(status_val)

    return last_status, error_message


async def _report_layer_progress(
    progress: Progress,
    chunk: dict[str, Any],
) -> str | None:
    """Report progress for a single layer chunk and return status if present.

    Args:
        progress: FastMCP Progress dependency
        chunk: Streaming chunk from Docker API

    Returns:
        Status string if present, None otherwise
    """
    layer_id = str(chunk.get("id", ""))[:12]
    status = str(chunk.get("status", ""))

    if "progressDetail" in chunk and chunk["progressDetail"]:
        detail = chunk["progressDetail"]
        current = detail.get("current", 0)
        total = detail.get("total", 0)
        if total > 0:
            pct = int((current / total) * 100)
            cur_mb = current / 1024 / 1024
            tot_mb = total / 1024 / 1024
            msg = f"Layer {layer_id}: {status} {pct}% ({cur_mb:.1f}MB/{tot_mb:.1f}MB)"
            await progress.set_message(msg)
        elif layer_id:
            await progress.set_message(f"Layer {layer_id}: {status}")
    elif status:
        if layer_id:
            await progress.set_message(f"Layer {layer_id}: {status}")
        else:
            await progress.set_message(status)

    return status if "status" in chunk else None


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


def create_pull_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the pull_image FastMCP tool with background task support."""

    async def pull_image(
        image: str,
        tag: str | None = None,
        all_tags: bool = False,
        platform: str | None = None,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Pull a Docker image from a registry with progress reporting."""
        try:
            validate_image_name(image)
            logger.info(f"Pulling image: {image}")

            await progress.set_message(f"Starting pull: {image}")

            # Build kwargs for the pull
            pull_tag = tag
            pull_platform = platform
            pull_all_tags = all_tags

            def _pull_with_streaming() -> list[dict[str, Any]]:
                """Pull image using low-level API with streaming."""
                stream = docker_client.client.api.pull(
                    repository=image,
                    tag=pull_tag,
                    stream=True,
                    decode=True,
                    all_tags=pull_all_tags,
                    platform=pull_platform,
                )
                return list(stream)

            # Run the blocking Docker pull in a thread
            chunks = await asyncio.to_thread(_pull_with_streaming)

            # Report progress and check for errors
            for chunk in chunks:
                # Check for errors first
                if "error" in chunk and chunk["error"] is not None:
                    error_msg = str(chunk["error"])
                    logger.error(f"Failed to pull image: {error_msg}")
                    raise DockerOperationError(f"Failed to pull image: {error_msg}")

                # Report progress using helper
                await _report_layer_progress(progress, chunk)

            # Get the final image object
            def _get_image() -> Any:
                full_name = f"{image}:{tag}" if tag else image
                return docker_client.client.images.get(full_name)

            image_obj = await asyncio.to_thread(_get_image)
            logger.info(f"Successfully pulled image: {image}")

            await progress.set_message(f"Pull complete: {image}")

            output = PullImageOutput(image=image, id=str(image_obj.id), tags=image_obj.tags or [])
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to pull image: {e}")
            raise DockerOperationError(f"Failed to pull image: {e}") from e

    return (
        "docker_pull_image",
        "Pull a Docker image from a registry",
        OperationSafety.MODERATE,
        True,  # idempotent
        True,  # open_world (pulls from registry)
        True,  # supports_task (background task with progress)
        pull_image,
    )


def create_build_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the build_image FastMCP tool with background task support."""

    async def build_image(  # noqa: PLR0913 - Docker API requires these parameters
        path: str,
        tag: str | None = None,
        dockerfile: str = "Dockerfile",
        buildargs: dict[str, str] | None = None,
        nocache: bool = False,
        rm: bool = True,
        pull: bool = False,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Build a Docker image from a Dockerfile with progress reporting."""
        try:
            if tag:
                validate_image_name(tag)

            # Validate build context path for security
            resolved_path = _validate_build_context_path(path)

            logger.info(f"Building image from: {resolved_path}")

            await progress.set_message(f"Starting build from: {resolved_path}")

            # Capture build parameters for closure
            build_tag = tag
            build_dockerfile = dockerfile
            build_nocache = nocache
            build_rm = rm
            build_pull = pull
            build_buildargs = buildargs

            def _build_with_streaming() -> tuple[Any, list[Any]]:
                """Build image and collect streaming logs."""
                kwargs: dict[str, Any] = {
                    "path": str(resolved_path),
                    "dockerfile": build_dockerfile,
                    "nocache": build_nocache,
                    "rm": build_rm,
                    "pull": build_pull,
                }
                if build_tag:
                    kwargs["tag"] = build_tag
                if build_buildargs:
                    kwargs["buildargs"] = build_buildargs

                image_obj, build_logs_gen = docker_client.client.images.build(**kwargs)
                # Collect the streaming logs
                build_logs = list(build_logs_gen)
                return image_obj, build_logs

            # Run the blocking Docker build in a thread
            image_obj, build_logs = await asyncio.to_thread(_build_with_streaming)

            # Report progress from the collected build logs
            log_messages = []
            for log_entry in build_logs:
                if isinstance(log_entry, dict) and "stream" in log_entry:
                    stream_val = log_entry.get("stream")
                    if isinstance(stream_val, str):
                        msg = stream_val.strip()
                        if msg:
                            log_messages.append(msg)
                            # Report step progress
                            if msg.startswith("Step "):
                                await progress.set_message(f"Build {msg}")
                            elif "Successfully built" in msg:
                                await progress.set_message(msg)

            logger.info(f"Successfully built image: {image_obj.id}")

            await progress.set_message(f"Build complete: {image_obj.id[:12]}")

            output = BuildImageOutput(
                image_id=str(image_obj.id), tags=image_obj.tags or [], logs=log_messages
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to build image: {e}")
            raise DockerOperationError(f"Failed to build image: {e}") from e

    return (
        "docker_build_image",
        "Build a Docker image from a Dockerfile",
        OperationSafety.MODERATE,
        False,  # not idempotent (creates different images)
        True,  # open_world (may pull base images)
        True,  # supports_task (background task with progress)
        build_image,
    )


def create_push_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, bool, Any]:
    """Create the push_image FastMCP tool with background task support."""

    async def push_image(
        image: str,
        tag: str | None = None,
        progress: Progress = Progress(),  # noqa: B008 - FastMCP dependency injection
    ) -> dict[str, Any]:
        """Push a Docker image to a registry with progress reporting."""
        try:
            validate_image_name(image)
            logger.info(f"Pushing image: {image}")

            await progress.set_message(f"Starting push: {image}")

            # Capture parameters for closure
            push_tag = tag

            def _push_with_streaming() -> list[dict[str, Any]]:
                """Push image using low-level API with streaming."""
                stream = docker_client.client.api.push(
                    repository=image,
                    tag=push_tag,
                    stream=True,
                    decode=True,
                )
                return list(stream)

            # Run the blocking Docker push in a thread
            chunks = await asyncio.to_thread(_push_with_streaming)

            # Report progress and check for errors
            last_status: str | None = None

            for chunk in chunks:
                # Check for errors first
                if "error" in chunk and chunk["error"] is not None:
                    error_msg = str(chunk["error"])
                    logger.error(f"Failed to push image: {error_msg}")
                    raise DockerOperationError(f"Failed to push image: {error_msg}")

                # Report progress using helper
                status = await _report_layer_progress(progress, chunk)
                if status:
                    last_status = status

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
