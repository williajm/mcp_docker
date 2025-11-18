"""FastMCP image tools (SAFE operations).

This module contains read-only image tools migrated to FastMCP 2.0.
"""

import json
from typing import Any

from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_IMAGE_NOT_FOUND
from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    truncate_list,
)
from mcp_docker.utils.prune_helpers import force_remove_all_images, prune_all_unused_images
from mcp_docker.utils.safety import OperationSafety
from mcp_docker.utils.validation import validate_image_name

logger = get_logger(__name__)


def _parse_build_logs(build_logs: Any) -> list[str]:
    """Parse Docker build logs and extract stream messages.

    Args:
        build_logs: Raw build logs from Docker API

    Returns:
        List of log message strings
    """
    log_messages = []
    for log in build_logs:
        if isinstance(log, dict) and "stream" in log:
            stream_val = log.get("stream")
            if isinstance(stream_val, str):
                log_messages.append(stream_val.strip())
    return log_messages


def _parse_push_stream(push_stream: str | bytes) -> tuple[str | None, str | None]:
    """Parse Docker push stream and extract status/error.

    Args:
        push_stream: Raw push stream from Docker API

    Returns:
        Tuple of (last_status, error_message)
    """
    last_status = None
    error_message = None

    # Convert bytes to str if needed
    stream_str = push_stream if isinstance(push_stream, str) else str(push_stream)
    lines = stream_str.split("\n")
    for line in lines:
        if not line.strip():
            continue
        try:
            status_obj = json.loads(line)
            if "error" in status_obj:
                error_message = status_obj["error"]
                break
            if "status" in status_obj:
                last_status = status_obj["status"]
        except json.JSONDecodeError:
            continue

    return last_status, error_message


# Common field descriptions (avoid string duplication per SonarCloud S1192)
DESC_IMAGE_ID = "Image name or ID"
DESC_TRUNCATION_INFO = "Information about output truncation if applied"

# Input/Output Models (reused from legacy tools)


class ListImagesInput(BaseModel):
    """Input for listing images."""

    all: bool = Field(default=False, description="Show all images including intermediates")
    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'dangling': ['true']}, {'reference': 'ubuntu:*'}, "
            "{'label': ['maintainer=myname']}"
        ),
    )


class ListImagesOutput(BaseModel):
    """Output for listing images."""

    images: list[dict[str, Any]] = Field(description="List of images with basic info")
    count: int = Field(description="Total number of images")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


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
    def parse_buildargs_json(cls, v: Any, info: Any) -> Any:
        """Parse JSON strings to objects (workaround for MCP client serialization bug)."""
        field_name = info.field_name if hasattr(info, "field_name") else "buildargs"
        return parse_json_string_field(v, field_name)


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
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the list_images FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
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

            # Apply output limits
            original_count = len(image_list)
            truncation_info: dict[str, Any] = {}
            if safety_config.max_list_results > 0:
                image_list, was_truncated = truncate_list(
                    image_list,
                    safety_config.max_list_results,
                )
                if was_truncated:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_count=original_count,
                        truncated_count=len(image_list),
                    )
                    truncation_info["message"] = (
                        f"Results truncated: showing {len(image_list)} of {original_count} "
                        f"images. Set SAFETY_MAX_LIST_RESULTS=0 to disable limit."
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
        list_images,
    )


def create_inspect_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the inspect_image FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
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
        inspect_image,
    )


def create_image_history_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the image_history FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
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

            # Apply output limits
            original_count = len(history)
            truncation_info: dict[str, Any] = {}
            if safety_config.max_list_results > 0:
                history, was_truncated = truncate_list(
                    history,
                    safety_config.max_list_results,
                )
                if was_truncated:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_count=original_count,
                        truncated_count=len(history),
                    )
                    truncation_info["message"] = (
                        f"Results truncated: showing {len(history)} of {original_count} "
                        f"layers. Set SAFETY_MAX_LIST_RESULTS=0 to disable limit."
                    )

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
        image_history,
    )


def create_pull_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the pull_image FastMCP tool."""

    def pull_image(
        image: str,
        tag: str | None = None,
        all_tags: bool = False,
        platform: str | None = None,
    ) -> dict[str, Any]:
        """Pull a Docker image from a registry."""
        try:
            validate_image_name(image)
            logger.info(f"Pulling image: {image}")

            kwargs: dict[str, Any] = {"repository": image}
            if tag:
                kwargs["tag"] = tag
            if all_tags:
                kwargs["all_tags"] = all_tags
            if platform:
                kwargs["platform"] = platform

            image_obj = docker_client.client.images.pull(**kwargs)
            logger.info(f"Successfully pulled image: {image}")

            output = PullImageOutput(image=image, id=str(image_obj.id), tags=image_obj.tags)
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
        pull_image,
    )


def create_build_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the build_image FastMCP tool."""

    def build_image(  # noqa: PLR0913 - Docker API requires these parameters
        path: str,
        tag: str | None = None,
        dockerfile: str = "Dockerfile",
        buildargs: dict[str, str] | None = None,
        nocache: bool = False,
        rm: bool = True,
        pull: bool = False,
    ) -> dict[str, Any]:
        """Build a Docker image from a Dockerfile."""
        try:
            if tag:
                validate_image_name(tag)

            logger.info(f"Building image from: {path}")

            kwargs: dict[str, Any] = {
                "path": path,
                "dockerfile": dockerfile,
                "nocache": nocache,
                "rm": rm,
                "pull": pull,
            }
            if tag:
                kwargs["tag"] = tag
            if buildargs:
                kwargs["buildargs"] = buildargs

            image_obj, build_logs = docker_client.client.images.build(**kwargs)

            log_messages = _parse_build_logs(build_logs)

            logger.info(f"Successfully built image: {image_obj.id}")
            output = BuildImageOutput(
                image_id=str(image_obj.id), tags=image_obj.tags, logs=log_messages
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
        build_image,
    )


def create_push_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the push_image FastMCP tool."""

    def push_image(
        image: str,
        tag: str | None = None,
    ) -> dict[str, Any]:
        """Push a Docker image to a registry."""
        try:
            validate_image_name(image)
            logger.info(f"Pushing image: {image}")

            kwargs: dict[str, Any] = {"repository": image}
            if tag:
                kwargs["tag"] = tag

            push_stream = docker_client.client.images.push(**kwargs)

            last_status, error_message = _parse_push_stream(push_stream)

            if error_message:
                logger.error(f"Failed to push image: {error_message}")
                raise DockerOperationError(f"Failed to push image: {error_message}")

            status = last_status if last_status else "pushed"
            logger.info(f"Successfully pushed image: {image}")
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
        push_image,
    )


def create_tag_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
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
        tag_image,
    )


def create_remove_image_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
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
        remove_image,
    )


def create_prune_images_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
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
                deleted, space_reclaimed = force_remove_all_images(docker_client.client)
                logger.info(
                    f"Successfully force-pruned {len(deleted)} images (force_all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            elif all:
                deleted, space_reclaimed = prune_all_unused_images(docker_client.client, filters)
                logger.info(
                    f"Successfully pruned {len(deleted)} images (all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            else:
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
