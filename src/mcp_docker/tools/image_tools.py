"""Image management tools for Docker MCP server.

This module provides tools for managing Docker images, including
listing, inspecting, pulling, building, pushing, and removing images.
"""

import json
from typing import Any

from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.prune_helpers import force_remove_all_images, prune_all_unused_images
from mcp_docker.utils.safety import OperationSafety
from mcp_docker.utils.validation import validate_image_name

logger = get_logger(__name__)

# Constants
IMAGE_NAME_OR_ID_DESCRIPTION = "Image name or ID"


# Input/Output Models


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


class InspectImageInput(BaseModel):
    """Input for inspecting an image."""

    image_name: str = Field(description=IMAGE_NAME_OR_ID_DESCRIPTION)


class InspectImageOutput(BaseModel):
    """Output for inspecting an image."""

    details: dict[str, Any] = Field(description="Detailed image information")


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

    image: str = Field(description=IMAGE_NAME_OR_ID_DESCRIPTION)
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
            "Examples: {'dangling': ['true']}, {'until': '24h'}, "
            "{'label': ['env=test']}"
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


class ImageHistoryInput(BaseModel):
    """Input for viewing image history."""

    image: str = Field(description=IMAGE_NAME_OR_ID_DESCRIPTION)


class ImageHistoryOutput(BaseModel):
    """Output for viewing image history."""

    history: list[dict[str, Any]] = Field(description="Image layer history")


# Tool Implementations


class ListImagesTool(BaseTool):
    """List Docker images with optional filters."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_list_images"

    @property
    def description(self) -> str:
        """Tool description."""
        return "List Docker images with optional filters"

    @property
    def input_schema(self) -> type[ListImagesInput]:
        """Input schema."""
        return ListImagesInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ListImagesInput) -> ListImagesOutput:
        """Execute the list images operation.

        Args:
            input_data: Input parameters

        Returns:
            List of images with basic info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing images (all={input_data.all}, filters={input_data.filters})")
            images = self.docker.client.images.list(all=input_data.all, filters=input_data.filters)

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

            logger.info(f"Found {len(image_list)} images")
            return ListImagesOutput(images=image_list, count=len(image_list))

        except APIError as e:
            logger.error(f"Failed to list images: {e}")
            raise DockerOperationError(f"Failed to list images: {e}") from e


class InspectImageTool(BaseTool):
    """Inspect a Docker image to get detailed information."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_inspect_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get detailed information about a Docker image"

    @property
    def input_schema(self) -> type[InspectImageInput]:
        """Input schema."""
        return InspectImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: InspectImageInput) -> InspectImageOutput:
        """Execute the inspect image operation.

        Args:
            input_data: Input parameters

        Returns:
            Detailed image information

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting image: {input_data.image_name}")
            image = self.docker.client.images.get(input_data.image_name)
            details = image.attrs

            logger.info(f"Successfully inspected image: {input_data.image_name}")
            return InspectImageOutput(details=details)

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image_name}")
            raise ImageNotFound(f"Image not found: {input_data.image_name}") from e
        except APIError as e:
            logger.error(f"Failed to inspect image: {e}")
            raise DockerOperationError(f"Failed to inspect image: {e}") from e


class PullImageTool(BaseTool):
    """Pull a Docker image from a registry."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_pull_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Pull a Docker image from a registry"

    @property
    def input_schema(self) -> type[PullImageInput]:
        """Input schema."""
        return PullImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: PullImageInput) -> PullImageOutput:
        """Execute the pull image operation.

        Args:
            input_data: Input parameters

        Returns:
            Pulled image information

        Raises:
            DockerOperationError: If pull fails
        """
        try:
            validate_image_name(input_data.image)

            logger.info(f"Pulling image: {input_data.image}")

            # Prepare kwargs for pull
            kwargs: dict[str, Any] = {"repository": input_data.image}
            if input_data.tag:
                kwargs["tag"] = input_data.tag
            if input_data.all_tags:
                kwargs["all_tags"] = input_data.all_tags
            if input_data.platform:
                kwargs["platform"] = input_data.platform

            image = self.docker.client.images.pull(**kwargs)

            logger.info(f"Successfully pulled image: {input_data.image}")
            return PullImageOutput(image=input_data.image, id=str(image.id), tags=image.tags)

        except APIError as e:
            logger.error(f"Failed to pull image: {e}")
            raise DockerOperationError(f"Failed to pull image: {e}") from e


class BuildImageTool(BaseTool):
    """Build a Docker image from a Dockerfile."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_build_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Build a Docker image from a Dockerfile"

    @property
    def input_schema(self) -> type[BuildImageInput]:
        """Input schema."""
        return BuildImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: BuildImageInput) -> BuildImageOutput:
        """Execute the build image operation.

        Args:
            input_data: Input parameters

        Returns:
            Built image information

        Raises:
            DockerOperationError: If build fails
        """
        try:
            if input_data.tag:
                validate_image_name(input_data.tag)

            logger.info(f"Building image from: {input_data.path}")

            # Prepare kwargs for build
            kwargs: dict[str, Any] = {
                "path": input_data.path,
                "dockerfile": input_data.dockerfile,
                "nocache": input_data.nocache,
                "rm": input_data.rm,
                "pull": input_data.pull,
            }
            if input_data.tag:
                kwargs["tag"] = input_data.tag
            if input_data.buildargs:
                kwargs["buildargs"] = input_data.buildargs

            image, build_logs = self.docker.client.images.build(**kwargs)

            # Extract log messages
            log_messages = []
            for log in build_logs:
                if isinstance(log, dict) and "stream" in log:
                    stream_val = log.get("stream")
                    if isinstance(stream_val, str):
                        log_messages.append(stream_val.strip())

            logger.info(f"Successfully built image: {image.id}")
            return BuildImageOutput(image_id=str(image.id), tags=image.tags, logs=log_messages)

        except APIError as e:
            logger.error(f"Failed to build image: {e}")
            raise DockerOperationError(f"Failed to build image: {e}") from e


class PushImageTool(BaseTool):
    """Push a Docker image to a registry."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_push_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Push a Docker image to a registry"

    @property
    def input_schema(self) -> type[PushImageInput]:
        """Input schema."""
        return PushImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: PushImageInput) -> PushImageOutput:
        """Execute the push image operation.

        Args:
            input_data: Input parameters

        Returns:
            Push operation status

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If push fails
        """
        try:
            validate_image_name(input_data.image)

            logger.info(f"Pushing image: {input_data.image}")

            # Prepare kwargs for push
            kwargs: dict[str, Any] = {"repository": input_data.image}
            if input_data.tag:
                kwargs["tag"] = input_data.tag

            # Push returns a generator of status updates (JSON strings)
            push_stream = self.docker.client.images.push(**kwargs)

            # Parse the stream to check for errors and get final status
            last_status = None
            error_message = None

            for line in push_stream.split("\n") if isinstance(push_stream, str) else [push_stream]:
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

            # If we found an error, raise it
            if error_message:
                logger.error(f"Failed to push image: {error_message}")
                raise DockerOperationError(f"Failed to push image: {error_message}")

            # Use the last status or default to "pushed"
            status = last_status if last_status else "pushed"

            logger.info(f"Successfully pushed image: {input_data.image}")
            return PushImageOutput(image=input_data.image, status=status)

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image}")
            raise ImageNotFound(f"Image not found: {input_data.image}") from e
        except APIError as e:
            logger.error(f"Failed to push image: {e}")
            raise DockerOperationError(f"Failed to push image: {e}") from e


class TagImageTool(BaseTool):
    """Tag a Docker image."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_tag_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Tag a Docker image"

    @property
    def input_schema(self) -> type[TagImageInput]:
        """Input schema."""
        return TagImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: TagImageInput) -> TagImageOutput:
        """Execute the tag image operation.

        Args:
            input_data: Input parameters

        Returns:
            Tag operation result

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If tagging fails
        """
        try:
            validate_image_name(f"{input_data.repository}:{input_data.tag}")

            logger.info(
                f"Tagging image: {input_data.image} as {input_data.repository}:{input_data.tag}"
            )

            image = self.docker.client.images.get(input_data.image)
            image.tag(repository=input_data.repository, tag=input_data.tag)

            target = f"{input_data.repository}:{input_data.tag}"
            logger.info(f"Successfully tagged image: {target}")
            return TagImageOutput(source=input_data.image, target=target)

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image}")
            raise ImageNotFound(f"Image not found: {input_data.image}") from e
        except APIError as e:
            logger.error(f"Failed to tag image: {e}")
            raise DockerOperationError(f"Failed to tag image: {e}") from e


class RemoveImageTool(BaseTool):
    """Remove a Docker image."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_remove_image"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Remove a Docker image"

    @property
    def input_schema(self) -> type[RemoveImageInput]:
        """Input schema."""
        return RemoveImageInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

    async def execute(self, input_data: RemoveImageInput) -> RemoveImageOutput:
        """Execute the remove image operation.

        Args:
            input_data: Input parameters

        Returns:
            Remove operation result

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(
                f"Removing image: {input_data.image} (force={input_data.force}, "
                f"noprune={input_data.noprune})"
            )

            self.docker.client.images.remove(
                image=input_data.image, force=input_data.force, noprune=input_data.noprune
            )

            logger.info(f"Successfully removed image: {input_data.image}")
            return RemoveImageOutput(deleted=[{"Deleted": input_data.image}])

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image}")
            raise ImageNotFound(f"Image not found: {input_data.image}") from e
        except APIError as e:
            logger.error(f"Failed to remove image: {e}")
            raise DockerOperationError(f"Failed to remove image: {e}") from e


class PruneImagesTool(BaseTool):
    """Remove unused Docker images."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_prune_images"

    @property
    def description(self) -> str:
        """Tool description."""
        return (
            "Prune Docker images. By default, removes only UNUSED/dangling images. "
            "To remove ALL images including tagged ones, use force_all=true. "
            "IMPORTANT: When user asks to 'remove all images' or 'delete all images', "
            "use force_all=true."
        )

    @property
    def input_schema(self) -> type[PruneImagesInput]:
        """Input schema."""
        return PruneImagesInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

    async def execute(self, input_data: PruneImagesInput) -> PruneImagesOutput:
        """Execute the prune images operation.

        Args:
            input_data: Input parameters

        Returns:
            Prune operation result

        Raises:
            DockerOperationError: If pruning fails
        """
        try:
            logger.info(
                f"Pruning images (all={input_data.all}, force_all={input_data.force_all}, "
                f"filters={input_data.filters})"
            )

            # Delegate to helper functions based on mode
            if input_data.force_all:
                deleted, space_reclaimed = force_remove_all_images(self.docker.client)
                logger.info(
                    f"Successfully force-pruned {len(deleted)} images (force_all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            elif input_data.all:
                deleted, space_reclaimed = prune_all_unused_images(
                    self.docker.client, input_data.filters
                )
                logger.info(
                    f"Successfully pruned {len(deleted)} images (all=True), "
                    f"reclaimed {space_reclaimed} bytes"
                )
            else:
                # Standard prune (only dangling images)
                result = self.docker.client.images.prune(filters=input_data.filters)
                deleted = result.get("ImagesDeleted") or []
                space_reclaimed = result.get("SpaceReclaimed", 0)
                logger.info(
                    f"Successfully pruned {len(deleted)} images, reclaimed {space_reclaimed} bytes"
                )

            return PruneImagesOutput(deleted=deleted, space_reclaimed=space_reclaimed)

        except APIError as e:
            logger.error(f"Failed to prune images: {e}")
            raise DockerOperationError(f"Failed to prune images: {e}") from e


class ImageHistoryTool(BaseTool):
    """View the history of a Docker image."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_image_history"

    @property
    def description(self) -> str:
        """Tool description."""
        return "View the history of a Docker image"

    @property
    def input_schema(self) -> type[ImageHistoryInput]:
        """Input schema."""
        return ImageHistoryInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ImageHistoryInput) -> ImageHistoryOutput:
        """Execute the image history operation.

        Args:
            input_data: Input parameters

        Returns:
            Image layer history

        Raises:
            ImageNotFound: If image doesn't exist
            DockerOperationError: If history retrieval fails
        """
        try:
            logger.info(f"Getting history for image: {input_data.image}")

            image = self.docker.client.images.get(input_data.image)
            history = image.history()

            logger.info(f"Successfully retrieved history for image: {input_data.image}")
            return ImageHistoryOutput(history=history)

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image}")
            raise ImageNotFound(f"Image not found: {input_data.image}") from e
        except APIError as e:
            logger.error(f"Failed to get image history: {e}")
            raise DockerOperationError(f"Failed to get image history: {e}") from e


# Export all tools
__all__ = [
    "ListImagesTool",
    "InspectImageTool",
    "PullImageTool",
    "BuildImageTool",
    "PushImageTool",
    "TagImageTool",
    "RemoveImageTool",
    "PruneImagesTool",
    "ImageHistoryTool",
]
