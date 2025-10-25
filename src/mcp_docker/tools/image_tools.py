"""Image management tools for Docker MCP server.

This module provides tools for managing Docker images, including
listing, inspecting, pulling, building, pushing, and removing images.
"""

import json
from typing import Any

from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.base import OperationSafety
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.validation import validate_image_name

logger = get_logger(__name__)


# Input/Output Models


class ListImagesInput(BaseModel):
    """Input for listing images."""

    all: bool = Field(default=False, description="Show all images including intermediates")
    filters: dict[str, str | list[str]] | None = Field(
        default=None, description="Filters to apply (e.g., {'dangling': ['true']})"
    )


class ListImagesOutput(BaseModel):
    """Output for listing images."""

    images: list[dict[str, Any]] = Field(description="List of images with basic info")
    count: int = Field(description="Total number of images")


class InspectImageInput(BaseModel):
    """Input for inspecting an image."""

    image_name: str = Field(description="Image name or ID")


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
    buildargs: dict[str, str] | None = Field(default=None, description="Build arguments")
    nocache: bool = Field(default=False, description="Do not use cache")
    rm: bool = Field(default=True, description="Remove intermediate containers")
    pull: bool = Field(default=False, description="Always pull newer base images")


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

    image: str = Field(description="Image name or ID")
    force: bool = Field(default=False, description="Force removal")
    noprune: bool = Field(default=False, description="Do not delete untagged parents")


class RemoveImageOutput(BaseModel):
    """Output for removing an image."""

    deleted: list[dict[str, Any]] = Field(description="List of deleted items")


class PruneImagesInput(BaseModel):
    """Input for pruning unused images."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None, description="Filters (e.g., {'dangling': ['true']})"
    )


class PruneImagesOutput(BaseModel):
    """Output for pruning images."""

    deleted: list[dict[str, Any]] = Field(description="List of deleted images")
    space_reclaimed: int = Field(description="Disk space reclaimed in bytes")


class ImageHistoryInput(BaseModel):
    """Input for viewing image history."""

    image: str = Field(description="Image name or ID")


class ImageHistoryOutput(BaseModel):
    """Output for viewing image history."""

    history: list[dict[str, Any]] = Field(description="Image layer history")


# Tool Implementations


class ListImagesTool:
    """List Docker images with optional filters."""

    name = "docker_list_images"
    description = "List Docker images with optional filters"
    input_model = ListImagesInput
    output_model = ListImagesOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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
            images = self.docker_client.client.images.list(
                all=input_data.all, filters=input_data.filters
            )

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


class InspectImageTool:
    """Inspect a Docker image to get detailed information."""

    name = "docker_inspect_image"
    description = "Get detailed information about a Docker image"
    input_model = InspectImageInput
    output_model = InspectImageOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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
            image = self.docker_client.client.images.get(input_data.image_name)
            details = image.attrs

            logger.info(f"Successfully inspected image: {input_data.image_name}")
            return InspectImageOutput(details=details)

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {input_data.image_name}")
            raise ImageNotFound(f"Image not found: {input_data.image_name}") from e
        except APIError as e:
            logger.error(f"Failed to inspect image: {e}")
            raise DockerOperationError(f"Failed to inspect image: {e}") from e


class PullImageTool:
    """Pull a Docker image from a registry."""

    name = "docker_pull_image"
    description = "Pull a Docker image from a registry"
    input_model = PullImageInput
    output_model = PullImageOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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

            image = self.docker_client.client.images.pull(**kwargs)

            logger.info(f"Successfully pulled image: {input_data.image}")
            return PullImageOutput(image=input_data.image, id=str(image.id), tags=image.tags)

        except APIError as e:
            logger.error(f"Failed to pull image: {e}")
            raise DockerOperationError(f"Failed to pull image: {e}") from e


class BuildImageTool:
    """Build a Docker image from a Dockerfile."""

    name = "docker_build_image"
    description = "Build a Docker image from a Dockerfile"
    input_model = BuildImageInput
    output_model = BuildImageOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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

            image, build_logs = self.docker_client.client.images.build(**kwargs)

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


class PushImageTool:
    """Push a Docker image to a registry."""

    name = "docker_push_image"
    description = "Push a Docker image to a registry"
    input_model = PushImageInput
    output_model = PushImageOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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
            push_stream = self.docker_client.client.images.push(**kwargs)

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


class TagImageTool:
    """Tag a Docker image."""

    name = "docker_tag_image"
    description = "Tag a Docker image"
    input_model = TagImageInput
    output_model = TagImageOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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

            image = self.docker_client.client.images.get(input_data.image)
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


class RemoveImageTool:
    """Remove a Docker image."""

    name = "docker_remove_image"
    description = "Remove a Docker image"
    input_model = RemoveImageInput
    output_model = RemoveImageOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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

            self.docker_client.client.images.remove(
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


class PruneImagesTool:
    """Remove unused Docker images."""

    name = "docker_prune_images"
    description = "Remove unused Docker images"
    input_model = PruneImagesInput
    output_model = PruneImagesOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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
            logger.info(f"Pruning images (filters={input_data.filters})")

            result = self.docker_client.client.images.prune(filters=input_data.filters)

            deleted = result.get("ImagesDeleted") or []
            space_reclaimed = result.get("SpaceReclaimed", 0)

            logger.info(
                f"Successfully pruned {len(deleted)} images, reclaimed {space_reclaimed} bytes"
            )
            return PruneImagesOutput(deleted=deleted, space_reclaimed=space_reclaimed)

        except APIError as e:
            logger.error(f"Failed to prune images: {e}")
            raise DockerOperationError(f"Failed to prune images: {e}") from e


class ImageHistoryTool:
    """View the history of a Docker image."""

    name = "docker_image_history"
    description = "View the history of a Docker image"
    input_model = ImageHistoryInput
    output_model = ImageHistoryOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

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

            image = self.docker_client.client.images.get(input_data.image)
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
