"""FastMCP image tools."""

from typing import Any

from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import (
    DESC_IMAGE_ID,
    FiltersInput,
    ToolSpec,
)
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_IMAGE_NOT_FOUND

logger = get_logger(__name__)


# Input/Output Models (reused from legacy tools)


class ListImagesInput(FiltersInput):
    """Input for listing images."""

    all: bool = Field(default=False, description="Show all images including intermediates")


class ListImagesOutput(BaseModel):
    """Output for listing images."""

    images: list[dict[str, Any]] = Field(description="List of images with basic info")
    count: int = Field(description="Total number of images found")


class InspectImageInput(BaseModel):
    """Input for inspecting an image."""

    image_name: str = Field(description=DESC_IMAGE_ID)


class InspectImageOutput(BaseModel):
    """Output for inspecting an image."""

    details: dict[str, Any] = Field(description="Detailed image information")


# FastMCP Tool Functions


def create_list_images_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the list_images tool."""

    def list_images(
        all: bool = False,
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker images with optional filters."""
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

            logger.info(f"Found {len(image_list)} images")

            output = ListImagesOutput(
                images=image_list,
                count=len(image_list),
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list images: {e}")
            raise DockerOperationError(f"Failed to list images: {e}") from e

    return ToolSpec(
        name="docker_list_images",
        description="List Docker images with optional filters",
        safety=OperationSafety.SAFE,
        func=list_images,
        idempotent=True,
    )


def create_inspect_image_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the inspect_image tool."""

    def inspect_image(
        image_name: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker image."""
        try:
            logger.info(f"Inspecting image: {image_name}")
            image = docker_client.client.images.get(image_name)
            details = image.attrs

            logger.info(f"Successfully inspected image: {image_name}")

            output = InspectImageOutput(details=details)

            return output.model_dump()

        except (DockerImageNotFound, NotFound) as e:
            logger.error(f"Image not found: {image_name}")
            raise ImageNotFound(ERROR_IMAGE_NOT_FOUND.format(image_name)) from e
        except APIError as e:
            logger.error(f"Failed to inspect image: {e}")
            raise DockerOperationError(f"Failed to inspect image: {e}") from e

    return ToolSpec(
        name="docker_inspect_image",
        description="Get detailed information about a Docker image",
        safety=OperationSafety.SAFE,
        func=inspect_image,
        idempotent=True,
    )


def register_image_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register read-only image tools with FastMCP."""
    tools = [
        create_list_images_tool(docker_client),
        create_inspect_image_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
