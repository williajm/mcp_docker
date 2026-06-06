"""FastMCP volume tools."""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import (
    FiltersInput,
    ToolSpec,
)
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# Input/Output Models (reused from legacy tools)


class ListVolumesInput(FiltersInput):
    """Input for listing volumes."""


class ListVolumesOutput(BaseModel):
    """Output for listing volumes."""

    volumes: list[dict[str, Any]] = Field(description="List of volumes with basic info")
    count: int = Field(description="Total number of volumes found")


# FastMCP Tool Functions


def create_list_volumes_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the list_volumes tool."""

    def list_volumes(
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker volumes with optional filters."""
        try:
            logger.info(f"Listing volumes (filters={filters})")
            volumes = docker_client.client.volumes.list(filters=filters)

            volume_list = [
                {
                    "name": vol.name,
                    "driver": vol.attrs.get("Driver", "unknown"),
                    "mountpoint": vol.attrs.get("Mountpoint", ""),
                    "labels": vol.attrs.get("Labels", {}),
                    "scope": vol.attrs.get("Scope", "unknown"),
                }
                for vol in volumes
            ]

            logger.info(f"Found {len(volume_list)} volumes")

            output = ListVolumesOutput(
                volumes=volume_list,
                count=len(volume_list),
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list volumes: {e}")
            raise DockerOperationError(f"Failed to list volumes: {e}") from e

    return ToolSpec(
        name="docker_list_volumes",
        description="List Docker volumes with optional filters",
        safety=OperationSafety.SAFE,
        func=list_volumes,
        idempotent=True,
    )


def register_volume_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register read-only volume tools with FastMCP."""
    tools = [
        create_list_volumes_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
