"""FastMCP network tools."""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import ToolSpec
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# Input/Output Models


class ListNetworksOutput(BaseModel):
    """Output for listing networks."""

    networks: list[dict[str, Any]] = Field(description="List of networks with basic info")
    count: int = Field(description="Total number of networks found")


# FastMCP Tool Functions


def create_list_networks_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the list_networks tool."""

    def list_networks(
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker networks with optional filters."""
        try:
            logger.info(f"Listing networks (filters={filters})")
            networks = docker_client.client.networks.list(filters=filters)

            network_list = [
                {
                    "id": net.id,
                    "short_id": net.short_id,
                    "name": net.name,
                    "driver": net.attrs.get("Driver", "unknown"),
                    "scope": net.attrs.get("Scope", "unknown"),
                    "labels": net.attrs.get("Labels", {}),
                }
                for net in networks
            ]

            logger.info(f"Found {len(network_list)} networks")

            output = ListNetworksOutput(
                networks=network_list,
                count=len(network_list),
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list networks: {e}")
            raise DockerOperationError(f"Failed to list networks: {e}") from e

    return ToolSpec(
        name="docker_list_networks",
        description="List Docker networks with optional filters",
        safety=OperationSafety.SAFE,
        func=list_networks,
        idempotent=True,
    )


def register_network_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register read-only network tools with FastMCP."""
    tools = [
        create_list_networks_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
