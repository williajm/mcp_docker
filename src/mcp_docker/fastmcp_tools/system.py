"""FastMCP system tools.

This module contains system-level Docker tools migrated to FastMCP 2.0.
Currently includes only the prune_system DESTRUCTIVE operation.
"""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)

# Input/Output Models


class SystemPruneInput(BaseModel):
    """Input for pruning all unused resources."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'until': '24h'}, {'label': ['env=test']}"
        ),
    )
    volumes: bool = Field(default=False, description="Prune volumes in addition to other resources")


class SystemPruneOutput(BaseModel):
    """Output for system prune operation."""

    containers_deleted: list[str] = Field(description="Deleted container IDs")
    images_deleted: list[dict[str, Any]] = Field(description="Deleted images")
    networks_deleted: list[str] = Field(description="Deleted network IDs")
    volumes_deleted: list[str] = Field(description="Deleted volume names")
    space_reclaimed: int = Field(description="Total disk space reclaimed in bytes")


# FastMCP Tool Functions


def create_prune_system_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the prune_system FastMCP tool."""

    def prune_system(
        filters: dict[str, str | list[str]] | None = None,
        volumes: bool = False,
    ) -> dict[str, Any]:
        """Prune all unused Docker resources (containers, images, networks, volumes).

        Args:
            filters: Filters to apply (e.g., {'until': '24h'})
            volumes: Prune volumes in addition to other resources

        Returns:
            Dictionary with deleted resources and space reclaimed

        Raises:
            DockerOperationError: If pruning fails
        """
        try:
            logger.info(f"Pruning all unused resources (filters={filters}, volumes={volumes})")

            # System prune removes stopped containers, unused networks,
            # dangling images, and optionally volumes
            result = docker_client.client.api.prune_containers(  # type: ignore[no-untyped-call]
                filters=filters
            )
            containers_deleted = result.get("ContainersDeleted", []) or []

            result_images = docker_client.client.images.prune(filters=filters)
            images_deleted = result_images.get("ImagesDeleted", []) or []

            result_networks = docker_client.client.api.prune_networks(  # type: ignore[no-untyped-call]
                filters=filters
            )
            networks_deleted = result_networks.get("NetworksDeleted", []) or []

            # Only prune volumes if explicitly requested
            volumes_deleted: list[str] = []
            volumes_space_reclaimed = 0
            if volumes:
                result_volumes = docker_client.client.volumes.prune(filters=filters)
                volumes_deleted = result_volumes.get("VolumesDeleted", []) or []
                volumes_space_reclaimed = result_volumes.get("SpaceReclaimed", 0)

            # Calculate total space reclaimed
            space_reclaimed = (
                result.get("SpaceReclaimed", 0)
                + result_images.get("SpaceReclaimed", 0)
                + result_networks.get("SpaceReclaimed", 0)
                + volumes_space_reclaimed
            )

            logger.info(
                f"Pruned {len(containers_deleted)} containers, {len(images_deleted)} images, "
                f"{len(networks_deleted)} networks, {len(volumes_deleted)} volumes. "
                f"Reclaimed {space_reclaimed} bytes"
            )

            output = SystemPruneOutput(
                containers_deleted=containers_deleted,
                images_deleted=images_deleted,
                networks_deleted=networks_deleted,
                volumes_deleted=volumes_deleted,
                space_reclaimed=space_reclaimed,
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to prune system: {e}")
            raise DockerOperationError(f"Failed to prune system: {e}") from e

    return (
        "docker_prune_system",
        "Prune all unused Docker resources (containers, images, networks, volumes)",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (different resources may be pruned each time)
        False,  # not open_world
        prune_system,
    )


def register_system_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: Any = None,
) -> list[str]:
    """Register all system tools with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration (optional, for tool filtering)

    Returns:
        List of registered tool names
    """
    tools = [
        # DESTRUCTIVE tools (permanent deletion)
        create_prune_system_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
