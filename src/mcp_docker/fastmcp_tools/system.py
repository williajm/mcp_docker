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


class VersionOutput(BaseModel):
    """Output for Docker version information."""

    version: str = Field(description="Docker version")
    api_version: str = Field(description="Docker API version")
    platform: dict[str, str] = Field(description="Platform information")
    components: list[dict[str, Any]] = Field(description="Docker components")


class EventsInput(BaseModel):
    """Input for Docker events."""

    since: str | None = Field(
        default=None,
        description=(
            "Show events since timestamp. Accepts Unix timestamp (seconds since epoch) "
            "or ISO 8601 datetime (e.g., '2024-01-15T10:00:00')"
        ),
    )
    until: str = Field(
        description=(
            "Show events until timestamp (REQUIRED to prevent infinite streaming). "
            "Accepts Unix timestamp (seconds since epoch) or ISO 8601 datetime "
            "(e.g., '2024-01-15T11:00:00')"
        ),
    )
    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply. Examples: {'type': 'container'}, "
            "{'event': ['start', 'stop']}, {'container': 'my-container'}"
        ),
    )


class EventsOutput(BaseModel):
    """Output for Docker events."""

    events: list[dict[str, Any]] = Field(description="List of Docker events")
    count: int = Field(description="Number of events returned")


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


def create_version_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the docker_version FastMCP tool."""

    def version() -> dict[str, Any]:
        """Get Docker version information.

        Returns:
            Dictionary with Docker version, API version, platform info, and components

        Raises:
            DockerOperationError: If getting version fails
        """
        try:
            logger.info("Getting Docker version information")

            version_info = docker_client.client.version()  # type: ignore[no-untyped-call]

            # Extract key information
            output = VersionOutput(
                version=version_info.get("Version", "unknown"),
                api_version=version_info.get("ApiVersion", "unknown"),
                platform={
                    "name": version_info.get("Platform", {}).get("Name", "unknown"),
                    "os": version_info.get("Os", "unknown"),
                    "arch": version_info.get("Arch", "unknown"),
                    "kernel": version_info.get("KernelVersion", "unknown"),
                },
                components=version_info.get("Components", []),
            )

            logger.info(f"Docker version: {output.version}, API: {output.api_version}")
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to get Docker version: {e}")
            raise DockerOperationError(f"Failed to get Docker version: {e}") from e

    return (
        "docker_version",
        "Get Docker version information including API version, platform, and components",
        OperationSafety.SAFE,
        True,  # idempotent (always returns same info)
        False,  # not open_world
        version,
    )


def create_events_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the docker_events FastMCP tool."""

    def events(
        until: str,
        since: str | None = None,
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """Get Docker events from the daemon.

        Args:
            until: End timestamp (REQUIRED - Unix timestamp or ISO 8601 datetime)
            since: Start timestamp (optional - Unix timestamp or ISO 8601 datetime)
            filters: Filters to apply (e.g., {'type': 'container', 'event': 'start'})

        Returns:
            Dictionary with list of events and count

        Raises:
            DockerOperationError: If getting events fails

        Note:
            The 'until' parameter is required to prevent infinite streaming.
            Without it, Docker's events API will block indefinitely waiting for new events.
        """
        try:
            logger.info(f"Getting Docker events (since={since}, until={until}, filters={filters})")

            # Get events from Docker API
            # Note: This returns a generator, so we need to decode and collect events
            event_generator = docker_client.client.events(  # type: ignore[no-untyped-call]
                since=since,
                until=until,
                filters=filters,
                decode=True,
            )

            # Collect events (limit to prevent excessive memory usage)
            events_list = []
            max_events = 1000  # Safety limit

            for event in event_generator:
                events_list.append(event)
                if len(events_list) >= max_events:
                    logger.warning(f"Reached max events limit ({max_events}), stopping collection")
                    break

            logger.info(f"Retrieved {len(events_list)} Docker events")

            output = EventsOutput(
                events=events_list,
                count=len(events_list),
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to get Docker events: {e}")
            raise DockerOperationError(f"Failed to get Docker events: {e}") from e

    return (
        "docker_events",
        "Get Docker events with time range and filters (requires 'until')",
        OperationSafety.SAFE,
        False,  # not idempotent (events change over time)
        False,  # not open_world
        events,
    )


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
        # SAFE tools (read-only)
        create_version_tool(docker_client),
        create_events_tool(docker_client),
        # DESTRUCTIVE tools (permanent deletion)
        create_prune_system_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
