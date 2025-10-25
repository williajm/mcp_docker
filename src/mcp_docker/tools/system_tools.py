"""System management tools for Docker MCP server.

This module provides tools for system-level Docker operations, including
system information, disk usage, pruning, version info, and health checks.
"""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.base import OperationSafety
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# Input/Output Models


class SystemInfoInput(BaseModel):
    """Input for getting system information."""

    pass  # No input parameters needed


class SystemInfoOutput(BaseModel):
    """Output for system information."""

    info: dict[str, Any] = Field(description="Docker system information")


class SystemDfInput(BaseModel):
    """Input for getting disk usage statistics."""

    pass  # No input parameters needed


class SystemDfOutput(BaseModel):
    """Output for disk usage statistics."""

    usage: dict[str, Any] = Field(description="Complete disk usage information including Images, Containers, Volumes, and BuildCache")


class SystemPruneInput(BaseModel):
    """Input for pruning all unused resources."""

    filters: dict[str, str | list[str]] | None = Field(default=None, description="Filters to apply")


class SystemPruneOutput(BaseModel):
    """Output for system prune operation."""

    containers_deleted: list[str] = Field(description="Deleted container IDs")
    images_deleted: list[dict[str, Any]] = Field(description="Deleted images")
    networks_deleted: list[str] = Field(description="Deleted network IDs")
    volumes_deleted: list[str] = Field(description="Deleted volume names")
    space_reclaimed: int = Field(description="Total disk space reclaimed in bytes")


class VersionInput(BaseModel):
    """Input for getting Docker version."""

    pass  # No input parameters needed


class VersionOutput(BaseModel):
    """Output for Docker version information."""

    version: dict[str, Any] = Field(description="Docker version information")


class EventsInput(BaseModel):
    """Input for streaming Docker events."""

    since: str | None = Field(default=None, description="Show events since timestamp")
    until: str | None = Field(default=None, description="Show events until timestamp")
    filters: dict[str, str | list[str]] | None = Field(default=None, description="Event filters")
    decode: bool = Field(default=True, description="Decode JSON events")


class EventsOutput(BaseModel):
    """Output for Docker events."""

    events: list[dict[str, Any]] = Field(description="List of Docker events")
    count: int = Field(description="Number of events retrieved")


class HealthCheckInput(BaseModel):
    """Input for Docker daemon health check."""

    pass  # No input parameters needed


class HealthCheckOutput(BaseModel):
    """Output for health check."""

    healthy: bool = Field(description="Whether Docker daemon is healthy")
    message: str = Field(description="Health check message")
    details: dict[str, Any] | None = Field(default=None, description="Additional details")


# Tool Implementations


class SystemInfoTool:
    """Get Docker system information."""

    name = "docker_system_info"
    description = "Get Docker system information"
    input_model = SystemInfoInput
    output_model = SystemInfoOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: SystemInfoInput) -> SystemInfoOutput:  # noqa: ARG002
        """Execute the system info operation.

        Args:
            input_data: Input parameters

        Returns:
            Docker system information

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info("Getting Docker system information")
            info = self.docker_client.client.info()  # type: ignore[no-untyped-call]

            logger.info("Successfully retrieved system information")
            return SystemInfoOutput(info=info)

        except APIError as e:
            logger.error(f"Failed to get system info: {e}")
            raise DockerOperationError(f"Failed to get system info: {e}") from e


class SystemDfTool:
    """Get Docker disk usage statistics."""

    name = "docker_system_df"
    description = "Get Docker disk usage statistics"
    input_model = SystemDfInput
    output_model = SystemDfOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: SystemDfInput) -> SystemDfOutput:  # noqa: ARG002
        """Execute the system df operation.

        Args:
            input_data: Input parameters

        Returns:
            Disk usage statistics

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info("Getting Docker disk usage statistics")
            df_info = self.docker_client.client.df()  # type: ignore[no-untyped-call]

            logger.info("Successfully retrieved disk usage statistics")
            return SystemDfOutput(usage=df_info)

        except APIError as e:
            logger.error(f"Failed to get disk usage: {e}")
            raise DockerOperationError(f"Failed to get disk usage: {e}") from e


class SystemPruneTool:
    """Prune all unused Docker resources."""

    name = "docker_system_prune"
    description = "Prune all unused Docker resources (containers, images, networks, volumes)"
    input_model = SystemPruneInput
    output_model = SystemPruneOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: SystemPruneInput) -> SystemPruneOutput:
        """Execute the system prune operation.

        Args:
            input_data: Input parameters

        Returns:
            Prune operation results

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info(f"Pruning all unused resources (filters={input_data.filters})")

            # System prune removes stopped containers, unused networks,
            # dangling images, and optionally volumes
            result = self.docker_client.client.api.prune_containers(  # type: ignore[no-untyped-call]
                filters=input_data.filters
            )
            containers_deleted = result.get("ContainersDeleted", []) or []

            result_images = self.docker_client.client.images.prune(filters=input_data.filters)
            images_deleted = result_images.get("ImagesDeleted", []) or []

            result_networks = self.docker_client.client.api.prune_networks(  # type: ignore[no-untyped-call]
                filters=input_data.filters
            )
            networks_deleted = result_networks.get("NetworksDeleted", []) or []

            # Only prune volumes if explicitly requested
            volumes_deleted: list[str] = []
            if input_data.filters and input_data.filters.get("volumes"):
                result_volumes = self.docker_client.client.volumes.prune(filters=input_data.filters)
                volumes_deleted = result_volumes.get("VolumesDeleted", []) or []

            # Calculate total space reclaimed
            space_reclaimed = (
                result.get("SpaceReclaimed", 0)
                + result_images.get("SpaceReclaimed", 0)
                + result_networks.get("SpaceReclaimed", 0)
            )

            logger.info(
                f"Pruned {len(containers_deleted)} containers, {len(images_deleted)} images, "
                f"{len(networks_deleted)} networks, {len(volumes_deleted)} volumes. "
                f"Reclaimed {space_reclaimed} bytes"
            )

            return SystemPruneOutput(
                containers_deleted=containers_deleted,
                images_deleted=images_deleted,
                networks_deleted=networks_deleted,
                volumes_deleted=volumes_deleted,
                space_reclaimed=space_reclaimed,
            )

        except APIError as e:
            logger.error(f"Failed to prune system: {e}")
            raise DockerOperationError(f"Failed to prune system: {e}") from e


class VersionTool:
    """Get Docker version information."""

    name = "docker_version"
    description = "Get Docker version information"
    input_model = VersionInput
    output_model = VersionOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: VersionInput) -> VersionOutput:  # noqa: ARG002
        """Execute the version operation.

        Args:
            input_data: Input parameters

        Returns:
            Docker version information

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info("Getting Docker version information")
            version = self.docker_client.client.version()  # type: ignore[no-untyped-call]

            logger.info("Successfully retrieved version information")
            return VersionOutput(version=version)

        except APIError as e:
            logger.error(f"Failed to get version: {e}")
            raise DockerOperationError(f"Failed to get version: {e}") from e


class EventsTool:
    """Stream Docker events."""

    name = "docker_events"
    description = "Stream Docker events (limited to recent events)"
    input_model = EventsInput
    output_model = EventsOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: EventsInput) -> EventsOutput:
        """Execute the events operation.

        Args:
            input_data: Input parameters

        Returns:
            List of Docker events

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info("Getting Docker events")

            # Prepare kwargs for events
            kwargs: dict[str, Any] = {"decode": input_data.decode}
            if input_data.since:
                kwargs["since"] = input_data.since
            if input_data.until:
                kwargs["until"] = input_data.until
            if input_data.filters:
                kwargs["filters"] = input_data.filters

            # Get events generator (non-streaming for now)
            events_gen = self.docker_client.client.events(**kwargs)  # type: ignore[no-untyped-call]

            # Collect events (limit to prevent infinite loops)
            events = []
            try:
                for i, event in enumerate(events_gen):
                    if i >= 100:  # Limit to 100 events
                        break
                    events.append(event)
            except Exception:
                # Stop collecting if any error occurs
                pass

            logger.info(f"Successfully retrieved {len(events)} events")
            return EventsOutput(events=events, count=len(events))

        except APIError as e:
            logger.error(f"Failed to get events: {e}")
            raise DockerOperationError(f"Failed to get events: {e}") from e


class HealthCheckTool:
    """Check Docker daemon health."""

    name = "docker_healthcheck"
    description = "Check Docker daemon health"
    input_model = HealthCheckInput
    output_model = HealthCheckOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: HealthCheckInput) -> HealthCheckOutput:  # noqa: ARG002
        """Execute the health check operation.

        Args:
            input_data: Input parameters

        Returns:
            Health check results

        Raises:
            DockerOperationError: If operation fails
        """
        try:
            logger.info("Checking Docker daemon health")

            # Perform health check
            health_status = self.docker_client.health_check()

            # Extract status
            healthy = health_status.get("status") == "healthy"
            message = "Docker daemon is healthy" if healthy else "Docker daemon is unhealthy"

            # Use the daemon_info from health_status as details
            details = {
                "daemon_info": health_status.get("daemon_info", {}),
                "containers": health_status.get("containers", {}),
                "images": health_status.get("images", 0),
            }

            logger.info(f"Health check result: {message}")
            return HealthCheckOutput(healthy=healthy, message=message, details=details)

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return HealthCheckOutput(
                healthy=False, message=f"Health check failed: {str(e)}", details=None
            )


# Export all tools
__all__ = [
    "SystemInfoTool",
    "SystemDfTool",
    "SystemPruneTool",
    "VersionTool",
    "EventsTool",
    "HealthCheckTool",
]
