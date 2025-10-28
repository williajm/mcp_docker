"""System management tools for Docker MCP server.

This module provides tools for system-level Docker operations, including
system information, disk usage, pruning, version info, and health checks.
"""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

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

    usage: dict[str, Any] = Field(
        description="Disk usage info for Images, Containers, Volumes, and BuildCache"
    )


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
    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Event filters as key-value pairs. "
            "Examples: {'type': ['container']}, {'event': ['start', 'stop']}, "
            "{'container': ['my-container']}"
        ),
    )
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


class SystemInfoTool(BaseTool):
    """Get Docker system information."""

    output_model = SystemInfoOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_system_info"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get Docker system information"

    @property
    def input_schema(self) -> type[SystemInfoInput]:
        """Input schema."""
        return SystemInfoInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            info = self.docker.client.info()  # type: ignore[no-untyped-call]

            logger.info("Successfully retrieved system information")
            return SystemInfoOutput(info=info)

        except APIError as e:
            logger.error(f"Failed to get system info: {e}")
            raise DockerOperationError(f"Failed to get system info: {e}") from e


class SystemDfTool(BaseTool):
    """Get Docker disk usage statistics."""

    output_model = SystemDfOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_system_df"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get Docker disk usage statistics"

    @property
    def input_schema(self) -> type[SystemDfInput]:
        """Input schema."""
        return SystemDfInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            df_info = self.docker.client.df()  # type: ignore[no-untyped-call]

            # Summarize the output to avoid token limit issues
            summary = {
                "LayersSize": df_info.get("LayersSize", 0),
                "Images": {
                    "total_count": len(df_info.get("Images", [])),
                    "total_size": sum(img.get("Size", 0) for img in df_info.get("Images", [])),
                    "shared_size": sum(
                        img.get("SharedSize", 0) for img in df_info.get("Images", [])
                    ),
                },
                "Containers": {
                    "total_count": len(df_info.get("Containers", [])),
                    "total_size": sum(c.get("SizeRw", 0) for c in df_info.get("Containers", [])),
                },
                "Volumes": {
                    "total_count": len(df_info.get("Volumes", [])),
                    "total_size": sum(
                        v.get("UsageData", {}).get("Size", 0)
                        for v in df_info.get("Volumes", [])
                        if v.get("UsageData")
                    ),
                },
                "BuildCache": {
                    "total_count": len(df_info.get("BuildCache", [])),
                    "total_size": sum(b.get("Size", 0) for b in df_info.get("BuildCache", [])),
                    "shared_size": sum(b.get("Shared", 0) for b in df_info.get("BuildCache", [])),
                },
            }

            logger.info("Successfully retrieved disk usage statistics")
            return SystemDfOutput(usage=summary)

        except APIError as e:
            logger.error(f"Failed to get disk usage: {e}")
            raise DockerOperationError(f"Failed to get disk usage: {e}") from e


class SystemPruneTool(BaseTool):
    """Prune all unused Docker resources."""

    output_model = SystemPruneOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_system_prune"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Prune all unused Docker resources (containers, images, networks, volumes)"

    @property
    def input_schema(self) -> type[SystemPruneInput]:
        """Input schema."""
        return SystemPruneInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

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
            result = self.docker.client.api.prune_containers(  # type: ignore[no-untyped-call]
                filters=input_data.filters
            )
            containers_deleted = result.get("ContainersDeleted", []) or []

            result_images = self.docker.client.images.prune(filters=input_data.filters)
            images_deleted = result_images.get("ImagesDeleted", []) or []

            result_networks = self.docker.client.api.prune_networks(  # type: ignore[no-untyped-call]
                filters=input_data.filters
            )
            networks_deleted = result_networks.get("NetworksDeleted", []) or []

            # Only prune volumes if explicitly requested
            volumes_deleted: list[str] = []
            volumes_space_reclaimed = 0
            if input_data.volumes:
                result_volumes = self.docker.client.volumes.prune(filters=input_data.filters)
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


class VersionTool(BaseTool):
    """Get Docker version information."""

    output_model = VersionOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_version"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get Docker version information"

    @property
    def input_schema(self) -> type[VersionInput]:
        """Input schema."""
        return VersionInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            version = self.docker.client.version()  # type: ignore[no-untyped-call]

            logger.info("Successfully retrieved version information")
            return VersionOutput(version=version)

        except APIError as e:
            logger.error(f"Failed to get version: {e}")
            raise DockerOperationError(f"Failed to get version: {e}") from e


class EventsTool(BaseTool):
    """Stream Docker events."""

    output_model = EventsOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_events"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Stream Docker events (limited to recent events)"

    @property
    def input_schema(self) -> type[EventsInput]:
        """Input schema."""
        return EventsInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            events_gen = self.docker.client.events(**kwargs)  # type: ignore[no-untyped-call]

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


class HealthCheckTool(BaseTool):
    """Check Docker daemon health."""

    output_model = HealthCheckOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_healthcheck"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Check Docker daemon health"

    @property
    def input_schema(self) -> type[HealthCheckInput]:
        """Input schema."""
        return HealthCheckInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            health_status = self.docker.health_check()

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
