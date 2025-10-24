"""Volume management tools for Docker MCP server.

This module provides tools for managing Docker volumes, including
creating, listing, inspecting, and removing volumes.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.base import OperationSafety
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# Input/Output Models


class ListVolumesInput(BaseModel):
    """Input for listing volumes."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None, description="Filters to apply (e.g., {'dangling': ['true']})"
    )


class ListVolumesOutput(BaseModel):
    """Output for listing volumes."""

    volumes: list[dict[str, Any]] = Field(description="List of volumes with basic info")
    count: int = Field(description="Total number of volumes")


class InspectVolumeInput(BaseModel):
    """Input for inspecting a volume."""

    volume_name: str = Field(description="Volume name")


class InspectVolumeOutput(BaseModel):
    """Output for inspecting a volume."""

    details: dict[str, Any] = Field(description="Detailed volume information")


class CreateVolumeInput(BaseModel):
    """Input for creating a volume."""

    name: str | None = Field(default=None, description="Volume name (auto-generated if not set)")
    driver: str = Field(default="local", description="Volume driver")
    driver_opts: dict[str, str] | None = Field(default=None, description="Driver options")
    labels: dict[str, str] | None = Field(default=None, description="Volume labels")


class CreateVolumeOutput(BaseModel):
    """Output for creating a volume."""

    name: str = Field(description="Created volume name")
    driver: str = Field(description="Volume driver")
    mountpoint: str = Field(description="Volume mountpoint")


class RemoveVolumeInput(BaseModel):
    """Input for removing a volume."""

    volume_name: str = Field(description="Volume name")
    force: bool = Field(default=False, description="Force removal")


class RemoveVolumeOutput(BaseModel):
    """Output for removing a volume."""

    volume_name: str = Field(description="Removed volume name")


class PruneVolumesInput(BaseModel):
    """Input for pruning unused volumes."""

    filters: dict[str, str | list[str]] | None = Field(default=None, description="Filters to apply")


class PruneVolumesOutput(BaseModel):
    """Output for pruning volumes."""

    deleted: list[str] = Field(description="List of deleted volume names")
    space_reclaimed: int = Field(description="Disk space reclaimed in bytes")


# Tool Implementations


class ListVolumesTool:
    """List Docker volumes with optional filters."""

    name = "docker_list_volumes"
    description = "List Docker volumes with optional filters"
    input_model = ListVolumesInput
    output_model = ListVolumesOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: ListVolumesInput) -> ListVolumesOutput:
        """Execute the list volumes operation.

        Args:
            input_data: Input parameters

        Returns:
            List of volumes with basic info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing volumes (filters={input_data.filters})")
            volumes = self.docker_client.client.volumes.list(filters=input_data.filters)

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
            return ListVolumesOutput(volumes=volume_list, count=len(volume_list))

        except APIError as e:
            logger.error(f"Failed to list volumes: {e}")
            raise DockerOperationError(f"Failed to list volumes: {e}") from e


class InspectVolumeTool:
    """Inspect a Docker volume to get detailed information."""

    name = "docker_inspect_volume"
    description = "Get detailed information about a Docker volume"
    input_model = InspectVolumeInput
    output_model = InspectVolumeOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: InspectVolumeInput) -> InspectVolumeOutput:
        """Execute the inspect volume operation.

        Args:
            input_data: Input parameters

        Returns:
            Detailed volume information

        Raises:
            VolumeNotFound: If volume doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting volume: {input_data.volume_name}")
            volume = self.docker_client.client.volumes.get(input_data.volume_name)
            details = volume.attrs

            logger.info(f"Successfully inspected volume: {input_data.volume_name}")
            return InspectVolumeOutput(details=details)

        except NotFound as e:
            logger.error(f"Volume not found: {input_data.volume_name}")
            raise VolumeNotFound(f"Volume not found: {input_data.volume_name}") from e
        except APIError as e:
            logger.error(f"Failed to inspect volume: {e}")
            raise DockerOperationError(f"Failed to inspect volume: {e}") from e


class CreateVolumeTool:
    """Create a new Docker volume."""

    name = "docker_create_volume"
    description = "Create a new Docker volume"
    input_model = CreateVolumeInput
    output_model = CreateVolumeOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: CreateVolumeInput) -> CreateVolumeOutput:
        """Execute the create volume operation.

        Args:
            input_data: Input parameters

        Returns:
            Created volume information

        Raises:
            DockerOperationError: If creation fails
        """
        try:
            logger.info(f"Creating volume: {input_data.name or '(auto-generated)'}")

            # Prepare kwargs for volume creation
            kwargs: dict[str, Any] = {"driver": input_data.driver}

            if input_data.name:
                kwargs["name"] = input_data.name
            if input_data.driver_opts:
                kwargs["driver_opts"] = input_data.driver_opts
            if input_data.labels:
                kwargs["labels"] = input_data.labels

            volume = self.docker_client.client.volumes.create(**kwargs)

            logger.info(f"Successfully created volume: {volume.name}")
            return CreateVolumeOutput(
                name=volume.name,
                driver=volume.attrs.get("Driver", "local"),
                mountpoint=volume.attrs.get("Mountpoint", ""),
            )

        except APIError as e:
            logger.error(f"Failed to create volume: {e}")
            raise DockerOperationError(f"Failed to create volume: {e}") from e


class RemoveVolumeTool:
    """Remove a Docker volume."""

    name = "docker_remove_volume"
    description = "Remove a Docker volume"
    input_model = RemoveVolumeInput
    output_model = RemoveVolumeOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: RemoveVolumeInput) -> RemoveVolumeOutput:
        """Execute the remove volume operation.

        Args:
            input_data: Input parameters

        Returns:
            Remove operation result

        Raises:
            VolumeNotFound: If volume doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(f"Removing volume: {input_data.volume_name} (force={input_data.force})")

            volume = self.docker_client.client.volumes.get(input_data.volume_name)
            volume.remove(force=input_data.force)

            logger.info(f"Successfully removed volume: {input_data.volume_name}")
            return RemoveVolumeOutput(volume_name=input_data.volume_name)

        except NotFound as e:
            logger.error(f"Volume not found: {input_data.volume_name}")
            raise VolumeNotFound(f"Volume not found: {input_data.volume_name}") from e
        except APIError as e:
            logger.error(f"Failed to remove volume: {e}")
            raise DockerOperationError(f"Failed to remove volume: {e}") from e


class PruneVolumesTool:
    """Remove unused Docker volumes."""

    name = "docker_prune_volumes"
    description = "Remove unused Docker volumes"
    input_model = PruneVolumesInput
    output_model = PruneVolumesOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: PruneVolumesInput) -> PruneVolumesOutput:
        """Execute the prune volumes operation.

        Args:
            input_data: Input parameters

        Returns:
            Prune operation result

        Raises:
            DockerOperationError: If pruning fails
        """
        try:
            logger.info(f"Pruning volumes (filters={input_data.filters})")

            result = self.docker_client.client.volumes.prune(filters=input_data.filters)

            deleted = result.get("VolumesDeleted", []) or []
            space_reclaimed = result.get("SpaceReclaimed", 0)

            logger.info(
                f"Successfully pruned {len(deleted)} volumes, reclaimed {space_reclaimed} bytes"
            )
            return PruneVolumesOutput(deleted=deleted, space_reclaimed=space_reclaimed)

        except APIError as e:
            logger.error(f"Failed to prune volumes: {e}")
            raise DockerOperationError(f"Failed to prune volumes: {e}") from e


# Export all tools
__all__ = [
    "ListVolumesTool",
    "InspectVolumeTool",
    "CreateVolumeTool",
    "RemoveVolumeTool",
    "PruneVolumesTool",
]
