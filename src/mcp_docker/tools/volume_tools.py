"""Volume management tools for Docker MCP server.

This module provides tools for managing Docker volumes, including
creating, listing, inspecting, and removing volumes.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.prune_helpers import force_remove_all_volumes
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)


# Input/Output Models


class ListVolumesInput(BaseModel):
    """Input for listing volumes."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'dangling': ['true']}, {'driver': 'local'}, "
            "{'label': ['env=prod']}"
        ),
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
    driver_opts: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Driver-specific options as key-value pairs. "
            "Example: {'type': 'nfs', 'device': ':/path/to/dir', 'o': 'addr=10.0.0.1'}"
        ),
    )
    labels: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Volume labels as key-value pairs. "
            "Example: {'environment': 'production', 'backup': 'daily'}"
        ),
    )

    @field_validator("driver_opts", "labels", mode="before")
    @classmethod
    def parse_json_strings(cls, v: Any, info: Any) -> Any:
        """Parse JSON strings to objects (workaround for MCP client serialization bug)."""
        field_name = info.field_name if hasattr(info, "field_name") else "field"
        return parse_json_string_field(v, field_name)


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
    """Input for pruning Docker volumes (unused by default, all with force_all=true)."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'label': ['env=test']}, {'dangling': ['true']}. "
            "NOTE: Filters only apply when force_all=false (standard prune mode)."
        ),
    )
    force_all: bool = Field(
        default=False,
        description=(
            "Force remove ALL volumes, even if named or in use. "
            "USE THIS when user asks to 'remove all volumes', 'delete all volumes', "
            "or 'prune all volumes'. "
            "When True, removes EVERY volume regardless of name or usage. "
            "WARNING: This is extremely destructive and will delete all volumes. "
            "Requires user confirmation."
        ),
    )


class PruneVolumesOutput(BaseModel):
    """Output for pruning volumes."""

    deleted: list[str] = Field(description="List of deleted volume names")
    space_reclaimed: int = Field(description="Disk space reclaimed in bytes")


# Tool Implementations


class ListVolumesTool(BaseTool):
    """List Docker volumes with optional filters."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_list_volumes"

    @property
    def description(self) -> str:
        """Tool description."""
        return "List Docker volumes with optional filters"

    @property
    def input_schema(self) -> type[ListVolumesInput]:
        """Input schema."""
        return ListVolumesInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            volumes = self.docker.client.volumes.list(filters=input_data.filters)

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


class InspectVolumeTool(BaseTool):
    """Inspect a Docker volume to get detailed information."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_inspect_volume"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get detailed information about a Docker volume"

    @property
    def input_schema(self) -> type[InspectVolumeInput]:
        """Input schema."""
        return InspectVolumeInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

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
            volume = self.docker.client.volumes.get(input_data.volume_name)
            details = volume.attrs

            logger.info(f"Successfully inspected volume: {input_data.volume_name}")
            return InspectVolumeOutput(details=details)

        except NotFound as e:
            logger.error(f"Volume not found: {input_data.volume_name}")
            raise VolumeNotFound(f"Volume not found: {input_data.volume_name}") from e
        except APIError as e:
            logger.error(f"Failed to inspect volume: {e}")
            raise DockerOperationError(f"Failed to inspect volume: {e}") from e


class CreateVolumeTool(BaseTool):
    """Create a new Docker volume."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_create_volume"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Create a new Docker volume"

    @property
    def input_schema(self) -> type[CreateVolumeInput]:
        """Input schema."""
        return CreateVolumeInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

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

            volume = self.docker.client.volumes.create(**kwargs)

            logger.info(f"Successfully created volume: {volume.name}")
            return CreateVolumeOutput(
                name=volume.name,
                driver=volume.attrs.get("Driver", "local"),
                mountpoint=volume.attrs.get("Mountpoint", ""),
            )

        except APIError as e:
            logger.error(f"Failed to create volume: {e}")
            raise DockerOperationError(f"Failed to create volume: {e}") from e


class RemoveVolumeTool(BaseTool):
    """Remove a Docker volume."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_remove_volume"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Remove a Docker volume"

    @property
    def input_schema(self) -> type[RemoveVolumeInput]:
        """Input schema."""
        return RemoveVolumeInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

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

            volume = self.docker.client.volumes.get(input_data.volume_name)
            volume.remove(force=input_data.force)

            logger.info(f"Successfully removed volume: {input_data.volume_name}")
            return RemoveVolumeOutput(volume_name=input_data.volume_name)

        except NotFound as e:
            logger.error(f"Volume not found: {input_data.volume_name}")
            raise VolumeNotFound(f"Volume not found: {input_data.volume_name}") from e
        except APIError as e:
            logger.error(f"Failed to remove volume: {e}")
            raise DockerOperationError(f"Failed to remove volume: {e}") from e


class PruneVolumesTool(BaseTool):
    """Remove unused Docker volumes."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_prune_volumes"

    @property
    def description(self) -> str:
        """Tool description."""
        return (
            "Prune Docker volumes. By default, removes only UNUSED volumes. "
            "To remove ALL volumes including named ones, use force_all=true. "
            "IMPORTANT: When user asks to 'remove all volumes' or 'delete all volumes', "
            "use force_all=true."
        )

    @property
    def input_schema(self) -> type[PruneVolumesInput]:
        """Input schema."""
        return PruneVolumesInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

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
            logger.info(
                f"Pruning volumes (force_all={input_data.force_all}, filters={input_data.filters})"
            )

            # Delegate to helper function based on mode
            if input_data.force_all:
                deleted = force_remove_all_volumes(self.docker.client)
                logger.info(f"Successfully force-pruned {len(deleted)} volumes (force_all=True)")
                return PruneVolumesOutput(deleted=deleted, space_reclaimed=0)

            # Standard prune (only unused volumes)
            result = self.docker.client.volumes.prune(filters=input_data.filters)
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
