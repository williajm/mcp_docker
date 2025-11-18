"""FastMCP volume tools.

This module contains all volume tools migrated to FastMCP 2.0,
including SAFE (read-only), MODERATE (state-changing), and DESTRUCTIVE operations.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_VOLUME_NOT_FOUND
from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    truncate_list,
)
from mcp_docker.utils.prune_helpers import force_remove_all_volumes
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)

# Input/Output Models (reused from legacy tools)


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
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description="Information about output truncation if applied",
    )


class InspectVolumeInput(BaseModel):
    """Input for inspecting a volume."""

    volume_name: str = Field(description="Volume name")


class InspectVolumeOutput(BaseModel):
    """Output for inspecting a volume."""

    details: dict[str, Any] = Field(description="Detailed volume information")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description="Information about output truncation if applied",
    )


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


# FastMCP Tool Functions


def create_list_volumes_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the list_volumes FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def list_volumes(
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker volumes with optional filters.

        Args:
            filters: Filters to apply (e.g., {'dangling': ['true']})

        Returns:
            Dictionary with volumes list, count, and truncation info

        Raises:
            DockerOperationError: If listing fails
        """
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

            # Apply output limits
            original_count = len(volume_list)
            truncation_info: dict[str, Any] = {}
            if safety_config.max_list_results > 0:
                volume_list, was_truncated = truncate_list(
                    volume_list,
                    safety_config.max_list_results,
                )
                if was_truncated:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_count=original_count,
                        truncated_count=len(volume_list),
                    )
                    truncation_info["message"] = (
                        f"Results truncated: showing {len(volume_list)} of {original_count} "
                        f"volumes. Set SAFETY_MAX_LIST_RESULTS=0 to disable limit."
                    )

            logger.info(f"Found {len(volume_list)} volumes (total: {original_count})")

            # Convert to output model for validation
            output = ListVolumesOutput(
                volumes=volume_list,
                count=original_count,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list volumes: {e}")
            raise DockerOperationError(f"Failed to list volumes: {e}") from e

    return (
        "docker_list_volumes",
        "List Docker volumes with optional filters",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        list_volumes,
    )


def create_inspect_volume_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the inspect_volume FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def inspect_volume(
        volume_name: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker volume.

        Args:
            volume_name: Volume name

        Returns:
            Dictionary with detailed volume information

        Raises:
            VolumeNotFound: If volume doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting volume: {volume_name}")
            volume = docker_client.client.volumes.get(volume_name)
            details = volume.attrs

            # Apply output limits (truncate large fields)
            truncation_info: dict[str, Any] = {}
            # Note: truncate_dict_fields would be imported if we use it
            # For now, returning full info

            logger.info(f"Successfully inspected volume: {volume_name}")

            # Convert to output model for validation
            output = InspectVolumeOutput(
                details=details,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Volume not found: {volume_name}")
            raise VolumeNotFound(ERROR_VOLUME_NOT_FOUND.format(volume_name)) from e
        except APIError as e:
            logger.error(f"Failed to inspect volume: {e}")
            raise DockerOperationError(f"Failed to inspect volume: {e}") from e

    return (
        "docker_inspect_volume",
        "Get detailed information about a Docker volume",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        inspect_volume,
    )


def create_create_volume_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the create_volume FastMCP tool."""

    def create_volume(
        name: str | None = None,
        driver: str = "local",
        driver_opts: dict[str, str] | None = None,
        labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create a new Docker volume.

        Args:
            name: Volume name (auto-generated if not set)
            driver: Volume driver
            driver_opts: Driver-specific options
            labels: Volume labels

        Returns:
            Dictionary with created volume info

        Raises:
            DockerOperationError: If creation fails
        """
        try:
            logger.info(f"Creating volume: {name or '(auto-generated)'}")

            # Prepare kwargs for volume creation
            kwargs: dict[str, Any] = {"driver": driver}

            if name:
                kwargs["name"] = name
            if driver_opts:
                kwargs["driver_opts"] = driver_opts
            if labels:
                kwargs["labels"] = labels

            volume = docker_client.client.volumes.create(**kwargs)

            logger.info(f"Successfully created volume: {volume.name}")
            output = CreateVolumeOutput(
                name=volume.name,
                driver=volume.attrs.get("Driver", "local"),
                mountpoint=volume.attrs.get("Mountpoint", ""),
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to create volume: {e}")
            raise DockerOperationError(f"Failed to create volume: {e}") from e

    return (
        "docker_create_volume",
        "Create a new Docker volume",
        OperationSafety.MODERATE,
        False,  # not idempotent (creates different volumes)
        False,  # not open_world
        create_volume,
    )


def create_remove_volume_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the remove_volume FastMCP tool."""

    def remove_volume(
        volume_name: str,
        force: bool = False,
    ) -> dict[str, Any]:
        """Remove a Docker volume.

        Args:
            volume_name: Volume name
            force: Force removal

        Returns:
            Dictionary with removed volume name

        Raises:
            VolumeNotFound: If volume doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(f"Removing volume: {volume_name} (force={force})")

            volume = docker_client.client.volumes.get(volume_name)
            volume.remove(force=force)

            logger.info(f"Successfully removed volume: {volume_name}")
            output = RemoveVolumeOutput(volume_name=volume_name)
            return output.model_dump()

        except NotFound as e:
            logger.error(f"Volume not found: {volume_name}")
            raise VolumeNotFound(f"Volume not found: {volume_name}") from e
        except APIError as e:
            logger.error(f"Failed to remove volume: {e}")
            raise DockerOperationError(f"Failed to remove volume: {e}") from e

    return (
        "docker_remove_volume",
        "Remove a Docker volume",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (volume is gone after first removal)
        False,  # not open_world
        remove_volume,
    )


def create_prune_volumes_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the prune_volumes FastMCP tool."""

    def prune_volumes(
        filters: dict[str, str | list[str]] | None = None,
        force_all: bool = False,
    ) -> dict[str, Any]:
        """Prune Docker volumes (unused by default, all with force_all=true).

        Args:
            filters: Filters to apply (only when force_all=False)
            force_all: Force remove ALL volumes

        Returns:
            Dictionary with deleted volumes and space reclaimed

        Raises:
            DockerOperationError: If pruning fails
        """
        try:
            logger.info(f"Pruning volumes (force_all={force_all}, filters={filters})")

            # Delegate to helper function based on mode
            if force_all:
                deleted = force_remove_all_volumes(docker_client.client)
                logger.info(f"Successfully force-pruned {len(deleted)} volumes (force_all=True)")
                output = PruneVolumesOutput(deleted=deleted, space_reclaimed=0)
                return output.model_dump()

            # Standard prune (only unused volumes)
            result = docker_client.client.volumes.prune(filters=filters)
            deleted = result.get("VolumesDeleted", []) or []
            space_reclaimed = result.get("SpaceReclaimed", 0)

            logger.info(
                f"Successfully pruned {len(deleted)} volumes, reclaimed {space_reclaimed} bytes"
            )
            output = PruneVolumesOutput(deleted=deleted, space_reclaimed=space_reclaimed)
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to prune volumes: {e}")
            raise DockerOperationError(f"Failed to prune volumes: {e}") from e

    return (
        "docker_prune_volumes",
        "Prune Docker volumes (unused by default, all with force_all=true)",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (different volumes may be pruned each time)
        False,  # not open_world
        prune_volumes,
    )


def register_volume_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all volume tools with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        List of registered tool names
    """
    tools = [
        # SAFE tools (read-only)
        create_list_volumes_tool(docker_client, safety_config),
        create_inspect_volume_tool(docker_client),
        # MODERATE tools (state-changing)
        create_create_volume_tool(docker_client),
        # DESTRUCTIVE tools (permanent deletion)
        create_remove_volume_tool(docker_client),
        create_prune_volumes_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
