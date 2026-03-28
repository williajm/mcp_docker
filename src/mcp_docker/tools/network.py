"""FastMCP network tools."""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import (
    DESC_NETWORK_ID,
    FiltersInput,
    ToolSpec,
)
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    NetworkNotFound,
)
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND, ERROR_NETWORK_NOT_FOUND

logger = get_logger(__name__)


def _build_connect_kwargs(
    container_id: str,
    aliases: list[str] | None,
    ipv4_address: str | None,
    ipv6_address: str | None,
    links: list[str] | None,
) -> dict[str, Any]:
    """Build kwargs for network.connect() call.

    Args:
        container_id: Container ID or name
        aliases: Network-scoped aliases
        ipv4_address: IPv4 address
        ipv6_address: IPv6 address
        links: Legacy container links

    Returns:
        Dictionary of kwargs for network.connect()
    """
    kwargs: dict[str, Any] = {"container": container_id}
    if aliases:
        kwargs["aliases"] = aliases
    if ipv4_address:
        kwargs["ipv4_address"] = ipv4_address
    if ipv6_address:
        kwargs["ipv6_address"] = ipv6_address
    if links:
        kwargs["links"] = links
    return kwargs


# Input/Output Models (reused from legacy tools)


class ListNetworksInput(FiltersInput):
    """Input for listing networks."""


class ListNetworksOutput(BaseModel):
    """Output for listing networks."""

    networks: list[dict[str, Any]] = Field(description="List of networks with basic info")
    count: int = Field(description="Total number of networks found")


class InspectNetworkInput(BaseModel):
    """Input for inspecting a network."""

    network_id: str = Field(description=DESC_NETWORK_ID)


class InspectNetworkOutput(BaseModel):
    """Output for inspecting a network."""

    details: dict[str, Any] = Field(description="Detailed network information")


class CreateNetworkInput(BaseModel):
    """Input for creating a network."""

    name: str = Field(description="Network name")
    driver: str = Field(default="bridge", description="Network driver (bridge, overlay, etc.)")
    options: dict[str, Any] | str | None = Field(
        default=None,
        description=(
            "Driver-specific options as key-value pairs. "
            "Example: {'com.docker.network.bridge.name': 'docker1', 'mtu': '1500'}"
        ),
    )
    ipam: dict[str, Any] | str | None = Field(
        default=None,
        description=(
            "IPAM (IP Address Management) configuration. "
            "Example: {'Config': [{'Subnet': '172.20.0.0/16', 'Gateway': '172.20.0.1'}]}"
        ),
    )
    internal: bool = Field(default=False, description="Restrict external access")
    labels: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Network labels as key-value pairs. "
            "Example: {'environment': 'production', 'team': 'backend'}"
        ),
    )
    enable_ipv6: bool = Field(default=False, description="Enable IPv6")
    attachable: bool = Field(default=False, description="Enable manual container attachment")

    @field_validator("options", "ipam", "labels", mode="before")
    @classmethod
    def _parse_json_fields(cls, v: Any, info: Any) -> Any:
        """Parse JSON string fields to dicts."""
        return parse_json_string_field(v, info.field_name)


class CreateNetworkOutput(BaseModel):
    """Output for creating a network."""

    network_id: str = Field(description="Created network ID")
    name: str = Field(description="Network name")
    warnings: list[str] | None = Field(default=None, description="Any warnings from creation")


class ConnectContainerInput(BaseModel):
    """Input for connecting a container to a network."""

    network_id: str = Field(description=DESC_NETWORK_ID)
    container_id: str = Field(description="Container ID or name")
    aliases: list[str] | None = Field(default=None, description="Network-scoped aliases")
    ipv4_address: str | None = Field(default=None, description="IPv4 address")
    ipv6_address: str | None = Field(default=None, description="IPv6 address")
    links: list[str] | None = Field(default=None, description="Legacy container links")


class ConnectContainerOutput(BaseModel):
    """Output for connecting a container to a network."""

    network_id: str = Field(description="Network ID")
    container_id: str = Field(description="Container ID")
    status: str = Field(description="Connection status")


class DisconnectContainerInput(BaseModel):
    """Input for disconnecting a container from a network."""

    network_id: str = Field(description=DESC_NETWORK_ID)
    container_id: str = Field(description="Container ID or name")
    force: bool = Field(default=False, description="Force disconnection")


class DisconnectContainerOutput(BaseModel):
    """Output for disconnecting a container from a network."""

    network_id: str = Field(description="Network ID")
    container_id: str = Field(description="Container ID")
    status: str = Field(description="Disconnection status")


class RemoveNetworkInput(BaseModel):
    """Input for removing a network."""

    network_id: str = Field(description=DESC_NETWORK_ID)


class RemoveNetworkOutput(BaseModel):
    """Output for removing a network."""

    network_id: str = Field(description="Removed network ID")


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


def create_inspect_network_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the inspect_network tool."""

    def inspect_network(
        network_id: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker network."""
        try:
            logger.info(f"Inspecting network: {network_id}")
            network = docker_client.client.networks.get(network_id)
            details = network.attrs

            logger.info(f"Successfully inspected network: {network_id}")

            output = InspectNetworkOutput(details=details)

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Network not found: {network_id}")
            raise NetworkNotFound(ERROR_NETWORK_NOT_FOUND.format(network_id)) from e
        except APIError as e:
            logger.error(f"Failed to inspect network: {e}")
            raise DockerOperationError(f"Failed to inspect network: {e}") from e

    return ToolSpec(
        name="docker_inspect_network",
        description="Get detailed information about a Docker network",
        safety=OperationSafety.SAFE,
        func=inspect_network,
        idempotent=True,
    )


def create_create_network_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the create_network tool."""

    def create_network(  # noqa: PLR0913 - Docker API requires these parameters
        name: str,
        driver: str = "bridge",
        options: dict[str, Any] | None = None,
        ipam: dict[str, Any] | None = None,
        internal: bool = False,
        labels: dict[str, str] | None = None,
        enable_ipv6: bool = False,
        attachable: bool = False,
    ) -> dict[str, Any]:
        """Create a new Docker network."""
        try:
            logger.info(f"Creating network: {name} (driver={driver})")

            # Prepare kwargs for network creation
            kwargs: dict[str, Any] = {
                "name": name,
                "driver": driver,
                "internal": internal,
                "enable_ipv6": enable_ipv6,
                "attachable": attachable,
            }

            if options:
                kwargs["options"] = options
            if ipam:
                kwargs["ipam"] = ipam
            if labels:
                kwargs["labels"] = labels

            network = docker_client.client.networks.create(**kwargs)

            logger.info(f"Successfully created network: {network.id}")
            output = CreateNetworkOutput(
                network_id=str(network.id),
                name=str(network.name),
                warnings=None,
            )
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to create network: {e}")
            raise DockerOperationError(f"Failed to create network: {e}") from e

    return ToolSpec(
        name="docker_create_network",
        description="Create a new Docker network",
        safety=OperationSafety.MODERATE,
        func=create_network,
    )


def create_connect_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the connect_container tool."""

    def connect_container(  # noqa: PLR0913 - Docker API requires these parameters
        network_id: str,
        container_id: str,
        aliases: list[str] | None = None,
        ipv4_address: str | None = None,
        ipv6_address: str | None = None,
        links: list[str] | None = None,
    ) -> dict[str, Any]:
        """Connect a container to a Docker network."""
        try:
            logger.info(f"Connecting container {container_id} to network {network_id}")

            network = docker_client.client.networks.get(network_id)

            # Resolve container name/ID to full container ID for comparison
            # (input can be name or ID, but network.attrs uses full IDs)
            try:
                container = docker_client.client.containers.get(container_id)
                container_full_id = str(container.id)
            except NotFound:
                # Container doesn't exist - will error below, let it proceed
                container_full_id = container_id

            # Check if already connected (idempotent behavior for basic connect)
            # Only return early if no aliases/IPs are specified - otherwise proceed
            # and let Docker error if user is trying to change network settings
            has_network_config = bool(aliases or ipv4_address or ipv6_address or links)
            containers_in_network = network.attrs.get("Containers", {})
            if not has_network_config and container_full_id in containers_in_network:
                # Basic connect without config changes - safe to return early (idempotent)
                logger.info(f"Container {container_id} already connected to network {network_id}")
                return ConnectContainerOutput(
                    network_id=str(network.id),
                    container_id=container_id,
                    status="connected",
                ).model_dump()

            # Not connected - perform the connection
            kwargs = _build_connect_kwargs(container_id, aliases, ipv4_address, ipv6_address, links)
            network.connect(**kwargs)

            logger.info(f"Successfully connected container {container_id} to network {network_id}")
            output = ConnectContainerOutput(
                network_id=str(network.id),
                container_id=container_id,
                status="connected",
            )
            return output.model_dump()

        except NotFound as e:
            # Try to determine if it's a network or container not found
            error_msg = str(e).lower()
            if "network" in error_msg:
                logger.error(f"Network not found: {network_id}")
                raise NetworkNotFound(f"Network not found: {network_id}") from e
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(container_id))
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to connect container: {e}")
            raise DockerOperationError(f"Failed to connect container: {e}") from e

    return ToolSpec(
        name="docker_connect_container",
        description="Connect a container to a Docker network",
        safety=OperationSafety.MODERATE,
        func=connect_container,
    )


def create_disconnect_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the disconnect_container tool."""

    def disconnect_container(
        network_id: str,
        container_id: str,
        force: bool = False,
    ) -> dict[str, Any]:
        """Disconnect a container from a Docker network."""
        try:
            logger.info(f"Disconnecting container {container_id} from network {network_id}")

            network = docker_client.client.networks.get(network_id)

            # Resolve container name/ID to full container ID for comparison
            # (input can be name or ID, but network.attrs uses full IDs)
            try:
                container = docker_client.client.containers.get(container_id)
                container_full_id = str(container.id)
            except NotFound:
                # Container doesn't exist - will error below, let it proceed
                container_full_id = container_id

            # Check if already disconnected (idempotent: avoid error-based detection)
            containers_in_network = network.attrs.get("Containers", {})
            if container_full_id not in containers_in_network:
                logger.info(
                    f"Container {container_id} not connected to network {network_id} "
                    f"(already disconnected)"
                )
                return DisconnectContainerOutput(
                    network_id=str(network.id),
                    container_id=container_id,
                    status="disconnected",
                ).model_dump()

            # Still connected - perform the disconnection
            network.disconnect(container=container_id, force=force)

            logger.info(
                f"Successfully disconnected container {container_id} from network {network_id}"
            )
            output = DisconnectContainerOutput(
                network_id=str(network.id),
                container_id=container_id,
                status="disconnected",
            )
            return output.model_dump()

        except NotFound as e:
            # Try to determine if it's a network or container not found
            error_msg = str(e).lower()
            if "network" in error_msg:
                logger.error(f"Network not found: {network_id}")
                raise NetworkNotFound(f"Network not found: {network_id}") from e
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(container_id))
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to disconnect container: {e}")
            raise DockerOperationError(f"Failed to disconnect container: {e}") from e

    return ToolSpec(
        name="docker_disconnect_container",
        description="Disconnect a container from a Docker network",
        safety=OperationSafety.MODERATE,
        func=disconnect_container,
        idempotent=True,
    )


def create_remove_network_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the remove_network tool."""

    def remove_network(
        network_id: str,
    ) -> dict[str, Any]:
        """Remove a Docker network."""
        try:
            logger.info(f"Removing network: {network_id}")

            network = docker_client.client.networks.get(network_id)
            network_id_str = network.id
            network.remove()

            logger.info(f"Successfully removed network: {network_id_str}")
            output = RemoveNetworkOutput(network_id=str(network_id_str))
            return output.model_dump()

        except NotFound as e:
            logger.error(f"Network not found: {network_id}")
            raise NetworkNotFound(f"Network not found: {network_id}") from e
        except APIError as e:
            logger.error(f"Failed to remove network: {e}")
            raise DockerOperationError(f"Failed to remove network: {e}") from e

    return ToolSpec(
        name="docker_remove_network",
        description="Remove a Docker network",
        safety=OperationSafety.DESTRUCTIVE,
        func=remove_network,
    )


def register_network_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all network tools with FastMCP."""
    tools = [
        # SAFE tools (read-only)
        create_list_networks_tool(docker_client),
        create_inspect_network_tool(docker_client),
        # MODERATE tools (state-changing)
        create_create_network_tool(docker_client),
        create_connect_container_tool(docker_client),
        create_disconnect_container_tool(docker_client),
        # DESTRUCTIVE tools (permanent deletion)
        create_remove_network_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
