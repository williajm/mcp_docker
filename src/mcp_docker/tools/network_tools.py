"""Network management tools for Docker MCP server.

This module provides tools for managing Docker networks, including
creating, listing, inspecting, connecting, and removing networks.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.base import OperationSafety
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError, NetworkNotFound
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# Input/Output Models


class ListNetworksInput(BaseModel):
    """Input for listing networks."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None, description="Filters to apply (e.g., {'driver': ['bridge']})"
    )


class ListNetworksOutput(BaseModel):
    """Output for listing networks."""

    networks: list[dict[str, Any]] = Field(description="List of networks with basic info")
    count: int = Field(description="Total number of networks")


class InspectNetworkInput(BaseModel):
    """Input for inspecting a network."""

    network_id: str = Field(description="Network ID or name")


class InspectNetworkOutput(BaseModel):
    """Output for inspecting a network."""

    details: dict[str, Any] = Field(description="Detailed network information")


class CreateNetworkInput(BaseModel):
    """Input for creating a network."""

    name: str = Field(description="Network name")
    driver: str = Field(default="bridge", description="Network driver (bridge, overlay, etc.)")
    options: dict[str, Any] | None = Field(default=None, description="Driver options")
    ipam: dict[str, Any] | None = Field(default=None, description="IPAM configuration")
    internal: bool = Field(default=False, description="Restrict external access")
    labels: dict[str, str] | None = Field(default=None, description="Network labels")
    enable_ipv6: bool = Field(default=False, description="Enable IPv6")
    attachable: bool = Field(default=False, description="Enable manual container attachment")


class CreateNetworkOutput(BaseModel):
    """Output for creating a network."""

    network_id: str = Field(description="Created network ID")
    name: str = Field(description="Network name")
    warnings: list[str] | None = Field(default=None, description="Any warnings from creation")


class ConnectContainerInput(BaseModel):
    """Input for connecting a container to a network."""

    network_id: str = Field(description="Network ID or name")
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

    network_id: str = Field(description="Network ID or name")
    container_id: str = Field(description="Container ID or name")
    force: bool = Field(default=False, description="Force disconnection")


class DisconnectContainerOutput(BaseModel):
    """Output for disconnecting a container from a network."""

    network_id: str = Field(description="Network ID")
    container_id: str = Field(description="Container ID")
    status: str = Field(description="Disconnection status")


class RemoveNetworkInput(BaseModel):
    """Input for removing a network."""

    network_id: str = Field(description="Network ID or name")


class RemoveNetworkOutput(BaseModel):
    """Output for removing a network."""

    network_id: str = Field(description="Removed network ID")


# Tool Implementations


class ListNetworksTool:
    """List Docker networks with optional filters."""

    name = "docker_list_networks"
    description = "List Docker networks with optional filters"
    input_model = ListNetworksInput
    output_model = ListNetworksOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: ListNetworksInput) -> ListNetworksOutput:
        """Execute the list networks operation.

        Args:
            input_data: Input parameters

        Returns:
            List of networks with basic info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing networks (filters={input_data.filters})")
            networks = self.docker_client.client.networks.list(filters=input_data.filters)

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
            return ListNetworksOutput(networks=network_list, count=len(network_list))

        except APIError as e:
            logger.error(f"Failed to list networks: {e}")
            raise DockerOperationError(f"Failed to list networks: {e}") from e


class InspectNetworkTool:
    """Inspect a Docker network to get detailed information."""

    name = "docker_inspect_network"
    description = "Get detailed information about a Docker network"
    input_model = InspectNetworkInput
    output_model = InspectNetworkOutput
    safety_level = OperationSafety.SAFE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: InspectNetworkInput) -> InspectNetworkOutput:
        """Execute the inspect network operation.

        Args:
            input_data: Input parameters

        Returns:
            Detailed network information

        Raises:
            NetworkNotFound: If network doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting network: {input_data.network_id}")
            network = self.docker_client.client.networks.get(input_data.network_id)
            details = network.attrs

            logger.info(f"Successfully inspected network: {input_data.network_id}")
            return InspectNetworkOutput(details=details)

        except NotFound as e:
            logger.error(f"Network not found: {input_data.network_id}")
            raise NetworkNotFound(f"Network not found: {input_data.network_id}") from e
        except APIError as e:
            logger.error(f"Failed to inspect network: {e}")
            raise DockerOperationError(f"Failed to inspect network: {e}") from e


class CreateNetworkTool:
    """Create a new Docker network."""

    name = "docker_create_network"
    description = "Create a new Docker network"
    input_model = CreateNetworkInput
    output_model = CreateNetworkOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: CreateNetworkInput) -> CreateNetworkOutput:
        """Execute the create network operation.

        Args:
            input_data: Input parameters

        Returns:
            Created network information

        Raises:
            DockerOperationError: If creation fails
        """
        try:
            logger.info(f"Creating network: {input_data.name} (driver={input_data.driver})")

            # Prepare kwargs for network creation
            kwargs: dict[str, Any] = {
                "name": input_data.name,
                "driver": input_data.driver,
                "internal": input_data.internal,
                "enable_ipv6": input_data.enable_ipv6,
                "attachable": input_data.attachable,
            }

            if input_data.options:
                kwargs["options"] = input_data.options
            if input_data.ipam:
                kwargs["ipam"] = input_data.ipam
            if input_data.labels:
                kwargs["labels"] = input_data.labels

            network = self.docker_client.client.networks.create(**kwargs)

            logger.info(f"Successfully created network: {network.id}")
            return CreateNetworkOutput(
                network_id=str(network.id), name=str(network.name), warnings=None
            )

        except APIError as e:
            logger.error(f"Failed to create network: {e}")
            raise DockerOperationError(f"Failed to create network: {e}") from e


class ConnectContainerTool:
    """Connect a container to a network."""

    name = "docker_connect_container"
    description = "Connect a container to a Docker network"
    input_model = ConnectContainerInput
    output_model = ConnectContainerOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: ConnectContainerInput) -> ConnectContainerOutput:
        """Execute the connect container operation.

        Args:
            input_data: Input parameters

        Returns:
            Connection result

        Raises:
            NetworkNotFound: If network doesn't exist
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If connection fails
        """
        try:
            logger.info(
                f"Connecting container {input_data.container_id} "
                f"to network {input_data.network_id}"
            )

            network = self.docker_client.client.networks.get(input_data.network_id)

            # Prepare kwargs for connect
            kwargs: dict[str, Any] = {"container": input_data.container_id}
            if input_data.aliases:
                kwargs["aliases"] = input_data.aliases
            if input_data.ipv4_address:
                kwargs["ipv4_address"] = input_data.ipv4_address
            if input_data.ipv6_address:
                kwargs["ipv6_address"] = input_data.ipv6_address
            if input_data.links:
                kwargs["links"] = input_data.links

            network.connect(**kwargs)

            logger.info(
                f"Successfully connected container {input_data.container_id} "
                f"to network {input_data.network_id}"
            )
            return ConnectContainerOutput(
                network_id=str(network.id),
                container_id=input_data.container_id,
                status="connected",
            )

        except NotFound as e:
            # Try to determine if it's a network or container not found
            error_msg = str(e).lower()
            if "network" in error_msg:
                logger.error(f"Network not found: {input_data.network_id}")
                raise NetworkNotFound(f"Network not found: {input_data.network_id}") from e
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(
                f"Container not found: {input_data.container_id}"
            ) from e
        except APIError as e:
            logger.error(f"Failed to connect container: {e}")
            raise DockerOperationError(f"Failed to connect container: {e}") from e


class DisconnectContainerTool:
    """Disconnect a container from a network."""

    name = "docker_disconnect_container"
    description = "Disconnect a container from a Docker network"
    input_model = DisconnectContainerInput
    output_model = DisconnectContainerOutput
    safety_level = OperationSafety.MODERATE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: DisconnectContainerInput) -> DisconnectContainerOutput:
        """Execute the disconnect container operation.

        Args:
            input_data: Input parameters

        Returns:
            Disconnection result

        Raises:
            NetworkNotFound: If network doesn't exist
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If disconnection fails
        """
        try:
            logger.info(
                f"Disconnecting container {input_data.container_id} "
                f"from network {input_data.network_id}"
            )

            network = self.docker_client.client.networks.get(input_data.network_id)
            network.disconnect(container=input_data.container_id, force=input_data.force)

            logger.info(
                f"Successfully disconnected container {input_data.container_id} "
                f"from network {input_data.network_id}"
            )
            return DisconnectContainerOutput(
                network_id=str(network.id),
                container_id=input_data.container_id,
                status="disconnected",
            )

        except NotFound as e:
            # Try to determine if it's a network or container not found
            error_msg = str(e).lower()
            if "network" in error_msg:
                logger.error(f"Network not found: {input_data.network_id}")
                raise NetworkNotFound(f"Network not found: {input_data.network_id}") from e
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(
                f"Container not found: {input_data.container_id}"
            ) from e
        except APIError as e:
            logger.error(f"Failed to disconnect container: {e}")
            raise DockerOperationError(f"Failed to disconnect container: {e}") from e


class RemoveNetworkTool:
    """Remove a Docker network."""

    name = "docker_remove_network"
    description = "Remove a Docker network"
    input_model = RemoveNetworkInput
    output_model = RemoveNetworkOutput
    safety_level = OperationSafety.DESTRUCTIVE

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper instance
        """
        self.docker_client = docker_client

    async def execute(self, input_data: RemoveNetworkInput) -> RemoveNetworkOutput:
        """Execute the remove network operation.

        Args:
            input_data: Input parameters

        Returns:
            Remove operation result

        Raises:
            NetworkNotFound: If network doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(f"Removing network: {input_data.network_id}")

            network = self.docker_client.client.networks.get(input_data.network_id)
            network_id = network.id
            network.remove()

            logger.info(f"Successfully removed network: {network_id}")
            return RemoveNetworkOutput(network_id=str(network_id))

        except NotFound as e:
            logger.error(f"Network not found: {input_data.network_id}")
            raise NetworkNotFound(f"Network not found: {input_data.network_id}") from e
        except APIError as e:
            logger.error(f"Failed to remove network: {e}")
            raise DockerOperationError(f"Failed to remove network: {e}") from e


# Export all tools
__all__ = [
    "ListNetworksTool",
    "InspectNetworkTool",
    "CreateNetworkTool",
    "ConnectContainerTool",
    "DisconnectContainerTool",
    "RemoveNetworkTool",
]
