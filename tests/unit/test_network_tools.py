"""Unit tests for network tools."""

from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.network_tools import (
    ConnectContainerInput,
    ConnectContainerTool,
    CreateNetworkInput,
    CreateNetworkTool,
    DisconnectContainerInput,
    DisconnectContainerTool,
    InspectNetworkInput,
    InspectNetworkTool,
    ListNetworksInput,
    ListNetworksTool,
    RemoveNetworkInput,
    RemoveNetworkTool,
)
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    NetworkNotFound,
)


@pytest.fixture
def mock_docker_client() -> Any:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def mock_network() -> Any:
    """Create a mock network."""
    network = MagicMock()
    network.id = "net123"
    network.short_id = "net123"[:12]
    network.name = "my-network"
    network.attrs = {
        "Id": "net123",
        "Name": "my-network",
        "Driver": "bridge",
        "Scope": "local",
        "Labels": {"env": "test"},
    }
    return network


class TestListNetworksTool:
    """Tests for ListNetworksTool."""

    @pytest.mark.asyncio
    async def test_list_networks_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful network listing."""
        mock_docker_client.client.networks.list.return_value = [mock_network]

        tool = ListNetworksTool(mock_docker_client, safety_config)
        input_data = ListNetworksInput()
        result = await tool.execute(input_data)

        assert result.count == 1
        assert len(result.networks) == 1
        assert result.networks[0]["id"] == "net123"
        assert result.networks[0]["name"] == "my-network"
        assert result.networks[0]["driver"] == "bridge"
        mock_docker_client.client.networks.list.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_list_networks_with_filters(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test listing networks with filters."""
        mock_docker_client.client.networks.list.return_value = [mock_network]

        tool = ListNetworksTool(mock_docker_client, safety_config)
        input_data = ListNetworksInput(filters={"driver": ["bridge"]})
        result = await tool.execute(input_data)

        assert result.count == 1
        mock_docker_client.client.networks.list.assert_called_once_with(
            filters={"driver": ["bridge"]}
        )

    @pytest.mark.asyncio
    async def test_list_networks_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.networks.list.side_effect = APIError("API error")

        tool = ListNetworksTool(mock_docker_client, safety_config)
        input_data = ListNetworksInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestInspectNetworkTool:
    """Tests for InspectNetworkTool."""

    @pytest.mark.asyncio
    async def test_inspect_network_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful network inspection."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = InspectNetworkTool(mock_docker_client, safety_config)
        input_data = InspectNetworkInput(network_id="my-network")
        result = await tool.execute(input_data)

        assert result.details["Id"] == "net123"
        assert result.details["Name"] == "my-network"
        mock_docker_client.client.networks.get.assert_called_once_with("my-network")

    @pytest.mark.asyncio
    async def test_inspect_network_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of network not found."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        tool = InspectNetworkTool(mock_docker_client, safety_config)
        input_data = InspectNetworkInput(network_id="nonexistent")

        with pytest.raises(NetworkNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_inspect_network_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.networks.get.side_effect = APIError("API error")

        tool = InspectNetworkTool(mock_docker_client, safety_config)
        input_data = InspectNetworkInput(network_id="my-network")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestCreateNetworkTool:
    """Tests for CreateNetworkTool."""

    @pytest.mark.asyncio
    async def test_create_network_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful network creation."""
        mock_docker_client.client.networks.create.return_value = mock_network

        tool = CreateNetworkTool(mock_docker_client, safety_config)
        input_data = CreateNetworkInput(name="my-network", driver="bridge")
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.name == "my-network"
        mock_docker_client.client.networks.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_network_with_options(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test creating network with additional options."""
        mock_docker_client.client.networks.create.return_value = mock_network

        tool = CreateNetworkTool(mock_docker_client, safety_config)
        input_data = CreateNetworkInput(
            name="my-network",
            driver="overlay",
            internal=True,
            enable_ipv6=True,
            attachable=True,
            labels={"env": "test"},
            options={"com.docker.network.bridge.name": "docker1"},
        )
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        call_kwargs = mock_docker_client.client.networks.create.call_args[1]
        assert call_kwargs["internal"] is True
        assert call_kwargs["enable_ipv6"] is True
        assert call_kwargs["attachable"] is True
        assert call_kwargs["labels"] == {"env": "test"}

    @pytest.mark.asyncio
    async def test_create_network_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.networks.create.side_effect = APIError("API error")

        tool = CreateNetworkTool(mock_docker_client, safety_config)
        input_data = CreateNetworkInput(name="my-network")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestConnectContainerTool:
    """Tests for ConnectContainerTool."""

    @pytest.mark.asyncio
    async def test_connect_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful container connection."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(network_id="my-network", container_id="container123")
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "container123"
        assert result.status == "connected"
        mock_network.connect.assert_called_once_with(container="container123")

    @pytest.mark.asyncio
    async def test_connect_container_with_options(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test connecting container with additional options."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(
            network_id="my-network",
            container_id="container123",
            aliases=["web", "api"],
            ipv4_address="172.18.0.10",
        )
        result = await tool.execute(input_data)

        assert result.status == "connected"
        call_kwargs = mock_network.connect.call_args[1]
        assert call_kwargs["aliases"] == ["web", "api"]
        assert call_kwargs["ipv4_address"] == "172.18.0.10"

    @pytest.mark.asyncio
    async def test_connect_container_network_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of network not found."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(network_id="nonexistent", container_id="container123")

        with pytest.raises(NetworkNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_connect_container_not_found(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test handling of container not found."""
        mock_docker_client.client.networks.get.return_value = mock_network
        mock_network.connect.side_effect = NotFound("Container not found")

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(network_id="my-network", container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)


class TestDisconnectContainerTool:
    """Tests for DisconnectContainerTool."""

    @pytest.mark.asyncio
    async def test_disconnect_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful container disconnection."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="my-network", container_id="container123")
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "container123"
        assert result.status == "disconnected"
        mock_network.disconnect.assert_called_once_with(container="container123", force=False)

    @pytest.mark.asyncio
    async def test_disconnect_container_with_force(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test disconnecting container with force."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(
            network_id="my-network", container_id="container123", force=True
        )
        result = await tool.execute(input_data)

        assert result.status == "disconnected"
        mock_network.disconnect.assert_called_once_with(container="container123", force=True)

    @pytest.mark.asyncio
    async def test_disconnect_container_network_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of network not found."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="nonexistent", container_id="container123")

        with pytest.raises(NetworkNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_disconnect_container_not_found(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test handling of container not found."""
        mock_docker_client.client.networks.get.return_value = mock_network
        mock_network.disconnect.side_effect = NotFound("Container not found")

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="my-network", container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)


class TestRemoveNetworkTool:
    """Tests for RemoveNetworkTool."""

    @pytest.mark.asyncio
    async def test_remove_network_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful network removal."""
        mock_docker_client.client.networks.get.return_value = mock_network

        tool = RemoveNetworkTool(mock_docker_client, safety_config)
        input_data = RemoveNetworkInput(network_id="my-network")
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        mock_docker_client.client.networks.get.assert_called_once_with("my-network")
        mock_network.remove.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_network_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of network not found."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        tool = RemoveNetworkTool(mock_docker_client, safety_config)
        input_data = RemoveNetworkInput(network_id="nonexistent")

        with pytest.raises(NetworkNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_remove_network_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.networks.get.return_value = mock_network
        mock_network.remove.side_effect = APIError("API error")

        tool = RemoveNetworkTool(mock_docker_client, safety_config)
        input_data = RemoveNetworkInput(network_id="my-network")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)
