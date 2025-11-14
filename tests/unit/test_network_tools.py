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
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is NOT connected (so connect will be called)
        mock_network.attrs = {"Containers": {}}

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
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is NOT connected (so connect will be called)
        mock_network.attrs = {"Containers": {}}

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

    @pytest.mark.asyncio
    async def test_connect_container_already_connected_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test idempotent behavior when container is already connected."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is already connected
        mock_network.attrs = {"Containers": {"container123": {"IPv4Address": "172.18.0.10"}}}

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(network_id="my-network", container_id="container123")

        # Should succeed (idempotent) without calling connect
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "container123"
        assert result.status == "connected"
        # Verify connect was NOT called (container already connected)
        mock_network.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_container_with_name_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test idempotent behavior when using container name instead of ID."""
        # Mock container lookup to resolve name to full ID
        mock_container = Mock()
        mock_container.id = "abc123def456"  # Full container ID
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs with full container ID
        mock_network.attrs = {"Containers": {"abc123def456": {"IPv4Address": "172.18.0.10"}}}

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        # Use container name instead of ID
        input_data = ConnectContainerInput(network_id="my-network", container_id="my-container")

        # Should resolve name to ID and detect already connected (idempotent)
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "my-container"  # Returns input name, not resolved ID
        assert result.status == "connected"
        # Verify connect was NOT called (container already connected)
        mock_network.connect.assert_not_called()
        # Verify container name was resolved
        mock_docker_client.client.containers.get.assert_called_once_with("my-container")

    @pytest.mark.asyncio
    async def test_connect_container_other_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test that non-idempotent API errors still raise exceptions."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is NOT connected (so connect will be called)
        mock_network.attrs = {"Containers": {}}
        # Simulate a different Docker error (not "already connected")
        mock_network.connect.side_effect = APIError("network is full")

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        input_data = ConnectContainerInput(network_id="my-network", container_id="container123")

        # Should raise error for non-idempotent failures
        with pytest.raises(DockerOperationError, match="network is full"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_connect_container_with_aliases_bypasses_idempotent_check(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test that providing aliases bypasses idempotent check to allow Docker error."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Container is already connected
        mock_network.attrs = {"Containers": {"container123": {"IPv4Address": "172.18.0.10"}}}
        # Docker will error when trying to connect with new aliases
        mock_network.connect.side_effect = APIError("container already connected")

        tool = ConnectContainerTool(mock_docker_client, safety_config)
        # User is trying to add aliases to already-connected container
        input_data = ConnectContainerInput(
            network_id="my-network", container_id="container123", aliases=["newAlias"]
        )

        # Should NOT return early (idempotent check skipped), should proceed and error
        with pytest.raises(DockerOperationError, match="already connected"):
            await tool.execute(input_data)
        # Verify connect was actually called (not skipped by idempotent check)
        mock_network.connect.assert_called_once()


class TestDisconnectContainerTool:
    """Tests for DisconnectContainerTool."""

    @pytest.mark.asyncio
    async def test_disconnect_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test successful container disconnection."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is connected
        mock_network.attrs = {"Containers": {"container123": {"IPv4Address": "172.18.0.10"}}}

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
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is connected
        mock_network.attrs = {"Containers": {"container123": {"IPv4Address": "172.18.0.10"}}}

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
        # Mock container lookup to raise NotFound (container doesn't exist)
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is connected (so disconnect will be called)
        # Use the input ID since containers.get will fail
        mock_network.attrs = {"Containers": {"nonexistent": {"IPv4Address": "172.18.0.10"}}}
        mock_network.disconnect.side_effect = NotFound("Container not found")

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="my-network", container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_disconnect_container_not_connected_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test idempotent behavior when container is not connected."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is NOT connected (empty Containers dict)
        mock_network.attrs = {"Containers": {}}

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="my-network", container_id="container123")

        # Should succeed (idempotent) without calling disconnect
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "container123"
        assert result.status == "disconnected"
        # Verify disconnect was NOT called (container not connected)
        mock_network.disconnect.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_container_with_name_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test idempotent behavior when using container name instead of ID."""
        # Mock container lookup to resolve name to full ID
        mock_container = Mock()
        mock_container.id = "abc123def456"  # Full container ID
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs with no containers (already disconnected)
        mock_network.attrs = {"Containers": {}}

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        # Use container name instead of ID
        input_data = DisconnectContainerInput(network_id="my-network", container_id="my-container")

        # Should resolve name to ID and detect not connected (idempotent)
        result = await tool.execute(input_data)

        assert result.network_id == "net123"
        assert result.container_id == "my-container"  # Returns input name, not resolved ID
        assert result.status == "disconnected"
        # Verify disconnect was NOT called (container not connected)
        mock_network.disconnect.assert_not_called()
        # Verify container name was resolved
        mock_docker_client.client.containers.get.assert_called_once_with("my-container")

    @pytest.mark.asyncio
    async def test_disconnect_container_other_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_network: Any
    ) -> None:
        """Test that non-idempotent API errors still raise exceptions."""
        # Mock container lookup to return container with matching ID
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker_client.client.containers.get.return_value = mock_container

        mock_docker_client.client.networks.get.return_value = mock_network
        # Mock network.attrs to show container is connected (so disconnect will be called)
        mock_network.attrs = {"Containers": {"container123": {"IPv4Address": "172.18.0.10"}}}
        # Simulate a different Docker error (not related to idempotency)
        mock_network.disconnect.side_effect = APIError("network operation failed")

        tool = DisconnectContainerTool(mock_docker_client, safety_config)
        input_data = DisconnectContainerInput(network_id="my-network", container_id="container123")

        # Should raise error for non-idempotent failures
        with pytest.raises(DockerOperationError, match="network operation failed"):
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
