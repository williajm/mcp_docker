"""Unit tests for fastmcp_tools/network.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.network import (
    CreateNetworkInput,
    _build_connect_kwargs,
    create_connect_container_tool,
    create_create_network_tool,
    create_disconnect_container_tool,
    create_inspect_network_tool,
    create_list_networks_tool,
    create_remove_network_tool,
)
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    NetworkNotFound,
)


class TestBuildConnectKwargs:
    """Test _build_connect_kwargs helper function."""

    def test_build_minimal_kwargs(self):
        """Test building kwargs with only container_id."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=None,
            ipv4_address=None,
            ipv6_address=None,
            links=None,
        )
        assert kwargs == {"container": "abc123"}

    def test_build_with_aliases(self):
        """Test building kwargs with aliases."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=["web", "frontend"],
            ipv4_address=None,
            ipv6_address=None,
            links=None,
        )
        assert kwargs == {"container": "abc123", "aliases": ["web", "frontend"]}

    def test_build_with_ipv4_address(self):
        """Test building kwargs with IPv4 address."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=None,
            ipv4_address="172.20.0.5",
            ipv6_address=None,
            links=None,
        )
        assert kwargs == {"container": "abc123", "ipv4_address": "172.20.0.5"}

    def test_build_with_ipv6_address(self):
        """Test building kwargs with IPv6 address."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=None,
            ipv4_address=None,
            ipv6_address="2001:db8::1",
            links=None,
        )
        assert kwargs == {"container": "abc123", "ipv6_address": "2001:db8::1"}

    def test_build_with_links(self):
        """Test building kwargs with links."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=None,
            ipv4_address=None,
            ipv6_address=None,
            links=["db:database"],
        )
        assert kwargs == {"container": "abc123", "links": ["db:database"]}

    def test_build_with_all_options(self):
        """Test building kwargs with all options."""
        kwargs = _build_connect_kwargs(
            container_id="abc123",
            aliases=["web", "api"],
            ipv4_address="172.20.0.5",
            ipv6_address="2001:db8::1",
            links=["db:database"],
        )
        assert kwargs == {
            "container": "abc123",
            "aliases": ["web", "api"],
            "ipv4_address": "172.20.0.5",
            "ipv6_address": "2001:db8::1",
            "links": ["db:database"],
        }


class TestCreateNetworkInputValidation:
    """Test CreateNetworkInput Pydantic model validation."""

    def test_json_string_parsing_options(self):
        """Test that options JSON string is parsed correctly."""
        input_data = CreateNetworkInput(
            name="my-network",
            options='{"com.docker.network.bridge.name": "docker1", "mtu": "1500"}',
        )
        assert input_data.options == {
            "com.docker.network.bridge.name": "docker1",
            "mtu": "1500",
        }

    def test_json_string_parsing_ipam(self):
        """Test that ipam JSON string is parsed correctly."""
        input_data = CreateNetworkInput(
            name="my-network",
            ipam='{"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]}',
        )
        assert input_data.ipam == {"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]}

    def test_json_string_parsing_labels(self):
        """Test that labels JSON string is parsed correctly."""
        input_data = CreateNetworkInput(
            name="my-network",
            labels='{"environment": "production", "team": "backend"}',
        )
        assert input_data.labels == {"environment": "production", "team": "backend"}

    def test_dict_passthrough(self):
        """Test that dict values are passed through."""
        input_data = CreateNetworkInput(
            name="my-network",
            options={"mtu": "1500"},
            ipam={"Config": [{"Subnet": "172.20.0.0/16"}]},
            labels={"env": "prod"},
        )
        assert input_data.options == {"mtu": "1500"}
        assert input_data.ipam == {"Config": [{"Subnet": "172.20.0.0/16"}]}
        assert input_data.labels == {"env": "prod"}


class TestListNetworksTool:
    """Test docker_list_networks tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_list_networks_success(self, mock_docker_client, safety_config):
        """Test successful network listing."""
        # Mock network objects
        net1 = Mock()
        net1.id = "net1id"
        net1.short_id = "net1"
        net1.name = "bridge"
        net1.attrs = {"Driver": "bridge", "Scope": "local", "Labels": {}}

        net2 = Mock()
        net2.id = "net2id"
        net2.short_id = "net2"
        net2.name = "my-network"
        net2.attrs = {"Driver": "bridge", "Scope": "local", "Labels": {"env": "test"}}

        mock_docker_client.client.networks.list.return_value = [net1, net2]

        # Get the list function
        _, _, _, _, _, list_func = create_list_networks_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify
        assert result["count"] == 2
        assert len(result["networks"]) == 2
        assert result["networks"][0]["name"] == "bridge"
        assert result["networks"][1]["name"] == "my-network"
        assert result["networks"][1]["labels"] == {"env": "test"}

    def test_list_networks_with_filters(self, mock_docker_client, safety_config):
        """Test network listing with filters."""
        mock_docker_client.client.networks.list.return_value = []

        # Get the list function
        _, _, _, _, _, list_func = create_list_networks_tool(mock_docker_client, safety_config)

        # Execute with filters
        filters = {"driver": ["bridge"]}
        result = list_func(filters=filters)

        # Verify filters were passed
        mock_docker_client.client.networks.list.assert_called_once_with(filters=filters)
        assert result["count"] == 0

    def test_list_networks_with_truncation(self, mock_docker_client):
        """Test network listing with output truncation."""
        # Create safety config with limit
        safety_config = SafetyConfig(max_list_results=1)

        # Mock multiple networks
        net1 = Mock()
        net1.id = "net1id"
        net1.short_id = "net1"
        net1.name = "bridge"
        net1.attrs = {"Driver": "bridge", "Scope": "local", "Labels": {}}

        net2 = Mock()
        net2.id = "net2id"
        net2.short_id = "net2"
        net2.name = "my-network"
        net2.attrs = {"Driver": "bridge", "Scope": "local", "Labels": {}}

        mock_docker_client.client.networks.list.return_value = [net1, net2]

        # Get the list function
        _, _, _, _, _, list_func = create_list_networks_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify truncation
        assert result["count"] == 2  # Original count
        assert len(result["networks"]) == 1  # Truncated to 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]

    def test_list_networks_api_error(self, mock_docker_client, safety_config):
        """Test network listing with API error."""
        mock_docker_client.client.networks.list.side_effect = APIError("List failed")

        # Get the list function
        _, _, _, _, _, list_func = create_list_networks_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to list networks"):
            list_func()


class TestInspectNetworkTool:
    """Test docker_inspect_network tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        return client

    def test_inspect_network_success(self, mock_docker_client):
        """Test successful network inspection."""
        # Mock network object
        network = Mock()
        network.attrs = {
            "Name": "my-network",
            "Id": "abc123",
            "Driver": "bridge",
            "Scope": "local",
            "IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]},
        }

        mock_docker_client.client.networks.get.return_value = network

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_network_tool(mock_docker_client)

        # Execute
        result = inspect_func(network_id="my-network")

        # Verify
        assert result["details"]["Name"] == "my-network"
        assert result["details"]["Driver"] == "bridge"
        mock_docker_client.client.networks.get.assert_called_once_with("my-network")

    def test_inspect_network_not_found(self, mock_docker_client):
        """Test inspecting non-existent network."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_network_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(NetworkNotFound, match="Network not found"):
            inspect_func(network_id="nonexistent")

    def test_inspect_network_api_error(self, mock_docker_client):
        """Test network inspection with API error."""
        mock_docker_client.client.networks.get.side_effect = APIError("Inspect failed")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_network_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to inspect network"):
            inspect_func(network_id="my-network")


class TestCreateNetworkTool:
    """Test docker_create_network tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        return client

    def test_create_network_minimal(self, mock_docker_client):
        """Test creating network with minimal parameters."""
        # Mock network object
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute
        result = create_func(name="my-network")

        # Verify
        assert result["network_id"] == "abc123"
        assert result["name"] == "my-network"
        assert result["warnings"] is None
        mock_docker_client.client.networks.create.assert_called_once()

    def test_create_network_with_driver(self, mock_docker_client):
        """Test creating network with custom driver."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-overlay"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute
        create_func(name="my-overlay", driver="overlay")

        # Verify
        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        assert call_kwargs["driver"] == "overlay"

    def test_create_network_with_options(self, mock_docker_client):
        """Test creating network with options."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute
        options = {"com.docker.network.bridge.name": "docker1", "mtu": "1500"}
        create_func(name="my-network", options=options)

        # Verify
        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        assert call_kwargs["options"] == options

    def test_create_network_with_ipam(self, mock_docker_client):
        """Test creating network with IPAM configuration."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute
        ipam = {"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]}
        create_func(name="my-network", ipam=ipam)

        # Verify
        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        assert call_kwargs["ipam"] == ipam

    def test_create_network_with_labels(self, mock_docker_client):
        """Test creating network with labels."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute
        labels = {"environment": "production", "team": "backend"}
        create_func(name="my-network", labels=labels)

        # Verify
        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        assert call_kwargs["labels"] == labels

    def test_create_network_with_all_options(self, mock_docker_client):
        """Test creating network with all options."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"

        mock_docker_client.client.networks.create.return_value = network

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute with all options
        create_func(
            name="my-network",
            driver="bridge",
            options={"mtu": "1500"},
            ipam={"Config": [{"Subnet": "172.20.0.0/16"}]},
            internal=True,
            labels={"env": "prod"},
            enable_ipv6=True,
            attachable=True,
        )

        # Verify all options were passed
        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        assert call_kwargs["name"] == "my-network"
        assert call_kwargs["driver"] == "bridge"
        assert call_kwargs["options"] == {"mtu": "1500"}
        assert call_kwargs["ipam"] == {"Config": [{"Subnet": "172.20.0.0/16"}]}
        assert call_kwargs["internal"] is True
        assert call_kwargs["labels"] == {"env": "prod"}
        assert call_kwargs["enable_ipv6"] is True
        assert call_kwargs["attachable"] is True

    def test_create_network_api_error(self, mock_docker_client):
        """Test network creation with API error."""
        mock_docker_client.client.networks.create.side_effect = APIError("Create failed")

        # Get the create function
        _, _, _, _, _, create_func = create_create_network_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to create network"):
            create_func(name="my-network")


class TestConnectContainerTool:
    """Test docker_connect_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        client.client.containers = Mock()
        return client

    def test_connect_container_success(self, mock_docker_client):
        """Test successfully connecting container to network."""
        # Mock network and container objects
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}  # Not connected
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute
        result = connect_func(network_id="net123", container_id="con123")

        # Verify
        assert result["network_id"] == "net123"
        assert result["container_id"] == "con123"
        assert result["status"] == "connected"
        network.connect.assert_called_once_with(container="con123")

    def test_connect_container_already_connected(self, mock_docker_client):
        """Test connecting already connected container (idempotent)."""
        # Mock network and container objects
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}  # Already connected

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute
        result = connect_func(network_id="net123", container_id="con123")

        # Verify - should return success without calling connect()
        assert result["status"] == "connected"

    def test_connect_container_with_aliases(self, mock_docker_client):
        """Test connecting container with aliases."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute with aliases
        connect_func(network_id="net123", container_id="con123", aliases=["web", "api"])

        # Verify aliases were passed
        network.connect.assert_called_once_with(
            container="con123",
            aliases=["web", "api"],
        )

    def test_connect_container_with_ip_addresses(self, mock_docker_client):
        """Test connecting container with IP addresses."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute with IP addresses
        connect_func(
            network_id="net123",
            container_id="con123",
            ipv4_address="172.20.0.5",
            ipv6_address="2001:db8::1",
        )

        # Verify IP addresses were passed
        network.connect.assert_called_once_with(
            container="con123",
            ipv4_address="172.20.0.5",
            ipv6_address="2001:db8::1",
        )

    def test_connect_container_with_links(self, mock_docker_client):
        """Test connecting container with links."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute with links
        connect_func(
            network_id="net123",
            container_id="con123",
            links=["db:database"],
        )

        # Verify links were passed
        network.connect.assert_called_once_with(
            container="con123",
            links=["db:database"],
        )

    def test_connect_container_network_not_found(self, mock_docker_client):
        """Test connecting to non-existent network."""
        mock_docker_client.client.networks.get.side_effect = NotFound("network not found")

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(NetworkNotFound, match="Network not found"):
            connect_func(network_id="nonexistent", container_id="con123")

    def test_connect_container_container_not_found(self, mock_docker_client):
        """Test connecting non-existent container."""
        network = Mock()
        network.attrs = {"Containers": {}}
        network.connect = Mock(side_effect=NotFound("container not found"))

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.side_effect = NotFound("container not found")

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            connect_func(network_id="net123", container_id="nonexistent")

    def test_connect_container_api_error(self, mock_docker_client):
        """Test connecting container with API error."""
        network = Mock()
        network.attrs = {"Containers": {}}
        network.connect = Mock(side_effect=APIError("Connect failed"))

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the connect function
        _, _, _, _, _, connect_func = create_connect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to connect container"):
            connect_func(network_id="net123", container_id="con123")


class TestDisconnectContainerTool:
    """Test docker_disconnect_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        client.client.containers = Mock()
        return client

    def test_disconnect_container_success(self, mock_docker_client):
        """Test successfully disconnecting container from network."""
        # Mock network and container objects
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}  # Connected
        network.disconnect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute
        result = disconnect_func(network_id="net123", container_id="con123")

        # Verify
        assert result["network_id"] == "net123"
        assert result["container_id"] == "con123"
        assert result["status"] == "disconnected"
        network.disconnect.assert_called_once_with(container="con123", force=False)

    def test_disconnect_container_already_disconnected(self, mock_docker_client):
        """Test disconnecting already disconnected container (idempotent)."""
        # Mock network and container objects
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}  # Not connected

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute
        result = disconnect_func(network_id="net123", container_id="con123")

        # Verify - should return success without calling disconnect()
        assert result["status"] == "disconnected"

    def test_disconnect_container_with_force(self, mock_docker_client):
        """Test disconnecting container with force flag."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}
        network.disconnect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute with force
        disconnect_func(network_id="net123", container_id="con123", force=True)

        # Verify force was used
        network.disconnect.assert_called_once_with(container="con123", force=True)

    def test_disconnect_container_network_not_found(self, mock_docker_client):
        """Test disconnecting from non-existent network."""
        mock_docker_client.client.networks.get.side_effect = NotFound("network not found")

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(NetworkNotFound, match="Network not found"):
            disconnect_func(network_id="nonexistent", container_id="con123")

    def test_disconnect_container_container_not_found_idempotent(self, mock_docker_client):
        """Test disconnecting non-existent container (idempotent behavior)."""
        # When container doesn't exist, it won't be in network's Containers
        # The function treats this as "already disconnected" (idempotent)
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}  # Container not in network

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.side_effect = NotFound("container not found")

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute - should return success (idempotent)
        result = disconnect_func(network_id="net123", container_id="nonexistent")

        # Verify - returns disconnected status without error
        assert result["status"] == "disconnected"

    def test_disconnect_container_not_found_during_disconnect(self, mock_docker_client):
        """Test when container not found error occurs during disconnect operation."""
        # This tests the case where disconnect() raises NotFound with container error
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}  # Container appears connected
        # Raise NotFound with message that doesn't contain "network"
        network.disconnect = Mock(side_effect=NotFound("container con123 not found"))

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute and expect ContainerNotFound error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            disconnect_func(network_id="net123", container_id="con123")

    def test_disconnect_container_api_error(self, mock_docker_client):
        """Test disconnecting container with API error."""
        network = Mock()
        network.attrs = {"Containers": {"con123": {}}}
        network.disconnect = Mock(side_effect=APIError("Disconnect failed"))

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        # Get the disconnect function
        _, _, _, _, _, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to disconnect container"):
            disconnect_func(network_id="net123", container_id="con123")


class TestRemoveNetworkTool:
    """Test docker_remove_network tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.networks = Mock()
        return client

    def test_remove_network_success(self, mock_docker_client):
        """Test successfully removing a network."""
        # Mock network object
        network = Mock()
        network.id = "net123"
        network.remove = Mock()

        mock_docker_client.client.networks.get.return_value = network

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_network_tool(mock_docker_client)

        # Execute
        result = remove_func(network_id="net123")

        # Verify
        assert result["network_id"] == "net123"
        network.remove.assert_called_once()

    def test_remove_network_not_found(self, mock_docker_client):
        """Test removing non-existent network."""
        mock_docker_client.client.networks.get.side_effect = NotFound("Network not found")

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_network_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(NetworkNotFound, match="Network not found"):
            remove_func(network_id="nonexistent")

    def test_remove_network_api_error(self, mock_docker_client):
        """Test removing network with API error."""
        network = Mock()
        network.id = "net123"
        network.remove.side_effect = APIError("Remove failed")

        mock_docker_client.client.networks.get.return_value = network

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_network_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to remove network"):
            remove_func(network_id="net123")
