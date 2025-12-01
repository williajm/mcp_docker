"""Unit tests for fastmcp_tools/network.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.network import (
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


# Module-level fixtures to avoid duplication across test classes
@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    client.client.networks = Mock()
    client.client.containers = Mock()
    return client


@pytest.fixture
def safety_config():
    """Create safety config."""
    return SafetyConfig()


class TestBuildConnectKwargs:
    """Test _build_connect_kwargs helper function."""

    @pytest.mark.parametrize(
        "kwargs,expected",
        [
            (
                {
                    "container_id": "abc123",
                    "aliases": None,
                    "ipv4_address": None,
                    "ipv6_address": None,
                    "links": None,
                },
                {"container": "abc123"},
            ),
            (
                {
                    "container_id": "abc123",
                    "aliases": ["web", "frontend"],
                    "ipv4_address": None,
                    "ipv6_address": None,
                    "links": None,
                },
                {"container": "abc123", "aliases": ["web", "frontend"]},
            ),
            (
                {
                    "container_id": "abc123",
                    "aliases": None,
                    "ipv4_address": "172.20.0.5",
                    "ipv6_address": None,
                    "links": None,
                },
                {"container": "abc123", "ipv4_address": "172.20.0.5"},
            ),
            (
                {
                    "container_id": "abc123",
                    "aliases": None,
                    "ipv4_address": None,
                    "ipv6_address": "2001:db8::1",
                    "links": None,
                },
                {"container": "abc123", "ipv6_address": "2001:db8::1"},
            ),
            (
                {
                    "container_id": "abc123",
                    "aliases": None,
                    "ipv4_address": None,
                    "ipv6_address": None,
                    "links": ["db:database"],
                },
                {"container": "abc123", "links": ["db:database"]},
            ),
            (
                {
                    "container_id": "abc123",
                    "aliases": ["web", "api"],
                    "ipv4_address": "172.20.0.5",
                    "ipv6_address": "2001:db8::1",
                    "links": ["db:database"],
                },
                {
                    "container": "abc123",
                    "aliases": ["web", "api"],
                    "ipv4_address": "172.20.0.5",
                    "ipv6_address": "2001:db8::1",
                    "links": ["db:database"],
                },
            ),
        ],
    )
    def test_build_connect_kwargs(self, kwargs, expected):
        """Test building kwargs with various combinations."""
        result = _build_connect_kwargs(**kwargs)
        assert result == expected


class TestCreateNetworkInputValidation:
    """Test CreateNetworkInput Pydantic model validation."""

    @pytest.mark.parametrize(
        "field,json_value,expected",
        [
            (
                "options",
                '{"com.docker.network.bridge.name": "docker1", "mtu": "1500"}',
                {"com.docker.network.bridge.name": "docker1", "mtu": "1500"},
            ),
            (
                "ipam",
                '{"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]}',
                {"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]},
            ),
            (
                "labels",
                '{"environment": "production", "team": "backend"}',
                {"environment": "production", "team": "backend"},
            ),
        ],
    )
    def test_json_string_parsing(self, field, json_value, expected):
        """Test that JSON strings are parsed correctly."""
        input_data = CreateNetworkInput(name="my-network", **{field: json_value})
        assert getattr(input_data, field) == expected

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


class TestNetworkNotFoundErrors:
    """Test network not found error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,call_kwargs",
        [
            (create_inspect_network_tool, {"network_id": "nonexistent"}),
            (create_remove_network_tool, {"network_id": "nonexistent"}),
            (
                create_connect_container_tool,
                {"network_id": "nonexistent", "container_id": "con123"},
            ),
            (
                create_disconnect_container_tool,
                {"network_id": "nonexistent", "container_id": "con123"},
            ),
        ],
    )
    def test_network_not_found(self, mock_docker_client, tool_creator, call_kwargs):
        """Test that NetworkNotFound is raised when network doesn't exist."""
        mock_docker_client.client.networks.get.side_effect = NotFound("network not found")

        *_, func = tool_creator(mock_docker_client)

        with pytest.raises(NetworkNotFound, match="Network not found"):
            func(**call_kwargs)


class TestAPIErrors:
    """Test API error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs,error_match,setup_error_on",
        [
            (create_list_networks_tool, True, {}, "Failed to list networks", "networks.list"),
            (
                create_inspect_network_tool,
                False,
                {"network_id": "test"},
                "Failed to inspect network",
                "networks.get",
            ),
            (
                create_create_network_tool,
                False,
                {"name": "test"},
                "Failed to create network",
                "networks.create",
            ),
        ],
    )
    def test_api_error(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        call_kwargs,
        error_match,
        setup_error_on,
    ):
        """Test that DockerOperationError is raised on API errors."""
        method_mapping = {
            "networks.list": mock_docker_client.client.networks.list,
            "networks.get": mock_docker_client.client.networks.get,
            "networks.create": mock_docker_client.client.networks.create,
        }
        method_mapping[setup_error_on].side_effect = APIError("API failed")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(DockerOperationError, match=error_match):
            func(**call_kwargs)

    def test_remove_network_api_error(self, mock_docker_client):
        """Test removing network with API error."""
        network = Mock()
        network.id = "net123"
        network.remove.side_effect = APIError("Remove failed")
        mock_docker_client.client.networks.get.return_value = network

        *_, remove_func = create_remove_network_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to remove network"):
            remove_func(network_id="net123")

    def test_connect_container_api_error(self, mock_docker_client):
        """Test connecting container with API error."""
        network = Mock()
        network.attrs = {"Containers": {}}
        network.connect = Mock(side_effect=APIError("Connect failed"))
        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, connect_func = create_connect_container_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to connect container"):
            connect_func(network_id="net123", container_id="con123")

    def test_disconnect_container_api_error(self, mock_docker_client):
        """Test disconnecting container with API error."""
        network = Mock()
        network.attrs = {"Containers": {"con123": {}}}
        network.disconnect = Mock(side_effect=APIError("Disconnect failed"))
        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to disconnect container"):
            disconnect_func(network_id="net123", container_id="con123")


class TestListNetworksTool:
    """Test docker_list_networks tool."""

    def test_list_networks_success(self, mock_docker_client, safety_config):
        """Test successful network listing."""
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

        *_, list_func = create_list_networks_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 2
        assert len(result["networks"]) == 2
        assert result["networks"][0]["name"] == "bridge"
        assert result["networks"][1]["name"] == "my-network"
        assert result["networks"][1]["labels"] == {"env": "test"}

    def test_list_networks_with_filters(self, mock_docker_client, safety_config):
        """Test network listing with filters."""
        mock_docker_client.client.networks.list.return_value = []

        *_, list_func = create_list_networks_tool(mock_docker_client, safety_config)
        filters = {"driver": ["bridge"]}
        result = list_func(filters=filters)

        mock_docker_client.client.networks.list.assert_called_once_with(filters=filters)
        assert result["count"] == 0

    def test_list_networks_with_truncation(self, mock_docker_client):
        """Test network listing with output truncation."""
        safety_config = SafetyConfig(max_list_results=1)

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

        *_, list_func = create_list_networks_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 2
        assert len(result["networks"]) == 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]


class TestInspectNetworkTool:
    """Test docker_inspect_network tool."""

    def test_inspect_network_success(self, mock_docker_client):
        """Test successful network inspection."""
        network = Mock()
        network.attrs = {
            "Name": "my-network",
            "Id": "abc123",
            "Driver": "bridge",
            "Scope": "local",
            "IPAM": {"Config": [{"Subnet": "172.20.0.0/16"}]},
        }
        mock_docker_client.client.networks.get.return_value = network

        *_, inspect_func = create_inspect_network_tool(mock_docker_client)
        result = inspect_func(network_id="my-network")

        assert result["details"]["Name"] == "my-network"
        assert result["details"]["Driver"] == "bridge"
        mock_docker_client.client.networks.get.assert_called_once_with("my-network")


class TestCreateNetworkTool:
    """Test docker_create_network tool."""

    def test_create_network_minimal(self, mock_docker_client):
        """Test creating network with minimal parameters."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"
        mock_docker_client.client.networks.create.return_value = network

        *_, create_func = create_create_network_tool(mock_docker_client)
        result = create_func(name="my-network")

        assert result["network_id"] == "abc123"
        assert result["name"] == "my-network"
        assert result["warnings"] is None
        mock_docker_client.client.networks.create.assert_called_once()

    @pytest.mark.parametrize(
        "extra_kwargs,expected_kwarg",
        [
            ({"driver": "overlay"}, ("driver", "overlay")),
            ({"options": {"mtu": "1500"}}, ("options", {"mtu": "1500"})),
            (
                {"ipam": {"Config": [{"Subnet": "172.20.0.0/16"}]}},
                ("ipam", {"Config": [{"Subnet": "172.20.0.0/16"}]}),
            ),
            ({"labels": {"env": "prod"}}, ("labels", {"env": "prod"})),
            ({"internal": True}, ("internal", True)),
            ({"enable_ipv6": True}, ("enable_ipv6", True)),
            ({"attachable": True}, ("attachable", True)),
        ],
    )
    def test_create_network_with_options(self, mock_docker_client, extra_kwargs, expected_kwarg):
        """Test creating network with various options."""
        network = Mock()
        network.id = "abc123"
        network.name = "my-network"
        mock_docker_client.client.networks.create.return_value = network

        *_, create_func = create_create_network_tool(mock_docker_client)
        create_func(name="my-network", **extra_kwargs)

        call_kwargs = mock_docker_client.client.networks.create.call_args.kwargs
        key, value = expected_kwarg
        assert call_kwargs[key] == value


class TestConnectContainerTool:
    """Test docker_connect_container tool."""

    def test_connect_container_success(self, mock_docker_client):
        """Test successfully connecting container to network."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, connect_func = create_connect_container_tool(mock_docker_client)
        result = connect_func(network_id="net123", container_id="con123")

        assert result["network_id"] == "net123"
        assert result["container_id"] == "con123"
        assert result["status"] == "connected"
        network.connect.assert_called_once_with(container="con123")

    def test_connect_container_already_connected(self, mock_docker_client):
        """Test connecting already connected container (idempotent)."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, connect_func = create_connect_container_tool(mock_docker_client)
        result = connect_func(network_id="net123", container_id="con123")

        assert result["status"] == "connected"

    @pytest.mark.parametrize(
        "extra_kwargs,expected_connect_kwargs",
        [
            ({"aliases": ["web", "api"]}, {"container": "con123", "aliases": ["web", "api"]}),
            (
                {"ipv4_address": "172.20.0.5", "ipv6_address": "2001:db8::1"},
                {
                    "container": "con123",
                    "ipv4_address": "172.20.0.5",
                    "ipv6_address": "2001:db8::1",
                },
            ),
            ({"links": ["db:database"]}, {"container": "con123", "links": ["db:database"]}),
        ],
    )
    def test_connect_container_with_options(
        self, mock_docker_client, extra_kwargs, expected_connect_kwargs
    ):
        """Test connecting container with various options."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}
        network.connect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, connect_func = create_connect_container_tool(mock_docker_client)
        connect_func(network_id="net123", container_id="con123", **extra_kwargs)

        network.connect.assert_called_once_with(**expected_connect_kwargs)

    def test_connect_container_container_not_found(self, mock_docker_client):
        """Test connecting non-existent container."""
        network = Mock()
        network.attrs = {"Containers": {}}
        network.connect = Mock(side_effect=NotFound("container not found"))

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.side_effect = NotFound("container not found")

        *_, connect_func = create_connect_container_tool(mock_docker_client)

        with pytest.raises(ContainerNotFound, match="Container not found"):
            connect_func(network_id="net123", container_id="nonexistent")


class TestDisconnectContainerTool:
    """Test docker_disconnect_container tool."""

    def test_disconnect_container_success(self, mock_docker_client):
        """Test successfully disconnecting container from network."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}
        network.disconnect = Mock()

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)
        result = disconnect_func(network_id="net123", container_id="con123")

        assert result["network_id"] == "net123"
        assert result["container_id"] == "con123"
        assert result["status"] == "disconnected"
        network.disconnect.assert_called_once_with(container="con123", force=False)

    def test_disconnect_container_already_disconnected(self, mock_docker_client):
        """Test disconnecting already disconnected container (idempotent)."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)
        result = disconnect_func(network_id="net123", container_id="con123")

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

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)
        disconnect_func(network_id="net123", container_id="con123", force=True)

        network.disconnect.assert_called_once_with(container="con123", force=True)

    def test_disconnect_container_not_found_idempotent(self, mock_docker_client):
        """Test disconnecting non-existent container (idempotent behavior)."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {}}

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.side_effect = NotFound("container not found")

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)
        result = disconnect_func(network_id="net123", container_id="nonexistent")

        assert result["status"] == "disconnected"

    def test_disconnect_container_not_found_during_disconnect(self, mock_docker_client):
        """Test when container not found error occurs during disconnect operation."""
        network = Mock()
        network.id = "net123"
        network.attrs = {"Containers": {"con123": {}}}
        network.disconnect = Mock(side_effect=NotFound("container con123 not found"))

        container = Mock()
        container.id = "con123"

        mock_docker_client.client.networks.get.return_value = network
        mock_docker_client.client.containers.get.return_value = container

        *_, disconnect_func = create_disconnect_container_tool(mock_docker_client)

        with pytest.raises(ContainerNotFound, match="Container not found"):
            disconnect_func(network_id="net123", container_id="con123")


class TestRemoveNetworkTool:
    """Test docker_remove_network tool."""

    def test_remove_network_success(self, mock_docker_client):
        """Test successfully removing a network."""
        network = Mock()
        network.id = "net123"
        network.remove = Mock()
        mock_docker_client.client.networks.get.return_value = network

        *_, remove_func = create_remove_network_tool(mock_docker_client)
        result = remove_func(network_id="net123")

        assert result["network_id"] == "net123"
        network.remove.assert_called_once()
