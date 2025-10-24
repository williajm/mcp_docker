"""Integration tests for network operations.

These tests require Docker to be running and will create/remove test networks.
"""

import pytest

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.container_tools import CreateContainerTool, RemoveContainerTool
from mcp_docker.tools.network_tools import (
    ConnectContainerTool,
    CreateNetworkTool,
    DisconnectContainerTool,
    InspectNetworkTool,
    ListNetworksTool,
    RemoveNetworkTool,
)


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_containers = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
def docker_wrapper(integration_config: Config) -> DockerClientWrapper:
    """Create Docker client wrapper."""
    wrapper = DockerClientWrapper(integration_config.docker)
    yield wrapper
    wrapper.close()


@pytest.fixture
def test_network_name() -> str:
    """Test network name."""
    return "mcp-docker-test-network"


@pytest.fixture
def cleanup_test_network(docker_wrapper: DockerClientWrapper, test_network_name: str):
    """Cleanup fixture to remove test network after tests."""
    yield
    try:
        network = docker_wrapper.client.networks.get(test_network_name)
        network.remove()
    except Exception:
        pass


@pytest.mark.integration
class TestNetworkOperations:
    """Integration tests for network operations."""

    @pytest.mark.asyncio
    async def test_create_and_remove_network(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network,
    ) -> None:
        """Test creating and removing a network."""
        create_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveNetworkTool(docker_wrapper, integration_config.safety)

        # Create network
        create_result = await create_tool.execute({"name": test_network_name})
        assert create_result.success is True
        assert "id" in create_result.data
        network_id = create_result.data["id"]

        # Remove network
        remove_result = await remove_tool.execute({"network_id": network_id})
        assert remove_result.success is True

    @pytest.mark.asyncio
    async def test_list_networks(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network,
    ) -> None:
        """Test listing networks."""
        create_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        list_tool = ListNetworksTool(docker_wrapper, integration_config.safety)

        # Create a test network
        await create_tool.execute({"name": test_network_name})

        # List networks
        list_result = await list_tool.execute({})
        assert list_result.success is True
        assert len(list_result.data["networks"]) > 0

        # Find our network
        found = False
        for network in list_result.data["networks"]:
            if network["name"] == test_network_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_inspect_network(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network,
    ) -> None:
        """Test inspecting a network."""
        create_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectNetworkTool(docker_wrapper, integration_config.safety)

        # Create network
        create_result = await create_tool.execute({"name": test_network_name})
        network_id = create_result.data["id"]

        # Inspect network
        inspect_result = await inspect_tool.execute({"network_id": network_id})
        assert inspect_result.success is True
        assert inspect_result.data["name"] == test_network_name
        assert "driver" in inspect_result.data

    @pytest.mark.asyncio
    async def test_connect_disconnect_container(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network,
    ) -> None:
        """Test connecting and disconnecting container to network."""
        create_network_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        create_container_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        connect_tool = ConnectContainerTool(docker_wrapper, integration_config.safety)
        disconnect_tool = DisconnectContainerTool(docker_wrapper, integration_config.safety)
        inspect_network_tool = InspectNetworkTool(docker_wrapper, integration_config.safety)
        remove_container_tool = RemoveContainerTool(docker_wrapper, integration_config.safety)

        # Create network
        network_result = await create_network_tool.execute({"name": test_network_name})
        network_id = network_result.data["id"]

        # Create container
        container_result = await create_container_tool.execute(
            {
                "image": "alpine:latest",
                "name": "mcp-test-network-container",
                "command": ["sleep", "300"],
            }
        )
        container_id = container_result.data["id"]

        try:
            # Connect container to network
            connect_result = await connect_tool.execute(
                {"network_id": network_id, "container_id": container_id}
            )
            assert connect_result.success is True

            # Verify connection
            inspect_result = await inspect_network_tool.execute({"network_id": network_id})
            assert inspect_result.success is True
            assert container_id in str(inspect_result.data.get("containers", {}))

            # Disconnect container from network
            disconnect_result = await disconnect_tool.execute(
                {"network_id": network_id, "container_id": container_id}
            )
            assert disconnect_result.success is True

            # Verify disconnection
            inspect_result = await inspect_network_tool.execute({"network_id": network_id})
            assert inspect_result.success is True
            containers_str = str(inspect_result.data.get("containers", {}))
            # After disconnect, container should not be in network
            assert container_id not in containers_str or len(containers_str) == 2  # Empty dict

        finally:
            # Cleanup container
            await remove_container_tool.execute({"container_id": container_id, "force": True})

    @pytest.mark.asyncio
    async def test_create_network_with_options(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        cleanup_test_network,
    ) -> None:
        """Test creating network with custom options."""
        create_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectNetworkTool(docker_wrapper, integration_config.safety)

        network_name = "mcp-docker-test-network-custom"

        try:
            # Create network with custom driver
            create_result = await create_tool.execute(
                {
                    "name": network_name,
                    "driver": "bridge",
                    "options": {"com.docker.network.bridge.name": "mcp-test-br0"},
                }
            )
            assert create_result.success is True
            network_id = create_result.data["id"]

            # Inspect to verify options
            inspect_result = await inspect_tool.execute({"network_id": network_id})
            assert inspect_result.success is True
            assert inspect_result.data["driver"] == "bridge"

        finally:
            # Cleanup
            try:
                network = docker_wrapper.client.networks.get(network_name)
                network.remove()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_network_error_handling(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid network operations."""
        inspect_tool = InspectNetworkTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveNetworkTool(docker_wrapper, integration_config.safety)
        connect_tool = ConnectContainerTool(docker_wrapper, integration_config.safety)

        # Try to inspect non-existent network
        inspect_result = await inspect_tool.execute({"network_id": "nonexistent-network"})
        assert inspect_result.success is False
        assert "not found" in inspect_result.error.lower()

        # Try to remove non-existent network
        remove_result = await remove_tool.execute({"network_id": "nonexistent-network"})
        assert remove_result.success is False

        # Try to connect non-existent container to network
        connect_result = await connect_tool.execute(
            {"network_id": "bridge", "container_id": "nonexistent-container"}
        )
        assert connect_result.success is False

    @pytest.mark.asyncio
    async def test_list_networks_with_filters(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network,
    ) -> None:
        """Test listing networks with filters."""
        create_tool = CreateNetworkTool(docker_wrapper, integration_config.safety)
        list_tool = ListNetworksTool(docker_wrapper, integration_config.safety)

        # Create a test network
        await create_tool.execute({"name": test_network_name, "driver": "bridge"})

        # List with driver filter
        list_result = await list_tool.execute({"filters": {"driver": ["bridge"]}})
        assert list_result.success is True
        assert len(list_result.data["networks"]) > 0

        # Verify our network is in the list
        found = False
        for network in list_result.data["networks"]:
            if network["name"] == test_network_name:
                found = True
                assert network["driver"] == "bridge"
                break
        assert found is True
