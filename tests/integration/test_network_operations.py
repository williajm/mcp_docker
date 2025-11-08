"""Integration tests for network operations.

These tests require Docker to be running and will create/remove test networks.
"""

from collections.abc import AsyncGenerator
from typing import Any

import pytest

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_moderate_operations = True
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_containers = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
async def mcp_server(integration_config: Config) -> AsyncGenerator[MCPDockerServer, None]:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
def test_network_name() -> str:
    """Test network name."""
    return "mcp-docker-test-network"


@pytest.fixture
async def cleanup_test_network(
    mcp_server: MCPDockerServer, test_network_name: str
) -> AsyncGenerator[None, None]:
    """Cleanup fixture to remove test network after tests."""
    yield
    try:
        await mcp_server.call_tool("docker_remove_network", {"network_id": test_network_name})
    except Exception:
        pass  # Ignore cleanup errors - network may not exist


@pytest.mark.integration
class TestNetworkOperations:
    """Integration tests for network operations."""

    @pytest.mark.asyncio
    async def test_create_and_remove_network(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network: Any,
    ) -> None:
        """Test creating and removing a network."""
        # Create network
        create_result = await mcp_server.call_tool(
            "docker_create_network", {"name": test_network_name}
        )
        assert create_result["success"] is True
        assert "network_id" in create_result["result"]
        network_id = create_result["result"]["network_id"]

        # Remove network
        remove_result = await mcp_server.call_tool(
            "docker_remove_network", {"network_id": network_id}
        )
        assert remove_result["success"] is True

    @pytest.mark.asyncio
    async def test_list_networks(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network: Any,
    ) -> None:
        """Test listing networks."""
        # Create a test network
        await mcp_server.call_tool("docker_create_network", {"name": test_network_name})

        # List networks
        list_result = await mcp_server.call_tool("docker_list_networks", {})
        assert list_result["success"] is True
        assert len(list_result["result"]["networks"]) > 0

        # Find our network
        found = False
        for network in list_result["result"]["networks"]:
            if network["name"] == test_network_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_inspect_network(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network: Any,
    ) -> None:
        """Test inspecting a network."""
        # Create network
        create_result = await mcp_server.call_tool(
            "docker_create_network", {"name": test_network_name}
        )
        network_id = create_result["result"]["network_id"]

        # Inspect network
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_network", {"network_id": network_id}
        )
        assert inspect_result["success"] is True
        assert inspect_result["result"]["details"]["Name"] == test_network_name
        assert "Driver" in inspect_result["result"]["details"]

    @pytest.mark.asyncio
    async def test_connect_disconnect_container(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network: Any,
    ) -> None:
        """Test connecting and disconnecting container to network."""
        # Create network
        network_result = await mcp_server.call_tool(
            "docker_create_network", {"name": test_network_name}
        )
        network_id = network_result["result"]["network_id"]

        # Create container
        container_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": "mcp-test-network-container",
                "command": ["sleep", "300"],
            },
        )
        container_id = container_result["result"]["container_id"]

        try:
            # Start the container (needed for network connection to be visible)
            start_result = await mcp_server.call_tool(
                "docker_start_container", {"container_id": container_id}
            )
            assert start_result["success"] is True

            # Connect container to network
            connect_result = await mcp_server.call_tool(
                "docker_connect_container",
                {"network_id": network_id, "container_id": container_id},
            )
            assert connect_result["success"] is True

            # Verify connection
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_network", {"network_id": network_id}
            )
            assert inspect_result["success"] is True
            assert container_id in str(inspect_result["result"]["details"].get("Containers", {}))

            # Disconnect container from network
            disconnect_result = await mcp_server.call_tool(
                "docker_disconnect_container",
                {"network_id": network_id, "container_id": container_id},
            )
            assert disconnect_result["success"] is True

            # Verify disconnection
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_network", {"network_id": network_id}
            )
            assert inspect_result["success"] is True
            containers_str = str(inspect_result["result"]["details"].get("Containers", {}))
            # After disconnect, container should not be in network
            assert container_id not in containers_str or len(containers_str) == 2  # Empty dict

        finally:
            # Cleanup container
            await mcp_server.call_tool(
                "docker_remove_container", {"container_id": container_id, "force": True}
            )

    @pytest.mark.asyncio
    async def test_create_network_with_options(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        cleanup_test_network: Any,
    ) -> None:
        """Test creating network with custom options."""
        network_name = "mcp-docker-test-network-custom"

        try:
            # Create network with custom driver
            create_result = await mcp_server.call_tool(
                "docker_create_network",
                {
                    "name": network_name,
                    "driver": "bridge",
                    "options": {"com.docker.network.bridge.name": "mcp-test-br0"},
                },
            )
            assert create_result["success"] is True
            network_id = create_result["result"]["network_id"]

            # Inspect to verify options
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_network", {"network_id": network_id}
            )
            assert inspect_result["success"] is True
            assert inspect_result["result"]["details"]["Driver"] == "bridge"

        finally:
            # Cleanup
            try:
                await mcp_server.call_tool("docker_remove_network", {"network_id": network_name})
            except Exception:
                pass  # Ignore cleanup errors - network may already be removed

    @pytest.mark.asyncio
    async def test_network_error_handling(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid network operations."""
        # Try to inspect non-existent network
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_network", {"network_id": "nonexistent-network"}
        )
        assert inspect_result["success"] is False
        assert "not found" in inspect_result["error"].lower()

        # Try to remove non-existent network
        remove_result = await mcp_server.call_tool(
            "docker_remove_network", {"network_id": "nonexistent-network"}
        )
        assert remove_result["success"] is False

        # Try to connect non-existent container to network
        connect_result = await mcp_server.call_tool(
            "docker_connect_container",
            {"network_id": "bridge", "container_id": "nonexistent-container"},
        )
        assert connect_result["success"] is False

    @pytest.mark.asyncio
    async def test_list_networks_with_filters(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_network_name: str,
        cleanup_test_network: Any,
    ) -> None:
        """Test listing networks with filters."""
        # Create a test network
        await mcp_server.call_tool(
            "docker_create_network", {"name": test_network_name, "driver": "bridge"}
        )

        # List with driver filter
        list_result = await mcp_server.call_tool(
            "docker_list_networks", {"filters": {"driver": ["bridge"]}}
        )
        assert list_result["success"] is True
        assert len(list_result["result"]["networks"]) > 0

        # Verify our network is in the list
        found = False
        for network in list_result["result"]["networks"]:
            if network["name"] == test_network_name:
                found = True
                assert network["driver"] == "bridge"
                break
        assert found is True
