"""Integration tests for volume operations.

These tests require Docker to be running and will create/remove test volumes.
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
def test_volume_name() -> str:
    """Test volume name."""
    return "mcp-docker-test-volume"


@pytest.fixture
async def cleanup_test_volume(
    mcp_server: MCPDockerServer, test_volume_name: str
) -> AsyncGenerator[None, None]:
    """Cleanup fixture to remove test volume after tests."""
    yield
    try:
        await mcp_server.call_tool(
            "docker_remove_volume", {"volume_name": test_volume_name, "force": True}
        )
    except Exception:
        pass  # Ignore cleanup errors - volume may not exist


@pytest.mark.integration
class TestVolumeOperations:
    """Integration tests for volume operations."""

    @pytest.mark.asyncio
    async def test_create_and_remove_volume(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume: Any,
    ) -> None:
        """Test creating and removing a volume."""
        # Create volume
        create_result = await mcp_server.call_tool(
            "docker_create_volume", {"name": test_volume_name}
        )
        assert create_result["success"] is True
        assert create_result["result"]["name"] == test_volume_name

        # Remove volume
        remove_result = await mcp_server.call_tool(
            "docker_remove_volume", {"volume_name": test_volume_name}
        )
        assert remove_result["success"] is True

    @pytest.mark.asyncio
    async def test_list_volumes(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume: Any,
    ) -> None:
        """Test listing volumes."""
        # Create a test volume
        await mcp_server.call_tool("docker_create_volume", {"name": test_volume_name})

        # List volumes
        list_result = await mcp_server.call_tool("docker_list_volumes", {})
        assert list_result["success"] is True
        assert len(list_result["result"]["volumes"]) > 0

        # Find our volume
        found = False
        for volume in list_result["result"]["volumes"]:
            if volume["name"] == test_volume_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_inspect_volume(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume: Any,
    ) -> None:
        """Test inspecting a volume."""
        # Create volume
        await mcp_server.call_tool("docker_create_volume", {"name": test_volume_name})

        # Inspect volume
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_volume", {"volume_name": test_volume_name}
        )
        assert inspect_result["success"] is True
        assert inspect_result["result"]["details"]["Name"] == test_volume_name
        assert "Driver" in inspect_result["result"]["details"]
        assert "Mountpoint" in inspect_result["result"]["details"]

    @pytest.mark.asyncio
    async def test_create_volume_with_driver(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        cleanup_test_volume: Any,
    ) -> None:
        """Test creating volume with specific driver."""
        volume_name = "mcp-docker-test-volume-custom"

        try:
            # Create volume with local driver
            create_result = await mcp_server.call_tool(
                "docker_create_volume", {"name": volume_name, "driver": "local"}
            )
            assert create_result["success"] is True

            # Inspect to verify driver
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_volume", {"volume_name": volume_name}
            )
            assert inspect_result["success"] is True
            assert inspect_result["result"]["details"]["Driver"] == "local"

        finally:
            # Cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_volume", {"volume_name": volume_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - volume may already be removed

    @pytest.mark.asyncio
    async def test_create_volume_with_labels(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        cleanup_test_volume: Any,
    ) -> None:
        """Test creating volume with labels."""
        volume_name = "mcp-docker-test-volume-labels"

        try:
            # Create volume with labels
            create_result = await mcp_server.call_tool(
                "docker_create_volume",
                {
                    "name": volume_name,
                    "labels": {"test": "integration", "project": "mcp-docker"},
                },
            )
            assert create_result["success"] is True

            # Inspect to verify labels
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_volume", {"volume_name": volume_name}
            )
            assert inspect_result["success"] is True
            labels = inspect_result["result"]["details"].get("Labels", {})
            assert labels.get("test") == "integration"
            assert labels.get("project") == "mcp-docker"

        finally:
            # Cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_volume", {"volume_name": volume_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - volume may already be removed

    @pytest.mark.asyncio
    async def test_remove_volume_with_force(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_volume_name: str,
    ) -> None:
        """Test removing volume with force option."""
        # Create volume
        await mcp_server.call_tool("docker_create_volume", {"name": test_volume_name})

        # Remove with force
        remove_result = await mcp_server.call_tool(
            "docker_remove_volume", {"volume_name": test_volume_name, "force": True}
        )
        assert remove_result["success"] is True

        # Verify removal
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_volume", {"volume_name": test_volume_name}
        )
        assert inspect_result["success"] is False

    @pytest.mark.asyncio
    async def test_prune_volumes(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test pruning unused volumes."""
        # Prune volumes (might not remove anything, but should succeed)
        prune_result = await mcp_server.call_tool("docker_prune_volumes", {})
        assert prune_result["success"] is True
        assert "space_reclaimed" in prune_result["result"]
        assert "deleted" in prune_result["result"]

    @pytest.mark.asyncio
    async def test_volume_error_handling(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid volume operations."""
        # Try to inspect non-existent volume
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_volume", {"volume_name": "nonexistent-volume"}
        )
        assert inspect_result["success"] is False
        assert "not found" in inspect_result["error"].lower()

        # Try to remove non-existent volume
        remove_result = await mcp_server.call_tool(
            "docker_remove_volume", {"volume_name": "nonexistent-volume", "force": False}
        )
        assert remove_result["success"] is False

    @pytest.mark.asyncio
    async def test_list_volumes_with_filters(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume: Any,
    ) -> None:
        """Test listing volumes with filters."""
        # Create volume with label
        await mcp_server.call_tool(
            "docker_create_volume",
            {"name": test_volume_name, "labels": {"environment": "test"}},
        )

        # List with label filter
        list_result = await mcp_server.call_tool(
            "docker_list_volumes", {"filters": {"label": ["environment=test"]}}
        )
        assert list_result["success"] is True

        # Find our volume
        found = False
        for volume in list_result["result"]["volumes"]:
            if volume["name"] == test_volume_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_create_auto_named_volume(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test creating volume with auto-generated name."""
        # Create volume without specifying name
        create_result = await mcp_server.call_tool("docker_create_volume", {})
        assert create_result["success"] is True
        volume_name = create_result["result"]["name"]
        assert len(volume_name) > 0

        # Cleanup
        await mcp_server.call_tool(
            "docker_remove_volume", {"volume_name": volume_name, "force": True}
        )

    @pytest.mark.asyncio
    async def test_prune_volumes_with_filters(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test pruning volumes with filters."""
        # Create a volume with label for pruning test
        temp_volume_name = "mcp-docker-temp-volume"
        await mcp_server.call_tool(
            "docker_create_volume",
            {"name": temp_volume_name, "labels": {"temporary": "true"}},
        )

        try:
            # Prune with label filter
            prune_result = await mcp_server.call_tool(
                "docker_prune_volumes", {"filters": {"label": ["temporary=true"]}}
            )
            assert prune_result["success"] is True

        finally:
            # Ensure cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_volume", {"volume_name": temp_volume_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - volume may already be removed
