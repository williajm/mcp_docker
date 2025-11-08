"""Integration tests for container lifecycle operations.

These tests require Docker to be running and will create/remove test containers.
Tests use MCPServer.call_tool() pattern for realistic integration testing.
"""

from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration with destructive ops enabled."""
    cfg = Config()
    cfg.safety.allow_moderate_operations = True
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_containers = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
def mcp_server(integration_config: Config) -> Generator[MCPDockerServer, None, None]:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    yield server
    # Cleanup is handled by individual test fixtures


@pytest.fixture
def test_container_name() -> str:
    """Generate unique test container name."""
    return "mcp-docker-test-container"


@pytest.fixture
async def cleanup_test_container(
    mcp_server: MCPDockerServer, test_container_name: str
) -> AsyncGenerator[None, None]:
    """Cleanup fixture to remove test container after tests."""
    yield
    # Cleanup after test
    try:
        await mcp_server.call_tool(
            "docker_remove_container", {"container_id": test_container_name, "force": True}
        )
    except Exception:
        pass  # Container doesn't exist or already removed


@pytest.mark.integration
class TestContainerLifecycle:
    """Integration tests for complete container lifecycle using MCPServer."""

    @pytest.mark.asyncio
    async def test_create_start_stop_remove_container(
        self, mcp_server: MCPDockerServer, test_container_name: str, cleanup_test_container: Any
    ) -> None:
        """Test complete container lifecycle: create, start, stop, remove."""
        # Create container
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            },
        )
        assert create_result["success"] is True
        container_id = create_result["result"]["container_id"]

        # Inspect container (should be created but not running)
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": container_id}
        )
        assert inspect_result["success"] is True
        state = inspect_result["result"]["details"]["State"]["Status"]
        assert state == "created"

        # Start container
        start_result = await mcp_server.call_tool(
            "docker_start_container", {"container_id": container_id}
        )
        assert start_result["success"] is True

        # Inspect container (should be running)
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": container_id}
        )
        assert inspect_result["success"] is True
        state = inspect_result["result"]["details"]["State"]["Status"]
        assert state == "running"

        # Stop container
        stop_result = await mcp_server.call_tool(
            "docker_stop_container", {"container_id": container_id, "timeout": 5}
        )
        assert stop_result["success"] is True

        # Inspect container (should be stopped)
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": container_id}
        )
        assert inspect_result["success"] is True
        state = inspect_result["result"]["details"]["State"]["Status"]
        assert state in ["exited", "stopped"]

        # Remove container
        remove_result = await mcp_server.call_tool(
            "docker_remove_container", {"container_id": container_id, "force": True}
        )
        assert remove_result["success"] is True

    @pytest.mark.asyncio
    async def test_container_restart(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test container restart operation."""
        # Create and start container
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            },
        )
        container_id = create_result["result"]["container_id"]

        await mcp_server.call_tool("docker_start_container", {"container_id": container_id})

        # Get initial start time
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": container_id}
        )
        initial_start_time = inspect_result["result"]["details"]["State"]["StartedAt"]

        # Restart container
        restart_result = await mcp_server.call_tool(
            "docker_restart_container", {"container_id": container_id, "timeout": 5}
        )
        assert restart_result["success"] is True

        # Verify container is running and start time changed
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": container_id}
        )
        assert inspect_result["result"]["details"]["State"]["Status"] == "running"
        new_start_time = inspect_result["result"]["details"]["State"]["StartedAt"]
        assert new_start_time != initial_start_time

    @pytest.mark.asyncio
    async def test_container_logs(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test retrieving container logs."""
        # Create container that produces output
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sh", "-c", "echo 'Hello from container' && sleep 10"],
            },
        )
        container_id = create_result["result"]["container_id"]

        await mcp_server.call_tool("docker_start_container", {"container_id": container_id})

        # Wait a moment for output
        import asyncio

        await asyncio.sleep(1)

        # Get logs
        logs_result = await mcp_server.call_tool(
            "docker_container_logs", {"container_id": container_id, "tail": 100}
        )
        assert logs_result["success"] is True
        assert "Hello from container" in logs_result["result"]["logs"]

    @pytest.mark.asyncio
    async def test_container_stats(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test retrieving container statistics."""
        # Create and start container
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            },
        )
        assert create_result["success"] is True
        container_id = create_result["result"]["container_id"]

        start_result = await mcp_server.call_tool(
            "docker_start_container", {"container_id": container_id}
        )
        assert start_result["success"] is True

        # Get stats (stream=False by default)
        stats_result = await mcp_server.call_tool(
            "docker_container_stats", {"container_id": container_id, "stream": False}
        )
        assert stats_result["success"] is True
        # Check for actual raw Docker stats fields
        assert "stats" in stats_result["result"]
        stats = stats_result["result"]["stats"]
        assert "cpu_stats" in stats
        assert "memory_stats" in stats
        assert "pids_stats" in stats
        assert stats_result["result"]["container_id"] == container_id

    @pytest.mark.asyncio
    async def test_container_exec(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test executing commands in container."""
        # Create and start container
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            },
        )
        container_id = create_result["result"]["container_id"]

        await mcp_server.call_tool("docker_start_container", {"container_id": container_id})

        # Execute command
        exec_result = await mcp_server.call_tool(
            "docker_exec_command", {"container_id": container_id, "command": ["echo", "test"]}
        )
        assert exec_result["success"] is True
        assert "test" in exec_result["result"]["output"]

    @pytest.mark.asyncio
    async def test_list_containers(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test listing containers."""
        # Create container
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            },
        )
        container_id = create_result["result"]["container_id"]

        # List all containers
        list_result = await mcp_server.call_tool("docker_list_containers", {"all": True})
        assert list_result["success"] is True
        assert len(list_result["result"]["containers"]) > 0

        # Find our container
        found = False
        for container in list_result["result"]["containers"]:
            if container["id"] == container_id:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_container_with_environment_variables(
        self,
        mcp_server: MCPDockerServer,
        test_container_name: str,
        cleanup_test_container: Any,
    ) -> None:
        """Test creating container with environment variables."""
        # Create container with environment variables
        create_result = await mcp_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
                "environment": {"TEST_VAR": "test_value", "ANOTHER_VAR": "another_value"},
            },
        )
        container_id = create_result["result"]["container_id"]

        await mcp_server.call_tool("docker_start_container", {"container_id": container_id})

        # Verify environment variable
        exec_result = await mcp_server.call_tool(
            "docker_exec_command",
            {"container_id": container_id, "command": ["sh", "-c", "echo $TEST_VAR"]},
        )
        assert exec_result["success"] is True
        assert "test_value" in exec_result["result"]["output"]

    @pytest.mark.asyncio
    async def test_container_error_handling(self, mcp_server: MCPDockerServer) -> None:
        """Test error handling for invalid operations."""
        # Try to inspect non-existent container
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_container", {"container_id": "nonexistent-container"}
        )
        assert inspect_result["success"] is False
        assert "not found" in inspect_result["error"].lower()

        # Try to start non-existent container
        start_result = await mcp_server.call_tool(
            "docker_start_container", {"container_id": "nonexistent-container"}
        )
        assert start_result["success"] is False
