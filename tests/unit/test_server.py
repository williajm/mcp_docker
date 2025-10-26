"""Unit tests for MCP Docker server."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from pydantic import BaseModel, Field

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    from mcp_docker.config import SafetyConfig

    config = Mock(spec=Config)
    config.docker = Mock()
    config.safety = SafetyConfig()  # Use real SafetyConfig with defaults
    return config


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client wrapper."""
    with patch("mcp_docker.server.DockerClientWrapper") as mock_class:
        client = Mock()
        client.health_check.return_value = {
            "status": "healthy",
            "daemon_info": {},
            "containers": {},
            "images": 0,
        }
        mock_class.return_value = client
        yield client


class TestMCPDockerServer:
    """Tests for MCPDockerServer."""

    def test_server_initialization(self, mock_config, mock_docker_client):
        """Test server initialization."""
        server = MCPDockerServer(mock_config)

        assert server.config == mock_config
        assert server.docker_client == mock_docker_client
        assert len(server.tools) == 36  # Total tools: 10+9+6+5+6

    def test_tool_registration(self, mock_config, mock_docker_client):
        """Test that all tools are registered correctly."""
        server = MCPDockerServer(mock_config)

        # Check container tools (10)
        assert "docker_list_containers" in server.tools
        assert "docker_inspect_container" in server.tools
        assert "docker_create_container" in server.tools
        assert "docker_start_container" in server.tools
        assert "docker_stop_container" in server.tools
        assert "docker_restart_container" in server.tools
        assert "docker_remove_container" in server.tools
        assert "docker_container_logs" in server.tools
        assert "docker_exec_command" in server.tools
        assert "docker_container_stats" in server.tools

        # Check image tools (9)
        assert "docker_list_images" in server.tools
        assert "docker_inspect_image" in server.tools
        assert "docker_pull_image" in server.tools
        assert "docker_build_image" in server.tools
        assert "docker_push_image" in server.tools
        assert "docker_tag_image" in server.tools
        assert "docker_remove_image" in server.tools
        assert "docker_prune_images" in server.tools
        assert "docker_image_history" in server.tools

        # Check network tools (6)
        assert "docker_list_networks" in server.tools
        assert "docker_inspect_network" in server.tools
        assert "docker_create_network" in server.tools
        assert "docker_connect_container" in server.tools
        assert "docker_disconnect_container" in server.tools
        assert "docker_remove_network" in server.tools

        # Check volume tools (5)
        assert "docker_list_volumes" in server.tools
        assert "docker_inspect_volume" in server.tools
        assert "docker_create_volume" in server.tools
        assert "docker_remove_volume" in server.tools
        assert "docker_prune_volumes" in server.tools

        # Check system tools (6)
        assert "docker_system_info" in server.tools
        assert "docker_system_df" in server.tools
        assert "docker_system_prune" in server.tools
        assert "docker_version" in server.tools
        assert "docker_events" in server.tools
        assert "docker_healthcheck" in server.tools

    def test_list_tools(self, mock_config, mock_docker_client):
        """Test listing all tools."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        assert len(tools) == 36
        assert all("name" in tool for tool in tools)
        assert all("description" in tool for tool in tools)
        assert all("inputSchema" in tool for tool in tools)

        # Check specific tool format
        container_tools = [t for t in tools if t["name"] == "docker_list_containers"]
        assert len(container_tools) == 1
        assert "List Docker containers" in container_tools[0]["description"]

    @pytest.mark.asyncio
    async def test_call_tool_success(self, mock_config, mock_docker_client):
        """Test successful tool call."""
        server = MCPDockerServer(mock_config)

        # Mock a tool's run method (server calls run(), not execute())
        class MockOutput(BaseModel):
            result: str = Field(description="Result")

        mock_tool = Mock()
        mock_tool.name = "test_tool"
        mock_tool.run = AsyncMock(return_value=MockOutput(result="success"))

        server.tools["test_tool"] = mock_tool

        result = await server.call_tool("test_tool", {})

        assert result["success"] is True
        assert result["result"]["result"] == "success"

    @pytest.mark.asyncio
    async def test_call_tool_not_found(self, mock_config, mock_docker_client):
        """Test calling non-existent tool."""
        server = MCPDockerServer(mock_config)

        with pytest.raises(ValueError, match="Tool not found"):
            await server.call_tool("nonexistent_tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_validation_error(self, mock_config, mock_docker_client):
        """Test tool call with validation error."""
        from pydantic import ValidationError as PydanticValidationError

        server = MCPDockerServer(mock_config)

        # Mock a tool that raises validation error on run()
        mock_tool = Mock()
        mock_tool.name = "test_tool"
        mock_tool.run = AsyncMock(
            side_effect=PydanticValidationError.from_exception_data(
                "ValidationError",
                [{"loc": ("required_field",), "msg": "field required", "type": "missing"}],
            )
        )

        server.tools["test_tool"] = mock_tool

        result = await server.call_tool("test_tool", {})  # Missing required field

        assert result["success"] is False
        assert "error" in result
        assert result["error_type"] == "ValidationError"

    @pytest.mark.asyncio
    async def test_call_tool_execution_error(self, mock_config, mock_docker_client):
        """Test tool call with execution error."""
        server = MCPDockerServer(mock_config)

        # Mock a tool that raises an exception on run()
        mock_tool = Mock()
        mock_tool.name = "test_tool"
        mock_tool.run = AsyncMock(side_effect=Exception("Execution failed"))

        server.tools["test_tool"] = mock_tool

        result = await server.call_tool("test_tool", {})

        assert result["success"] is False
        assert "Execution failed" in result["error"]
        assert result["error_type"] == "Exception"

    @pytest.mark.asyncio
    async def test_start_healthy(self, mock_config, mock_docker_client):
        """Test server start with healthy Docker daemon."""
        mock_docker_client.health_check.return_value = {
            "status": "healthy",
            "daemon_info": {},
            "containers": {},
            "images": 0,
        }

        server = MCPDockerServer(mock_config)
        await server.start()

        mock_docker_client.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_unhealthy(self, mock_config, mock_docker_client):
        """Test server start with unhealthy Docker daemon."""
        mock_docker_client.health_check.return_value = {
            "status": "unhealthy",
            "daemon_info": {},
            "containers": {},
            "images": 0,
        }

        server = MCPDockerServer(mock_config)
        await server.start()  # Should not fail, just log warning

        mock_docker_client.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_health_check_error(self, mock_config, mock_docker_client):
        """Test server start with health check error."""
        mock_docker_client.health_check.side_effect = Exception("Connection failed")

        server = MCPDockerServer(mock_config)
        await server.start()  # Should not fail, just log warning

        mock_docker_client.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop(self, mock_config, mock_docker_client):
        """Test server stop."""
        server = MCPDockerServer(mock_config)
        await server.stop()

        mock_docker_client.close.assert_called_once()

    def test_repr(self, mock_config, mock_docker_client):
        """Test server string representation."""
        server = MCPDockerServer(mock_config)
        repr_str = repr(server)

        assert "MCPDockerServer" in repr_str
        assert "tools=36" in repr_str

    @pytest.mark.asyncio
    async def test_safety_check_destructive_with_confirmation_required(
        self, mock_config, mock_docker_client
    ):
        """Test that confirmation requirement is logged for destructive operations."""
        from mcp_docker.config import SafetyConfig

        # Set up config with confirmation required
        mock_config.safety = SafetyConfig(
            allow_destructive_operations=True,
            require_confirmation_for_destructive=True,
            allow_privileged_containers=True,
        )

        server = MCPDockerServer(mock_config)

        # Mock a destructive tool
        class MockInput(BaseModel):
            container_id: str = Field(description="Container ID")

        mock_tool = Mock()
        mock_tool.name = "docker_remove_container"
        mock_tool.run = AsyncMock(side_effect=Exception("Container not found"))

        server.tools["docker_remove_container"] = mock_tool

        # Call tool - should log warning but fail on execution
        result = await server.call_tool("docker_remove_container", {"container_id": "test"})

        # Should execute past safety check (will fail on execution, but that's OK)
        assert result["success"] is False
        assert result["error_type"] == "Exception"

    @pytest.mark.asyncio
    async def test_check_tool_safety_safe_operation(self, mock_config, mock_docker_client):
        """Test that safe operations pass safety checks."""
        from mcp_docker.config import SafetyConfig

        # Set up config with everything disabled
        mock_config.safety = SafetyConfig(
            allow_destructive_operations=False,
            require_confirmation_for_destructive=True,
            allow_privileged_containers=False,
        )

        server = MCPDockerServer(mock_config)

        # Mock a safe tool
        class MockInput(BaseModel):
            pass

        mock_tool = Mock()
        mock_tool.name = "docker_list_containers"
        mock_tool.run = AsyncMock(return_value=Mock(model_dump=lambda: {"containers": []}))

        server.tools["docker_list_containers"] = mock_tool

        # Call tool - should succeed
        result = await server.call_tool("docker_list_containers", {})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_max_concurrent_operations_limiting(self, mock_config, mock_docker_client):
        """Test that max_concurrent_operations setting limits concurrent tool execution."""
        import asyncio

        from mcp_docker.config import SafetyConfig

        # Set up config with max 2 concurrent operations
        mock_config.safety = SafetyConfig(
            allow_destructive_operations=False,
            require_confirmation_for_destructive=False,
            allow_privileged_containers=False,
            max_concurrent_operations=2,
        )

        server = MCPDockerServer(mock_config)

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent_count = 0
        lock = asyncio.Lock()

        async def slow_execute(input_data):
            """Simulate a slow operation that tracks concurrency."""
            nonlocal concurrent_count, max_concurrent_count
            async with lock:
                concurrent_count += 1
                max_concurrent_count = max(max_concurrent_count, concurrent_count)

            # Simulate work
            await asyncio.sleep(0.1)

            async with lock:
                concurrent_count -= 1

            return Mock(model_dump=lambda: {"result": "done"})

        # Create a mock tool

        class MockInput(BaseModel):
            pass

        mock_tool = Mock()
        mock_tool.name = "docker_slow_tool"
        mock_tool.run = slow_execute

        server.tools["docker_slow_tool"] = mock_tool

        # Execute 5 operations concurrently
        tasks = [server.call_tool("docker_slow_tool", {}) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r["success"] for r in results)

        # But max concurrent should never exceed configured limit
        assert max_concurrent_count <= 2
