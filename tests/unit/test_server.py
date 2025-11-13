"""Unit tests for MCP Docker server."""

from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pydantic import BaseModel, Field

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def mock_config(tmp_path: Any) -> Any:
    """Create a mock configuration."""
    from mcp_docker.config import SafetyConfig, SecurityConfig

    config = Mock(spec=Config)
    config.docker = Mock()
    config.safety = SafetyConfig()  # Use real SafetyConfig with defaults
    config.security = SecurityConfig(
        audit_log_file=tmp_path / "audit.log",
    )
    return config


@pytest.fixture
def mock_docker_client() -> Any:
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

    def test_server_initialization(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test server initialization."""
        server = MCPDockerServer(mock_config)

        assert server.config == mock_config
        assert server.docker_client == mock_docker_client
        assert len(server.tools) == 36  # Total tools: 10+9+6+5+6 (compose tools removed)

    def test_tool_registration(self, mock_config: Any, mock_docker_client: Any) -> None:
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

    def test_list_tools(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing all tools with default safety config."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # With default safety config (allow_moderate=True, allow_destructive=False),
        # we should get SAFE + MODERATE tools, but not DESTRUCTIVE tools
        # SAFE: 12 tools (list/inspect/logs/stats/version/info/df/healthcheck/events/image_history)
        # MODERATE: 17 tools (create/start/stop/restart/exec/pull/build/push/tag/connect/disconnect)
        # DESTRUCTIVE: 7 tools (remove_container/image/network/volume/prune variants)
        # Expected: 12 + 17 = 29 tools
        assert len(tools) == 29
        assert all("name" in tool for tool in tools)
        assert all("description" in tool for tool in tools)
        assert all("inputSchema" in tool for tool in tools)

        # Check specific tool format
        container_tools = [t for t in tools if t["name"] == "docker_list_containers"]
        assert len(container_tools) == 1
        assert "List Docker containers" in container_tools[0]["description"]

    def test_list_tools_with_all_operations_allowed(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test listing tools when all operations are allowed."""
        from mcp_docker.config import SafetyConfig

        # Allow everything
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get all 36 tools
        assert len(tools) == 36

    def test_list_tools_read_only_mode(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing tools in read-only mode (no moderate or destructive operations)."""
        from mcp_docker.config import SafetyConfig

        # Read-only mode: only SAFE operations
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=False,
            allow_destructive_operations=False,
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get SAFE tools
        # SAFE tools include: list, inspect, logs, stats, version, info, df, healthcheck, events, image_history, system_df, system_info
        # Count: docker_list_containers, docker_inspect_container, docker_container_logs,
        #        docker_container_stats, docker_list_images, docker_inspect_image,
        #        docker_image_history, docker_list_networks, docker_inspect_network,
        #        docker_list_volumes, docker_inspect_volume, docker_version,
        #        docker_system_info, docker_system_df, docker_healthcheck, docker_events
        # Expected: approximately 12-16 SAFE tools
        assert len(tools) < 36
        assert len(tools) >= 12  # At minimum the core read-only tools

        # Verify SAFE tools are present
        tool_names = [t["name"] for t in tools]
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_container_logs" in tool_names
        assert "docker_list_images" in tool_names

        # Verify MODERATE tools are absent
        assert "docker_create_container" not in tool_names
        assert "docker_start_container" not in tool_names
        assert "docker_pull_image" not in tool_names

        # Verify DESTRUCTIVE tools are absent
        assert "docker_remove_container" not in tool_names
        assert "docker_remove_image" not in tool_names
        assert "docker_prune_volumes" not in tool_names

    def test_list_tools_moderate_only(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing tools with moderate operations allowed but not destructive."""
        from mcp_docker.config import SafetyConfig

        # Allow moderate operations but not destructive (default config)
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=False,
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get SAFE + MODERATE tools
        tool_names = [t["name"] for t in tools]

        # Verify SAFE tools are present
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names

        # Verify MODERATE tools are present
        assert "docker_create_container" in tool_names
        assert "docker_start_container" in tool_names
        assert "docker_stop_container" in tool_names
        assert "docker_pull_image" in tool_names

        # Verify DESTRUCTIVE tools are absent
        assert "docker_remove_container" not in tool_names
        assert "docker_remove_image" not in tool_names
        assert "docker_prune_volumes" not in tool_names
        assert "docker_system_prune" not in tool_names

    def test_list_tools_destructive_filtered(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that destructive tools are filtered when not allowed."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=False,  # Block destructive
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Count destructive tools that should be filtered
        tool_names = [t["name"] for t in tools]
        destructive_tools = [
            "docker_remove_container",
            "docker_remove_image",
            "docker_remove_network",
            "docker_remove_volume",
            "docker_prune_images",
            "docker_prune_volumes",
            "docker_system_prune",
        ]

        for destructive_tool in destructive_tools:
            assert destructive_tool not in tool_names

    @pytest.mark.asyncio
    async def test_call_tool_success(self, mock_config: Any, mock_docker_client: Any) -> None:
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
    async def test_call_tool_not_found(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test calling non-existent tool."""
        server = MCPDockerServer(mock_config)

        result = await server.call_tool("nonexistent_tool", {})

        assert result["success"] is False
        assert "Tool not found" in result["error"]
        assert result["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_call_tool_validation_error(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test tool call with validation error."""
        from pydantic import ValidationError as PydanticValidationError

        server = MCPDockerServer(mock_config)

        # Mock a tool that raises validation error on run()
        mock_tool = Mock()
        mock_tool.name = "test_tool"
        mock_tool.run = AsyncMock(
            side_effect=PydanticValidationError.from_exception_data(
                "ValidationError",
                [{"loc": ("required_field",), "input": None, "type": "missing"}],
            )
        )

        server.tools["test_tool"] = mock_tool

        result = await server.call_tool("test_tool", {})  # Missing required field

        assert result["success"] is False
        assert "error" in result
        assert result["error_type"] == "ValidationError"

    @pytest.mark.asyncio
    async def test_call_tool_execution_error(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test tool call with execution error."""
        server = MCPDockerServer(mock_config)

        # Mock a tool that raises an exception on run()
        mock_tool = Mock()
        mock_tool.name = "test_tool"
        mock_tool.run = AsyncMock(side_effect=Exception("Execution failed"))

        server.tools["test_tool"] = mock_tool

        result = await server.call_tool("test_tool", {})

        assert result["success"] is False
        # Error sanitizer hides internal error messages
        assert "An unexpected error occurred" in result["error"]
        assert "test_tool" in result["error"]
        assert result["error_type"] == "InternalError"

    @pytest.mark.asyncio
    async def test_start_healthy(self, mock_config: Any, mock_docker_client: Any) -> None:
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
    async def test_start_unhealthy(self, mock_config: Any, mock_docker_client: Any) -> None:
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
    async def test_start_health_check_error(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test server start with health check error."""
        mock_docker_client.health_check.side_effect = Exception("Connection failed")

        server = MCPDockerServer(mock_config)
        await server.start()  # Should not fail, just log warning

        mock_docker_client.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test server stop."""
        server = MCPDockerServer(mock_config)
        await server.stop()

        mock_docker_client.close.assert_called_once()

    def test_repr(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test server string representation."""
        server = MCPDockerServer(mock_config)
        repr_str = repr(server)

        assert "MCPDockerServer" in repr_str
        assert "tools=36" in repr_str

    @pytest.mark.asyncio
    async def test_safety_check_destructive_with_confirmation_required(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
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
        mock_tool = Mock()
        mock_tool.name = "docker_remove_container"
        mock_tool.run = AsyncMock(side_effect=Exception("Container not found"))

        server.tools["docker_remove_container"] = mock_tool

        # Call tool - should log warning but fail on execution
        result = await server.call_tool("docker_remove_container", {"container_id": "test"})

        # Should execute past safety check (will fail on execution, but that's OK)
        assert result["success"] is False
        # Error sanitizer maps unknown errors to InternalError
        assert result["error_type"] == "InternalError"

    @pytest.mark.asyncio
    async def test_check_tool_safety_safe_operation(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
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
        mock_tool = Mock()
        mock_tool.name = "docker_list_containers"
        mock_tool.run = AsyncMock(return_value=Mock(model_dump=lambda: {"containers": []}))

        server.tools["docker_list_containers"] = mock_tool

        # Call tool - should succeed
        result = await server.call_tool("docker_list_containers", {})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_max_concurrent_operations_limiting(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that max_concurrent_operations setting limits concurrent tool execution."""
        import asyncio

        from mcp_docker.config import SafetyConfig

        # Set up config with max 2 concurrent operations (safety semaphore)
        mock_config.safety = SafetyConfig(
            allow_destructive_operations=False,
            require_confirmation_for_destructive=False,
            allow_privileged_containers=False,
            max_concurrent_operations=2,
        )
        # Increase security rate limiter concurrency to not interfere
        mock_config.security.rate_limit_concurrent = 10

        server = MCPDockerServer(mock_config)

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent_count = 0
        lock = asyncio.Lock()

        async def slow_execute(input_data: Any) -> Any:
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
        mock_tool = Mock()
        mock_tool.name = "docker_slow_tool"
        mock_tool.run = slow_execute

        server.tools["docker_slow_tool"] = mock_tool

        # Execute 5 operations concurrently
        tasks = [server.call_tool("docker_slow_tool", {}) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r["success"] for r in results)

        # But max concurrent should never exceed configured limit (safety semaphore)
        assert max_concurrent_count <= 2

    def test_list_resources_success(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing resources successfully."""
        server = MCPDockerServer(mock_config)

        # Mock resource provider
        mock_resource = Mock()
        mock_resource.uri = "container://logs/abc123"
        mock_resource.name = "Container Logs"
        mock_resource.description = "Logs for container abc123"
        mock_resource.mime_type = "text/plain"

        with patch.object(
            server.resource_provider, "list_resources", Mock(return_value=[mock_resource])
        ):
            resources = server.list_resources()

            assert len(resources) == 1
            assert resources[0]["uri"] == "container://logs/abc123"
            assert resources[0]["name"] == "Container Logs"
            assert resources[0]["mimeType"] == "text/plain"

    def test_list_resources_with_exception(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing resources when an exception occurs."""
        server = MCPDockerServer(mock_config)

        # Mock resource provider to raise an exception
        with patch.object(
            server.resource_provider,
            "list_resources",
            Mock(side_effect=Exception("Failed to list resources")),
        ):
            # Should return empty list instead of crashing
            resources = server.list_resources()

            assert resources == []

    @pytest.mark.asyncio
    async def test_read_resource_with_text(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test reading resource with text content."""
        server = MCPDockerServer(mock_config)

        # Mock resource content
        mock_content = Mock()
        mock_content.uri = "container://logs/abc123"
        mock_content.mime_type = "text/plain"
        mock_content.text = "Log content here"
        mock_content.blob = None

        with patch.object(
            server.resource_provider, "read_resource", AsyncMock(return_value=mock_content)
        ):
            result = await server.read_resource("container://logs/abc123")

            assert result["uri"] == "container://logs/abc123"
            assert result["mimeType"] == "text/plain"
            assert result["text"] == "Log content here"
            assert "blob" not in result

    @pytest.mark.asyncio
    async def test_read_resource_with_blob(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test reading resource with blob content."""
        server = MCPDockerServer(mock_config)

        # Mock resource content with blob
        mock_content = Mock()
        mock_content.uri = "container://data/abc123"
        mock_content.mime_type = "application/octet-stream"
        mock_content.text = None
        mock_content.blob = b"binary data"

        with patch.object(
            server.resource_provider, "read_resource", AsyncMock(return_value=mock_content)
        ):
            result = await server.read_resource("container://data/abc123")

            assert result["uri"] == "container://data/abc123"
            assert result["mimeType"] == "application/octet-stream"
            assert result["blob"] == "binary data"  # Decoded from bytes
            assert "text" not in result

    @pytest.mark.asyncio
    async def test_read_resource_with_exception(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test reading resource when an exception occurs."""
        server = MCPDockerServer(mock_config)

        # Mock resource provider to raise an exception
        with patch.object(
            server.resource_provider,
            "read_resource",
            AsyncMock(side_effect=Exception("Resource not found")),
        ):
            # Should raise the exception
            with pytest.raises(Exception, match="Resource not found"):
                await server.read_resource("container://logs/nonexistent")

    def test_list_prompts_success(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing prompts successfully."""
        server = MCPDockerServer(mock_config)

        # Mock prompt metadata
        mock_prompt = Mock()
        mock_prompt.name = "troubleshoot_container"
        mock_prompt.description = "Troubleshoot a container"
        mock_prompt.arguments = [{"name": "container_id", "description": "Container ID"}]

        with patch.object(server.prompt_provider, "list_prompts", Mock(return_value=[mock_prompt])):
            prompts = server.list_prompts()

            assert len(prompts) == 1
            assert prompts[0]["name"] == "troubleshoot_container"
            assert prompts[0]["description"] == "Troubleshoot a container"
            assert len(prompts[0]["arguments"]) == 1

    def test_list_prompts_with_exception(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing prompts when an exception occurs."""
        server = MCPDockerServer(mock_config)

        # Mock prompt provider to raise an exception
        with patch.object(
            server.prompt_provider,
            "list_prompts",
            Mock(side_effect=Exception("Failed to list prompts")),
        ):
            # Should return empty list instead of crashing
            prompts = server.list_prompts()

            assert prompts == []

    @pytest.mark.asyncio
    async def test_get_prompt_success(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test getting a prompt successfully."""
        server = MCPDockerServer(mock_config)

        # Mock prompt result
        mock_message = Mock()
        mock_message.role = "user"
        mock_message.content = "Troubleshoot container abc123"

        mock_result = Mock()
        mock_result.description = "Troubleshooting prompt"
        mock_result.messages = [mock_message]

        with patch.object(
            server.prompt_provider, "get_prompt", AsyncMock(return_value=mock_result)
        ):
            result = await server.get_prompt("troubleshoot_container", {"container_id": "abc123"})

            assert result["description"] == "Troubleshooting prompt"
            assert len(result["messages"]) == 1
            assert result["messages"][0]["role"] == "user"
            assert "abc123" in result["messages"][0]["content"]

    @pytest.mark.asyncio
    async def test_get_prompt_with_exception(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test getting a prompt when an exception occurs."""
        server = MCPDockerServer(mock_config)

        # Mock prompt provider to raise an exception
        with patch.object(
            server.prompt_provider,
            "get_prompt",
            AsyncMock(side_effect=Exception("Prompt not found")),
        ):
            # Should raise the exception
            with pytest.raises(Exception, match="Prompt not found"):
                await server.get_prompt("nonexistent_prompt", {})

    def test_list_tools_with_allowed_tools(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing tools with allowed_tools filter."""
        from mcp_docker.config import SafetyConfig

        # Configure to allow only specific tools
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allowed_tools=["docker_list_containers", "docker_inspect_container", "docker_version"],
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get the 3 allowed tools
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_version" in tool_names

        # Other tools should be filtered out
        assert "docker_create_container" not in tool_names
        assert "docker_remove_container" not in tool_names

    def test_list_tools_with_denied_tools(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test listing tools with denied_tools filter."""
        from mcp_docker.config import SafetyConfig

        denied_tool_names = [
            "docker_remove_container",
            "docker_prune_images",
            "docker_system_prune",
        ]

        # First, get baseline count with all tools enabled
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
        )
        baseline_server = MCPDockerServer(mock_config)
        total_tools = len(baseline_server.list_tools())

        # Configure to deny specific tools
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            denied_tools=denied_tool_names,
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get all tools except the denied ones
        expected_count = total_tools - len(denied_tool_names)
        assert len(tools) == expected_count
        tool_names = [t["name"] for t in tools]

        # Denied tools should not be present
        for denied_tool in denied_tool_names:
            assert denied_tool not in tool_names

        # Other tools should be present
        assert "docker_list_containers" in tool_names
        assert "docker_create_container" in tool_names

    def test_list_tools_with_allowed_and_denied_tools(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that denied_tools takes precedence over allowed_tools."""
        from mcp_docker.config import SafetyConfig

        # Configure both allowed and denied tools
        # docker_list_containers is in both lists - deny should win
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allowed_tools=[
                "docker_list_containers",
                "docker_inspect_container",
                "docker_version",
            ],
            denied_tools=["docker_list_containers"],  # Deny one of the allowed tools
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get 2 tools (docker_list_containers denied even though allowed)
        assert len(tools) == 2
        tool_names = [t["name"] for t in tools]

        # docker_list_containers should be filtered out (deny takes precedence)
        assert "docker_list_containers" not in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_version" in tool_names

    def test_list_tools_with_allowed_and_safety_levels(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that allowed_tools works alongside safety level filtering."""
        from mcp_docker.config import SafetyConfig

        # Configure allowed tools including a destructive one, but disable destructive operations
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=False,  # Destructive disabled
            allowed_tools=[
                "docker_list_containers",
                "docker_create_container",
                "docker_remove_container",  # This is destructive - should be filtered by safety level
            ],
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get 2 tools (docker_remove_container filtered by safety level)
        assert len(tools) == 2
        tool_names = [t["name"] for t in tools]
        assert "docker_list_containers" in tool_names
        assert "docker_create_container" in tool_names
        assert "docker_remove_container" not in tool_names  # Filtered by safety level

    @pytest.mark.asyncio
    async def test_call_tool_denied_by_deny_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that calling a denied tool fails at execution time."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            denied_tools=["docker_remove_container"],
        )

        server = MCPDockerServer(mock_config)

        # Try to call a denied tool
        result = await server.call_tool("docker_remove_container", {"container_id": "test"})

        assert result["success"] is False
        assert "Tool denied by configuration" in result["error"]
        assert result["error_type"] == "UnsafeOperationError"

    @pytest.mark.asyncio
    async def test_call_tool_not_in_allow_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that calling a tool not in allow list fails at execution time."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allowed_tools=["docker_list_containers", "docker_version"],
        )

        server = MCPDockerServer(mock_config)

        # Try to call a tool not in the allow list
        result = await server.call_tool("docker_create_container", {"image": "alpine"})

        assert result["success"] is False
        assert "Tool not in allow list" in result["error"]
        assert result["error_type"] == "UnsafeOperationError"

    @pytest.mark.asyncio
    async def test_call_tool_in_allow_list_succeeds(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that calling a tool in the allow list succeeds."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allowed_tools=["docker_list_containers"],
        )

        server = MCPDockerServer(mock_config)

        # Mock the tool's run method
        mock_tool = Mock()
        mock_tool.name = "docker_list_containers"
        mock_tool.run = AsyncMock(return_value=Mock(model_dump=lambda: {"containers": []}))

        server.tools["docker_list_containers"] = mock_tool

        # Call the allowed tool
        result = await server.call_tool("docker_list_containers", {})

        assert result["success"] is True

    def test_list_tools_with_empty_allowed_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that empty allowed_tools list allows all tools (based on safety level)."""
        from mcp_docker.config import SafetyConfig

        # Empty allowed_tools should not filter any tools
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allowed_tools=[],  # Empty list = allow all
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get all 36 tools (no filtering by allow list)
        assert len(tools) == 36
        tool_names = [t["name"] for t in tools]
        assert "docker_list_containers" in tool_names
        assert "docker_remove_container" in tool_names

    def test_list_tools_with_empty_denied_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that empty denied_tools list denies nothing."""
        from mcp_docker.config import SafetyConfig

        # Empty denied_tools should not filter any tools
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            denied_tools=[],  # Empty list = deny nothing
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get all 36 tools
        assert len(tools) == 36

    def test_list_tools_with_nonexistent_tool_in_allow_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that nonexistent tools in allow list don't cause errors."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allowed_tools=[
                "docker_list_containers",
                "nonexistent_tool",  # This doesn't exist
                "another_fake_tool",
            ],
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get the 1 valid tool
        assert len(tools) == 1
        assert tools[0]["name"] == "docker_list_containers"

    def test_list_tools_with_nonexistent_tool_in_deny_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that nonexistent tools in deny list don't cause errors."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            denied_tools=["nonexistent_tool", "another_fake_tool"],
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get all 36 tools (fake tools don't affect anything)
        assert len(tools) == 36

    def test_list_tools_deny_all_via_allowed_list(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that setting allowed_tools to list of nonexistent tools denies everything."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allowed_tools=["nonexistent_tool"],  # Only allow a tool that doesn't exist
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should get 0 tools
        assert len(tools) == 0

    def test_list_tools_with_all_safety_levels_disabled(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test listing tools when all safety operations are disabled."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=False,
            allow_destructive_operations=False,
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Should only get SAFE tools (read-only operations)
        # These include: list, inspect, logs, stats, version, info, etc.
        tool_names = [t["name"] for t in tools]

        # Verify some safe tools are present
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_version" in tool_names

        # Verify moderate/destructive tools are filtered
        assert "docker_create_container" not in tool_names  # MODERATE
        assert "docker_remove_container" not in tool_names  # DESTRUCTIVE

    def test_list_tools_combined_filtering(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test complex filtering with safety levels + allow/deny lists."""
        from mcp_docker.config import SafetyConfig

        # Scenario: Moderate allowed, destructive denied, with custom allow/deny lists
        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=False,  # Block destructive
            allowed_tools=[
                "docker_list_containers",
                "docker_create_container",  # MODERATE - should pass
                "docker_remove_container",  # DESTRUCTIVE - blocked by safety level
                "docker_inspect_container",
            ],
            denied_tools=["docker_create_container"],  # Deny this even though in allow list
        )

        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Expected: Only docker_list_containers and docker_inspect_container
        # - docker_create_container: In allow list but also in deny list (deny wins)
        # - docker_remove_container: In allow list but blocked by safety level
        assert len(tools) == 2
        tool_names = [t["name"] for t in tools]
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_create_container" not in tool_names
        assert "docker_remove_container" not in tool_names

    @pytest.mark.asyncio
    async def test_call_tool_denied_takes_precedence_over_allowed(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that deny list takes precedence even if tool is in allow list."""
        from mcp_docker.config import SafetyConfig

        mock_config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allowed_tools=["docker_list_containers"],
            denied_tools=["docker_list_containers"],  # Also denied
        )

        server = MCPDockerServer(mock_config)

        # Try to call a tool that's in both allow and deny lists
        result = await server.call_tool("docker_list_containers", {})

        assert result["success"] is False
        assert "Tool denied by configuration" in result["error"]
        assert result["error_type"] == "UnsafeOperationError"
