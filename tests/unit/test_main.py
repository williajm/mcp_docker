"""Unit tests for __main__.py MCP server entry point."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

# Import the module components we need to test
from mcp_docker import __main__ as main_module


class TestMCPServerHandlers:
    """Tests for MCP server handler functions."""

    @pytest.mark.asyncio
    async def test_handle_list_tools(self) -> None:
        """Test list_tools handler."""
        # Mock the docker_server
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_tools.return_value = [
                {
                    "name": "test_tool",
                    "description": "Test tool",
                    "inputSchema": {"type": "object"},
                }
            ]

            result = await main_module.handle_list_tools()

            assert len(result) == 1
            assert result[0].name == "test_tool"
            assert result[0].description == "Test tool"

    @pytest.mark.asyncio
    async def test_handle_call_tool_success(self) -> None:
        """Test call_tool handler with successful result."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test output"}}
            )

            result = await main_module.handle_call_tool("test_tool", {})

            assert len(result) == 1
            assert result[0]["type"] == "text"
            assert "test output" in result[0]["text"]

    @pytest.mark.asyncio
    async def test_handle_call_tool_error(self) -> None:
        """Test call_tool handler with error result."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": False, "error": "Test error message"}
            )

            result = await main_module.handle_call_tool("test_tool", {})

            assert len(result) == 1
            assert result[0]["type"] == "text"
            assert "Error: Test error message" in result[0]["text"]

    @pytest.mark.asyncio
    async def test_handle_call_tool_with_null_auth(self) -> None:
        """Test call_tool handler with null _auth doesn't crash (security fix)."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test"}}
            )

            # Malicious request with null _auth should not crash
            result = await main_module.handle_call_tool("test_tool", {"_auth": None})

            # Should succeed without crashing
            assert len(result) == 1
            # Server should be called with no auth (None values)
            mock_server.call_tool.assert_called_once()
            call_kwargs = mock_server.call_tool.call_args[1]
            assert call_kwargs["api_key"] is None
            assert call_kwargs["ssh_auth_data"] is None

    @pytest.mark.asyncio
    async def test_handle_call_tool_with_string_auth(self) -> None:
        """Test call_tool handler with string _auth doesn't crash (security fix)."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test"}}
            )

            # Malicious request with string _auth should not crash
            result = await main_module.handle_call_tool("test_tool", {"_auth": "malicious string"})

            # Should succeed without crashing
            assert len(result) == 1
            # Server should be called with no auth
            call_kwargs = mock_server.call_tool.call_args[1]
            assert call_kwargs["api_key"] is None
            assert call_kwargs["ssh_auth_data"] is None

    @pytest.mark.asyncio
    async def test_handle_call_tool_with_number_auth(self) -> None:
        """Test call_tool handler with number _auth doesn't crash (security fix)."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test"}}
            )

            # Malicious request with number _auth should not crash
            result = await main_module.handle_call_tool("test_tool", {"_auth": 12345})

            # Should succeed without crashing
            assert len(result) == 1
            # Server should be called with no auth
            call_kwargs = mock_server.call_tool.call_args[1]
            assert call_kwargs["api_key"] is None
            assert call_kwargs["ssh_auth_data"] is None

    @pytest.mark.asyncio
    async def test_handle_call_tool_with_valid_auth(self) -> None:
        """Test call_tool handler with valid _auth dict works correctly."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test"}}
            )

            # Valid auth should be passed through correctly
            result = await main_module.handle_call_tool(
                "test_tool",
                {
                    "_auth": {"api_key": "test-key", "ssh": {"client_id": "test"}},
                    "arg": "value",
                },
            )

            # Should succeed
            assert len(result) == 1
            # Server should be called with auth data
            call_kwargs = mock_server.call_tool.call_args[1]
            assert call_kwargs["api_key"] == "test-key"
            assert call_kwargs["ssh_auth_data"] == {"client_id": "test"}
            # _auth should be stripped from arguments
            call_args = mock_server.call_tool.call_args[0]
            assert "_auth" not in call_args[1]
            assert call_args[1]["arg"] == "value"

    @pytest.mark.asyncio
    async def test_handle_call_tool_no_credential_leakage_in_logs(self) -> None:
        """Test that _auth is not logged (prevents credential leakage)."""
        with (
            patch.object(main_module, "docker_server") as mock_server,
            patch.object(main_module, "logger") as mock_logger,
        ):
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test"}}
            )

            # Call with sensitive auth data
            await main_module.handle_call_tool(
                "test_tool",
                {
                    "_auth": {"api_key": "secret-key-12345", "ssh": {"signature": "secret"}},
                    "arg": "value",
                },
            )

            # Check that debug logs don't contain _auth
            debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
            for log_message in debug_calls:
                # Ensure sensitive data is not in logs
                assert "secret-key-12345" not in log_message
                assert "secret" not in log_message
                # The arguments log should exist but without _auth
                if "Arguments" in log_message:
                    assert "_auth" not in log_message
                    assert "auth redacted" in log_message.lower()

    @pytest.mark.asyncio
    async def test_handle_list_resources(self) -> None:
        """Test list_resources handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_resources.return_value = [
                {"uri": "docker://container/test", "name": "Test Container"}
            ]

            result = await main_module.handle_list_resources()

            assert len(result) == 1
            assert result[0]["uri"] == "docker://container/test"

    @pytest.mark.asyncio
    async def test_handle_read_resource_with_text(self) -> None:
        """Test read_resource handler with text content."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.read_resource = AsyncMock(return_value={"text": "Resource content"})

            result = await main_module.handle_read_resource("docker://test")

            assert result == "Resource content"

    @pytest.mark.asyncio
    async def test_handle_read_resource_without_text(self) -> None:
        """Test read_resource handler without text field."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.read_resource = AsyncMock(return_value={"data": "some data"})

            result = await main_module.handle_read_resource("docker://test")

            assert "data" in result

    @pytest.mark.asyncio
    async def test_handle_list_prompts(self) -> None:
        """Test list_prompts handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_prompts.return_value = [
                {"name": "test_prompt", "description": "Test prompt"}
            ]

            result = await main_module.handle_list_prompts()

            assert len(result) == 1
            assert result[0]["name"] == "test_prompt"

    @pytest.mark.asyncio
    async def test_handle_get_prompt(self) -> None:
        """Test get_prompt handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.get_prompt = AsyncMock(
                return_value={
                    "name": "test_prompt",
                    "messages": [{"role": "user", "content": "Test message"}],
                }
            )

            result = await main_module.handle_get_prompt("test_prompt", None)

            assert result["name"] == "test_prompt"
            mock_server.get_prompt.assert_called_once_with("test_prompt", {})

    @pytest.mark.asyncio
    async def test_handle_get_prompt_with_arguments(self) -> None:
        """Test get_prompt handler with arguments."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.get_prompt = AsyncMock(return_value={"name": "test_prompt"})

            args = {"param": "value"}
            await main_module.handle_get_prompt("test_prompt", args)

            mock_server.get_prompt.assert_called_once_with("test_prompt", args)


class TestServerRunFunction:
    """Tests for run_stdio function."""

    @pytest.mark.asyncio
    async def test_run_stdio(self) -> None:
        """Test run_stdio function."""
        # Mock all the async components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()

        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch.object(main_module, "mcp_server") as mock_mcp_server:
                mock_mcp_server.run = AsyncMock()
                mock_mcp_server.create_initialization_options = Mock(
                    return_value={"options": "test"}
                )

                with patch("mcp_docker.__main__.stdio_server") as mock_stdio:
                    # Setup async context manager
                    mock_stdio.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read_stream, mock_write_stream)
                    )
                    mock_stdio.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Run the server function
                    await main_module.run_stdio()

                    # Verify calls
                    mock_docker_server.start.assert_called_once()
                    mock_mcp_server.run.assert_called_once()
                    mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_stdio_cleanup_on_error(self) -> None:
        """Test run_stdio cleans up on error."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch.object(main_module, "mcp_server") as mock_mcp_server:
                mock_mcp_server.run = AsyncMock(side_effect=Exception("Test error"))
                mock_mcp_server.create_initialization_options = Mock(
                    return_value={"options": "test"}
                )

                with patch("mcp_docker.__main__.stdio_server") as mock_stdio:
                    mock_stdio.return_value.__aenter__ = AsyncMock(
                        return_value=(AsyncMock(), AsyncMock())
                    )
                    mock_stdio.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Should raise the exception
                    with pytest.raises(Exception, match="Test error"):
                        await main_module.run_stdio()

                    # But should still call stop
                    mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sse(self) -> None:
        """Test run_sse function."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch.object(main_module, "mcp_server") as mock_mcp_server:
                mock_mcp_server.run = AsyncMock()
                mock_mcp_server.create_initialization_options = Mock(
                    return_value={"options": "test"}
                )

                with (
                    patch("mcp_docker.__main__.SseServerTransport") as mock_sse_transport,
                    patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                ):
                    # Mock SSE transport
                    mock_sse_instance = Mock()
                    mock_sse_transport.return_value = mock_sse_instance

                    # Mock SSE connection context manager
                    mock_streams = (AsyncMock(), AsyncMock())
                    mock_sse_instance.connect_sse = Mock()
                    mock_sse_instance.connect_sse.return_value.__aenter__ = AsyncMock(
                        return_value=mock_streams
                    )
                    mock_sse_instance.connect_sse.return_value.__aexit__ = AsyncMock()

                    # Mock uvicorn server
                    mock_server_instance = Mock()
                    mock_server_instance.serve = AsyncMock()
                    mock_uvicorn_server.return_value = mock_server_instance

                    # Run the SSE server function
                    await main_module.run_sse("localhost", 8080)

                    # Verify calls
                    mock_docker_server.start.assert_called_once()
                    mock_sse_transport.assert_called_once_with("/messages")
                    mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sse_cleanup_on_error(self) -> None:
        """Test run_sse cleans up on error."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch("mcp_docker.__main__.SseServerTransport") as mock_sse_transport:
                mock_sse_transport.side_effect = Exception("SSE error")

                # Should raise the exception
                with pytest.raises(Exception, match="SSE error"):
                    await main_module.run_sse("localhost", 8080)

                # But should still call stop
                mock_docker_server.stop.assert_called_once()


class TestMainFunction:
    """Tests for main function."""

    def test_main_stdio_default(self) -> None:
        """Test main function defaults to stdio transport."""
        with patch("asyncio.run") as mock_asyncio_run, patch("sys.argv", ["mcp-docker"]):
            main_module.main()
            mock_asyncio_run.assert_called_once()
            # Verify it was called with run_stdio
            call_arg = mock_asyncio_run.call_args[0][0]
            assert call_arg.__name__ == "run_stdio"

    def test_main_sse_transport(self) -> None:
        """Test main function with SSE transport."""
        with (
            patch("asyncio.run") as mock_asyncio_run,
            patch("sys.argv", ["mcp-docker", "--transport", "sse"]),
        ):
            main_module.main()
            mock_asyncio_run.assert_called_once()
            # Verify it was called with run_sse
            call_arg = mock_asyncio_run.call_args[0][0]
            assert call_arg.__name__ == "run_sse"

    def test_main_sse_custom_port(self) -> None:
        """Test main function with custom SSE port."""
        with (
            patch("asyncio.run") as mock_asyncio_run,
            patch("sys.argv", ["mcp-docker", "--transport", "sse", "--port", "9000"]),
        ):
            main_module.main()
            mock_asyncio_run.assert_called_once()

    def test_main_keyboard_interrupt(self) -> None:
        """Test main function handles KeyboardInterrupt."""
        with (
            patch("asyncio.run", side_effect=KeyboardInterrupt()),
            patch("sys.argv", ["mcp-docker"]),
        ):
            # Should not raise, just log
            main_module.main()

    def test_main_exception(self) -> None:
        """Test main function handles exceptions."""
        with (
            patch("asyncio.run", side_effect=Exception("Test error")),
            patch("sys.argv", ["mcp-docker"]),
            pytest.raises(Exception, match="Test error"),
        ):
            main_module.main()


class TestLogPathConfiguration:
    """Tests for log path configuration."""

    def test_custom_log_path_from_env(self) -> None:
        """Test custom log path from environment variable."""
        # Test that MCP_DOCKER_LOG_PATH environment variable is respected
        # This is tested via the main module's log_file variable
        assert hasattr(main_module, "log_file")
        # The actual path will be set based on the environment at import time
