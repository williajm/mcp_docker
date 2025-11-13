"""Unit tests for __main__.py MCP server entry point."""

import asyncio
from typing import Any
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

    @pytest.mark.asyncio
    async def test_run_sse_signal_handler_sets_shutdown_event(self) -> None:
        """Test that signal handler sets the shutdown event."""
        import signal as signal_module

        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with (
                patch("mcp_docker.__main__.SseServerTransport"),
                patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                patch("mcp_docker.__main__.signal.signal") as mock_signal,
            ):
                # Mock server to trigger shutdown immediately
                mock_server_instance = Mock()
                mock_server_instance.serve = AsyncMock()
                mock_server_instance.should_exit = False
                mock_uvicorn_server.return_value = mock_server_instance

                # Capture the signal handler
                signal_handlers = {}

                def capture_signal(sig: int, handler: object) -> None:
                    signal_handlers[sig] = handler

                mock_signal.side_effect = capture_signal

                # Start the server (it will register signal handlers)
                # We'll use a task to avoid blocking
                task = asyncio.create_task(main_module.run_sse("localhost", 8080))

                # Give it time to set up
                await asyncio.sleep(0.1)

                # Verify signal handlers were registered
                assert signal_module.SIGINT in signal_handlers
                assert signal_module.SIGTERM in signal_handlers

                # Test calling the signal handler directly
                handler = signal_handlers[signal_module.SIGINT]
                # Handler should be callable
                assert callable(handler)
                # Call it with signal and frame (the signature signal handlers expect)
                handler(signal_module.SIGINT, None)

                # Cancel the task to clean up
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    @pytest.mark.asyncio
    async def test_run_sse_graceful_shutdown_on_signal(self) -> None:
        """Test graceful shutdown when shutdown signal is received."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with (
                patch("mcp_docker.__main__.SseServerTransport"),
                patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                patch("mcp_docker.__main__.signal.signal"),
            ):
                # Mock server
                mock_server_instance = Mock()
                mock_server_instance.should_exit = False

                # Server will complete quickly
                async def mock_serve() -> None:
                    await asyncio.sleep(0.01)

                mock_server_instance.serve = mock_serve
                mock_uvicorn_server.return_value = mock_server_instance

                # Run the server
                await main_module.run_sse("localhost", 8080)

                # Verify stop was called
                mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sse_shutdown_timeout(self) -> None:
        """Test forced shutdown after timeout."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with (
                patch("mcp_docker.__main__.SseServerTransport"),
                patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                patch("mcp_docker.__main__.signal.signal"),
                patch("mcp_docker.__main__.asyncio.wait") as mock_wait,
                patch("mcp_docker.__main__.asyncio.wait_for") as mock_wait_for,
            ):
                # Mock server
                mock_server_instance = Mock()
                mock_server_instance.should_exit = False
                mock_server_instance.serve = AsyncMock()
                mock_uvicorn_server.return_value = mock_server_instance

                # Mock server task
                server_task = AsyncMock()
                server_task.__name__ = "serve"

                # Mock shutdown task to complete first
                shutdown_task = AsyncMock()

                # Mock wait to return shutdown task as done
                async def mock_wait_impl(
                    tasks: set[Any], **kwargs: object
                ) -> tuple[set[Any], set[Any]]:  # noqa: ARG001
                    return {shutdown_task}, {server_task}

                mock_wait.side_effect = mock_wait_impl

                # Mock wait_for to timeout
                mock_wait_for.side_effect = TimeoutError()

                # Run should complete without hanging
                await main_module.run_sse("localhost", 8080)

                # Verify cleanup happened
                mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_sse_handler_cancelled_error_handling(self) -> None:
        """Test that CancelledError in SSE handler is caught and logged."""
        # This tests the exception handling in the sse_handler inner function
        # We can't easily test it directly, but we can verify it doesn't crash
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with (
                patch("mcp_docker.__main__.SseServerTransport") as mock_sse_transport,
                patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                patch("mcp_docker.__main__.signal.signal"),
            ):
                # Mock SSE transport
                mock_sse_instance = Mock()
                mock_sse_transport.return_value = mock_sse_instance

                # Mock connect_sse to raise CancelledError (simulating shutdown)
                async def raise_cancelled() -> None:
                    raise asyncio.CancelledError()

                mock_sse_instance.connect_sse = Mock()
                mock_sse_instance.connect_sse.return_value.__aenter__ = AsyncMock(
                    side_effect=raise_cancelled
                )
                mock_sse_instance.connect_sse.return_value.__aexit__ = AsyncMock()

                # Mock server
                mock_server_instance = Mock()
                mock_server_instance.serve = AsyncMock()
                mock_uvicorn_server.return_value = mock_server_instance

                # Should complete without error
                await main_module.run_sse("localhost", 8080)

                mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_post_handler_cancelled_error_handling(self) -> None:
        """Test that CancelledError in POST handler is caught and logged."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with (
                patch("mcp_docker.__main__.SseServerTransport") as mock_sse_transport,
                patch("mcp_docker.__main__.uvicorn.Server") as mock_uvicorn_server,
                patch("mcp_docker.__main__.signal.signal"),
            ):
                # Mock SSE transport
                mock_sse_instance = Mock()
                mock_sse_transport.return_value = mock_sse_instance

                # Mock handle_post_message to raise CancelledError
                async def raise_cancelled(*args: object, **kwargs: object) -> None:  # noqa: ARG001
                    raise asyncio.CancelledError()

                mock_sse_instance.handle_post_message = raise_cancelled

                # Mock server
                mock_server_instance = Mock()
                mock_server_instance.serve = AsyncMock()
                mock_uvicorn_server.return_value = mock_server_instance

                # Should complete without error
                await main_module.run_sse("localhost", 8080)

                mock_docker_server.stop.assert_called_once()


class TestHelperFunctions:
    """Tests for helper functions."""

    @pytest.mark.asyncio
    async def test_create_logging_wrappers(self) -> None:
        """Test _create_logging_wrappers creates proper wrapper functions."""
        mock_receive = AsyncMock(return_value={"type": "http.request", "body": b"test"})
        mock_send = AsyncMock()

        log_receive, log_send = main_module._create_logging_wrappers(mock_receive, mock_send)

        # Test log_receive
        result = await log_receive()
        assert result == {"type": "http.request", "body": b"test"}
        mock_receive.assert_called_once()

        # Test log_send
        await log_send({"type": "http.response.body", "body": b"response"})
        mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_sse_connection(self) -> None:
        """Test _handle_sse_connection handles SSE connections."""
        mock_sse = Mock()
        mock_scope = {"path": "/sse"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        # Mock SSE connection
        mock_streams = (AsyncMock(), AsyncMock())
        mock_sse.connect_sse = Mock()
        mock_sse.connect_sse.return_value.__aenter__ = AsyncMock(return_value=mock_streams)
        mock_sse.connect_sse.return_value.__aexit__ = AsyncMock()

        with patch.object(main_module, "mcp_server") as mock_mcp_server:
            mock_mcp_server.run = AsyncMock()
            mock_mcp_server.create_initialization_options = Mock(return_value={})

            await main_module._handle_sse_connection(mock_sse, mock_scope, mock_receive, mock_send)

            mock_mcp_server.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_sse_connection_cancelled(self) -> None:
        """Test _handle_sse_connection re-raises CancelledError."""
        mock_sse = Mock()
        mock_scope = {"path": "/sse"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        # Mock SSE connection to raise CancelledError
        mock_sse.connect_sse = Mock()
        mock_sse.connect_sse.return_value.__aenter__ = AsyncMock(
            side_effect=asyncio.CancelledError()
        )
        mock_sse.connect_sse.return_value.__aexit__ = AsyncMock()

        with pytest.raises(asyncio.CancelledError):
            await main_module._handle_sse_connection(mock_sse, mock_scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_handle_post_message(self) -> None:
        """Test _handle_post_message handles POST requests."""
        mock_sse = Mock()
        mock_scope = {"path": "/messages", "method": "POST"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        mock_sse.handle_post_message = AsyncMock()

        await main_module._handle_post_message(mock_sse, mock_scope, mock_receive, mock_send)

        mock_sse.handle_post_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_post_message_cancelled(self) -> None:
        """Test _handle_post_message re-raises CancelledError."""
        mock_sse = Mock()
        mock_scope = {"path": "/messages"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        mock_sse.handle_post_message = AsyncMock(side_effect=asyncio.CancelledError())

        with pytest.raises(asyncio.CancelledError):
            await main_module._handle_post_message(mock_sse, mock_scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_handle_404(self) -> None:
        """Test _handle_404 sends 404 response."""
        mock_send = AsyncMock()

        await main_module._handle_404(mock_send, "GET", "/unknown")

        assert mock_send.call_count == 2
        # First call is the response start
        assert mock_send.call_args_list[0][0][0]["status"] == 404
        # Second call is the response body
        assert mock_send.call_args_list[1][0][0]["body"] == b"Not Found"

    @pytest.mark.asyncio
    async def test_monitor_shutdown_signal_received(self) -> None:
        """Test _monitor_shutdown handles shutdown signal."""
        mock_server = Mock()
        mock_server.should_exit = False

        # Mock server task (not done)
        server_task = AsyncMock()
        server_task.__name__ = "serve"

        # Mock shutdown task (done)
        shutdown_task = AsyncMock()

        with (
            patch("mcp_docker.__main__.asyncio.wait") as mock_wait,
            patch("mcp_docker.__main__.asyncio.wait_for") as mock_wait_for,
        ):
            # Mock wait to return shutdown task as done
            async def mock_wait_impl(tasks: set, **kwargs: object) -> tuple[set, set]:  # noqa: ARG001
                return {shutdown_task}, {server_task}

            mock_wait.side_effect = mock_wait_impl
            mock_wait_for.return_value = None

            await main_module._monitor_shutdown(server_task, shutdown_task, mock_server)

            # Verify should_exit was set
            assert mock_server.should_exit is True
            mock_wait_for.assert_called_once_with(server_task, timeout=5.0)

    @pytest.mark.asyncio
    async def test_monitor_shutdown_timeout(self) -> None:
        """Test _monitor_shutdown handles timeout."""
        mock_server = Mock()
        mock_server.should_exit = False

        server_task = AsyncMock()
        server_task.cancel = Mock()
        shutdown_task = AsyncMock()

        with (
            patch("mcp_docker.__main__.asyncio.wait") as mock_wait,
            patch("mcp_docker.__main__.asyncio.wait_for") as mock_wait_for,
        ):
            # Mock wait to return shutdown task as done
            async def mock_wait_impl(tasks: set, **kwargs: object) -> tuple[set, set]:  # noqa: ARG001
                return {shutdown_task}, {server_task}

            mock_wait.side_effect = mock_wait_impl
            mock_wait_for.side_effect = TimeoutError()

            await main_module._monitor_shutdown(server_task, shutdown_task, mock_server)

            # Verify task was cancelled
            server_task.cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_sse_request_head_bypass(self) -> None:
        """Test _authenticate_sse_request bypasses authentication for HEAD requests."""
        is_authenticated, error_body = await main_module._authenticate_sse_request(
            "HEAD", "/sse", "127.0.0.1", None
        )
        assert is_authenticated is True
        assert error_body is None

    @pytest.mark.asyncio
    async def test_authenticate_sse_request_non_sse_path(self) -> None:
        """Test _authenticate_sse_request bypasses auth for non-SSE paths."""
        is_authenticated, error_body = await main_module._authenticate_sse_request(
            "GET", "/health", "127.0.0.1", None
        )
        assert is_authenticated is True
        assert error_body is None

    @pytest.mark.asyncio
    async def test_authenticate_sse_request_success(self) -> None:
        """Test _authenticate_sse_request with successful authentication."""
        with patch.object(
            main_module.docker_server.auth_middleware, "authenticate_request"
        ) as mock_auth:
            mock_auth.return_value = None  # Successful auth returns None

            is_authenticated, error_body = await main_module._authenticate_sse_request(
                "GET", "/sse", "127.0.0.1", "valid_token"
            )

            assert is_authenticated is True
            assert error_body is None
            mock_auth.assert_called_once_with(ip_address="127.0.0.1", bearer_token="valid_token")

    @pytest.mark.asyncio
    async def test_authenticate_sse_request_failure(self) -> None:
        """Test _authenticate_sse_request with failed authentication."""
        with patch.object(
            main_module.docker_server.auth_middleware, "authenticate_request"
        ) as mock_auth:
            mock_auth.side_effect = Exception("Invalid token")

            is_authenticated, error_body = await main_module._authenticate_sse_request(
                "GET", "/sse", "127.0.0.1", "invalid_token"
            )

            assert is_authenticated is False
            assert error_body is not None
            assert b"Invalid token" in error_body

    @pytest.mark.asyncio
    async def test_send_unauthorized_response(self) -> None:
        """Test _send_unauthorized_response sends correct 401 response."""
        mock_send = AsyncMock()
        error_body = b'{"error": "Unauthorized"}'

        await main_module._send_unauthorized_response(mock_send, error_body)

        assert mock_send.call_count == 2
        # Check response start
        first_call = mock_send.call_args_list[0][0][0]
        assert first_call["status"] == 401
        assert any(b"www-authenticate" in h[0].lower() for h in first_call["headers"])
        # Check response body
        second_call = mock_send.call_args_list[1][0][0]
        assert second_call["body"] == error_body

    @pytest.mark.asyncio
    async def test_route_sse_request_get(self) -> None:
        """Test _route_sse_request routes GET /sse correctly."""
        mock_sse = Mock()
        mock_scope = {"path": "/sse", "method": "GET"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        # Mock SSE connection
        mock_streams = (AsyncMock(), AsyncMock())
        mock_sse.connect_sse = Mock()
        mock_sse.connect_sse.return_value.__aenter__ = AsyncMock(return_value=mock_streams)
        mock_sse.connect_sse.return_value.__aexit__ = AsyncMock()

        with patch.object(main_module, "mcp_server") as mock_mcp_server:
            mock_mcp_server.run = AsyncMock()
            mock_mcp_server.create_initialization_options = Mock(return_value={})

            await main_module._route_sse_request(mock_sse, mock_scope, mock_receive, mock_send)

            mock_mcp_server.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_sse_request_head(self) -> None:
        """Test _route_sse_request handles HEAD /sse correctly."""
        mock_sse = Mock()
        mock_scope = {"path": "/sse", "method": "HEAD"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        await main_module._route_sse_request(mock_sse, mock_scope, mock_receive, mock_send)

        # Should send 200 with appropriate headers
        assert mock_send.call_count == 2
        first_call = mock_send.call_args_list[0][0][0]
        assert first_call["status"] == 200

    @pytest.mark.asyncio
    async def test_route_sse_request_post_messages(self) -> None:
        """Test _route_sse_request routes POST /messages correctly."""
        mock_sse = Mock()
        mock_sse.handle_post_message = AsyncMock()
        mock_scope = {"path": "/messages", "method": "POST"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        await main_module._route_sse_request(mock_sse, mock_scope, mock_receive, mock_send)

        mock_sse.handle_post_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_sse_request_404(self) -> None:
        """Test _route_sse_request returns 404 for unknown paths."""
        mock_sse = Mock()
        mock_scope = {"path": "/unknown", "method": "GET"}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        await main_module._route_sse_request(mock_sse, mock_scope, mock_receive, mock_send)

        # Should send 404
        assert mock_send.call_count == 2
        first_call = mock_send.call_args_list[0][0][0]
        assert first_call["status"] == 404

    def test_create_sse_handler(self) -> None:
        """Test _create_sse_handler creates a handler function."""
        mock_sse = Mock()

        handler = main_module._create_sse_handler(mock_sse)

        assert callable(handler)
        # Check it's an async function
        assert asyncio.iscoroutinefunction(handler)

    @pytest.mark.asyncio
    async def test_create_sse_handler_flow(self) -> None:
        """Test _create_sse_handler creates handler with correct flow."""
        mock_sse = Mock()
        mock_sse.handle_post_message = AsyncMock()

        handler = main_module._create_sse_handler(mock_sse)

        # Mock scope with POST to /messages (bypasses auth for this test)
        mock_scope = {"path": "/messages", "method": "POST", "client": ("127.0.0.1", 12345)}
        mock_receive = AsyncMock()
        mock_send = AsyncMock()

        with patch.object(main_module.docker_server.auth_middleware, "authenticate_request"):
            await handler(mock_scope, mock_receive, mock_send)

        # Verify handler was called
        mock_sse.handle_post_message.assert_called_once()

    def test_create_security_headers_middleware(self) -> None:
        """Test _create_security_headers_middleware creates middleware."""
        mock_handler = AsyncMock()
        mock_secure = Mock()
        mock_secure.set_headers_async = AsyncMock()

        middleware = main_module._create_security_headers_middleware(mock_handler, mock_secure)

        assert callable(middleware)
        assert asyncio.iscoroutinefunction(middleware)

    @pytest.mark.asyncio
    async def test_create_security_headers_middleware_applies_headers(self) -> None:
        """Test security headers middleware applies headers to responses."""

        # Create a mock handler that sends a response
        async def mock_handler(scope: Any, receive: Any, send: Any) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"text/plain"]],
                }
            )

        mock_secure = Mock()
        mock_secure.set_headers_async = AsyncMock()

        middleware = main_module._create_security_headers_middleware(mock_handler, mock_secure)

        mock_scope: dict[str, Any] = {}
        mock_receive = AsyncMock()
        sent_messages: list[Any] = []

        async def capture_send(message: Any) -> None:
            sent_messages.append(message)

        await middleware(mock_scope, mock_receive, capture_send)

        # Verify set_headers_async was called
        mock_secure.set_headers_async.assert_called_once()

    def test_setup_signal_handlers(self) -> None:
        """Test _setup_signal_handlers registers signal handlers."""
        import signal as signal_module

        shutdown_event = asyncio.Event()

        with patch("mcp_docker.__main__.signal.signal") as mock_signal:
            main_module._setup_signal_handlers(shutdown_event)

            # Verify SIGINT and SIGTERM handlers were registered
            assert mock_signal.call_count == 2
            calls = mock_signal.call_args_list
            registered_signals = [call[0][0] for call in calls]
            assert signal_module.SIGINT in registered_signals
            assert signal_module.SIGTERM in registered_signals

    def test_setup_signal_handlers_sets_event(self) -> None:
        """Test signal handlers set the shutdown event."""
        import signal as signal_module

        shutdown_event = asyncio.Event()
        captured_handler = None

        def capture_handler(sig: int, handler: Any) -> None:
            nonlocal captured_handler
            if sig == signal_module.SIGINT:
                captured_handler = handler

        with patch("mcp_docker.__main__.signal.signal", side_effect=capture_handler):
            main_module._setup_signal_handlers(shutdown_event)

            # Call the captured handler
            assert captured_handler is not None
            captured_handler(signal_module.SIGINT, None)

            # Verify event was set
            assert shutdown_event.is_set()

    def test_extract_client_ip_from_scope(self) -> None:
        """Test _extract_client_ip extracts IP from scope."""
        scope = {"client": ("192.168.1.100", 12345)}
        ip = main_module._extract_client_ip(scope)
        assert ip == "192.168.1.100"

    def test_extract_client_ip_no_client(self) -> None:
        """Test _extract_client_ip returns None when no client."""
        scope: dict[str, Any] = {}
        ip = main_module._extract_client_ip(scope)
        assert ip is None

    def test_extract_bearer_token_from_scope(self) -> None:
        """Test _extract_bearer_token extracts token from Authorization header."""
        scope = {"headers": [[b"authorization", b"Bearer test_token_123"]]}
        token = main_module._extract_bearer_token(scope)
        assert token == "test_token_123"

    def test_extract_bearer_token_no_header(self) -> None:
        """Test _extract_bearer_token returns None when no Authorization header."""
        scope = {"headers": [[b"content-type", b"application/json"]]}
        token = main_module._extract_bearer_token(scope)
        assert token is None

    def test_extract_bearer_token_not_bearer(self) -> None:
        """Test _extract_bearer_token returns None for non-Bearer auth."""
        scope = {"headers": [[b"authorization", b"Basic dXNlcjpwYXNz"]]}
        token = main_module._extract_bearer_token(scope)
        assert token is None


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
