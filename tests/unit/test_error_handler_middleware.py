"""Unit tests for ErrorHandlerMiddleware."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from mcp_docker.middleware.error_handler import ErrorHandlerMiddleware
from mcp_docker.utils.errors import MCPDockerError


class TestErrorHandlerMiddleware:
    """Test ErrorHandlerMiddleware."""

    def test_init_debug_mode_false(self):
        """Test ErrorHandlerMiddleware initialization with debug_mode=False."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        assert middleware.debug_mode is False

    def test_init_debug_mode_true(self):
        """Test ErrorHandlerMiddleware initialization with debug_mode=True."""
        middleware = ErrorHandlerMiddleware(debug_mode=True)

        assert middleware.debug_mode is True

    @pytest.mark.asyncio
    async def test_call_success_passthrough(self):
        """Test that successful calls pass through unchanged."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware returning success
        call_next = AsyncMock(return_value={"status": "success", "data": "test"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success", "data": "test"}
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_error_sanitized_when_debug_false(self):
        """Test that errors are sanitized when debug_mode=False."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising an error with sensitive info
        original_error = RuntimeError(
            "Connection to /var/run/docker.sock failed: Permission denied"
        )
        call_next = AsyncMock(side_effect=original_error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware should raise sanitized MCPDockerError
        with pytest.raises(MCPDockerError) as exc_info:
            await middleware(context, call_next)

        # Verify error is sanitized (no file paths)
        error_msg = str(exc_info.value)
        assert "/var/run/docker.sock" not in error_msg
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_error_passthrough_when_debug_true(self):
        """Test that errors pass through unchanged when debug_mode=True."""
        middleware = ErrorHandlerMiddleware(debug_mode=True)

        # Mock next middleware raising an error
        original_error = RuntimeError(
            "Connection to /var/run/docker.sock failed: Permission denied"
        )
        call_next = AsyncMock(side_effect=original_error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware should raise original error unchanged
        with pytest.raises(RuntimeError) as exc_info:
            await middleware(context, call_next)

        # Verify original error passed through
        assert "Permission denied" in str(exc_info.value)
        assert "/var/run/docker.sock" in str(exc_info.value)
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_sanitizes_connection_errors(self):
        """Test that connection errors are sanitized properly."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock connection error
        from docker.errors import DockerException

        original_error = DockerException("Error while fetching server API version")
        call_next = AsyncMock(side_effect=original_error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_version"
        context = Mock()
        context.message = message

        # Call middleware should raise sanitized error
        with pytest.raises(MCPDockerError):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_sanitizes_not_found_errors(self):
        """Test that not found errors are sanitized properly."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock not found error
        from mcp_docker.utils.errors import ContainerNotFound

        original_error = ContainerNotFound("Container abc123def456 not found")
        call_next = AsyncMock(side_effect=original_error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_inspect_container"
        context = Mock()
        context.message = message

        # Call middleware should raise sanitized error
        with pytest.raises(MCPDockerError):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_with_no_tool_name_in_context(self):
        """Test error handling when context has no tool name."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising an error
        original_error = ValueError("Invalid parameter")
        call_next = AsyncMock(side_effect=original_error)

        # Create context without tool name
        message = Mock(spec=[])  # No 'name' attribute
        context = Mock()
        context.message = message

        # Call middleware should still sanitize the error
        with pytest.raises(MCPDockerError):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_mcp_docker_error_passthrough(self):
        """Test that MCPDockerError is re-raised (already sanitized)."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising an already-sanitized error
        original_error = MCPDockerError("Container operation failed")
        call_next = AsyncMock(side_effect=original_error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_start_container"
        context = Mock()
        context.message = message

        # Call middleware should re-raise as MCPDockerError
        with pytest.raises(MCPDockerError) as exc_info:
            await middleware(context, call_next)

        # The sanitizer may wrap it again, but it should still be MCPDockerError
        assert isinstance(exc_info.value, MCPDockerError)
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_cancelled_error_propagates(self):
        """Test that asyncio.CancelledError is re-raised without sanitization.

        CRITICAL: Swallowing CancelledError can cause subtle shutdown/timeout bugs.
        This test ensures cancellation exceptions propagate correctly.
        """
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising CancelledError (simulating task cancellation)
        call_next = AsyncMock(side_effect=asyncio.CancelledError())

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware should re-raise CancelledError without sanitization
        with pytest.raises(asyncio.CancelledError):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_keyboard_interrupt_propagates(self):
        """Test that KeyboardInterrupt is re-raised without sanitization."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising KeyboardInterrupt
        call_next = AsyncMock(side_effect=KeyboardInterrupt())

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware should re-raise KeyboardInterrupt without sanitization
        with pytest.raises(KeyboardInterrupt):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_system_exit_propagates(self):
        """Test that SystemExit is re-raised without sanitization."""
        middleware = ErrorHandlerMiddleware(debug_mode=False)

        # Mock next middleware raising SystemExit
        call_next = AsyncMock(side_effect=SystemExit(0))

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        context = Mock()
        context.message = message

        # Call middleware should re-raise SystemExit without sanitization
        with pytest.raises(SystemExit):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)
