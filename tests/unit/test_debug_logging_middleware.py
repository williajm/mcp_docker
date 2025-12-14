"""Unit tests for DebugLoggingMiddleware."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_docker.middleware.debug_logging import DebugLoggingMiddleware


class TestDebugLoggingMiddleware:
    """Test DebugLoggingMiddleware functionality."""

    @pytest.fixture
    def middleware(self):
        """Create DebugLoggingMiddleware instance."""
        return DebugLoggingMiddleware()

    def test_init(self, middleware):
        """Test middleware initialization."""
        assert middleware is not None

    @pytest.mark.asyncio
    async def test_logs_tool_call_request_and_response(self, middleware):
        """Test that middleware logs tool call operations."""
        # Create mock context for tool call
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Mock successful response
        mock_result = {"containers": [], "count": 0}
        call_next = AsyncMock(return_value=mock_result)

        # Call middleware
        result = await middleware(context, call_next)

        # Verify result is returned
        assert result == mock_result
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_logs_mcp_protocol_operations(self, middleware):
        """Test that middleware logs MCP protocol operations like tools/list."""
        # Create mock context for tools/list
        message = Mock()
        message.method = "tools/list"
        # Remove 'name' and 'arguments' attributes to make it a protocol operation
        del message.name
        del message.arguments

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Mock response
        mock_result = [{"name": "docker_list_containers"}]
        call_next = AsyncMock(return_value=mock_result)

        # Call middleware
        result = await middleware(context, call_next)

        # Verify result is returned
        assert result == mock_result
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_logs_errors(self, middleware):
        """Test that middleware logs errors correctly."""
        # Create mock context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "abc123"}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Mock error
        error = RuntimeError("Container not found")
        call_next = AsyncMock(side_effect=error)

        # Call middleware - should raise
        with pytest.raises(RuntimeError, match="Container not found"):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    def test_truncate_small_data(self, middleware):
        """Test that small data is not truncated."""
        data = {"key": "value"}
        result = middleware._truncate_if_needed(data, max_length=1000)
        assert '"key": "value"' in result
        assert "truncated" not in result

    def test_truncate_large_data(self, middleware):
        """Test that large data is truncated."""
        large_dict = {"data": "x" * 10000}
        result = middleware._truncate_if_needed(large_dict, max_length=100)
        assert "truncated" in result
        assert "10" in result  # Should mention total bytes

    def test_truncate_list_data(self, middleware):
        """Test that list data is properly converted."""
        data = ["item1", "item2", "item3"]
        result = middleware._truncate_if_needed(data)
        assert "item1" in result
        assert "item2" in result

    def test_truncate_string_data(self, middleware):
        """Test that string data is handled."""
        data = "simple string"
        result = middleware._truncate_if_needed(data)
        assert result == "simple string"

    def test_truncate_non_json_serializable(self, middleware):
        """Test that non-JSON-serializable data falls back to str()."""

        class CustomObject:
            def __str__(self):
                return "custom object string"

        data = CustomObject()
        result = middleware._truncate_if_needed(data)
        assert "custom object string" in result

    @pytest.mark.asyncio
    async def test_handles_message_without_arguments(self, middleware):
        """Test middleware handles messages without arguments attribute."""
        message = Mock(spec=[])  # No attributes
        context = Mock()
        context.message = message
        context.fastmcp_context = None

        call_next = AsyncMock(return_value="success")

        result = await middleware(context, call_next)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_handles_none_result(self, middleware):
        """Test middleware handles None as result."""
        message = Mock()
        message.name = "some_operation"
        message.arguments = {}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        call_next = AsyncMock(return_value=None)

        result = await middleware(context, call_next)
        assert result is None

    @pytest.mark.asyncio
    async def test_handles_dict_message_type(self, middleware):
        """Test middleware handles dict-type messages."""
        message = {"method": "tools/list"}
        context = Mock()
        context.message = message
        context.fastmcp_context = None

        call_next = AsyncMock(return_value=[])

        result = await middleware(context, call_next)
        assert result == []

    @pytest.mark.asyncio
    async def test_with_fastmcp_context(self, middleware):
        """Test middleware with fastmcp_context present."""
        message = Mock()
        message.name = "docker_inspect_container"
        message.arguments = {"container_id": "test123"}

        fastmcp_ctx = Mock()
        context = Mock()
        context.message = message
        context.fastmcp_context = fastmcp_ctx

        call_next = AsyncMock(return_value={"Id": "test123"})

        result = await middleware(context, call_next)
        assert result == {"Id": "test123"}

    @pytest.mark.asyncio
    async def test_early_return_when_debug_disabled(self, middleware):
        """Test that middleware returns early when DEBUG logging is disabled.

        This test verifies the performance optimization where no JSON serialization
        or string formatting occurs when log level is INFO or higher.
        """
        # Mock logger._core.min_level to simulate INFO level (20)
        # DEBUG is level 10, INFO is 20, so min_level > 10 means DEBUG is disabled
        with patch("mcp_docker.middleware.debug_logging.logger._core.min_level", 20):
            message = Mock()
            message.name = "docker_list_containers"
            message.arguments = {"all": True, "large_data": "x" * 10000}

            context = Mock()
            context.message = message
            context.fastmcp_context = None

            mock_result = {"containers": [], "count": 0}
            call_next = AsyncMock(return_value=mock_result)

            # Spy on _truncate_if_needed to ensure it's NOT called
            with patch.object(middleware, "_truncate_if_needed") as mock_truncate:
                result = await middleware(context, call_next)

                # Verify result is returned correctly
                assert result == mock_result
                call_next.assert_called_once_with(context)

                # Verify _truncate_if_needed was never called (performance optimization)
                mock_truncate.assert_not_called()

    @pytest.mark.asyncio
    async def test_processes_when_debug_enabled(self):
        """Test that middleware processes normally when debug_enabled=True.

        This test verifies that when debug_enabled=True is passed to the constructor,
        the middleware performs its normal logging operations.
        """
        # Create middleware with debug_enabled=True
        debug_middleware = DebugLoggingMiddleware(debug_enabled=True)

        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        mock_result = {"containers": [], "count": 0}
        call_next = AsyncMock(return_value=mock_result)

        # Spy on _truncate_if_needed to ensure it IS called when debug is enabled
        with patch.object(
            debug_middleware, "_truncate_if_needed", return_value="truncated"
        ) as mock_truncate:
            result = await debug_middleware(context, call_next)

            # Verify result is returned correctly
            assert result == mock_result
            call_next.assert_called_once_with(context)

            # Verify _truncate_if_needed was called (normal DEBUG operation)
            # Should be called twice: once for arguments, once for result
            assert mock_truncate.call_count == 2
