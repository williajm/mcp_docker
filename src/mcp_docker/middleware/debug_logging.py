"""Debug logging middleware for MCP protocol operations.

This middleware logs all incoming MCP protocol requests and outgoing responses
at DEBUG level only. Useful for debugging and understanding what the server
is exposing (tools/list, resources/list, etc.) and what's being returned.
"""

import json
from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_type
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class DebugLoggingMiddleware:
    """FastMCP middleware for debug-level request/response logging.

    This middleware logs all MCP protocol operations (tools/list, resources/list,
    prompts/list, tool calls, etc.) and their responses at DEBUG level only.

    Performance:
    - When debug_enabled=False, the middleware returns immediately without any
      JSON serialization or string formatting.
    - Zero performance overhead for production deployments.

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.middleware import DebugLoggingMiddleware

        app = FastMCP("mcp-docker")
        middleware = DebugLoggingMiddleware(debug_enabled=True)

        # Register middleware (should be outermost for full visibility)
        app.add_middleware(middleware)
        ```
    """

    def __init__(self, debug_enabled: bool = False) -> None:
        """Initialize debug logging middleware.

        Args:
            debug_enabled: Whether to enable debug logging. When False, the
                middleware returns early without any processing overhead.
        """
        self._debug_enabled = debug_enabled
        if debug_enabled:
            logger.info("DebugLoggingMiddleware initialized (debug logging ENABLED)")
        else:
            logger.info("DebugLoggingMiddleware initialized (debug logging disabled)")

    def _truncate_if_needed(self, data: Any, max_length: int = 5000) -> str:
        """Convert data to string and truncate if too long.

        Args:
            data: Data to convert to string
            max_length: Maximum length before truncation

        Returns:
            String representation, possibly truncated
        """
        if isinstance(data, (dict, list)):
            try:
                data_str = json.dumps(data, indent=2)
            except (TypeError, ValueError):
                data_str = str(data)
        else:
            data_str = str(data)

        if len(data_str) > max_length:
            return data_str[:max_length] + f"\n... (truncated, {len(data_str)} total bytes)"
        return data_str

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Log MCP protocol request and response at DEBUG level.

        Early return if debug logging is disabled to avoid performance overhead
        from JSON serialization and string formatting.

        Args:
            context: FastMCP middleware context
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler
        """
        # Early return if debug logging is disabled (performance optimization)
        if not self._debug_enabled:
            return await call_next(context)

        # Extract operation information (only when DEBUG is enabled)
        operation_type = get_operation_type(context)
        arguments = getattr(context.message, "arguments", None) or getattr(
            context.message, "params", {}
        )

        # Log incoming request
        logger.debug("=" * 80)
        logger.debug(f"MCP Request: {operation_type}")
        if arguments:
            args_str = self._truncate_if_needed(arguments, max_length=2000)
            logger.debug(f"Arguments:\n{args_str}")

        # Execute the operation and capture result
        try:
            result = await call_next(context)

            # Log successful response
            logger.debug(f"MCP Response: {operation_type} - SUCCESS")
            result_str = self._truncate_if_needed(result, max_length=5000)
            logger.debug(f"Result:\n{result_str}")
            logger.debug("=" * 80)

            return result

        except Exception as e:
            # Log error response
            logger.debug(f"MCP Response: {operation_type} - ERROR")
            logger.debug(f"Error: {type(e).__name__}: {str(e)}")
            logger.debug("=" * 80)
            raise


def create_debug_logging_middleware(debug_enabled: bool = False) -> DebugLoggingMiddleware:
    """Factory function to create debug logging middleware.

    Args:
        debug_enabled: Whether to enable debug logging (default: False)

    Returns:
        Configured DebugLoggingMiddleware instance

    Example:
        ```python
        from mcp_docker.middleware.debug_logging import create_debug_logging_middleware

        middleware = create_debug_logging_middleware(debug_enabled=True)
        app.add_middleware(middleware)
        ```
    """
    return DebugLoggingMiddleware(debug_enabled=debug_enabled)
