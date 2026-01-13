"""Error handling middleware for MCP Docker server.

SECURITY: Sanitizes error messages before they reach clients to prevent
information disclosure. Uses the error_sanitizer utility which maps internal
errors to safe, generic messages.
"""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_name
from mcp_docker.utils.error_sanitizer import sanitize_error_for_client
from mcp_docker.utils.errors import MCPDockerError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class ErrorHandlerMiddleware:
    """FastMCP middleware for error sanitization.

    SECURITY: When debug_mode is False, this middleware catches exceptions
    and sanitizes them before they reach the client. This prevents information
    disclosure through error messages (file paths, internal details, etc.).

    When debug_mode is True, errors pass through unchanged for debugging.

    This should be one of the outermost middlewares (after debug logging)
    to catch errors from all inner middlewares and handlers.
    """

    def __init__(self, debug_mode: bool = False):
        """Initialize error handler middleware.

        Args:
            debug_mode: If True, errors pass through unchanged.
                       If False, errors are sanitized before reaching client.
        """
        self.debug_mode = debug_mode
        if debug_mode:
            logger.warning("ErrorHandlerMiddleware: debug_mode=True - errors will NOT be sanitized")
        else:
            logger.info("ErrorHandlerMiddleware: Initialized (errors will be sanitized)")

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Catch and sanitize errors before they reach the client.

        Args:
            context: FastMCP middleware context
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler

        Raises:
            MCPDockerError: Sanitized error (when debug_mode=False)
            Original exception: When debug_mode=True
        """
        try:
            return await call_next(context)
        except Exception as e:
            # In debug mode, let errors pass through for debugging
            if self.debug_mode:
                raise

            # Get operation name for error message context
            operation_name = get_operation_name(context)

            # Log the full error server-side for debugging
            logger.error(
                f"ErrorHandlerMiddleware: Error in {operation_name}: {type(e).__name__}: {e}"
            )

            # Sanitize the error message for the client
            sanitized_message, error_type = sanitize_error_for_client(e, operation_name)

            logger.debug(
                f"ErrorHandlerMiddleware: Sanitized error type={error_type}, "
                f"message={sanitized_message}"
            )

            # Re-raise as a sanitized MCPDockerError
            # Using 'from None' to hide the original traceback from clients
            raise MCPDockerError(sanitized_message) from None
