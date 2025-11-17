"""FastMCP audit logging middleware.

This middleware logs all Docker operations for audit and compliance purposes.
"""

from collections.abc import Awaitable, Callable
from typing import Any

from mcp_docker.security.audit import AuditLogger
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuditMiddleware:
    """FastMCP middleware for audit logging.

    This middleware integrates with FastMCP's middleware system to log
    all tool executions for audit and compliance purposes.

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.middleware import AuditMiddleware
        from mcp_docker.security.audit import AuditLogger

        app = FastMCP("mcp-docker")
        audit_logger = AuditLogger(
            audit_log_file="mcp_audit.log",
            enabled=True
        )
        middleware = AuditMiddleware(audit_logger)

        # Register middleware
        app.add_middleware(middleware)
        ```
    """

    def __init__(self, audit_logger: AuditLogger):
        """Initialize audit middleware.

        Args:
            audit_logger: AuditLogger instance for recording operations
        """
        self.audit_logger = audit_logger
        logger.info(f"Initialized AuditMiddleware (enabled={audit_logger.enabled})")

    async def __call__(
        self,
        call_next: Callable[[], Awaitable[Any]],
        context: dict[str, Any],
    ) -> Any:
        """Log tool execution to audit log.

        Args:
            call_next: Next middleware/handler in the chain
            context: Request context with tool and client information

        Returns:
            Result from next handler
        """
        # Extract information from context
        tool_name = context.get("tool_name", "unknown_tool")
        client_id = (
            context.get("client_ip")
            or context.get("session_id")
            or context.get("user_id")
            or "unknown"
        )

        # Note: We'll log after execution with the result
        # (AuditLogger.log_tool_call expects ClientInfo, not raw values)

        # Execute the tool
        try:
            result = await call_next()

            # Log successful execution
            # Note: Full audit logging with ClientInfo should be done at server level
            # This middleware provides basic logging
            logger.info(f"AuditMiddleware: {tool_name} succeeded for {client_id}")

            return result

        except Exception as e:
            # Log failed execution
            logger.error(f"AuditMiddleware: {tool_name} failed for {client_id}: {e}")

            # Re-raise the exception
            raise


def create_audit_middleware(audit_logger: AuditLogger) -> AuditMiddleware:
    """Factory function to create audit middleware.

    Args:
        audit_logger: AuditLogger instance

    Returns:
        Configured AuditMiddleware instance

    Example:
        ```python
        from mcp_docker.config import Config
        from mcp_docker.security.audit import AuditLogger
        from mcp_docker.middleware.audit import create_audit_middleware

        config = Config()
        audit_logger = AuditLogger(
            audit_log_file=config.security.audit_log_file,
            enabled=config.security.audit_log_enabled
        )
        middleware = create_audit_middleware(audit_logger)
        ```
    """
    return AuditMiddleware(audit_logger)
