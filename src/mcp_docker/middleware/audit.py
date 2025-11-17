"""FastMCP audit logging middleware.

This middleware logs all Docker operations for audit and compliance purposes.
"""

from collections.abc import Awaitable, Callable
from typing import Any

from mcp_docker.auth.models import ClientInfo
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
        arguments = context.get("arguments", {})

        # Build ClientInfo from context
        # Try multiple sources for client identification
        client_ip = context.get("client_ip", "unknown")
        session_id = context.get("session_id")
        user_id = context.get("user_id")
        client_id = session_id or user_id or client_ip

        # Get API key hash if available (for authenticated requests)
        api_key_hash = context.get("api_key_hash") or "none"

        # Get user agent or other description
        description = context.get("user_agent") or None

        # Create ClientInfo for structured audit logging
        client_info = ClientInfo(
            client_id=client_id,
            ip_address=client_ip,
            api_key_hash=api_key_hash,
            description=description,
        )

        # Execute the tool and log the result
        try:
            result = await call_next()

            # Log successful execution to structured audit log
            self.audit_logger.log_tool_call(
                client_info=client_info,
                tool_name=tool_name,
                arguments=arguments,
                result=result if isinstance(result, dict) else {"value": str(result)},
            )

            logger.debug(f"AuditMiddleware: Logged successful {tool_name} for {client_id}")
            return result

        except Exception as e:
            # Log failed execution to structured audit log
            self.audit_logger.log_tool_call(
                client_info=client_info,
                tool_name=tool_name,
                arguments=arguments,
                error=str(e),
            )

            logger.debug(f"AuditMiddleware: Logged failed {tool_name} for {client_id}: {e}")

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
