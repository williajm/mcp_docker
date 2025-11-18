"""FastMCP audit logging middleware.

This middleware logs all Docker operations for audit and compliance purposes.
"""

from typing import Any, cast

from fastmcp.server.middleware import CallNext, MiddlewareContext

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

    def _get_client_info_from_context(self, context: MiddlewareContext[Any]) -> ClientInfo:
        """Extract or create ClientInfo from FastMCP context.

        Args:
            context: FastMCP middleware context

        Returns:
            ClientInfo for the request
        """
        # First, try to get authenticated client info from auth middleware
        if context.fastmcp_context and hasattr(context.fastmcp_context, "client_info"):
            return cast(ClientInfo, context.fastmcp_context.client_info)

        # Fall back to extracting from context (e.g., stdio transport)
        return self._create_fallback_client_info(context)

    def _create_fallback_client_info(self, context: MiddlewareContext[Any]) -> ClientInfo:
        """Create fallback ClientInfo when auth middleware info is unavailable.

        Args:
            context: FastMCP middleware context

        Returns:
            ClientInfo with extracted or default values
        """
        client_id = self._extract_client_id(context)
        client_ip = self._extract_client_ip(context)

        return ClientInfo(
            client_id=client_id,
            ip_address=client_ip,
            api_key_hash="none",
            description=None,
        )

    def _extract_client_id(self, context: MiddlewareContext[Any]) -> str:
        """Extract client ID from context or return 'unknown'.

        Args:
            context: FastMCP middleware context

        Returns:
            Client ID string
        """
        if not (context.fastmcp_context and hasattr(context.fastmcp_context, "request_context")):
            return "unknown"

        req_ctx = context.fastmcp_context.request_context
        if not req_ctx:
            return "unknown"

        session_id = cast(str | None, getattr(context.fastmcp_context, "session_id", None))
        return session_id if session_id else "unknown"

    def _extract_client_ip(self, context: MiddlewareContext[Any]) -> str:
        """Extract client IP from context or return 'unknown'.

        Args:
            context: FastMCP middleware context

        Returns:
            Client IP address string
        """
        if not (context.fastmcp_context and hasattr(context.fastmcp_context, "request_context")):
            return "unknown"

        req_ctx = context.fastmcp_context.request_context
        if not (req_ctx and hasattr(req_ctx, "request")):
            return "unknown"

        request = req_ctx.request
        if not (request and hasattr(request, "client")):
            return "unknown"

        client = request.client
        if client and hasattr(client, "host"):
            return client.host

        return "unknown"

    def _log_tool_execution(
        self, client_info: ClientInfo, tool_name: str, arguments: dict[str, Any], result: Any
    ) -> None:
        """Log successful tool execution.

        Args:
            client_info: Client information
            tool_name: Name of the tool
            arguments: Tool arguments
            result: Tool execution result
        """
        self.audit_logger.log_tool_call(
            client_info=client_info,
            tool_name=tool_name,
            arguments=arguments,
            result=result if isinstance(result, dict) else {"value": str(result)},
        )
        logger.debug(f"AuditMiddleware: Logged successful {tool_name} for {client_info.client_id}")

    def _log_tool_error(
        self, client_info: ClientInfo, tool_name: str, arguments: dict[str, Any], error: Exception
    ) -> None:
        """Log failed tool execution.

        Args:
            client_info: Client information
            tool_name: Name of the tool
            arguments: Tool arguments
            error: Exception that occurred
        """
        self.audit_logger.log_tool_call(
            client_info=client_info,
            tool_name=tool_name,
            arguments=arguments,
            error=str(error),
        )
        logger.debug(
            f"AuditMiddleware: Logged failed {tool_name} for {client_info.client_id}: {error}"
        )

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Log tool execution to audit log.

        Args:
            context: FastMCP middleware context with tool and client information
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler
        """
        # Extract tool information from context
        tool_name = getattr(context.message, "name", "unknown_tool")
        arguments = getattr(context.message, "arguments", {}) or {}

        # Extract client information
        client_info = self._get_client_info_from_context(context)

        # Execute the tool and log the result
        try:
            result = await call_next(context)
            self._log_tool_execution(client_info, tool_name, arguments, result)
            return result
        except Exception as e:
            self._log_tool_error(client_info, tool_name, arguments, e)
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
