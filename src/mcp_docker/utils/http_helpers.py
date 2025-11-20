"""HTTP request utilities for extracting client information from FastMCP contexts."""

from typing import Any

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import MiddlewareContext

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def extract_client_ip(context: MiddlewareContext[Any]) -> str | None:
    """Extract client IP address from FastMCP middleware context.

    Tries multiple strategies in priority order:
    1. FastMCP's dependency injection (works during initialization)
    2. Context extraction (for unit tests with mocked contexts)

    Args:
        context: FastMCP middleware context

    Returns:
        IP address string or None if not available

    Note:
        This function is shared by AuthMiddleware and AuditMiddleware to avoid
        code duplication. Both middlewares need to extract client IPs for
        authorization and audit logging respectively.
    """
    # Strategy 1: Try FastMCP's dependency injection (works during initialization)
    try:
        request = get_http_request()
        if (
            request
            and hasattr(request, "client")
            and request.client
            and hasattr(request.client, "host")
        ):
            return request.client.host
    except (RuntimeError, LookupError):
        # Expected: Not in HTTP context (stdio) or dependency injection unavailable (unit tests)
        # Will fall back to context extraction below
        logger.debug(
            "get_http_request() unavailable (stdio transport or unit test), "
            "falling back to context extraction"
        )

    # Strategy 2: Fall back to context extraction (for unit tests with mocked contexts)
    if not (context.fastmcp_context and hasattr(context.fastmcp_context, "request_context")):
        return None

    req_ctx = context.fastmcp_context.request_context
    if not (req_ctx and hasattr(req_ctx, "request")):
        return None

    ctx_request = req_ctx.request
    if not (ctx_request and hasattr(ctx_request, "client")):
        return None

    client = ctx_request.client
    if client and hasattr(client, "host"):
        host = client.host
        return str(host) if host is not None else None

    return None
