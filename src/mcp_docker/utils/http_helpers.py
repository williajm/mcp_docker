"""HTTP request utilities for extracting client information from FastMCP contexts."""

import ipaddress
from typing import Any

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import MiddlewareContext

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def _is_ip_in_trusted_proxies(ip: str, trusted_proxies: list[str]) -> bool:
    """Check if an IP address is in the trusted proxies list.

    Supports both exact IP matching and CIDR notation (e.g., '10.0.0.0/24').

    Args:
        ip: IP address to check
        trusted_proxies: List of trusted proxy IPs or CIDR networks

    Returns:
        True if IP is trusted, False otherwise
    """
    if not trusted_proxies:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logger.debug(f"Invalid IP address format: {ip}")
        return False

    for proxy in trusted_proxies:
        try:
            # Try as network (CIDR notation)
            if "/" in proxy:
                network = ipaddress.ip_network(proxy, strict=False)
                if ip_obj in network:
                    return True
            # Try as single IP
            elif ip_obj == ipaddress.ip_address(proxy):
                return True
        except ValueError:
            logger.debug(f"Invalid trusted proxy format: {proxy}")
            continue

    return False


def _parse_x_forwarded_for(
    xff_header: str, trusted_proxies: list[str], direct_client_ip: str
) -> str:
    """Parse X-Forwarded-For header and return the real client IP.

    Finds the leftmost IP that is NOT a trusted proxy. This handles
    multiple proxy hops correctly.

    Args:
        xff_header: Value of X-Forwarded-For header
        trusted_proxies: List of trusted proxy IPs or CIDR networks
        direct_client_ip: The IP that directly connected to us

    Returns:
        The real client IP address

    Example:
        X-Forwarded-For: client, proxy1, proxy2
        If proxy1 and proxy2 are trusted, returns 'client'.
        If only proxy2 is trusted, returns 'proxy1' (can't trust it).
    """
    # Parse XFF header (comma-separated list)
    ips = [ip.strip() for ip in xff_header.split(",") if ip.strip()]

    if not ips:
        return direct_client_ip

    # Walk from right to left (closest proxy to us first)
    # Stop at the first non-trusted IP - that's the real client
    # We include direct_client_ip at the end of the chain
    full_chain = ips + [direct_client_ip]

    for i in range(len(full_chain) - 1, -1, -1):
        ip = full_chain[i]
        if not _is_ip_in_trusted_proxies(ip, trusted_proxies):
            return ip

    # All IPs are trusted (shouldn't happen in practice) - return leftmost
    return ips[0]


def _extract_from_fastmcp_request() -> tuple[str | None, str | None]:
    """Extract IP and XFF header using FastMCP's dependency injection.

    Returns:
        Tuple of (direct_ip, xff_header), both may be None
    """
    try:
        request = get_http_request()
    except (RuntimeError, LookupError):
        logger.debug(
            "get_http_request() unavailable (stdio transport or unit test), "
            "falling back to context extraction"
        )
        return None, None

    if not request:
        return None, None

    direct_ip = _get_host_from_client(getattr(request, "client", None))
    xff_header = None
    if hasattr(request, "headers"):
        xff_header = request.headers.get("x-forwarded-for")

    return direct_ip, xff_header


def _get_host_from_client(client: Any) -> str | None:
    """Extract host from a client object safely.

    Args:
        client: Client object that may have a host attribute

    Returns:
        Host string or None
    """
    if not client or not hasattr(client, "host"):
        return None
    host = client.host
    return str(host) if host is not None else None


def _extract_from_context(context: MiddlewareContext[Any]) -> tuple[str | None, str | None]:
    """Extract IP and XFF header from FastMCP context (for unit tests).

    Args:
        context: FastMCP middleware context

    Returns:
        Tuple of (direct_ip, xff_header), both may be None
    """
    if not context.fastmcp_context or not hasattr(context.fastmcp_context, "request_context"):
        return None, None

    req_ctx = context.fastmcp_context.request_context
    if not req_ctx or not hasattr(req_ctx, "request"):
        return None, None

    ctx_request = req_ctx.request
    if not ctx_request:
        return None, None

    direct_ip = _get_host_from_client(getattr(ctx_request, "client", None))
    xff_header = None
    if hasattr(ctx_request, "headers"):
        xff_header = ctx_request.headers.get("x-forwarded-for")

    return direct_ip, xff_header


def extract_client_ip(
    context: MiddlewareContext[Any],
    trusted_proxies: list[str] | None = None,
) -> str | None:
    """Extract client IP address from FastMCP middleware context.

    Tries multiple strategies in priority order:
    1. FastMCP's dependency injection (works during initialization)
    2. Context extraction (for unit tests with mocked contexts)

    When trusted_proxies is configured, parses X-Forwarded-For header
    to extract the real client IP behind reverse proxies.

    Args:
        context: FastMCP middleware context
        trusted_proxies: List of trusted proxy IPs/CIDRs. If the direct
            connection comes from a trusted proxy, X-Forwarded-For header
            will be parsed to find the real client IP.

    Returns:
        IP address string or None if not available

    Note:
        This function is shared by AuthMiddleware and AuditMiddleware to avoid
        code duplication. Both middlewares need to extract client IPs for
        authorization and audit logging respectively.
    """
    # Strategy 1: Try FastMCP's dependency injection
    direct_ip, xff_header = _extract_from_fastmcp_request()

    # Strategy 2: Fall back to context extraction (for unit tests)
    if direct_ip is None:
        direct_ip, xff_header = _extract_from_context(context)

    if direct_ip is None:
        return None

    # Parse X-Forwarded-For if connection is from a trusted proxy
    if trusted_proxies and xff_header and _is_ip_in_trusted_proxies(direct_ip, trusted_proxies):
        real_ip = _parse_x_forwarded_for(xff_header, trusted_proxies, direct_ip)
        logger.debug(
            f"Extracted real client IP {real_ip} from X-Forwarded-For "
            f"(direct connection from trusted proxy {direct_ip})"
        )
        return real_ip

    return direct_ip
