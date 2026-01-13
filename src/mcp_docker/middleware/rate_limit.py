"""FastMCP rate limiting middleware.

This middleware enforces global rate limits for Docker operations to prevent abuse.
"""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_name
from mcp_docker.services.rate_limiter import PreAuthRateLimiter, RateLimiter, RateLimitExceeded
from mcp_docker.utils.http_helpers import extract_client_ip
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware:
    """FastMCP middleware for global rate limiting.

    This middleware integrates with FastMCP's middleware system to enforce
    global rate limits on tool executions. It uses the existing RateLimiter class.

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.middleware import RateLimitMiddleware
        from mcp_docker.services.rate_limiter import RateLimiter

        app = FastMCP("mcp-docker")
        rate_limiter = RateLimiter(
            enabled=True,
            requests_per_minute=60,
            max_concurrent=3
        )
        middleware = RateLimitMiddleware(rate_limiter)

        # Register middleware
        app.add_middleware(middleware)
        ```
    """

    def __init__(self, rate_limiter: RateLimiter):
        """Initialize rate limit middleware.

        Args:
            rate_limiter: RateLimiter instance for enforcing limits
        """
        self.rate_limiter = rate_limiter
        logger.info(
            f"Initialized RateLimitMiddleware (enabled={rate_limiter.enabled}, "
            f"rpm={rate_limiter.rpm})"
        )

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Check global rate limits before tool execution.

        Args:
            context: FastMCP middleware context
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler

        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        # Get operation name (tool name or MCP protocol operation)
        operation_name = get_operation_name(context)

        # Check rate limit and acquire concurrent slot
        if self.rate_limiter.enabled:
            try:
                # Check RPM limit
                await self.rate_limiter.check_rate_limit()
                logger.debug(f"RateLimitMiddleware: RPM check passed for {operation_name}")

                # Acquire concurrent slot
                await self.rate_limiter.acquire_concurrent_slot()
                logger.debug(f"RateLimitMiddleware: Concurrent slot acquired for {operation_name}")
            except RateLimitExceeded as e:
                logger.warning(f"RateLimitMiddleware: Blocked {operation_name} - {e}")
                raise

        # Execute the tool and ensure concurrent slot is released
        try:
            return await call_next(context)
        finally:
            # Always release the concurrent slot, even if the tool fails
            if self.rate_limiter.enabled:
                self.rate_limiter.release_concurrent_slot()
                logger.debug(f"RateLimitMiddleware: Concurrent slot released for {operation_name}")


def create_rate_limit_middleware(rate_limiter: RateLimiter) -> RateLimitMiddleware:
    """Factory function to create rate limit middleware.

    Args:
        rate_limiter: RateLimiter instance

    Returns:
        Configured RateLimitMiddleware instance

    Example:
        ```python
        from mcp_docker.config import Config
        from mcp_docker.services.rate_limiter import RateLimiter
        from mcp_docker.middleware.rate_limit import create_rate_limit_middleware

        config = Config()
        rate_limiter = RateLimiter(
            enabled=config.security.rate_limit_enabled,
            requests_per_minute=config.security.rate_limit_rpm
        )
        middleware = create_rate_limit_middleware(rate_limiter)
        ```
    """
    return RateLimitMiddleware(rate_limiter)


class PreAuthRateLimitMiddleware:
    """FastMCP middleware for pre-authentication rate limiting.

    SECURITY: This middleware runs BEFORE authentication to prevent brute-force
    attacks. It uses IP-based rate limiting with lower limits than the post-auth
    rate limiter.

    Middleware order should be:
    Debug → Audit → PreAuthRateLimit → Auth → Safety → PostAuthRateLimit

    This ensures:
    - All requests (including blocked ones) are logged (Audit)
    - Brute force attempts are blocked before auth (PreAuthRateLimit)
    - After authentication, legitimate users get higher limits (PostAuthRateLimit)
    """

    def __init__(
        self,
        pre_auth_limiter: PreAuthRateLimiter,
        trusted_proxies: list[str] | None = None,
    ):
        """Initialize pre-auth rate limit middleware.

        Args:
            pre_auth_limiter: PreAuthRateLimiter instance for IP-based limiting
            trusted_proxies: Trusted proxy IPs for X-Forwarded-For parsing
        """
        self.pre_auth_limiter = pre_auth_limiter
        self.trusted_proxies = trusted_proxies or []
        logger.info(
            f"Initialized PreAuthRateLimitMiddleware (enabled={pre_auth_limiter.enabled}, "
            f"rpm={pre_auth_limiter.rpm} per IP)"
        )

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Check pre-auth rate limits before passing to next middleware.

        Args:
            context: FastMCP middleware context
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler

        Raises:
            RateLimitExceeded: If pre-auth rate limit is exceeded
        """
        # Extract IP address for rate limiting
        ip_address = extract_client_ip(context, trusted_proxies=self.trusted_proxies)

        # Get operation name for logging
        operation_name = get_operation_name(context)

        # Check pre-auth rate limit (IP-based)
        if self.pre_auth_limiter.enabled:
            try:
                await self.pre_auth_limiter.check_rate_limit(ip_address)
                logger.debug(
                    f"PreAuthRateLimitMiddleware: IP {ip_address} passed rate limit "
                    f"for {operation_name}"
                )
            except RateLimitExceeded as e:
                logger.warning(
                    f"PreAuthRateLimitMiddleware: Blocked {operation_name} from "
                    f"IP {ip_address} - {e}"
                )
                raise

        return await call_next(context)
