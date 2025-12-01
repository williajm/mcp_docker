"""FastMCP rate limiting middleware.

This middleware enforces global rate limits for Docker operations to prevent abuse.
"""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_name
from mcp_docker.services.rate_limiter import RateLimiter, RateLimitExceeded
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
