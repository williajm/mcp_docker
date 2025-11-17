"""FastMCP rate limiting middleware.

This middleware enforces rate limits for Docker operations to prevent abuse.
"""

from collections.abc import Awaitable, Callable
from typing import Any

from mcp_docker.security.rate_limiter import RateLimiter, RateLimitExceeded
from mcp_docker.utils.context_helpers import extract_client_id
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware:
    """FastMCP middleware for rate limiting.

    This middleware integrates with FastMCP's middleware system to enforce
    rate limits on tool executions. It uses the existing RateLimiter class.

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.middleware import RateLimitMiddleware
        from mcp_docker.security.rate_limiter import RateLimiter

        app = FastMCP("mcp-docker")
        rate_limiter = RateLimiter(
            enabled=True,
            requests_per_minute=60,
            max_concurrent_per_client=3
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
        call_next: Callable[[], Awaitable[Any]],
        context: dict[str, Any],
    ) -> Any:
        """Check rate limits before tool execution.

        Args:
            call_next: Next middleware/handler in the chain
            context: Request context with client information

        Returns:
            Result from next handler

        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        # Extract client identifier from context
        client_id = extract_client_id(context)
        tool_name = context.get("tool_name", "unknown_tool")

        # Check rate limit and acquire concurrent slot
        if self.rate_limiter.enabled:
            try:
                # Check RPM limit
                await self.rate_limiter.check_rate_limit(client_id)
                logger.debug(f"RateLimitMiddleware: RPM check passed for {tool_name} ({client_id})")

                # Acquire concurrent slot
                await self.rate_limiter.acquire_concurrent_slot(client_id)
                logger.debug(
                    f"RateLimitMiddleware: Concurrent slot acquired for {tool_name} ({client_id})"
                )
            except RateLimitExceeded as e:
                logger.warning(f"RateLimitMiddleware: Blocked {tool_name} for {client_id} - {e}")
                raise

        # Execute the tool and ensure concurrent slot is released
        try:
            return await call_next()
        finally:
            # Always release the concurrent slot, even if the tool fails
            if self.rate_limiter.enabled:
                self.rate_limiter.release_concurrent_slot(client_id)
                logger.debug(
                    f"RateLimitMiddleware: Concurrent slot released for {tool_name} ({client_id})"
                )


def create_rate_limit_middleware(rate_limiter: RateLimiter) -> RateLimitMiddleware:
    """Factory function to create rate limit middleware.

    Args:
        rate_limiter: RateLimiter instance

    Returns:
        Configured RateLimitMiddleware instance

    Example:
        ```python
        from mcp_docker.config import Config
        from mcp_docker.security.rate_limiter import RateLimiter
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
