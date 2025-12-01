"""Rate limiting for MCP Docker operations using limits library.

SECURITY: Uses battle-tested limits library for RPM tracking.
Concurrent request limiting uses asyncio.Semaphore (stdlib, battle-tested).
"""

import asyncio
import threading
from typing import Any

from limits import parse
from limits.aio.storage import MemoryStorage
from limits.aio.strategies import MovingWindowRateLimiter

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)

# Timeout for acquiring concurrent request slots (in seconds)
# Fast fail for immediate feedback when concurrent limit is reached
CONCURRENT_SLOT_TIMEOUT_SECONDS = 0.1


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""


# Backward compatibility alias
RateLimitExceeded = RateLimitExceededError


class RateLimiter:
    """Handles global rate limiting for MCP Docker operations.

    Uses battle-tested libraries for security-critical rate limiting:
    - limits library: RPM tracking with MovingWindowRateLimiter
    - asyncio.Semaphore: Concurrent request limiting (stdlib)

    Implements two types of rate limiting:
    1. Requests per minute (RPM) - sliding window via limits library
    2. Concurrent requests - global semaphore (asyncio stdlib)

    Both limits are global (not per-client) for simplicity.
    """

    def __init__(
        self,
        enabled: bool = True,
        requests_per_minute: int = 60,
        max_concurrent: int = 3,
    ) -> None:
        """Initialize rate limiter.

        Args:
            enabled: Whether rate limiting is enabled
            requests_per_minute: Maximum requests per minute (global)
            max_concurrent: Maximum concurrent requests (global)
        """
        self.enabled = enabled
        self.rpm = requests_per_minute
        self.max_concurrent = max_concurrent

        # Initialize limits library for RPM tracking
        # SECURITY: Uses battle-tested limits library, not custom dict tracking
        self.rpm_limit = parse(f"{requests_per_minute} per 1 minute")
        self.storage = MemoryStorage()
        self.limiter = MovingWindowRateLimiter(self.storage)

        # Global concurrent requests tracking (using asyncio.Semaphore)
        # SECURITY: Uses stdlib semaphore, battle-tested for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._concurrent_count = 0
        # Lock protects _concurrent_count for accurate stats (counter is informational only)
        self._counter_lock = threading.Lock()

        if self.enabled:
            logger.info(
                f"Rate limiting enabled: {self.rpm} RPM (global), "
                f"{self.max_concurrent} concurrent (global)"
            )
        else:
            logger.warning("Rate limiting DISABLED")

    async def check_rate_limit(self) -> None:
        """Check if global RPM rate limit has been exceeded.

        Uses limits library's AsyncMovingWindowRateLimiter for thread-safe,
        memory-bounded rate limiting with automatic expiration.

        Raises:
            RateLimitExceeded: If rate limit has been exceeded
        """
        if not self.enabled:
            return

        # Test and increment using limits library (thread-safe, automatic expiration)
        # Use a constant identifier since we're doing global rate limiting
        if not await self.limiter.hit(self.rpm_limit, "global"):
            logger.warning("Global RPM limit exceeded")
            raise RateLimitExceeded(f"Rate limit exceeded: {self.rpm} requests per minute")

    async def acquire_concurrent_slot(self) -> None:
        """Acquire a global concurrent request slot.

        Uses asyncio.Semaphore (stdlib) for battle-tested concurrency control.

        Raises:
            RateLimitExceeded: If concurrent request limit is exceeded
        """
        if not self.enabled:
            return

        # Try to acquire with timeout
        try:
            await asyncio.wait_for(
                self._semaphore.acquire(), timeout=CONCURRENT_SLOT_TIMEOUT_SECONDS
            )
        except TimeoutError:
            # Note: In Python 3.11+, asyncio.TimeoutError is an alias for built-in TimeoutError
            logger.warning("Global concurrent request limit exceeded")
            raise RateLimitExceeded(
                f"Concurrent request limit exceeded: {self.max_concurrent}"
            ) from None

        # Increment counter (protected by lock for accurate stats)
        with self._counter_lock:
            self._concurrent_count += 1
            count = self._concurrent_count
        logger.debug(f"Global concurrent requests: {count}/{self.max_concurrent}")

    def release_concurrent_slot(self) -> None:
        """Release a global concurrent request slot."""
        if not self.enabled:
            return

        # Release semaphore slot
        self._semaphore.release()

        # Decrement counter (protected by lock for accurate stats)
        with self._counter_lock:
            if self._concurrent_count > 0:
                self._concurrent_count -= 1
                count = self._concurrent_count
                logger.debug(f"Global concurrent requests: {count}/{self.max_concurrent}")
            else:
                logger.debug("Global counter already at 0")

    def get_stats(self) -> dict[str, Any]:
        """Get global rate limit statistics.

        Returns:
            Dictionary with rate limit statistics
        """
        # Note: limits library doesn't expose request counts directly
        # We just return the limits configuration and current concurrent count
        with self._counter_lock:
            concurrent_count = self._concurrent_count
        return {
            "rpm_limit": self.rpm,
            "concurrent_requests": concurrent_count,
            "concurrent_limit": self.max_concurrent,
        }

    async def cleanup_old_data(self) -> None:
        """Clean up old data (no-op for limits library).

        The limits library handles automatic expiration and memory management.
        This method exists for backward compatibility.
        """
        # NO-OP: limits library handles cleanup automatically via TTL
        pass
