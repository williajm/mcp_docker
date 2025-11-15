"""Rate limiting for MCP Docker operations using limits library.

SECURITY: Uses battle-tested limits library for RPM tracking.
Concurrent request limiting uses asyncio.Semaphore (stdlib, battle-tested).
"""

import asyncio
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
    """Raised when a client exceeds their rate limit."""


# Backward compatibility alias
RateLimitExceeded = RateLimitExceededError


class RateLimiter:
    """Handles rate limiting for MCP Docker operations.

    Uses battle-tested libraries for security-critical rate limiting:
    - limits library: RPM tracking with MovingWindowRateLimiter
    - asyncio.Semaphore: Concurrent request limiting (stdlib)

    Implements two types of rate limiting:
    1. Requests per minute (RPM) - sliding window via limits library
    2. Concurrent requests - semaphore per client (asyncio stdlib)
    """

    def __init__(
        self,
        enabled: bool = True,
        requests_per_minute: int = 60,
        max_concurrent_per_client: int = 3,
        max_clients: int = 10,
    ) -> None:
        """Initialize rate limiter.

        Args:
            enabled: Whether rate limiting is enabled
            requests_per_minute: Maximum requests per minute per client
            max_concurrent_per_client: Maximum concurrent requests per client
            max_clients: Maximum number of unique clients to track (prevents memory exhaustion)
        """
        self.enabled = enabled
        self.rpm = requests_per_minute
        self.max_concurrent = max_concurrent_per_client
        self.max_clients = max_clients

        # Initialize limits library for RPM tracking
        # SECURITY: Uses battle-tested limits library, not custom dict tracking
        self.rpm_limit = parse(f"{requests_per_minute} per 1 minute")
        self.storage = MemoryStorage()
        self.limiter = MovingWindowRateLimiter(self.storage)

        # Track concurrent requests per client (using asyncio.Semaphore)
        # SECURITY: Uses stdlib semaphore, battle-tested for concurrency control
        self._concurrent_requests: dict[str, int] = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}

        if self.enabled:
            logger.info(
                f"Rate limiting enabled: {self.rpm} RPM, "
                f"{self.max_concurrent} concurrent per client, "
                f"max {self.max_clients} clients"
            )
        else:
            logger.warning("Rate limiting DISABLED")

    async def check_rate_limit(self, client_id: str) -> None:
        """Check if a client is within their RPM rate limit.

        Uses limits library's AsyncMovingWindowRateLimiter for thread-safe,
        memory-bounded rate limiting with automatic expiration.

        Args:
            client_id: Unique identifier for the client

        Raises:
            RateLimitExceeded: If client has exceeded their rate limit
        """
        if not self.enabled:
            return

        # Test and increment using limits library (thread-safe, automatic expiration)
        if not await self.limiter.hit(self.rpm_limit, client_id):
            logger.warning(f"RPM limit exceeded for client: {client_id}")
            raise RateLimitExceeded(f"Rate limit exceeded: {self.rpm} requests per minute")

    async def acquire_concurrent_slot(self, client_id: str) -> None:
        """Acquire a concurrent request slot for a client.

        Uses asyncio.Semaphore (stdlib) for battle-tested concurrency control.

        Args:
            client_id: Unique identifier for the client

        Raises:
            RateLimitExceeded: If concurrent request limit is exceeded or max clients reached
        """
        if not self.enabled:
            return

        # Get or create semaphore for this client (stdlib asyncio.Semaphore)
        if client_id not in self._semaphores:
            # SECURITY: Prevent memory exhaustion by limiting total tracked clients
            if len(self._semaphores) >= self.max_clients:
                # Try to evict an idle client to make room
                idle_clients = [
                    cid for cid, count in self._concurrent_requests.items() if count == 0
                ]
                if idle_clients:
                    # Evict first idle client (simple LRU)
                    evict_id = idle_clients[0]
                    del self._semaphores[evict_id]
                    del self._concurrent_requests[evict_id]
                    logger.info(f"Evicted idle client {evict_id} to make room for {client_id}")
                else:
                    # All clients are active - reject new client
                    logger.warning(
                        f"Maximum active clients limit reached: {self.max_clients}. "
                        f"Rejecting new client: {client_id}"
                    )
                    raise RateLimitExceeded(
                        f"Maximum concurrent clients ({self.max_clients}) reached. "
                        "Try again later or contact administrator."
                    )
            self._semaphores[client_id] = asyncio.Semaphore(self.max_concurrent)
            self._concurrent_requests[client_id] = 0

        semaphore = self._semaphores[client_id]

        # Try to acquire with timeout
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=CONCURRENT_SLOT_TIMEOUT_SECONDS)
        except TimeoutError:
            # Note: In Python 3.11+, asyncio.TimeoutError is an alias for built-in TimeoutError
            logger.warning(f"Concurrent request limit exceeded for client: {client_id}")
            raise RateLimitExceeded(
                f"Concurrent request limit exceeded: {self.max_concurrent}"
            ) from None

        # Increment counter
        self._concurrent_requests[client_id] += 1
        logger.debug(
            f"Client {client_id} concurrent requests: "
            f"{self._concurrent_requests[client_id]}/{self.max_concurrent}"
        )

    def release_concurrent_slot(self, client_id: str) -> None:
        """Release a concurrent request slot for a client.

        Args:
            client_id: Unique identifier for the client
        """
        if not self.enabled:
            return

        # Release semaphore slot
        if client_id in self._semaphores:
            semaphore = self._semaphores[client_id]
            semaphore.release()

            # Decrement counter
            if client_id in self._concurrent_requests and self._concurrent_requests[client_id] > 0:
                self._concurrent_requests[client_id] -= 1
                logger.debug(
                    f"Client {client_id} concurrent requests: "
                    f"{self._concurrent_requests[client_id]}/{self.max_concurrent}"
                )
            else:
                logger.debug(f"Client {client_id} counter already at 0")

    def get_client_stats(self, client_id: str) -> dict[str, Any]:
        """Get rate limit statistics for a client.

        Args:
            client_id: Unique identifier for the client

        Returns:
            Dictionary with rate limit statistics
        """
        # Note: limits library doesn't expose request counts directly
        # We just return the limits configuration
        return {
            "client_id": client_id,
            "rpm_limit": self.rpm,
            "concurrent_requests": self._concurrent_requests.get(client_id, 0),
            "concurrent_limit": self.max_concurrent,
        }

    async def cleanup_old_data(self) -> None:
        """Clean up old data (no-op for limits library).

        The limits library handles automatic expiration and memory management.
        This method exists for backward compatibility.
        """
        # NO-OP: limits library handles cleanup automatically via TTL
        pass
