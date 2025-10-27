"""Rate limiting for MCP Docker operations."""

import asyncio
import time
from collections import defaultdict
from typing import Any

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitExceededError(Exception):
    """Raised when a client exceeds their rate limit."""

    pass


# Backward compatibility alias
RateLimitExceeded = RateLimitExceededError


class RateLimiter:
    """Handles rate limiting for MCP Docker operations.

    Implements two types of rate limiting:
    1. Requests per minute (RPM) - sliding window
    2. Concurrent requests - semaphore per client
    """

    def __init__(
        self,
        enabled: bool = True,
        requests_per_minute: int = 60,
        max_concurrent_per_client: int = 3,
    ) -> None:
        """Initialize rate limiter.

        Args:
            enabled: Whether rate limiting is enabled
            requests_per_minute: Maximum requests per minute per client
            max_concurrent_per_client: Maximum concurrent requests per client
        """
        self.enabled = enabled
        self.rpm = requests_per_minute
        self.max_concurrent = max_concurrent_per_client

        # Track request timestamps per client (for RPM limiting)
        self._request_times: dict[str, list[float]] = defaultdict(list)

        # Track concurrent requests per client (for concurrency limiting)
        self._concurrent_requests: dict[str, int] = defaultdict(int)
        self._semaphores: dict[str, asyncio.Semaphore] = {}

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        if self.enabled:
            logger.info(
                f"Rate limiting enabled: {self.rpm} RPM, "
                f"{self.max_concurrent} concurrent per client"
            )
        else:
            logger.warning("Rate limiting DISABLED")

    async def check_rate_limit(self, client_id: str) -> None:
        """Check if a client is within their rate limits.

        Args:
            client_id: Unique identifier for the client

        Raises:
            RateLimitExceeded: If client has exceeded their rate limit
        """
        if not self.enabled:
            return

        async with self._lock:
            # Check RPM limit
            await self._check_rpm_limit(client_id)

    async def _check_rpm_limit(self, client_id: str) -> None:
        """Check requests per minute limit using sliding window.

        Args:
            client_id: Unique identifier for the client

        Raises:
            RateLimitExceeded: If RPM limit is exceeded
        """
        current_time = time.time()
        window_start = current_time - 60.0  # 1 minute window

        # Remove timestamps older than 1 minute
        self._request_times[client_id] = [
            ts for ts in self._request_times[client_id] if ts > window_start
        ]

        # Check if limit exceeded
        if len(self._request_times[client_id]) >= self.rpm:
            logger.warning(f"RPM limit exceeded for client: {client_id}")
            raise RateLimitExceeded(
                f"Rate limit exceeded: {self.rpm} requests per minute"
            )

        # Add current request timestamp
        self._request_times[client_id].append(current_time)

    async def acquire_concurrent_slot(self, client_id: str) -> None:
        """Acquire a concurrent request slot for a client.

        Args:
            client_id: Unique identifier for the client

        Raises:
            RateLimitExceeded: If concurrent request limit is exceeded
        """
        if not self.enabled:
            return

        # Get or create semaphore for this client
        if client_id not in self._semaphores:
            self._semaphores[client_id] = asyncio.Semaphore(self.max_concurrent)

        semaphore = self._semaphores[client_id]

        # Try to acquire with timeout
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=0.1)
        except TimeoutError:
            logger.warning(f"Concurrent request limit exceeded for client: {client_id}")
            raise RateLimitExceeded(
                f"Concurrent request limit exceeded: {self.max_concurrent}"
            ) from None

        self._concurrent_requests[client_id] += 1
        logger.debug(
            f"Client {client_id} concurrent requests: "
            f"{self._concurrent_requests[client_id]}/{self.max_concurrent}"
        )

    async def release_concurrent_slot(self, client_id: str) -> None:
        """Release a concurrent request slot for a client.

        Args:
            client_id: Unique identifier for the client
        """
        if not self.enabled:
            return

        if client_id in self._semaphores:
            semaphore = self._semaphores[client_id]
            semaphore.release()
            self._concurrent_requests[client_id] -= 1

            logger.debug(
                f"Client {client_id} concurrent requests: "
                f"{self._concurrent_requests[client_id]}/{self.max_concurrent}"
            )

    def get_client_stats(self, client_id: str) -> dict[str, Any]:
        """Get rate limit statistics for a client.

        Args:
            client_id: Unique identifier for the client

        Returns:
            Dictionary with rate limit statistics
        """
        current_time = time.time()
        window_start = current_time - 60.0

        # Count requests in current window
        request_count = sum(
            1 for ts in self._request_times.get(client_id, []) if ts > window_start
        )

        return {
            "client_id": client_id,
            "requests_last_minute": request_count,
            "rpm_limit": self.rpm,
            "concurrent_requests": self._concurrent_requests.get(client_id, 0),
            "concurrent_limit": self.max_concurrent,
        }

    async def cleanup_old_data(self) -> None:
        """Clean up old request timestamps to prevent memory growth.

        Should be called periodically (e.g., every few minutes).
        """
        if not self.enabled:
            return

        async with self._lock:
            current_time = time.time()
            window_start = current_time - 120.0  # Keep 2 minutes of history

            # Clean up old timestamps
            for client_id in list(self._request_times.keys()):
                self._request_times[client_id] = [
                    ts for ts in self._request_times[client_id] if ts > window_start
                ]

                # Remove empty entries
                if not self._request_times[client_id]:
                    del self._request_times[client_id]

            logger.debug(f"Cleaned up rate limiter data for {len(self._request_times)} clients")
