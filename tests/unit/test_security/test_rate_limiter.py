"""Unit tests for rate limiter."""

import asyncio

import pytest

from mcp_docker.security.rate_limiter import RateLimiter, RateLimitExceededError


class TestRateLimiter:
    """Tests for RateLimiter."""

    @pytest.mark.asyncio
    async def test_init_enabled(self) -> None:
        """Test initializing rate limiter when enabled."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent=3)

        assert limiter.enabled is True
        assert limiter.rpm == 60
        assert limiter.max_concurrent == 3

    @pytest.mark.asyncio
    async def test_init_disabled(self) -> None:
        """Test initializing rate limiter when disabled."""
        limiter = RateLimiter(enabled=False)

        assert limiter.enabled is False

    @pytest.mark.asyncio
    async def test_check_rate_limit_disabled(self) -> None:
        """Test rate limit check when disabled."""
        limiter = RateLimiter(enabled=False)

        # Should not raise error
        await limiter.check_rate_limit()
        await limiter.check_rate_limit()

    @pytest.mark.asyncio
    async def test_check_rate_limit_within_limit(self) -> None:
        """Test rate limit check when within limit."""
        limiter = RateLimiter(enabled=True, requests_per_minute=10)

        # Should not raise error for first 10 requests
        for _ in range(10):
            await limiter.check_rate_limit()

    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self) -> None:
        """Test rate limit check when limit is exceeded."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # First 5 requests should succeed
        for _ in range(5):
            await limiter.check_rate_limit()

        # 6th request should fail
        with pytest.raises(RateLimitExceededError, match="Rate limit exceeded"):
            await limiter.check_rate_limit()

    @pytest.mark.asyncio
    async def test_check_rate_limit_global(self) -> None:
        """Test that rate limits are global (not per client)."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # Use up the global limit
        for _ in range(5):
            await limiter.check_rate_limit()

        # Should be rate limited globally
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit()

    @pytest.mark.asyncio
    async def test_check_rate_limit_sliding_window(self) -> None:
        """Test that rate limit uses sliding window."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # Use up the limit
        for _ in range(5):
            await limiter.check_rate_limit()

        # Should be rate limited
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit()

        # Wait for 1 second and check that oldest request is still in window
        await asyncio.sleep(1.1)

        # Should still be rate limited (all 5 requests still in 60s window)
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit()

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_disabled(self) -> None:
        """Test acquiring concurrent slot when disabled."""
        limiter = RateLimiter(enabled=False)

        # Should not raise error
        await limiter.acquire_concurrent_slot()
        limiter.release_concurrent_slot()

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_within_limit(self) -> None:
        """Test acquiring concurrent slots within limit."""
        limiter = RateLimiter(enabled=True, max_concurrent=3)

        # Should be able to acquire 3 slots
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()

        # Release all slots
        limiter.release_concurrent_slot()
        limiter.release_concurrent_slot()
        limiter.release_concurrent_slot()

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_exceeded(self) -> None:
        """Test acquiring concurrent slots when limit is exceeded."""
        limiter = RateLimiter(enabled=True, max_concurrent=2)

        # Acquire 2 slots
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()

        # 3rd slot should fail (with timeout)
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot()

    @pytest.mark.asyncio
    async def test_concurrent_slot_global(self) -> None:
        """Test that concurrent slots are global (not per client)."""
        limiter = RateLimiter(enabled=True, max_concurrent=2)

        # Use both global slots
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()

        # No more slots available globally
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot()

        # Release all
        limiter.release_concurrent_slot()
        limiter.release_concurrent_slot()

    @pytest.mark.asyncio
    async def test_release_concurrent_slot(self) -> None:
        """Test releasing a concurrent slot."""
        limiter = RateLimiter(enabled=True, max_concurrent=1)

        # Acquire slot
        await limiter.acquire_concurrent_slot()

        # Can't acquire another
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot()

        # Release slot
        limiter.release_concurrent_slot()

        # Now should be able to acquire again
        await limiter.acquire_concurrent_slot()
        limiter.release_concurrent_slot()

    @pytest.mark.asyncio
    async def test_get_stats(self) -> None:
        """Test getting global statistics."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent=3)

        # Make some requests
        await limiter.check_rate_limit()
        await limiter.check_rate_limit()
        await limiter.acquire_concurrent_slot()

        stats = limiter.get_stats()

        # NOTE: limits library doesn't expose request counts, just the limits
        assert stats["rpm_limit"] == 60
        assert stats["concurrent_requests"] == 1
        assert stats["concurrent_limit"] == 3

        # Release slot
        limiter.release_concurrent_slot()

    @pytest.mark.asyncio
    async def test_get_stats_no_activity(self) -> None:
        """Test getting stats with no activity."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent=3)

        stats = limiter.get_stats()

        # NOTE: limits library doesn't expose request counts, just the limits
        assert stats["rpm_limit"] == 60
        assert stats["concurrent_requests"] == 0
        assert stats["concurrent_limit"] == 3

    @pytest.mark.asyncio
    async def test_cleanup_old_data(self) -> None:
        """Test cleaning up old request data.

        NOTE: After refactoring to use limits library, cleanup is a no-op.
        The limits library handles automatic expiration via TTL.
        This test verifies the method exists for backward compatibility.
        """
        limiter = RateLimiter(enabled=True, requests_per_minute=60)

        # Make requests
        await limiter.check_rate_limit()

        # Cleanup is a no-op but should not raise errors
        await limiter.cleanup_old_data()

        # Verify the method can be called without errors
        # (actual cleanup is handled automatically by limits library)

    @pytest.mark.asyncio
    async def test_cleanup_old_data_disabled(self) -> None:
        """Test cleanup when rate limiting is disabled."""
        limiter = RateLimiter(enabled=False)

        # Should not raise error
        await limiter.cleanup_old_data()

    @pytest.mark.asyncio
    async def test_concurrent_count_tracking(self) -> None:
        """Test that concurrent count is tracked properly."""
        limiter = RateLimiter(enabled=True, max_concurrent=3)

        # Acquire 3 slots
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()

        assert limiter._concurrent_count == 3

        # Release 1 slot - counter should decrement
        limiter.release_concurrent_slot()
        assert limiter._concurrent_count == 2

        # Release 2nd slot - counter should decrement
        limiter.release_concurrent_slot()
        assert limiter._concurrent_count == 1

        # Release final slot - counter reaches 0
        limiter.release_concurrent_slot()
        assert limiter._concurrent_count == 0

    @pytest.mark.asyncio
    async def test_multiple_concurrent_requests(self) -> None:
        """Test multiple concurrent requests with global limit."""
        limiter = RateLimiter(enabled=True, max_concurrent=3)

        # Acquire 3 slots
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()
        await limiter.acquire_concurrent_slot()

        assert limiter._concurrent_count == 3

        # Can't acquire more
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot()

        # Release all slots
        limiter.release_concurrent_slot()
        limiter.release_concurrent_slot()
        limiter.release_concurrent_slot()

        assert limiter._concurrent_count == 0

        # Now can acquire again
        await limiter.acquire_concurrent_slot()
        limiter.release_concurrent_slot()
