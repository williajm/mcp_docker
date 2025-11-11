"""Unit tests for rate limiter."""

import asyncio

import pytest

from mcp_docker.security.rate_limiter import RateLimiter, RateLimitExceededError


class TestRateLimiter:
    """Tests for RateLimiter."""

    @pytest.mark.asyncio
    async def test_init_enabled(self) -> None:
        """Test initializing rate limiter when enabled."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent_per_client=3)

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
        await limiter.check_rate_limit("test-client")
        await limiter.check_rate_limit("test-client")

    @pytest.mark.asyncio
    async def test_check_rate_limit_within_limit(self) -> None:
        """Test rate limit check when within limit."""
        limiter = RateLimiter(enabled=True, requests_per_minute=10)

        # Should not raise error for first 10 requests
        for _ in range(10):
            await limiter.check_rate_limit("test-client")

    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self) -> None:
        """Test rate limit check when limit is exceeded."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # First 5 requests should succeed
        for _ in range(5):
            await limiter.check_rate_limit("test-client")

        # 6th request should fail
        with pytest.raises(RateLimitExceededError, match="Rate limit exceeded"):
            await limiter.check_rate_limit("test-client")

    @pytest.mark.asyncio
    async def test_check_rate_limit_per_client(self) -> None:
        """Test that rate limits are enforced per client."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # Client 1 uses up their limit
        for _ in range(5):
            await limiter.check_rate_limit("client1")

        # Client 1 should be rate limited
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit("client1")

        # Client 2 should still have their full quota
        await limiter.check_rate_limit("client2")

    @pytest.mark.asyncio
    async def test_check_rate_limit_sliding_window(self) -> None:
        """Test that rate limit uses sliding window."""
        limiter = RateLimiter(enabled=True, requests_per_minute=5)

        # Use up the limit
        for _ in range(5):
            await limiter.check_rate_limit("test-client")

        # Should be rate limited
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit("test-client")

        # Wait for 1 second and check that oldest request is still in window
        await asyncio.sleep(1.1)

        # Should still be rate limited (all 5 requests still in 60s window)
        with pytest.raises(RateLimitExceededError):
            await limiter.check_rate_limit("test-client")

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_disabled(self) -> None:
        """Test acquiring concurrent slot when disabled."""
        limiter = RateLimiter(enabled=False)

        # Should not raise error
        await limiter.acquire_concurrent_slot("test-client")
        limiter.release_concurrent_slot("test-client")

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_within_limit(self) -> None:
        """Test acquiring concurrent slots within limit."""
        limiter = RateLimiter(enabled=True, max_concurrent_per_client=3)

        # Should be able to acquire 3 slots
        await limiter.acquire_concurrent_slot("test-client")
        await limiter.acquire_concurrent_slot("test-client")
        await limiter.acquire_concurrent_slot("test-client")

        # Release all slots
        limiter.release_concurrent_slot("test-client")
        limiter.release_concurrent_slot("test-client")
        limiter.release_concurrent_slot("test-client")

    @pytest.mark.asyncio
    async def test_acquire_concurrent_slot_exceeded(self) -> None:
        """Test acquiring concurrent slots when limit is exceeded."""
        limiter = RateLimiter(enabled=True, max_concurrent_per_client=2)

        # Acquire 2 slots
        await limiter.acquire_concurrent_slot("test-client")
        await limiter.acquire_concurrent_slot("test-client")

        # 3rd slot should fail (with timeout)
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot("test-client")

    @pytest.mark.asyncio
    async def test_concurrent_slot_per_client(self) -> None:
        """Test that concurrent slots are tracked per client."""
        limiter = RateLimiter(enabled=True, max_concurrent_per_client=2)

        # Client 1 uses both slots
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client1")

        # Client 2 should have their own quota
        await limiter.acquire_concurrent_slot("client2")
        await limiter.acquire_concurrent_slot("client2")

        # Release all
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client2")
        limiter.release_concurrent_slot("client2")

    @pytest.mark.asyncio
    async def test_release_concurrent_slot(self) -> None:
        """Test releasing a concurrent slot."""
        limiter = RateLimiter(enabled=True, max_concurrent_per_client=1)

        # Acquire slot
        await limiter.acquire_concurrent_slot("test-client")

        # Can't acquire another
        with pytest.raises((RateLimitExceededError, asyncio.TimeoutError)):
            await limiter.acquire_concurrent_slot("test-client")

        # Release slot
        limiter.release_concurrent_slot("test-client")

        # Now should be able to acquire again
        await limiter.acquire_concurrent_slot("test-client")
        limiter.release_concurrent_slot("test-client")

    @pytest.mark.asyncio
    async def test_get_client_stats(self) -> None:
        """Test getting client statistics."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent_per_client=3)

        # Make some requests
        await limiter.check_rate_limit("test-client")
        await limiter.check_rate_limit("test-client")
        await limiter.acquire_concurrent_slot("test-client")

        stats = limiter.get_client_stats("test-client")

        assert stats["client_id"] == "test-client"
        # NOTE: limits library doesn't expose request counts, just the limits
        assert stats["rpm_limit"] == 60
        assert stats["concurrent_requests"] == 1
        assert stats["concurrent_limit"] == 3

        # Release slot
        limiter.release_concurrent_slot("test-client")

    @pytest.mark.asyncio
    async def test_get_client_stats_no_activity(self) -> None:
        """Test getting stats for a client with no activity."""
        limiter = RateLimiter(enabled=True, requests_per_minute=60, max_concurrent_per_client=3)

        stats = limiter.get_client_stats("new-client")

        assert stats["client_id"] == "new-client"
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
        await limiter.check_rate_limit("test-client")

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
