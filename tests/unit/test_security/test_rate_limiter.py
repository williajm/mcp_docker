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

    @pytest.mark.asyncio
    async def test_init_max_clients(self) -> None:
        """Test initializing rate limiter with max_clients."""
        limiter = RateLimiter(enabled=True, max_clients=50)

        assert limiter.max_clients == 50

    @pytest.mark.asyncio
    async def test_max_clients_limit_enforced(self) -> None:
        """Test that max clients limit prevents memory exhaustion."""
        limiter = RateLimiter(enabled=True, max_clients=3)

        # Create 3 clients
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client2")
        await limiter.acquire_concurrent_slot("client3")

        # 4th client should be rejected with RateLimitExceededError
        with pytest.raises(RateLimitExceededError, match="Maximum concurrent clients"):
            await limiter.acquire_concurrent_slot("client4")

        # Release slots
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client2")
        limiter.release_concurrent_slot("client3")

    @pytest.mark.asyncio
    async def test_existing_client_can_acquire_at_max_clients(self) -> None:
        """Test that existing clients can still acquire slots when at max clients."""
        limiter = RateLimiter(enabled=True, max_clients=2, max_concurrent_per_client=2)

        # Create 2 clients (at max)
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client2")

        # New client should be rejected
        with pytest.raises(RateLimitExceededError, match="Maximum concurrent clients"):
            await limiter.acquire_concurrent_slot("client3")

        # Existing client should be able to acquire another slot
        await limiter.acquire_concurrent_slot("client1")  # client1 now has 2 slots

        # Release all slots
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client2")

    @pytest.mark.asyncio
    async def test_client_cleanup_when_idle(self) -> None:
        """Test that idle clients don't count toward max_clients limit.

        NOTE: We no longer cleanup semaphores when count reaches 0.
        Instead, we only count ACTIVE clients (count > 0) toward max_clients limit.
        """
        limiter = RateLimiter(enabled=True, max_clients=10)

        # Acquire and release a slot
        await limiter.acquire_concurrent_slot("client1")
        assert "client1" in limiter._semaphores
        assert "client1" in limiter._concurrent_requests
        assert limiter._concurrent_requests["client1"] == 1

        limiter.release_concurrent_slot("client1")

        # Semaphore and counter still exist but count is 0 (idle)
        assert "client1" in limiter._semaphores
        assert "client1" in limiter._concurrent_requests
        assert limiter._concurrent_requests["client1"] == 0

    @pytest.mark.asyncio
    async def test_idle_client_eviction_allows_new_clients(self) -> None:
        """Test that idle clients are evicted to allow new clients (prevents permanent DoS).

        When at max_clients, idle clients (count==0) are evicted to make room for new clients.
        This allows normal multi-user operation while still preventing memory exhaustion.
        """
        limiter = RateLimiter(enabled=True, max_clients=2)

        # Fill to max tracked clients
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client2")

        # New client rejected when all slots active
        with pytest.raises(RateLimitExceededError, match="Maximum.*clients"):
            await limiter.acquire_concurrent_slot("client3")

        # Release all slots - clients become idle (count == 0)
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client2")

        # New client can connect now - idle client1 gets evicted
        await limiter.acquire_concurrent_slot("client3")
        assert "client1" not in limiter._semaphores  # client1 was evicted
        assert "client2" in limiter._semaphores  # client2 still idle
        assert "client3" in limiter._semaphores  # client3 is new

        # Another new client evicts client2
        limiter.release_concurrent_slot("client3")  # client3 becomes idle
        await limiter.acquire_concurrent_slot("client4")
        assert "client2" not in limiter._semaphores  # client2 was evicted
        assert "client3" in limiter._semaphores  # client3 still idle
        assert "client4" in limiter._semaphores  # client4 is new

        # Cleanup
        limiter.release_concurrent_slot("client4")

    @pytest.mark.asyncio
    async def test_active_clients_block_new_clients(self) -> None:
        """Test that new clients are rejected when all tracked clients are active.

        When max_clients is reached and all have active requests, new clients cannot connect.
        """
        limiter = RateLimiter(enabled=True, max_clients=2)

        # Fill to max with active clients
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client2")

        # Both clients are active (count > 0), so new client is rejected
        with pytest.raises(RateLimitExceededError, match="Maximum.*clients"):
            await limiter.acquire_concurrent_slot("client3")

        # Release one slot
        limiter.release_concurrent_slot("client1")
        limiter.release_concurrent_slot("client2")

        # Now client3 can connect (evicts an idle client)
        await limiter.acquire_concurrent_slot("client3")
        limiter.release_concurrent_slot("client3")

    @pytest.mark.asyncio
    async def test_partial_cleanup_with_multiple_slots(self) -> None:
        """Test that counter decrements properly with multiple concurrent requests.

        NOTE: We no longer cleanup semaphores. Counter stays at 0 after all releases.
        """
        limiter = RateLimiter(enabled=True, max_clients=10, max_concurrent_per_client=3)

        # Acquire 3 slots for same client
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client1")
        await limiter.acquire_concurrent_slot("client1")

        assert limiter._concurrent_requests["client1"] == 3

        # Release 1 slot - counter should decrement
        limiter.release_concurrent_slot("client1")
        assert "client1" in limiter._semaphores
        assert limiter._concurrent_requests["client1"] == 2

        # Release 2nd slot - counter should decrement
        limiter.release_concurrent_slot("client1")
        assert "client1" in limiter._semaphores
        assert limiter._concurrent_requests["client1"] == 1

        # Release final slot - counter reaches 0 but semaphore remains (idle)
        limiter.release_concurrent_slot("client1")
        assert "client1" in limiter._semaphores
        assert "client1" in limiter._concurrent_requests
        assert limiter._concurrent_requests["client1"] == 0
