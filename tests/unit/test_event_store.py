"""Unit tests for InMemoryEventStore."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mcp_docker.event_store import InMemoryEventStore


class TestInMemoryEventStore:
    """Test InMemoryEventStore implementation."""

    def test_init_default_values(self) -> None:
        """Test EventStore initialization with default values."""
        store = InMemoryEventStore()
        stats = store.get_stats()

        assert stats["total_events"] == 0
        assert stats["max_events"] == 1000
        assert stats["ttl_seconds"] == 300

    def test_init_custom_values(self) -> None:
        """Test EventStore initialization with custom values."""
        store = InMemoryEventStore(max_events=500, ttl_seconds=180)
        stats = store.get_stats()

        assert stats["max_events"] == 500
        assert stats["ttl_seconds"] == 180

    @pytest.mark.asyncio
    async def test_store_event_returns_event_id(self) -> None:
        """Test that store_event returns a valid event ID."""
        store = InMemoryEventStore()

        # Create a mock message
        message = {"jsonrpc": "2.0", "method": "test", "params": {}}

        event_id = await store.store_event("stream-1", message)  # type: ignore[arg-type]

        # Verify event_id is returned
        assert event_id is not None
        assert isinstance(event_id, str)
        assert len(event_id) > 0

        # Verify event was stored
        stats = store.get_stats()
        assert stats["total_events"] == 1

    @pytest.mark.asyncio
    async def test_store_multiple_events(self) -> None:
        """Test storing multiple events."""
        store = InMemoryEventStore()

        # Store multiple events
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        message2 = {"jsonrpc": "2.0", "method": "test2", "params": {}}
        message3 = {"jsonrpc": "2.0", "method": "test3", "params": {}}

        await store.store_event("stream-1", message1)  # type: ignore[arg-type]
        await store.store_event("stream-1", message2)  # type: ignore[arg-type]
        await store.store_event("stream-1", message3)  # type: ignore[arg-type]

        stats = store.get_stats()
        assert stats["total_events"] == 3

    def test_max_events_limit(self) -> None:
        """Test that max_events limit is enforced (FIFO)."""
        store = InMemoryEventStore(max_events=3, ttl_seconds=300)
        stats = store.get_stats()

        # Verify max_events is set correctly
        assert stats["max_events"] == 3

    def test_get_stats(self) -> None:
        """Test get_stats returns correct statistics."""
        store = InMemoryEventStore(max_events=500, ttl_seconds=180)

        # Initially empty
        stats = store.get_stats()
        assert stats["total_events"] == 0
        assert stats["max_events"] == 500
        assert stats["ttl_seconds"] == 180
        assert stats["oldest_event_age_seconds"] == 0

    @pytest.mark.asyncio
    async def test_replay_events_after(self) -> None:
        """Test replay_events_after with a mock callback."""
        store = InMemoryEventStore()

        # Store three events in the same stream
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        message2 = {"jsonrpc": "2.0", "method": "test2", "params": {}}
        message3 = {"jsonrpc": "2.0", "method": "test3", "params": {}}

        event_id1 = await store.store_event("stream-1", message1)  # type: ignore[arg-type]
        event_id2 = await store.store_event("stream-1", message2)  # type: ignore[arg-type]
        event_id3 = await store.store_event("stream-1", message3)  # type: ignore[arg-type]

        # Create a mock callback to track replayed events
        replayed_events: list[Any] = []

        async def mock_callback(event_message: Any) -> None:
            replayed_events.append(event_message)

        # Replay events after event_id1 (should get event2 and event3)
        stream_id = await store.replay_events_after(event_id1, mock_callback)

        # Verify correct stream returned
        assert stream_id == "stream-1"

        # Verify two events were replayed
        assert len(replayed_events) == 2

        # Verify the replayed events have correct IDs and messages
        assert replayed_events[0].event_id == event_id2
        assert replayed_events[0].message == message2
        assert replayed_events[1].event_id == event_id3
        assert replayed_events[1].message == message3

    @pytest.mark.asyncio
    async def test_replay_events_stream_isolation(self) -> None:
        """Test that replay only returns events from the target stream."""
        store = InMemoryEventStore()

        # Store events in multiple streams
        msg_a1 = {"jsonrpc": "2.0", "method": "a1", "params": {}}
        msg_a2 = {"jsonrpc": "2.0", "method": "a2", "params": {}}
        msg_b1 = {"jsonrpc": "2.0", "method": "b1", "params": {}}
        msg_a3 = {"jsonrpc": "2.0", "method": "a3", "params": {}}
        msg_b2 = {"jsonrpc": "2.0", "method": "b2", "params": {}}

        event_a1 = await store.store_event("stream-A", msg_a1)  # type: ignore[arg-type]
        event_a2 = await store.store_event("stream-A", msg_a2)  # type: ignore[arg-type]
        await store.store_event("stream-B", msg_b1)  # type: ignore[arg-type]
        event_a3 = await store.store_event("stream-A", msg_a3)  # type: ignore[arg-type]
        await store.store_event("stream-B", msg_b2)  # type: ignore[arg-type]

        # Replay events from stream-A after event_a1
        replayed_events: list[Any] = []

        async def mock_callback(event_message: Any) -> None:
            replayed_events.append(event_message)

        stream_id = await store.replay_events_after(event_a1, mock_callback)

        # Verify stream-A was returned
        assert stream_id == "stream-A"

        # Should only get a2 and a3, NOT b1 or b2 (stream isolation)
        assert len(replayed_events) == 2
        assert replayed_events[0].event_id == event_a2
        assert replayed_events[0].message["method"] == "a2"
        assert replayed_events[1].event_id == event_a3
        assert replayed_events[1].message["method"] == "a3"

    @pytest.mark.asyncio
    async def test_replay_events_not_found(self) -> None:
        """Test replay_events_after returns None when event not found."""
        store = InMemoryEventStore()

        # Store some events
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        await store.store_event("stream-1", message1)  # type: ignore[arg-type]

        # Try to replay from a non-existent event ID
        async def mock_callback(event_message: Any) -> None:
            pass

        stream_id = await store.replay_events_after("non-existent-id", mock_callback)

        # Should return None
        assert stream_id is None

    @pytest.mark.asyncio
    async def test_max_events_fifo_eviction(self) -> None:
        """Test that oldest events are evicted when max_events is exceeded."""
        store = InMemoryEventStore(max_events=3, ttl_seconds=300)

        # Store 4 events (exceeds max of 3)
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        message2 = {"jsonrpc": "2.0", "method": "test2", "params": {}}
        message3 = {"jsonrpc": "2.0", "method": "test3", "params": {}}
        message4 = {"jsonrpc": "2.0", "method": "test4", "params": {}}

        event_id1 = await store.store_event("stream-1", message1)  # type: ignore[arg-type]
        event_id2 = await store.store_event("stream-1", message2)  # type: ignore[arg-type]
        event_id3 = await store.store_event("stream-1", message3)  # type: ignore[arg-type]
        event_id4 = await store.store_event("stream-1", message4)  # type: ignore[arg-type]

        # Should only have 3 events (oldest evicted)
        stats = store.get_stats()
        assert stats["total_events"] == 3

        # Try to replay from event_id1 (should be evicted, return None)
        async def mock_callback(event_message: Any) -> None:
            pass

        stream_id = await store.replay_events_after(event_id1, mock_callback)
        assert stream_id is None

        # Replay from event_id2 should work (events 3 and 4)
        replayed_events: list[Any] = []

        async def tracking_callback(event_message: Any) -> None:
            replayed_events.append(event_message)

        stream_id = await store.replay_events_after(event_id2, tracking_callback)
        assert stream_id == "stream-1"
        assert len(replayed_events) == 2
        assert replayed_events[0].event_id == event_id3
        assert replayed_events[1].event_id == event_id4

    @pytest.mark.asyncio
    async def test_ttl_cleanup(self) -> None:
        """Test that events older than TTL are automatically cleaned up."""
        # Use a very short TTL for testing (60 seconds minimum per config)
        store = InMemoryEventStore(max_events=1000, ttl_seconds=60)

        # Store an event
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        event_id1 = await store.store_event("stream-1", message1)  # type: ignore[arg-type]

        # Verify event was stored
        stats = store.get_stats()
        assert stats["total_events"] == 1

        # Manually manipulate the timestamp to simulate an old event
        # Access the internal deque and update the timestamp
        old_timestamp = datetime.now(UTC) - timedelta(seconds=120)
        store._events[0] = (
            store._events[0][0],  # stream_id
            store._events[0][1],  # event_id
            store._events[0][2],  # message
            old_timestamp,  # old timestamp
        )

        # Store a new event to trigger cleanup
        message2 = {"jsonrpc": "2.0", "method": "test2", "params": {}}
        await store.store_event("stream-1", message2)  # type: ignore[arg-type]

        # Old event should have been cleaned up
        stats = store.get_stats()
        assert stats["total_events"] == 1

        # Try to replay from the old event (should return None)
        async def mock_callback(event_message: Any) -> None:
            pass

        stream_id = await store.replay_events_after(event_id1, mock_callback)
        assert stream_id is None

    @pytest.mark.asyncio
    async def test_replay_concurrent_mutation_safety(self) -> None:
        """Test that replay doesn't fail if events are added during iteration."""
        store = InMemoryEventStore()

        # Store initial events
        message1 = {"jsonrpc": "2.0", "method": "test1", "params": {}}
        message2 = {"jsonrpc": "2.0", "method": "test2", "params": {}}

        event_id1 = await store.store_event("stream-1", message1)  # type: ignore[arg-type]
        await store.store_event("stream-1", message2)  # type: ignore[arg-type]

        # Create a callback that stores a new event during replay
        async def mutating_callback(event_message: Any) -> None:
            # Add a new event to the store while we're iterating
            new_message = {"jsonrpc": "2.0", "method": "concurrent", "params": {}}
            await store.store_event("stream-1", new_message)  # type: ignore[arg-type]

        # This should not raise RuntimeError due to snapshot mechanism
        try:
            stream_id = await store.replay_events_after(event_id1, mutating_callback)
            assert stream_id == "stream-1"
        except RuntimeError as e:
            pytest.fail(f"Replay raised RuntimeError: {e}")
