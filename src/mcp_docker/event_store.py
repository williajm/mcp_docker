"""In-memory EventStore implementation for HTTP Stream Transport resumability.

This module provides a concrete implementation of the MCP SDK's abstract EventStore
class, enabling message history storage and reconnection support.
"""

import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from mcp.server.streamable_http import (
    EventCallback,
    EventId,
    EventMessage,
    EventStore,
    StreamId,
)
from mcp.types import JSONRPCMessage

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class InMemoryEventStore(EventStore):
    """In-memory implementation of EventStore for message history and resumability.

    This class stores events in memory with TTL (Time To Live) and size limits.
    Events older than the TTL or beyond the max_events limit are automatically
    cleaned up.

    Features:
    - Automatic TTL-based cleanup of old events
    - Size-limited storage with FIFO eviction
    - Efficient event lookup for resumability
    - Supports MCP SDK EventStore interface

    Args:
        max_events: Maximum number of events to store (default: 1000)
        ttl_seconds: Time-to-live for events in seconds (default: 300 = 5 minutes)
    """

    def __init__(self, max_events: int = 1000, ttl_seconds: int = 300) -> None:
        """Initialize the in-memory event store.

        Args:
            max_events: Maximum number of events to store before oldest are evicted
            ttl_seconds: Seconds before events expire and are cleaned up
        """
        # Use deque for efficient FIFO operations
        # Each entry is a tuple: (stream_id, event_id, message, timestamp)
        self._events: deque[tuple[StreamId, EventId, JSONRPCMessage, datetime]] = deque(
            maxlen=max_events
        )
        self._ttl = timedelta(seconds=ttl_seconds)
        self._max_events = max_events

        logger.info(f"EventStore initialized: max_events={max_events}, ttl={ttl_seconds}s")

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage) -> EventId:
        """Store an event with timestamp for TTL cleanup.

        Args:
            stream_id: ID of the stream the event belongs to
            message: The JSON-RPC message to store

        Returns:
            The generated event ID for the stored event
        """
        # Generate unique event ID
        event_id = str(uuid.uuid4())
        now = datetime.now(UTC)

        self._events.append((stream_id, event_id, message, now))

        # Cleanup old events after storing
        self._cleanup_old_events()

        logger.debug(
            f"Event stored: stream_id={stream_id}, event_id={event_id}, "
            f"total_events={len(self._events)}"
        )

        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        """Replay events that occurred after the specified event ID.

        Args:
            last_event_id: The ID of the last event the client received
            send_callback: A callback function to send events to the client

        Returns:
            The stream ID of the replayed events, or None if no events found
        """
        # Cleanup old events before replaying
        self._cleanup_old_events()

        # Take a snapshot to avoid RuntimeError if deque is mutated during iteration
        events_snapshot = list(self._events)

        # Find the stream_id that owns last_event_id
        target_stream_id: StreamId | None = None
        found_index = -1

        for idx, (sid, eid, _, _) in enumerate(events_snapshot):
            if eid == last_event_id:
                target_stream_id = sid
                found_index = idx
                break

        # If last_event_id not found, return None
        if target_stream_id is None:
            logger.debug(f"Event not found: last_event_id={last_event_id}")
            return None

        # Replay only events that belong to the same stream and come after last_event_id
        replayed_count = 0
        for sid, eid, message, _ in events_snapshot[found_index + 1 :]:
            # Only replay events from the same stream (critical for isolation)
            if sid == target_stream_id:
                event_message = EventMessage(message=message, event_id=eid)
                await send_callback(event_message)
                replayed_count += 1

        logger.debug(
            f"Events replayed: last_event_id={last_event_id}, "
            f"stream_id={target_stream_id}, replayed_count={replayed_count}"
        )

        return target_stream_id

    def _cleanup_old_events(self) -> None:
        """Remove events older than TTL.

        This is called automatically during store_event and replay_events_after
        to ensure stale events don't accumulate.
        """
        now = datetime.now(UTC)
        initial_count = len(self._events)

        # Remove events from the left (oldest) that are beyond TTL
        while self._events and (now - self._events[0][3]) > self._ttl:
            removed_event = self._events.popleft()
            logger.debug(f"Event expired: event_id={removed_event[1]}")

        removed_count = initial_count - len(self._events)
        if removed_count > 0:
            logger.debug(
                f"Cleaned up {removed_count} expired events, remaining={len(self._events)}"
            )

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the event store.

        Returns:
            Dictionary with event store statistics
        """
        return {
            "total_events": len(self._events),
            "max_events": self._max_events,
            "ttl_seconds": self._ttl.total_seconds(),
            "oldest_event_age_seconds": (
                (datetime.now(UTC) - self._events[0][3]).total_seconds() if self._events else 0
            ),
        }
