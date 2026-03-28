"""Shared streaming helpers for Docker image operations (pull, build, push)."""

import asyncio
import re
import threading
import time
from queue import Empty, Queue
from typing import Any

from fastmcp import Context

from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)

# Constants
MAX_PROGRESS_MESSAGE_LENGTH = 200
PROGRESS_THROTTLE_SECONDS = 0.1  # Max 10 updates per second
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def check_chunk_for_error(chunk: dict[str, Any], operation: str) -> None:
    """Check if a streaming chunk contains an error and raise if so."""
    if "error" in chunk and chunk["error"] is not None:
        error_msg = str(chunk["error"])
        logger.error(f"Failed to {operation} image: {error_msg}")
        raise DockerOperationError(f"Failed to {operation} image: {error_msg}")


def sanitize_progress_message(message: str) -> str:
    """Sanitize a progress message for safe display."""
    message = ANSI_ESCAPE_PATTERN.sub("", message)
    message = "".join(c for c in message if c.isprintable() or c in "\n\t")
    message = message.strip()
    if len(message) > MAX_PROGRESS_MESSAGE_LENGTH:
        message = message[: MAX_PROGRESS_MESSAGE_LENGTH - 3] + "..."
    return message


class ProgressThrottler:
    """Throttle progress updates to avoid overwhelming clients."""

    def __init__(self, min_interval: float = PROGRESS_THROTTLE_SECONDS) -> None:
        self.min_interval = min_interval
        self.last_update_time: float = 0.0
        self.last_message: str = ""

    def should_update(self, message: str) -> bool:
        """Check if we should send this progress update."""
        now = time.monotonic()
        time_elapsed = now - self.last_update_time >= self.min_interval
        message_changed = message != self.last_message

        if time_elapsed or (message_changed and "complete" in message.lower()):
            self.last_update_time = now
            self.last_message = message
            return True
        return False


def format_layer_message(chunk: dict[str, Any]) -> str | None:
    """Format a progress message from a Docker streaming chunk."""
    raw_id = chunk.get("id")
    layer_id = str(raw_id)[:12] if raw_id is not None else ""

    raw_status = chunk.get("status")
    status = str(raw_status) if raw_status is not None else ""

    detail = chunk.get("progressDetail")
    if detail:
        current = detail.get("current", 0) or 0
        total = detail.get("total", 0) or 0
        if total > 0:
            pct = int((current / total) * 100)
            cur_mb = current / 1024 / 1024
            tot_mb = total / 1024 / 1024
            return f"Layer {layer_id}: {status} {pct}% ({cur_mb:.1f}MB/{tot_mb:.1f}MB)"
        if layer_id:
            return f"Layer {layer_id}: {status}"
        return None

    if not status:
        return None
    return f"Layer {layer_id}: {status}" if layer_id else status


async def report_layer_progress(
    ctx: Context,
    chunk: dict[str, Any],
    throttler: ProgressThrottler | None = None,
) -> str | None:
    """Report progress for a single layer chunk and return status if present."""
    msg = format_layer_message(chunk)

    if msg:
        msg = sanitize_progress_message(msg)
        if throttler is None or throttler.should_update(msg):
            await ctx.info(msg)

    detail = chunk.get("progressDetail")
    if detail:
        current = detail.get("current", 0) or 0
        total = detail.get("total", 0) or 0
        if total > 0:
            await ctx.report_progress(current, total)

    raw_status = chunk.get("status")
    return str(raw_status) if raw_status is not None else None


async def cleanup_worker_task(
    task: asyncio.Future[None],
    chunk_queue: Queue[Any],
) -> None:
    """Clean up a worker task by draining its queue and awaiting completion."""
    while True:
        try:
            chunk = chunk_queue.get_nowait()
            if chunk is None:
                break
        except Empty:
            break

    try:
        await asyncio.wait_for(task, timeout=5.0)
    except TimeoutError:
        logger.warning("Worker thread did not complete within timeout")
    except Exception as e:
        logger.debug(f"Worker task cleanup: {type(e).__name__}: {e}")


def check_worker_error(
    error_list: list[Exception],
    error_event: threading.Event | None,
) -> None:
    """Check for errors from worker thread and raise if found."""
    if error_event is not None:
        if error_event.is_set() and error_list:
            raise error_list[0] from error_list[0]
        return

    if error_list:
        raise error_list[0] from error_list[0]


async def process_streaming_queue(  # noqa: PLR0913
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    ctx: Context,
    throttler: ProgressThrottler,
    operation: str,
    error_event: threading.Event | None = None,
) -> str | None:
    """Process chunks from a streaming queue with progress reporting."""
    last_status: str | None = None

    while True:
        try:
            chunk = await asyncio.to_thread(chunk_queue.get, True, 0.1)
        except Empty:
            check_worker_error(error_list, error_event)
            continue

        if chunk is None:
            break

        if isinstance(chunk, dict):
            check_chunk_for_error(chunk, operation)
            status = await report_layer_progress(ctx, chunk, throttler)
            if status:
                last_status = status

    return last_status


async def report_build_progress(
    ctx: Context,
    chunk: dict[str, Any],
    throttler: ProgressThrottler,
) -> None:
    """Report progress for a build log chunk."""
    stream_val = chunk.get("stream")
    if not isinstance(stream_val, str):
        return

    msg = stream_val.strip()
    if not msg:
        return

    sanitized_msg = sanitize_progress_message(msg)
    is_important = msg.startswith("Step ") or "Successfully" in msg
    if is_important or throttler.should_update(sanitized_msg):
        await ctx.info(f"Build: {sanitized_msg}")

    if msg.startswith("Step "):
        match = re.match(r"Step (\d+)/(\d+)", msg)
        if match:
            step = int(match.group(1))
            total = int(match.group(2))
            await ctx.report_progress(step, total)


async def process_build_streaming_queue(
    chunk_queue: Queue[Any],
    error_list: list[Exception],
    ctx: Context,
    throttler: ProgressThrottler,
    error_event: threading.Event | None = None,
) -> None:
    """Process build log chunks from a streaming queue with progress reporting."""
    while True:
        try:
            chunk = await asyncio.to_thread(chunk_queue.get, True, 0.1)
        except Empty:
            check_worker_error(error_list, error_event)
            continue

        if chunk is None:
            break

        if isinstance(chunk, dict):
            check_chunk_for_error(chunk, "build")
            await report_build_progress(ctx, chunk, throttler)
