"""Output limiting and truncation utilities for Docker operations.

This module provides functions to limit and truncate Docker operation outputs
to prevent resource exhaustion and token limit issues.
"""

from typing import Any

from humanfriendly import format_size  # type: ignore[import-untyped]

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def truncate_text(
    text: str,
    max_bytes: int,
    truncation_message: str | None = None,
) -> tuple[str, bool]:
    """Truncate text to a maximum number of bytes.

    Args:
        text: Text to truncate
        max_bytes: Maximum bytes allowed (0 = no limit)
        truncation_message: Optional message to append when truncated

    Returns:
        Tuple of (truncated_text, was_truncated)
    """
    if max_bytes <= 0 or len(text.encode("utf-8")) <= max_bytes:
        return text, False

    # Simple byte slicing - ignore broken UTF-8 sequences
    text_bytes = text.encode("utf-8")[:max_bytes]
    truncated = text_bytes.decode("utf-8", errors="ignore")

    # Add truncation message if provided
    if truncation_message:
        truncated += f"\n\n{truncation_message}"

    original_bytes = len(text.encode("utf-8"))
    truncated_bytes = len(truncated.encode("utf-8"))
    logger.debug(f"Truncated text from {original_bytes} bytes to {truncated_bytes} bytes")

    return truncated, True


def truncate_lines(
    text: str,
    max_lines: int,
    truncation_message: str | None = None,
) -> tuple[str, bool]:
    """Truncate text to a maximum number of lines.

    Args:
        text: Text to truncate
        max_lines: Maximum lines allowed (0 = no limit)
        truncation_message: Optional message to append when truncated

    Returns:
        Tuple of (truncated_text, was_truncated)
    """
    if max_lines <= 0:
        return text, False

    lines = text.splitlines(keepends=True)

    if len(lines) <= max_lines:
        return text, False

    # Take first max_lines
    truncated_lines = lines[:max_lines]
    truncated = "".join(truncated_lines)

    # Add truncation message if provided
    if truncation_message:
        truncated += f"\n{truncation_message}"

    logger.debug(f"Truncated output from {len(lines)} lines to {max_lines} lines")

    return truncated, True


def create_truncation_metadata(  # noqa: PLR0913
    was_truncated: bool,
    original_size: int | None = None,
    truncated_size: int | None = None,
    original_count: int | None = None,
    truncated_count: int | None = None,
    truncated_fields: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Create metadata about output truncation.

    Args:
        was_truncated: Whether any truncation occurred
        original_size: Original size in bytes (for text/exec output)
        truncated_size: Truncated size in bytes
        original_count: Original count (for lists/lines)
        truncated_count: Truncated count
        truncated_fields: Mapping of truncated field paths to original sizes

    Returns:
        Metadata dictionary

    Note:
        Function has many optional parameters for flexibility across different
        truncation scenarios (text, lists, dicts). The noqa comment is justified
        as all parameters are optional and contextually appropriate.
    """
    metadata: dict[str, Any] = {"truncated": was_truncated}

    if not was_truncated:
        return metadata

    if original_size is not None and truncated_size is not None:
        metadata["original_bytes"] = original_size
        metadata["truncated_bytes"] = truncated_size
        metadata["original_size_human"] = format_size(original_size)
        metadata["truncated_size_human"] = format_size(truncated_size)

    if original_count is not None and truncated_count is not None:
        metadata["original_count"] = original_count
        metadata["truncated_count"] = truncated_count

    if truncated_fields:
        metadata["truncated_fields"] = {
            path: {"original_bytes": size, "original_size_human": format_size(size)}
            for path, size in truncated_fields.items()
        }
        metadata["truncated_fields_count"] = len(truncated_fields)

    return metadata
