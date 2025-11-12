"""Output limiting and truncation utilities for Docker operations.

This module provides functions to limit and truncate Docker operation outputs
to prevent resource exhaustion and token limit issues.
"""

from typing import Any

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)

# Constants for size formatting
BYTES_PER_UNIT = 1024


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

    # Truncate to max_bytes, ensuring we don't break UTF-8 encoding
    text_bytes = text.encode("utf-8")[:max_bytes]

    # Try to decode, removing trailing partial UTF-8 sequences
    for i in range(4):  # UTF-8 sequences are at most 4 bytes
        try:
            truncated = text_bytes[: len(text_bytes) - i].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        # Fallback if we can't decode
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


def truncate_list(
    items: list[Any],
    max_items: int,
) -> tuple[list[Any], bool]:
    """Truncate a list to a maximum number of items.

    Args:
        items: List to truncate
        max_items: Maximum items allowed (0 = no limit)

    Returns:
        Tuple of (truncated_list, was_truncated)
    """
    if max_items <= 0 or len(items) <= max_items:
        return items, False

    truncated = items[:max_items]
    logger.debug(f"Truncated list from {len(items)} items to {max_items} items")

    return truncated, True


def _truncate_string_field(
    text: str,
    path: str,
    max_bytes: int,
    truncation_info: dict[str, int],
) -> str:
    """Truncate a single string field if it exceeds max bytes.

    Args:
        text: String to truncate
        path: Field path for tracking
        max_bytes: Maximum bytes allowed
        truncation_info: Dict to update with truncation info

    Returns:
        Truncated or original string
    """
    size = len(text.encode("utf-8"))
    if size <= max_bytes:
        return text

    truncated, _ = truncate_text(
        text,
        max_bytes,
        truncation_message=None,  # Don't add message to preserve data structure
    )
    truncation_info[path] = size
    return truncated


def truncate_dict_fields(
    data: dict[str, Any],
    max_field_bytes: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Recursively truncate large string fields in a dictionary.

    Args:
        data: Dictionary to process
        max_field_bytes: Maximum bytes per string field

    Returns:
        Tuple of (truncated_dict, truncation_info)
        where truncation_info maps field paths to original byte sizes
    """
    if max_field_bytes <= 0:
        return data, {}

    truncation_info: dict[str, int] = {}

    def _truncate_recursive(obj: Any, path: str = "") -> Any:
        """Recursively truncate fields in nested structures."""
        if isinstance(obj, dict):
            return {
                key: _truncate_recursive(value, f"{path}.{key}" if path else key)
                for key, value in obj.items()
            }

        if isinstance(obj, list):
            return [_truncate_recursive(item, f"{path}[{i}]") for i, item in enumerate(obj)]

        if isinstance(obj, str):
            return _truncate_string_field(obj, path, max_field_bytes, truncation_info)

        # Return other types as-is (int, float, bool, None, etc.)
        return obj

    truncated_data = _truncate_recursive(data)

    if truncation_info:
        logger.debug(f"Truncated {len(truncation_info)} fields in dictionary")

    return truncated_data, truncation_info


def format_size(bytes_value: int) -> str:
    """Format byte size in human-readable format.

    Args:
        bytes_value: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    size = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < BYTES_PER_UNIT:
            return f"{size:.1f} {unit}"
        size /= BYTES_PER_UNIT
    return f"{size:.1f} TB"


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
