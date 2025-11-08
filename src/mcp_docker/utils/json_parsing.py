"""JSON parsing utilities for MCP Docker.

This module provides utilities for parsing JSON strings in tool inputs,
working around MCP client serialization issues.
"""

import json
from typing import Any

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def parse_json_string_field(v: Any, field_name: str = "field") -> Any:
    """Parse JSON strings to objects (workaround for MCP client serialization bug).

    Args:
        v: The value to parse (dict or JSON string)
        field_name: Name of the field for error messages

    Returns:
        Parsed dict if v was a string, otherwise returns v unchanged

    Raises:
        ValueError: If v is a string but not valid JSON
    """
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            logger.warning(
                f"Received JSON string instead of object for {field_name}, auto-parsing. "
                "This is a workaround for MCP client serialization issues."
            )
            return parsed
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Received invalid JSON string for {field_name}: {v[:100]}... "
                f"Expected an object/dict, not a string. Error: {e}"
            ) from e
    return v


__all__ = ["parse_json_string_field"]
