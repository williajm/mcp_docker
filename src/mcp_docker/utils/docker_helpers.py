"""Helper utilities for working with Docker API responses.

This module provides null-safe helpers for accessing nested Docker API data,
preventing common null-reference errors when the Docker daemon returns
minimal or incomplete data structures.
"""

from typing import Any


def safe_get_list(data: dict[str, Any], *keys: str) -> list[Any]:
    """Get nested value as list, returning [] if None or missing.

    This handles the common pattern where Docker API responses may have
    null values (e.g., minimal containers with Env: null instead of []).

    Args:
        data: Source dictionary
        *keys: Nested keys to traverse

    Returns:
        List value if found and is a list, otherwise []

    Examples:
        >>> config = {"Env": ["PATH=/usr/bin", "HOME=/root"]}
        >>> safe_get_list(config, "Env")
        ['PATH=/usr/bin', 'HOME=/root']

        >>> config = {"Env": None}
        >>> safe_get_list(config, "Env")
        []

        >>> config = {}
        >>> safe_get_list(config, "Env")
        []
    """
    result: Any = data
    for key in keys:
        if not isinstance(result, dict):
            return []
        result = result.get(key)
        if result is None:
            return []
    return result if isinstance(result, list) else []


def safe_get_dict(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    """Get nested value as dict, returning {} if None or missing.

    This handles the common pattern where Docker API responses may have
    null values (e.g., minimal containers with Ports: null instead of {}).

    Args:
        data: Source dictionary
        *keys: Nested keys to traverse

    Returns:
        Dict value if found and is a dict, otherwise {}

    Examples:
        >>> container = {"NetworkSettings": {"Ports": {"80/tcp": [{"HostPort": "8080"}]}}}
        >>> safe_get_dict(container, "NetworkSettings", "Ports")
        {'80/tcp': [{'HostPort': '8080'}]}

        >>> container = {"NetworkSettings": {"Ports": None}}
        >>> safe_get_dict(container, "NetworkSettings", "Ports")
        {}

        >>> container = {}
        >>> safe_get_dict(container, "NetworkSettings", "Ports")
        {}
    """
    result: Any = data
    for key in keys:
        if not isinstance(result, dict):
            return {}
        result = result.get(key)
        if result is None:
            return {}
    return result if isinstance(result, dict) else {}


def safe_get_str(data: dict[str, Any], *keys: str, default: str = "") -> str:
    """Get nested value as string, returning default if None or missing.

    Args:
        data: Source dictionary
        *keys: Nested keys to traverse
        default: Default value to return if not found (default: "")

    Returns:
        String value if found, otherwise default

    Examples:
        >>> container = {"State": {"Status": "running"}}
        >>> safe_get_str(container, "State", "Status")
        'running'

        >>> container = {"State": {}}
        >>> safe_get_str(container, "State", "Status", default="unknown")
        'unknown'
    """
    result: Any = data
    for key in keys:
        if not isinstance(result, dict):
            return default
        result = result.get(key)
        if result is None:
            return default
    return str(result) if result is not None else default


__all__ = ["safe_get_list", "safe_get_dict", "safe_get_str"]
