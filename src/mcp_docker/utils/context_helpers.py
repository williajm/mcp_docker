"""Helper functions for FastMCP context handling.

This module provides utilities for extracting and processing data from
FastMCP request context dictionaries.
"""

from typing import Any


def extract_client_id(context: dict[str, Any]) -> str:
    """Extract client identifier from FastMCP request context.

    Tries multiple sources in priority order to identify the client making the request.

    Priority order:
        1. session_id - Unique session identifier from FastMCP
        2. user_id - User identifier from authentication
        3. client_ip - IP address of the client
        4. "unknown" - Fallback when no client info available

    Args:
        context: FastMCP request context dictionary

    Returns:
        Client identifier string, or "unknown" if no client info available

    Example:
        >>> context = {"session_id": "sess-123", "client_ip": "192.168.1.1"}
        >>> extract_client_id(context)
        'sess-123'

        >>> context = {"client_ip": "192.168.1.1"}
        >>> extract_client_id(context)
        '192.168.1.1'

        >>> context = {}
        >>> extract_client_id(context)
        'unknown'
    """
    return (
        context.get("session_id") or context.get("user_id") or context.get("client_ip") or "unknown"
    )
