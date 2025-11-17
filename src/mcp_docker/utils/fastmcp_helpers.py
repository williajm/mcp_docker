"""Helper functions for FastMCP integration.

This module provides utility functions for working with FastMCP 2.0.
"""

from typing import Any

from fastmcp import FastMCP

from mcp_docker.utils.safety import OperationSafety
from mcp_docker.version import __version__


def create_fastmcp_app(name: str = "mcp-docker") -> FastMCP:
    """Create and configure a FastMCP application instance.

    Args:
        name: Application name (default: "mcp-docker")

    Returns:
        Configured FastMCP instance
    """
    return FastMCP(
        name=name,
        version=__version__,
    )


def get_mcp_annotations(safety_level: OperationSafety) -> dict[str, Any]:
    """Get MCP annotations for a tool based on its safety level.

    MCP annotations help clients understand tool characteristics:
    - readOnly: Tool only reads data (no modifications)
    - destructive: Tool permanently deletes data

    Args:
        safety_level: The safety level of the operation

    Returns:
        Dictionary with readOnly and destructive flags

    Example:
        >>> get_mcp_annotations(OperationSafety.SAFE)
        {"readOnly": True, "destructive": False}
        >>> get_mcp_annotations(OperationSafety.DESTRUCTIVE)
        {"readOnly": False, "destructive": True}
    """
    return {
        "readOnly": safety_level == OperationSafety.SAFE,
        "destructive": safety_level == OperationSafety.DESTRUCTIVE,
    }
