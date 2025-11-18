"""Tool filtering utilities for registration.

This module provides utilities for filtering tools based on allow/deny lists.
Separated from registration.py to avoid circular imports.
"""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.utils.fastmcp_helpers import get_mcp_annotations
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)


def should_register_tool(tool_name: str, safety_config: SafetyConfig) -> bool:
    """Check if a tool should be registered based on allow/deny lists.

    Args:
        tool_name: Name of the tool to check
        safety_config: Safety configuration with allowed/denied tool lists

    Returns:
        True if tool should be registered, False otherwise

    Logic:
        1. If tool is in denied_tools -> False (deny list takes precedence)
        2. If allowed_tools is not empty and tool is NOT in it -> False
        3. Otherwise -> True
    """
    # Check deny list first (takes precedence)
    if safety_config.denied_tools and tool_name in safety_config.denied_tools:
        logger.debug(f"Skipping tool {tool_name} (in deny list)")
        return False

    # Check allow list (if specified)
    if safety_config.allowed_tools and tool_name not in safety_config.allowed_tools:
        logger.debug(f"Skipping tool {tool_name} (not in allow list)")
        return False

    return True


def register_tools_with_filtering(
    app: Any,
    tools: list[tuple[str, str, OperationSafety, bool, bool, Any]],
    safety_config: SafetyConfig | None,
) -> list[str]:
    """Register tools with filtering based on allow/deny lists.

    This helper reduces code duplication across tool registration modules.

    Args:
        app: FastMCP application instance
        tools: List of (name, description, safety_level, idempotent, open_world, func) tuples
        safety_config: Safety configuration (None to skip filtering)

    Returns:
        List of registered tool names
    """
    registered_names = []

    for name, description, safety_level, idempotent, open_world, func in tools:
        # Check if tool should be registered based on allow/deny lists
        if safety_config and not should_register_tool(name, safety_config):
            continue

        # Get MCP annotations based on safety level
        annotations = get_mcp_annotations(safety_level)
        annotations["idempotent"] = idempotent
        annotations["openWorldInteraction"] = open_world

        # Attach safety metadata for middleware BEFORE decoration
        # FastMCP stores the original function in tool.fn, so we need to attach metadata first
        func._safety_level = safety_level  # pyright: ignore[reportAttributeAccessIssue]
        func._tool_name = name  # pyright: ignore[reportAttributeAccessIssue]

        # Register with FastMCP
        app.tool(name=name, description=description, annotations=annotations)(func)

        registered_names.append(name)
        logger.debug(f"Registered FastMCP tool: {name} (safety: {safety_level.value})")

    return registered_names
