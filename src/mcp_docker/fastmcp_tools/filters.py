"""Tool filtering utilities for registration.

This module provides utilities for filtering tools based on allow/deny lists.
Separated from registration.py to avoid circular imports.
"""

from mcp_docker.config import SafetyConfig
from mcp_docker.utils.logger import get_logger

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
