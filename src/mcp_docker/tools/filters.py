"""Tool filtering utilities for registration."""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.tools.common import ToolSpec
from mcp_docker.utils.fastmcp_helpers import get_mcp_annotations
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def should_register_tool(tool_name: str, safety_config: SafetyConfig) -> bool:
    """Check if a tool should be registered based on allow/deny lists.

    Logic:
        1. If tool is in denied_tools -> False (deny list takes precedence)
        2. If allowed_tools is not empty and tool is NOT in it -> False
        3. Otherwise -> True
    """
    # Check deny list first (takes precedence)
    if safety_config.denied_tools is not None:
        if len(safety_config.denied_tools) == 0:
            logger.debug(f"Skipping tool {tool_name} (deny all - empty deny list)")
            return False
        if tool_name in safety_config.denied_tools:
            logger.debug(f"Skipping tool {tool_name} (in deny list)")
            return False

    # Check allow list (if specified)
    if safety_config.allowed_tools is not None and tool_name not in safety_config.allowed_tools:
        logger.debug(f"Skipping tool {tool_name} (not in allow list)")
        return False

    return True


def register_tools_with_filtering(
    app: Any,
    tools: list[ToolSpec],
    safety_config: SafetyConfig | None,
) -> list[str]:
    """Register tools with filtering based on allow/deny lists."""
    registered_names = []

    for spec in tools:
        if safety_config and not should_register_tool(spec.name, safety_config):
            continue

        annotations = get_mcp_annotations(spec.safety)
        annotations["idempotent"] = spec.idempotent
        annotations["openWorldInteraction"] = spec.open_world

        # Attach safety metadata for middleware BEFORE decoration
        spec.func._safety_level = spec.safety  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
        spec.func._tool_name = spec.name  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]

        app.tool(
            name=spec.name,
            description=spec.description,
            annotations=annotations,
        )(spec.func)

        registered_names.append(spec.name)
        logger.debug(f"Registered FastMCP tool: {spec.name} (safety: {spec.safety.value})")

    return registered_names
