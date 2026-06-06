"""Tool registration utilities."""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.tools.common import ToolSpec
from mcp_docker.utils.fastmcp_helpers import get_mcp_annotations
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def _resolve_timeout(
    tool_timeout: float | None,
    safety_config: SafetyConfig | None,
) -> float | None:
    """Resolve effective timeout for a tool."""
    if tool_timeout is not None:
        return None if tool_timeout == 0 else tool_timeout

    if safety_config is not None:
        default = safety_config.default_tool_timeout
        return None if default == 0 else default

    return None


def register_tools_with_filtering(
    app: Any,
    tools: list[ToolSpec],
    safety_config: SafetyConfig | None,
) -> list[str]:
    """Register tools with annotations and timeout metadata."""
    registered_names = []

    for spec in tools:
        annotations = get_mcp_annotations(spec.safety)
        annotations["idempotent"] = spec.idempotent
        annotations["openWorldInteraction"] = spec.open_world

        spec.func._safety_level = spec.safety  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
        spec.func._tool_name = spec.name  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]

        effective_timeout = _resolve_timeout(spec.timeout, safety_config)

        app.tool(
            name=spec.name,
            description=spec.description,
            annotations=annotations,
            timeout=effective_timeout,
        )(spec.func)

        registered_names.append(spec.name)
        logger.debug(
            f"Registered FastMCP tool: {spec.name} "
            f"(safety: {spec.safety.value}, timeout: {effective_timeout})"
        )

    return registered_names
