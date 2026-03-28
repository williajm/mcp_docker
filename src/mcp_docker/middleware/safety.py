"""FastMCP safety middleware."""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_type
from mcp_docker.services.safety import OperationSafety
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyMiddleware:
    """Enforces safety controls before tool execution via SafetyEnforcer."""

    def __init__(self, enforcer: SafetyEnforcer, app: Any):
        self.enforcer = enforcer
        self.app = app
        logger.info("Initialized SafetyMiddleware")

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Execute safety checks before tool execution."""
        # Extract tool information from context
        # For tool calls, context.message is a CallToolRequestParams
        tool_name = getattr(context.message, "name", None)
        arguments = getattr(context.message, "arguments", {}) or {}

        if not tool_name:
            # This is not a tool call - it's an MCP protocol operation (tools/list, etc.)
            operation_type = get_operation_type(context)
            logger.debug(
                f"SafetyMiddleware: Skipping safety checks for MCP protocol "
                f"operation: {operation_type}"
            )
            return await call_next(context)

        # Get safety level from tool metadata
        safety_level = await self._get_tool_safety_level(tool_name)

        # Perform safety checks
        logger.debug(f"SafetyMiddleware: Checking {tool_name} (level: {safety_level.value})")
        self.enforcer.enforce_all_checks(tool_name, safety_level, arguments)

        # Safety checks passed, proceed to next handler
        logger.debug(f"SafetyMiddleware: Approved {tool_name}")
        return await call_next(context)

    async def _get_tool_safety_level(self, tool_name: str) -> OperationSafety:
        """Get the safety level for a tool from its metadata."""
        try:
            # Get tool from FastMCP registry
            tool = await self.app.get_tool(tool_name)

            # Check if the tool's function has safety metadata
            if hasattr(tool, "fn") and hasattr(tool.fn, "_safety_level"):
                # Type is guaranteed by hasattr check above
                safety_level: OperationSafety = tool.fn._safety_level
                logger.debug(f"Retrieved safety level for {tool_name}: {safety_level.value}")
                return safety_level

            # SECURITY: Fail closed - default to DESTRUCTIVE if no metadata found
            # This ensures unknown tools require explicit allow_destructive_operations=true
            logger.warning(
                f"No safety level metadata found for {tool_name}, "
                "defaulting to DESTRUCTIVE (fail closed)"
            )
            return OperationSafety.DESTRUCTIVE

        except Exception as e:
            # SECURITY: Fail closed - if we can't determine safety level, treat as destructive
            logger.warning(
                f"Failed to get safety level for {tool_name}: {e}, "
                "defaulting to DESTRUCTIVE (fail closed)"
            )
            return OperationSafety.DESTRUCTIVE


def create_safety_middleware(enforcer: SafetyEnforcer, app: Any) -> SafetyMiddleware:
    """Factory function to create safety middleware."""
    return SafetyMiddleware(enforcer, app)
