"""FastMCP safety middleware.

This middleware enforces safety controls for all Docker operations
using the SafetyEnforcer class.
"""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.middleware.utils import get_operation_type
from mcp_docker.services.safety import OperationSafety
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyMiddleware:
    """FastMCP middleware for safety enforcement.

    This middleware integrates with FastMCP's middleware system to enforce
    safety controls before tool execution. It uses the SafetyEnforcer to
    perform all safety checks.

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.middleware import SafetyMiddleware

        app = FastMCP("mcp-docker")
        safety = SafetyMiddleware(enforcer, app)

        # Register middleware
        app.add_middleware(safety)
        ```
    """

    def __init__(self, enforcer: SafetyEnforcer, app: Any):
        """Initialize safety middleware.

        Args:
            enforcer: SafetyEnforcer instance for performing checks
            app: FastMCP app instance for tool metadata lookup
        """
        self.enforcer = enforcer
        self.app = app
        logger.info("Initialized SafetyMiddleware")

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Execute safety checks before tool execution.

        Args:
            context: FastMCP middleware context with tool information
            call_next: Next middleware/handler in the chain

        Returns:
            Result from next handler

        Raises:
            UnsafeOperationError: If safety checks fail
        """
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
        """Get the safety level for a tool from its metadata.

        Args:
            tool_name: Name of the tool

        Returns:
            Safety level of the tool (defaults to SAFE if not found)
        """
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
    """Factory function to create safety middleware.

    Args:
        enforcer: SafetyEnforcer instance
        app: FastMCP app instance for tool metadata lookup

    Returns:
        Configured SafetyMiddleware instance

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.config import Config
        from mcp_docker.services import SafetyEnforcer
        from mcp_docker.middleware.safety import create_safety_middleware

        config = Config()
        app = FastMCP("mcp-docker")
        enforcer = SafetyEnforcer(config.safety)
        middleware = create_safety_middleware(enforcer, app)
        ```
    """
    return SafetyMiddleware(enforcer, app)
