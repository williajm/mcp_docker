"""FastMCP safety middleware.

This middleware enforces safety controls for all Docker operations
using the SafetyEnforcer class.
"""

from typing import Any

from fastmcp.server.middleware import CallNext, MiddlewareContext

from mcp_docker.safety.core import SafetyEnforcer
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

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
            logger.warning("SafetyMiddleware: No tool name in context")
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

            # Default to SAFE if no metadata found
            logger.warning(f"No safety level metadata found for {tool_name}, defaulting to SAFE")
            return OperationSafety.SAFE

        except Exception as e:
            # If we can't get the tool, log warning and default to SAFE
            logger.warning(f"Failed to get safety level for {tool_name}: {e}, defaulting to SAFE")
            return OperationSafety.SAFE


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
        from mcp_docker.safety import SafetyEnforcer
        from mcp_docker.middleware.safety import create_safety_middleware

        config = Config()
        app = FastMCP("mcp-docker")
        enforcer = SafetyEnforcer(config.safety)
        middleware = create_safety_middleware(enforcer, app)
        ```
    """
    return SafetyMiddleware(enforcer, app)
