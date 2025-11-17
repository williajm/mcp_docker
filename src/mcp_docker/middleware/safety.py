"""FastMCP safety middleware.

This middleware enforces safety controls for all Docker operations
using the SafetyEnforcer class.
"""

from collections.abc import Awaitable, Callable
from typing import Any

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
        safety = SafetyMiddleware(enforcer)

        # Register middleware
        app.add_middleware(safety)
        ```
    """

    def __init__(self, enforcer: SafetyEnforcer):
        """Initialize safety middleware.

        Args:
            enforcer: SafetyEnforcer instance for performing checks
        """
        self.enforcer = enforcer
        logger.info("Initialized SafetyMiddleware")

    async def __call__(
        self,
        call_next: Callable[[], Awaitable[Any]],
        context: dict[str, Any],
    ) -> Any:
        """Execute safety checks before tool execution.

        Args:
            call_next: Next middleware/handler in the chain
            context: Request context with tool information

        Returns:
            Result from next handler

        Raises:
            UnsafeOperationError: If safety checks fail
        """
        # Extract tool information from context
        tool_name = context.get("tool_name")
        arguments = context.get("arguments", {})

        if not tool_name:
            logger.warning("SafetyMiddleware: No tool_name in context")
            return await call_next()

        # Get safety level from tool metadata
        # FastMCP tools should have _safety_level attribute from decorator
        tool_func = context.get("tool_func")
        safety_level = OperationSafety.SAFE  # Default to safe

        if tool_func and hasattr(tool_func, "_safety_level"):
            safety_level = tool_func._safety_level

        # Perform safety checks
        logger.debug(f"SafetyMiddleware: Checking {tool_name} (level: {safety_level.value})")
        self.enforcer.enforce_all_checks(tool_name, safety_level, arguments)

        # Safety checks passed, proceed to next handler
        logger.debug(f"SafetyMiddleware: Approved {tool_name}")
        return await call_next()


def create_safety_middleware(enforcer: SafetyEnforcer) -> SafetyMiddleware:
    """Factory function to create safety middleware.

    Args:
        enforcer: SafetyEnforcer instance

    Returns:
        Configured SafetyMiddleware instance

    Example:
        ```python
        from mcp_docker.config import Config
        from mcp_docker.safety import SafetyEnforcer
        from mcp_docker.middleware.safety import create_safety_middleware

        config = Config()
        enforcer = SafetyEnforcer(config.safety)
        middleware = create_safety_middleware(enforcer)
        ```
    """
    return SafetyMiddleware(enforcer)
