"""Safety enforcement for the slim MCP Docker server."""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety import OperationSafety
from mcp_docker.utils.errors import UnsafeOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyEnforcer:
    """Enforce the package's small safety policy."""

    def __init__(self, safety_config: SafetyConfig):
        self.config = safety_config
        logger.debug(f"Initialized SafetyEnforcer with config: {safety_config}")

    def check_operation_safety(
        self,
        tool_name: str,
        safety_level: OperationSafety,
    ) -> None:
        """Check if an operation is allowed based on its safety level."""
        if safety_level == OperationSafety.SAFE:
            return

        if safety_level == OperationSafety.MODERATE and self.config.allow_moderate_operations:
            return

        if safety_level == OperationSafety.MODERATE:
            raise UnsafeOperationError(
                f"Moderate operation '{tool_name}' is not allowed in read-only mode. "
                "Set SAFETY_ALLOW_MODERATE_OPERATIONS=true to enable reversible operations."
            )

        raise UnsafeOperationError(
            f"Destructive operation '{tool_name}' is not available in this slim package."
        )

    def enforce_all_checks(
        self,
        tool_name: str,
        safety_level: OperationSafety,
        arguments: dict[str, Any] | None = None,  # noqa: ARG002
    ) -> None:
        """Perform safety checks for a tool execution."""
        logger.debug(f"Enforcing safety for '{tool_name}' with level {safety_level.value}")
        self.check_operation_safety(tool_name, safety_level)
        logger.debug(f"Safety enforcement passed for '{tool_name}'")
