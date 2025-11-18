"""Framework-agnostic safety enforcement for Docker operations.

This module provides a centralized SafetyEnforcer class that can be used
with any MCP framework (legacy SDK or FastMCP). It extracts safety logic
from BaseTool to enable middleware-based enforcement.

This is the core safety abstraction created in Phase 2 of the FastMCP migration.
"""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.utils.errors import UnsafeOperationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import (
    OperationSafety,
    check_privileged_mode,
    classify_operation,
    is_destructive_operation,
    is_moderate_operation,
    is_privileged_operation,
    sanitize_command,
    validate_command_safety,
    validate_mount_path,
)

logger = get_logger(__name__)


class SafetyEnforcer:
    """Framework-agnostic safety enforcement for Docker operations.

    This class centralizes all safety checks and can be used by both
    the legacy MCP SDK implementation and FastMCP middleware.

    Example:
        ```python
        # In middleware
        enforcer = SafetyEnforcer(config.safety)

        # Check if tool is allowed
        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")

        # Check operation safety
        enforcer.check_operation_safety(
            "docker_remove_container",
            OperationSafety.DESTRUCTIVE
        )
        ```
    """

    def __init__(self, safety_config: SafetyConfig):
        """Initialize safety enforcer with configuration.

        Args:
            safety_config: Safety configuration from Config
        """
        self.config = safety_config
        logger.debug(f"Initialized SafetyEnforcer with config: {safety_config}")

    def is_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check if a tool is allowed based on allow/deny lists.

        Enforcement order:
        1. Deny list (takes precedence)
        2. Allow list (if non-empty, tool must be in it)
        3. Default allow

        Args:
            tool_name: Name of the tool to check

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Deny list takes precedence
        if self.config.denied_tools and tool_name in self.config.denied_tools:
            return False, f"Tool denied by configuration: {tool_name}"

        # If allow list is non-empty, tool must be in it
        if self.config.allowed_tools and tool_name not in self.config.allowed_tools:
            return False, f"Tool not in allow list: {tool_name}"

        return True, "Tool allowed"

    def check_operation_safety(
        self,
        tool_name: str,
        safety_level: OperationSafety,
    ) -> None:
        """Check if an operation is allowed based on its safety level.

        Args:
            tool_name: Name of the tool
            safety_level: Safety classification of the operation

        Raises:
            UnsafeOperationError: If operation is not allowed
        """
        # Check moderate operations (for read-only mode)
        if safety_level == OperationSafety.MODERATE and not self.config.allow_moderate_operations:
            raise UnsafeOperationError(
                f"Moderate operation '{tool_name}' is not allowed in read-only mode. "
                "Set SAFETY_ALLOW_MODERATE_OPERATIONS=true to enable state-changing operations."
            )

        # Check destructive operations
        if safety_level == OperationSafety.DESTRUCTIVE:
            if not self.config.allow_destructive_operations:
                raise UnsafeOperationError(
                    f"Destructive operation '{tool_name}' is not allowed. "
                    "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
                )

            if self.config.require_confirmation_for_destructive:
                logger.warning(
                    f"Destructive operation '{tool_name}' requires confirmation. "
                    "This would normally prompt for user confirmation."
                )

    def check_tool_allowed_and_safe(
        self,
        tool_name: str,
        safety_level: OperationSafety,
    ) -> None:
        """Combined check for tool allowance and safety level.

        This is a convenience method that combines is_tool_allowed()
        and check_operation_safety() into a single check.

        Args:
            tool_name: Name of the tool
            safety_level: Safety classification of the operation

        Raises:
            UnsafeOperationError: If tool is not allowed or unsafe
        """
        # Check allow/deny lists
        allowed, reason = self.is_tool_allowed(tool_name)
        if not allowed:
            raise UnsafeOperationError(reason)

        # Check safety level
        self.check_operation_safety(tool_name, safety_level)

    def validate_privileged_mode(self, privileged: bool) -> None:
        """Validate if privileged mode is allowed.

        Args:
            privileged: Whether privileged mode is requested

        Raises:
            UnsafeOperationError: If privileged mode is not allowed
        """
        check_privileged_mode(privileged, self.config.allow_privileged_containers)

    def validate_mount_path_safe(self, path: str) -> None:
        """Validate that a mount path is safe.

        Args:
            path: Mount path to validate

        Raises:
            UnsafeOperationError: If mount path is unsafe
        """
        # Config validators ensure these are always lists, safe to cast
        blocklist = (
            list(self.config.volume_mount_blocklist) if self.config.volume_mount_blocklist else []
        )
        allowlist = (
            list(self.config.volume_mount_allowlist) if self.config.volume_mount_allowlist else None
        )
        validate_mount_path(
            path,
            blocked_paths=blocklist,
            allowed_paths=allowlist,
            yolo_mode=self.config.yolo_mode,
        )

    def validate_command_safe(self, command: str | list[str]) -> None:
        """Validate that a command is safe to execute.

        Args:
            command: Command to validate

        Raises:
            UnsafeOperationError: If command contains dangerous patterns
        """
        validate_command_safety(command)

    def sanitize_and_validate_command(self, command: str | list[str]) -> list[str]:
        """Sanitize and validate a command for safe execution.

        Args:
            command: Command to sanitize

        Returns:
            Sanitized command as list

        Raises:
            ValidationError: If command structure is invalid
            UnsafeOperationError: If command contains dangerous patterns
        """
        return sanitize_command(command)

    def get_operation_metadata(self, tool_name: str) -> dict[str, Any]:
        """Get metadata about an operation's safety classification.

        Args:
            tool_name: Name of the tool

        Returns:
            Dictionary with safety metadata
        """
        safety_level = classify_operation(tool_name)
        return {
            "tool_name": tool_name,
            "safety_level": safety_level.value,
            "is_destructive": is_destructive_operation(tool_name),
            "is_moderate": is_moderate_operation(tool_name),
            "is_privileged": is_privileged_operation(tool_name),
            "allowed_by_config": self.is_tool_allowed(tool_name)[0],
        }

    def enforce_all_checks(
        self,
        tool_name: str,
        safety_level: OperationSafety,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Perform all safety checks for a tool execution.

        This is the main enforcement method that should be called
        before executing any tool.

        Args:
            tool_name: Name of the tool
            safety_level: Safety classification of the operation
            arguments: Tool arguments (optional, for argument-specific checks)

        Raises:
            UnsafeOperationError: If any safety check fails
        """
        # Log the enforcement attempt
        logger.debug(f"Enforcing safety for '{tool_name}' with level {safety_level.value}")

        # Check tool allow/deny lists and safety level
        self.check_tool_allowed_and_safe(tool_name, safety_level)

        # Check argument-specific safety if arguments provided
        if arguments:
            # Check privileged mode if requested
            if "privileged" in arguments:
                self.validate_privileged_mode(arguments["privileged"])

            # Check command safety if command provided
            if "command" in arguments:
                self.validate_command_safe(arguments["command"])

            # Check mount paths if binds/volumes provided
            if "binds" in arguments and arguments["binds"]:
                for bind in arguments["binds"]:
                    # Parse bind string (format: "/host/path:/container/path:ro")
                    host_path = bind.split(":")[0] if ":" in bind else bind
                    self.validate_mount_path_safe(host_path)

        logger.debug(f"Safety enforcement passed for '{tool_name}'")
