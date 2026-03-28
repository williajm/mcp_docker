"""Centralized safety enforcement for Docker operations."""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety import (
    OperationSafety,
    check_privileged_mode,
    validate_command_safety,
    validate_mount_path,
)
from mcp_docker.utils.errors import UnsafeOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class SafetyEnforcer:
    """Centralized safety enforcement for Docker operations."""

    def __init__(self, safety_config: SafetyConfig):
        self.config = safety_config
        logger.debug(f"Initialized SafetyEnforcer with config: {safety_config}")

    def is_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check if a tool is allowed based on allow/deny lists."""
        # Deny list takes precedence
        # None = no deny list, [] = deny all, ['foo'] = deny only foo
        if self.config.denied_tools is not None:
            # Empty list = deny all
            if len(self.config.denied_tools) == 0:
                return False, f"All tools denied by configuration (empty deny list): {tool_name}"
            # Non-empty list = deny only listed tools
            if tool_name in self.config.denied_tools:
                return False, f"Tool denied by configuration: {tool_name}"

        # If allow list is set, tool must be in it
        # None = allow all (default), [] = allow none, ['foo'] = allow only foo
        if self.config.allowed_tools is not None and tool_name not in self.config.allowed_tools:
            return False, f"Tool not in allow list: {tool_name}"

        return True, "Tool allowed"

    def check_operation_safety(
        self,
        tool_name: str,
        safety_level: OperationSafety,
    ) -> None:
        """Check if an operation is allowed based on its safety level."""
        # Check moderate operations (for read-only mode)
        if safety_level == OperationSafety.MODERATE and not self.config.allow_moderate_operations:
            raise UnsafeOperationError(
                f"Moderate operation '{tool_name}' is not allowed in read-only mode. "
                "Set SAFETY_ALLOW_MODERATE_OPERATIONS=true to enable state-changing operations."
            )

        # Check destructive operations
        if (
            safety_level == OperationSafety.DESTRUCTIVE
            and not self.config.allow_destructive_operations
        ):
            raise UnsafeOperationError(
                f"Destructive operation '{tool_name}' is not allowed. "
                "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
            )

    def check_tool_allowed_and_safe(
        self,
        tool_name: str,
        safety_level: OperationSafety,
    ) -> None:
        """Combined check for tool allowance and safety level."""
        # Check allow/deny lists
        allowed, reason = self.is_tool_allowed(tool_name)
        if not allowed:
            raise UnsafeOperationError(reason)

        # Check safety level
        self.check_operation_safety(tool_name, safety_level)

    def validate_privileged_mode(self, privileged: bool) -> None:
        """Validate if privileged mode is allowed."""
        check_privileged_mode(privileged, self.config.allow_privileged_containers)

    def validate_mount_path_safe(self, path: str) -> None:
        """Validate that a mount path is safe."""
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
        """Validate that a command is safe to execute."""
        validate_command_safety(command)

    def enforce_all_checks(
        self,
        tool_name: str,
        safety_level: OperationSafety,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Perform all safety checks for a tool execution."""
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
