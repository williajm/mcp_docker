"""Safety controls and validation for Docker operations."""

import re
from enum import Enum
from typing import Any

from mcp_docker.utils.errors import UnsafeOperationError, ValidationError


class OperationSafety(str, Enum):
    """Classification of operation safety levels."""

    SAFE = "safe"  # Read-only operations (list, inspect, logs)
    MODERATE = "moderate"  # State-changing but reversible (start, stop, pause)
    DESTRUCTIVE = "destructive"  # Permanent changes (rm, prune, rmi)


# Port security constants
PRIVILEGED_PORT_BOUNDARY = 1024  # Ports below this require root privileges on Unix systems

# Set of operations that are considered destructive
DESTRUCTIVE_OPERATIONS = {
    "docker_remove_container",
    "docker_remove_image",
    "docker_prune_images",
    "docker_remove_network",
    "docker_remove_volume",
    "docker_prune_volumes",
    "docker_system_prune",
    "docker_compose_down",  # Stops and removes compose services
}

# Set of operations that modify state but are reversible
MODERATE_OPERATIONS = {
    "docker_create_container",
    "docker_start_container",
    "docker_stop_container",
    "docker_restart_container",
    "docker_exec_command",
    "docker_pull_image",
    "docker_build_image",
    "docker_push_image",
    "docker_tag_image",
    "docker_create_network",
    "docker_connect_container",
    "docker_disconnect_container",
    "docker_create_volume",
    "docker_compose_up",  # Start compose services
    "docker_compose_restart",  # Restart compose services
    "docker_compose_stop",  # Stop compose services
    "docker_compose_scale",  # Scale compose services
    "docker_compose_exec",  # Execute commands in compose services
    "docker_compose_build",  # Build compose services
    "docker_compose_write_file",  # Write compose files to compose_files directory
}

# Dangerous patterns in commands that should be blocked or warned about
DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+-rf\s+/",  # Recursive deletion from root
    r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
    r"dd\s+if=/dev/(zero|random)",  # Disk filling
    r"mkfs\.",  # Filesystem creation
    r"fdisk",  # Partition management
    r"shutdown",  # System shutdown
    r"reboot",  # System reboot
    r"halt",  # System halt
    r"init\s+[06]",  # Init level change
    r"curl.*\|\s*bash",  # Piping to shell
    r"wget.*\|\s*sh",  # Piping to shell
]

# Privileged operations that require special permissions
PRIVILEGED_OPERATIONS = {
    "docker_exec_command",  # Can execute arbitrary commands
    "docker_build_image",  # Can run arbitrary Dockerfiles
    "docker_compose_exec",  # Can execute arbitrary commands in compose services
    "docker_compose_build",  # Can build images from Dockerfiles
}


def classify_operation(operation_name: str) -> OperationSafety:
    """Classify an operation by its safety level.

    Args:
        operation_name: Name of the operation

    Returns:
        Safety classification of the operation

    """
    if operation_name in DESTRUCTIVE_OPERATIONS:
        return OperationSafety.DESTRUCTIVE
    if operation_name in MODERATE_OPERATIONS:
        return OperationSafety.MODERATE
    return OperationSafety.SAFE


def is_destructive_operation(operation_name: str) -> bool:
    """Check if an operation is destructive.

    Args:
        operation_name: Name of the operation

    Returns:
        True if operation is destructive, False otherwise

    """
    return operation_name in DESTRUCTIVE_OPERATIONS


def is_privileged_operation(operation_name: str) -> bool:
    """Check if an operation requires privileged mode.

    Args:
        operation_name: Name of the operation

    Returns:
        True if operation requires privileges, False otherwise

    """
    return operation_name in PRIVILEGED_OPERATIONS


def is_moderate_operation(operation_name: str) -> bool:
    """Check if an operation is moderate (state-changing but reversible).

    Args:
        operation_name: Name of the operation

    Returns:
        True if operation is moderate, False otherwise

    """
    return operation_name in MODERATE_OPERATIONS


def validate_operation_allowed(
    operation_name: str,
    allow_moderate: bool = True,
    allow_destructive: bool = False,
    allow_privileged: bool = False,
) -> None:
    """Validate that an operation is allowed based on safety settings.

    Args:
        operation_name: Name of the operation
        allow_moderate: Whether moderate operations are allowed
        allow_destructive: Whether destructive operations are allowed
        allow_privileged: Whether privileged operations are allowed

    Raises:
        UnsafeOperationError: If operation is not allowed

    """
    # Check moderate operations (for read-only mode)
    if is_moderate_operation(operation_name) and not allow_moderate:
        raise UnsafeOperationError(
            f"Moderate operation '{operation_name}' is not allowed in read-only mode. "
            "Set SAFETY_ALLOW_MODERATE_OPERATIONS=true to enable state-changing operations."
        )

    # Check destructive operations
    if is_destructive_operation(operation_name) and not allow_destructive:
        raise UnsafeOperationError(
            f"Destructive operation '{operation_name}' is not allowed. "
            "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
        )

    # Check privileged operations
    if is_privileged_operation(operation_name) and not allow_privileged:
        raise UnsafeOperationError(
            f"Privileged operation '{operation_name}' is not allowed. "
            "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
        )


def sanitize_command(command: str | list[str]) -> list[str]:
    """Sanitize a command for safe execution.

    Args:
        command: Command string or list to sanitize

    Returns:
        Sanitized command as list

    Raises:
        ValidationError: If command is invalid
        UnsafeOperationError: If command contains dangerous patterns

    """
    # Convert to list format
    if isinstance(command, str):
        if not command.strip():
            raise ValidationError("Command cannot be empty")
        cmd_list = [command]
    elif isinstance(command, list):
        if not command:
            raise ValidationError("Command list cannot be empty")
        if not all(isinstance(item, str) for item in command):
            raise ValidationError("All command items must be strings")
        cmd_list = command
    else:
        raise ValidationError("Command must be a string or list of strings")

    # Check for dangerous patterns
    command_str = " ".join(cmd_list)
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command_str, re.IGNORECASE):
            raise UnsafeOperationError(
                f"Command contains dangerous pattern: {pattern}. "
                "This command has been blocked for safety reasons."
            )

    return cmd_list


def validate_command_safety(command: str | list[str]) -> None:
    """Validate command for dangerous patterns without sanitizing.

    Args:
        command: Command string or list to validate

    Raises:
        UnsafeOperationError: If command contains dangerous patterns

    """
    command_str = " ".join(command) if isinstance(command, list) else command

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command_str, re.IGNORECASE):
            raise UnsafeOperationError(
                f"Command contains dangerous pattern matching '{pattern}'. "
                "This command has been blocked for safety reasons."
            )


def check_privileged_mode(
    privileged: bool,
    allow_privileged: bool = False,
) -> None:
    """Check if privileged mode is allowed.

    Args:
        privileged: Whether privileged mode is requested
        allow_privileged: Whether privileged mode is allowed in config

    Raises:
        UnsafeOperationError: If privileged mode is requested but not allowed

    """
    if privileged and not allow_privileged:
        raise UnsafeOperationError(
            "Privileged mode is not allowed. "
            "Enable privileged operations in configuration to use privileged containers."
        )


def validate_mount_path(path: str, allowed_paths: list[str] | None = None) -> None:
    """Validate that a mount path is safe.

    Args:
        path: Path to validate
        allowed_paths: List of allowed path prefixes (None = allow all)

    Raises:
        UnsafeOperationError: If path is not allowed

    """
    # Block sensitive system paths
    dangerous_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh",
        "/home/.ssh",
        "/.ssh",
    ]

    for dangerous_path in dangerous_paths:
        if path.startswith(dangerous_path):
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                f"Mounting sensitive system paths like '{dangerous_path}' is blocked."
            )

    # Check against allowed paths if specified
    if allowed_paths is not None and not any(path.startswith(allowed) for allowed in allowed_paths):
        raise UnsafeOperationError(
            f"Mount path '{path}' is not in the allowed paths list: {allowed_paths}"
        )


def validate_port_binding(
    host_port: int,
    allow_privileged_ports: bool = False,
) -> None:
    """Validate that a port binding is safe.

    Args:
        host_port: Host port number to validate
        allow_privileged_ports: Whether to allow privileged ports (<1024)

    Raises:
        UnsafeOperationError: If port is privileged but not allowed

    """
    if host_port < PRIVILEGED_PORT_BOUNDARY and not allow_privileged_ports:
        raise UnsafeOperationError(
            f"Privileged port {host_port} (<{PRIVILEGED_PORT_BOUNDARY}) is not allowed. "
            f"Enable privileged ports in configuration or use a port >= {PRIVILEGED_PORT_BOUNDARY}."
        )


def validate_environment_variable(key: str, value: Any) -> tuple[str, str]:
    """Validate environment variable for safety.

    Args:
        key: Environment variable key
        value: Environment variable value

    Returns:
        Tuple of (validated_key, validated_value)

    Raises:
        ValidationError: If variable is invalid

    """
    if not key:
        raise ValidationError("Environment variable key cannot be empty")

    # Convert value to string
    value_str = str(value)

    # Warn about potentially sensitive variables
    sensitive_patterns = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "PRIVATE_KEY",
    ]

    if any(pattern in key.upper() for pattern in sensitive_patterns):
        # This would log a warning in production
        pass

    return key, value_str
