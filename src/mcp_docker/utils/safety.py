"""Safety controls and validation for Docker operations."""

import re
from enum import Enum
from typing import Any

from mcp_docker.utils.errors import UnsafeOperationError, ValidationError
from mcp_docker.utils.validation import (
    sanitize_command as validate_command_structure,
)


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


def _build_filesystem_destruction_patterns() -> list[str]:
    """Build patterns for detecting dangerous filesystem destruction commands."""
    return [
        r"rm\s+-rf\s+/",  # Recursive deletion from root
        r"rm\s+.*-rf\s+/",  # Recursive deletion from root (flags in different order)
        r"rm\s+-[rf]+\s+/\*",  # Deletion with wildcards at root
        r"rm\s+.*-r.*-f.*\s+/",  # Recursive deletion with separated flags
        r"rm\s+.*-f.*-r.*\s+/",  # Recursive deletion with separated flags (reversed)
        r"rm\s+.*~/\s+\*",  # rm with extra space before wildcard (common mistake)
        r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
    ]


def _build_disk_operation_patterns() -> list[str]:
    """Build patterns for detecting dangerous disk operations."""
    return [
        r"dd\s+if=/dev/(zero|random)",  # Disk filling
        r"dd\s+.*of=/dev/(sd[a-z]|hd[a-z]|nvme[0-9])",  # Overwriting physical disks
        r">\s*/dev/(sd[a-z]|hd[a-z]|nvme[0-9])",  # Redirecting to physical disks
        r"mkfs\.",  # Filesystem creation
        r"fdisk",  # Partition management
        r"parted",  # Partition editor
    ]


def _build_permission_bomb_patterns() -> list[str]:
    """Build patterns for detecting dangerous permission changes."""
    return [
        r"chmod\s+-R\s+777\s+/",  # Recursive 777 from root
        r"chmod\s+777\s+/",  # 777 permissions on root
        r"chmod\s+.*-R.*777.*[/~]",  # Recursive 777 with various flag orders
        r"chown\s+-R\s+.*\s+/",  # Recursive ownership change from root
    ]


def _build_system_control_patterns() -> list[str]:
    """Build patterns for detecting system shutdown/reboot commands."""
    return [
        r"shutdown",  # System shutdown
        r"reboot",  # System reboot
        r"halt",  # System halt
        r"poweroff",  # Power off system
        r"init\s+[06]",  # Init level change
        r"systemctl\s+(poweroff|reboot|halt)",  # Systemd power commands
    ]


def _build_remote_execution_patterns() -> list[str]:
    """Build patterns for detecting remote code execution attempts."""
    return [
        r"curl.*\|\s*bash",  # Piping curl to shell
        r"wget.*\|\s*sh",  # Piping wget to shell
        r"curl.*\|\s*sh",  # Piping curl to sh
        r"wget.*\|\s*bash",  # Piping wget to bash
        r"fetch.*\|\s*(bash|sh)",  # Piping fetch to shell
    ]


def _build_command_injection_patterns() -> list[str]:
    """Build patterns for detecting command injection via substitution."""
    return [
        r"\$\([^)]*rm[^)]*\)",  # Command substitution with rm
        r"`[^`]*rm[^`]*`",  # Backtick substitution with rm
        r"\$\([^)]*dd[^)]*\)",  # Command substitution with dd
        r"`[^`]*dd[^`]*`",  # Backtick substitution with dd
    ]


def _build_file_destruction_patterns() -> list[str]:
    """Build patterns for detecting file destruction commands."""
    return [
        r":\s*>\s*/",  # Truncating files at root
        r"mv\s+.*\s+/dev/null",  # Moving to null device
    ]


def _build_device_access_patterns() -> list[str]:
    """Build patterns for detecting direct device access."""
    return [
        r"/dev/(sd[a-z]|hd[a-z]|nvme[0-9])",  # Physical disk device access
        r"/dev/mem",  # Direct memory access
    ]


def _build_decompression_bomb_patterns() -> list[str]:
    """Build patterns for detecting decompression bombs."""
    return [
        r"tar\s+.*--to-command",  # Tar with command execution
        r"unzip.*-p.*\|",  # Unzip piped to commands
    ]


def _build_dangerous_patterns() -> list[str]:
    """Build comprehensive list of dangerous command patterns.

    Patterns are organized by category for maintainability:
    - Filesystem destruction (rm, fork bombs)
    - Disk operations (dd, mkfs, fdisk, parted)
    - Permission bombs (chmod 777, chown)
    - System control (shutdown, reboot, halt)
    - Remote execution (curl|bash, wget|sh)
    - Command injection (command substitution)
    - File destruction (truncation, /dev/null)
    - Device access (/dev/sd*, /dev/mem)
    - Decompression bombs (tar, unzip)

    Returns:
        list[str]: Complete list of dangerous command regex patterns
    """
    patterns = []
    patterns.extend(_build_filesystem_destruction_patterns())
    patterns.extend(_build_disk_operation_patterns())
    patterns.extend(_build_permission_bomb_patterns())
    patterns.extend(_build_system_control_patterns())
    patterns.extend(_build_remote_execution_patterns())
    patterns.extend(_build_command_injection_patterns())
    patterns.extend(_build_file_destruction_patterns())
    patterns.extend(_build_device_access_patterns())
    patterns.extend(_build_decompression_bomb_patterns())
    return patterns


# Dangerous patterns in commands that should be blocked or warned about
DANGEROUS_COMMAND_PATTERNS = _build_dangerous_patterns()

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
    """Sanitize a command for safe execution with security checks.

    This extends the basic command validation from utils.validation with
    additional safety checks for dangerous command patterns.

    Args:
        command: Command string or list to sanitize

    Returns:
        Sanitized command as list

    Raises:
        ValidationError: If command structure is invalid
        UnsafeOperationError: If command contains dangerous patterns

    """
    # First validate command structure using shared validation logic
    cmd_list = validate_command_structure(command)

    # Then check for dangerous patterns (safety-specific logic)
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


def _is_named_volume(path: str) -> bool:
    """Check if path is a Docker named volume (safe to mount).

    Named volumes are simple alphanumeric names without path separators.
    They are managed by Docker and don't grant filesystem access.

    Args:
        path: Path to check

    Returns:
        True if path is a named volume, False otherwise
    """
    # Named volumes don't have path separators
    if "/" in path or "\\" in path:
        return False

    # Named volumes don't start with . (hidden files/relative paths)
    if path.startswith("."):
        return False

    # Simple names without special characters are named volumes
    # Docker accepts alphanumeric + _ - . for volume names
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", path))


def validate_mount_path(
    path: str,
    blocked_paths: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    yolo_mode: bool = False,
) -> None:
    """Validate that a mount path is safe.

    Simple validation focused on preventing common Linux mistakes.
    For advanced use cases, enable YOLO mode to bypass validation.

    Args:
        path: Path to validate
        blocked_paths: List of blocked path prefixes (None = use defaults)
        allowed_paths: List of allowed path prefixes (None = allow all except blocked)
        yolo_mode: If True, bypass all validation (user takes responsibility)

    Raises:
        UnsafeOperationError: If path is not safe to mount
    """
    # YOLO mode: User takes full responsibility
    if yolo_mode:
        return

    # Named volumes are always safe (managed by Docker, no filesystem access)
    if _is_named_volume(path):
        return

    # Normalize path to prevent simple bypass attempts like /etc/../etc/passwd
    normalized = path.replace("\\", "/")  # Handle Windows paths
    normalized = "/" + normalized.lstrip("/")  # Collapse duplicate leading slashes

    # SECURITY: Block path traversal attempts (e.g., ../../etc)
    if ".." in normalized:
        raise UnsafeOperationError(
            f"Path traversal (..) not allowed in mount path: {path}. "
            "Use absolute paths only. Enable SAFETY_YOLO_MODE=true to bypass."
        )

    # Default blocklist: system paths (prefix matching)
    if blocked_paths is None:
        blocked_paths = [
            "/etc",  # System configuration
            "/root",  # Root user home
            "/var/run/docker.sock",  # Docker socket (container escape)
        ]

    # Default credential directories (substring matching to catch /home/user/.ssh etc.)
    credential_dirs = ["/.ssh", "/.aws", "/.kube", "/.docker"]

    # Check system paths (prefix matching)
    for blocked in blocked_paths:
        if normalized.startswith(blocked):
            raise UnsafeOperationError(
                f"Mount path '{path}' is blocked. "
                f"Matches blocklist entry: {blocked}. "
                "Enable SAFETY_YOLO_MODE=true to bypass."
            )

    # Check credential directories (substring matching to catch any user)
    for cred_dir in credential_dirs:
        if cred_dir in normalized:
            raise UnsafeOperationError(
                f"Mount path '{path}' contains credential directory '{cred_dir}'. "
                "Credential directories are blocked for safety. "
                "Enable SAFETY_YOLO_MODE=true to bypass."
            )

    # Check allowlist if specified
    if allowed_paths is not None and not any(
        normalized.startswith(allowed) for allowed in allowed_paths
    ):
        raise UnsafeOperationError(
            f"Mount path '{path}' is not in allowed paths. "
            "Configure SAFETY_VOLUME_MOUNT_ALLOWLIST to permit this path."
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
        ValidationError: If variable is invalid or contains dangerous characters

    """
    if not key:
        raise ValidationError("Environment variable key cannot be empty")

    # Convert value to string
    value_str = str(value)

    # Check for command injection characters in value
    # NOTE: Only block characters that are ALWAYS dangerous (command substitution, separators)
    # Docker passes env vars as structured data, not through shell, so & and | are safe
    # Common in connection strings: postgres://...?ssl=true&pool=10
    dangerous_chars = [
        "$(",  # Command substitution
        "`",  # Backtick command substitution
        ";",  # Command separator
        "\n",  # Newline injection
        "\r",  # Carriage return injection
    ]

    for char in dangerous_chars:
        if char in value_str:
            raise ValidationError(
                f"Environment variable '{key}' contains dangerous character '{char}'. "
                "Command injection characters are not allowed in environment variables."
            )

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
