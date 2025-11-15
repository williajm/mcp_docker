"""Safety controls and validation for Docker operations."""

import os
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


def validate_command_safety(
    command: str | list[str],
    yolo_mode: bool = False,
) -> None:
    """Validate command for dangerous patterns without sanitizing.

    Args:
        command: Command string or list to validate
        yolo_mode: If True, skip all safety checks (EXTREMELY DANGEROUS!)

    Raises:
        UnsafeOperationError: If command contains dangerous patterns

    """
    # YOLO mode bypasses all safety checks
    if yolo_mode:
        return

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
    """Check if path is a Docker named volume (not a bind mount).

    Docker named volumes are simple names without path separators.
    Examples: "my-volume", "workspace-data", "db_data"

    Bind mounts are absolute paths that should be validated.
    Examples: "/home/user/data", "C:\\data", "/var/lib/docker"

    Args:
        path: Path or volume name to check

    Returns:
        True if this appears to be a named volume, False if bind mount path

    """
    # Type check - if not a string, it will be caught by later validation
    if not isinstance(path, str):
        return False

    # Absolute paths are bind mounts, not named volumes
    if path.startswith("/") or path.startswith("\\"):
        return False

    # Windows drive letters (C:, D:, etc.) are bind mounts
    if re.match(r"^[A-Za-z]:", path):
        return False

    # If it contains path separators, it's a relative path (bind mount attempt)
    # Named volumes should be simple names without separators
    if "/" in path or "\\" in path:
        return False

    # UNC paths are bind mounts
    # Everything else is treated as a named volume
    # Docker accepts alphanumeric + _ - . for volume names
    return not (path.startswith("//") or path.startswith("\\\\"))


def _is_windows_absolute_path(path: str) -> bool:
    r"""Check if path is a Windows absolute path.

    Args:
        path: Path to check

    Returns:
        True if Windows absolute path (C:\, D:\, or UNC path), False otherwise
    """
    return bool(re.match(r"^[A-Za-z]:[/\\]", path) or path.startswith("\\\\"))


def _path_starts_with(path: str, prefix: str, case_insensitive: bool = False) -> bool:
    r"""Check if path starts with prefix, accounting for path separators.

    Special case: Root paths (/, C:\\, D:\\) only match exactly, not subdirectories.
    This allows blocking root filesystem mounts without blocking all subdirectories.

    Args:
        path: Path to check
        prefix: Prefix to match against
        case_insensitive: If True, perform case-insensitive comparison (for Windows)

    Returns:
        True if path starts with prefix
    """
    # Normalize casing for case-insensitive comparison
    if case_insensitive:
        path_cmp = path.casefold()
        prefix_cmp = prefix.casefold()
    else:
        path_cmp = path
        prefix_cmp = prefix

    # Exact match always returns True
    if path_cmp == prefix_cmp:
        return True
    if not path_cmp.startswith(prefix_cmp):
        return False

    # Special handling for Unix root "/" - only exact match, no subdirectories
    # This allows "/" in blocklist to block mounting "/" without blocking "/home", etc.
    # Windows root drives (C:\, D:\) match subdirectories (other drives still usable)
    if prefix_cmp == "/":
        return False

    # If prefix ends with a separator (and isn't a root), any path starting with it matches
    if prefix_cmp.endswith(("/", "\\")):
        return True

    # Otherwise, check if the next character after prefix is a path separator
    # Use original path for character checking (separators are ASCII, casing doesn't matter)
    if len(path) > len(prefix):
        next_char = path[len(prefix)]
        return next_char in ("/", "\\")
    return False


def _check_blocklist(path: str, normalized: str, blocked_paths: list[str]) -> None:
    """Check if path is in blocklist and raise error if it is.

    Args:
        path: Original path (for error messages)
        normalized: Normalized path to check
        blocked_paths: List of blocked path prefixes

    Raises:
        UnsafeOperationError: If path is blocked
    """
    # Windows paths need case-insensitive comparison
    is_windows = _is_windows_absolute_path(normalized)

    for blocked in blocked_paths:
        if _path_starts_with(normalized, blocked, case_insensitive=is_windows):
            # Special message for root filesystem paths
            # Use casefold for comparison if Windows
            normalized_cmp = normalized.casefold() if is_windows else normalized
            blocked_cmp = blocked.casefold() if is_windows else blocked
            if blocked in ("/", "C:\\", "D:\\") and normalized_cmp == blocked_cmp:
                raise UnsafeOperationError(
                    f"Mount path '{path}' is blocked. "
                    f"Mounting the root filesystem ({blocked}) could enable container escape. "
                    "Enable SAFETY_YOLO_MODE=true to bypass."
                )
            # Standard blocklist error message
            raise UnsafeOperationError(
                f"Mount path '{path}' is blocked. "
                f"This path matches blocklist entry: {blocked}. "
                "Enable SAFETY_YOLO_MODE=true to bypass."
            )


def _check_allowlist(path: str, normalized: str, allowed_paths: list[str]) -> None:
    """Check if path is in allowlist and raise error if not.

    Args:
        path: Original path (for error messages)
        normalized: Normalized path to check
        allowed_paths: List of allowed path prefixes

    Raises:
        UnsafeOperationError: If path is not in allowlist
    """
    # Windows paths need case-insensitive comparison
    is_windows = _is_windows_absolute_path(normalized)

    if not any(
        _path_starts_with(normalized, p, case_insensitive=is_windows) for p in allowed_paths
    ):
        raise UnsafeOperationError(
            f"Mount path '{path}' is not in the allowed paths list. "
            "Configure SAFETY_VOLUME_MOUNT_ALLOWLIST to permit this path."
        )


def validate_mount_path(
    path: str,
    allowed_paths: list[str] | None = None,
    blocked_paths: list[str] | None = None,
    yolo_mode: bool = False,
) -> None:
    r"""Validate that a mount path is safe.

    Validates bind mount paths against security policies:
    - Blocklist: Prevents mounting dangerous paths (e.g., /var/run/docker.sock, /, /etc)
    - Allowlist: If set, only allows paths starting with specified prefixes
    - Windows support: Recognizes Windows absolute paths (C:\, D:\, etc.)

    Docker named volumes (simple names like "my-volume") are allowed
    as they don't expose the host filesystem.

    Args:
        path: Path to validate (host path or named volume)
        allowed_paths: Optional allowlist of path prefixes (None = no allowlist)
        blocked_paths: Optional blocklist of dangerous paths (None = use defaults)
        yolo_mode: If True, skip all validation (DANGEROUS!)

    Raises:
        UnsafeOperationError: If path is dangerous or violates policy
        ValidationError: If path format is invalid
    """
    # YOLO mode bypasses all validation
    if yolo_mode:
        return

    # Validate path is a string
    if not isinstance(path, str):
        raise ValidationError(f"Invalid path format: {path}")

    # Named volumes are safe (Docker manages them internally)
    # BUT if allowlist is explicitly empty [], block ALL mounts (including named volumes)
    if _is_named_volume(path):
        # Empty allowlist means block ALL mounts (lockdown mode)
        if allowed_paths is not None and len(allowed_paths) == 0:
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                "Empty allowlist blocks ALL mounts including named volumes. "
                "Configure SAFETY_VOLUME_MOUNT_ALLOWLIST to permit mounts."
            )
        # Named volumes allowed when no allowlist or allowlist has entries
        return

    # Bind mounts must use absolute paths (Unix or Windows)
    if not path.startswith("/") and not _is_windows_absolute_path(path):
        raise UnsafeOperationError(
            f"Mount path '{path}' must be an absolute path. "
            "Relative paths are not allowed to prevent path traversal attacks. "
            "Use absolute paths like '/home/user/data' (Unix) or 'C:\\data' (Windows), "
            "or named volumes like 'my-volume'."
        )

    # Normalize path (resolves .., ., removes trailing slashes)
    try:
        normalized = os.path.normpath(path)
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid path format: {path}") from e

    # Check blocklist (if provided)
    if blocked_paths is not None:
        _check_blocklist(path, normalized, blocked_paths)

    # Check allowlist (if provided)
    if allowed_paths is not None:
        _check_allowlist(path, normalized, allowed_paths)


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
