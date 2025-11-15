"""Safety controls and validation for Docker operations."""

import os
import re
import socket
from enum import Enum
from pathlib import Path
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

# Path validation constants
UNC_REQUIRED_COMPONENTS = 2  # UNC paths require server + share components (e.g., \\server\share)
SENSITIVE_CREDENTIAL_DIRECTORIES = [
    ".ssh",  # SSH keys for passwordless authentication
    ".gnupg",  # GPG keys for encryption and signing
    ".aws",  # AWS credentials and configuration
    ".kube",  # Kubernetes cluster credentials
    ".docker",  # Docker registry credentials
]

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

    Note: This function checks the path format after normalization by
    _normalize_mount_path(), which converts forward-slash Windows paths
    (like C:/Windows or //./pipe/docker_engine) to backslash equivalents.

    Args:
        path: Path to check

    Returns:
        True if Windows absolute path (C:\, D:\, C:, or UNC path), False otherwise
    """
    # Check for:
    # - Drive letter with separator: C:\, C:/
    # - Normalized drive root (no separator): C:, D:
    # - UNC paths: \\server\share or //server/share
    return bool(
        re.match(r"^[A-Za-z]:([/\\]|$)", path) or path.startswith("\\\\") or path.startswith("//")
    )


def _extract_windows_prefix(normalized: str, original_path: str) -> tuple[str, str]:
    """Extract Windows path prefix (drive letter or UNC) from normalized path.

    Args:
        normalized: Path with forward slashes
        original_path: Original path for fallback

    Returns:
        Tuple of (prefix, remaining_path)
    """
    if re.match(r"^[A-Za-z]:/", normalized):
        # Drive letter: C:, D:, etc. (without trailing slash)
        prefix = normalized[:2]  # e.g., "C:"
        remaining = normalized[3:]  # Rest of path after "C:/"
        return prefix, remaining

    if normalized.startswith("//"):
        # UNC path: //server/share (without trailing slash)
        parts = normalized[2:].split("/", UNC_REQUIRED_COMPONENTS)
        if len(parts) >= UNC_REQUIRED_COMPONENTS:
            prefix = f"//{parts[0]}/{parts[1]}"
            remaining = (
                parts[UNC_REQUIRED_COMPONENTS] if len(parts) > UNC_REQUIRED_COMPONENTS else ""
            )
            return prefix, remaining
        # Malformed UNC, return as-is
        return "", original_path.replace("\\", "/")

    # Should never happen if _is_windows_absolute_path was checked first
    return "", original_path.replace("\\", "/")


def _resolve_path_components(components: list[str]) -> list[str]:
    """Resolve . and .. components in a path.

    Args:
        components: List of path components

    Returns:
        List of resolved path components
    """
    resolved: list[str] = []
    for component in components:
        if component in {".", ""}:
            # Skip current directory and empty components
            continue
        if component == "..":
            # Go up one directory (if possible)
            if resolved:
                resolved.pop()
            # If resolved is empty, we can't go up further (already at drive root)
        else:
            # Normal directory/file name
            resolved.append(component)
    return resolved


def _normalize_windows_path(path: str) -> str:
    r"""Normalize a Windows path using Windows semantics, regardless of host OS.

    This function ensures Windows paths are properly normalized even when the MCP
    server runs on Linux/macOS. It resolves .. and . components, normalizes separators,
    and preserves drive letters - preventing path traversal attacks that bypass
    blocklist/allowlist checks.

    SECURITY: Without this, os.path.normpath on Linux fails to normalize Windows paths:
        - C:\safe\..\Windows becomes C:\safe\..\Windows (.. not resolved!)
        - C:/safe/../Windows becomes Windows (drive letter lost!)

    Args:
        path: Windows path to normalize (with drive letter or UNC prefix)

    Returns:
        Normalized Windows path with forward slashes (e.g., C:/Windows/System32)

    Examples:
        >>> _normalize_windows_path(r'C:\safe\..\Windows')
        'C:/Windows'
        >>> _normalize_windows_path('C:/safe/../../Windows')
        'C:/Windows'
        >>> _normalize_windows_path(r'D:\Users\.\alice\..\bob\data')
        'D:/Users/bob/data'
    """
    # Replace all backslashes with forward slashes for consistent processing
    normalized = path.replace("\\", "/")

    # Extract prefix (drive letter or UNC) - prefix should NOT include trailing slash
    prefix, remaining = _extract_windows_prefix(normalized, path)
    if not prefix:
        # No valid prefix found, return early
        return remaining

    # Split path into components and resolve . and ..
    components = remaining.split("/") if remaining else []
    resolved = _resolve_path_components(components)

    # Reconstruct path with prefix
    if resolved:
        # Add separator between prefix and resolved path components
        return prefix + "/" + "/".join(resolved)
    # Path resolved to root (e.g., C:/..)
    return prefix.rstrip("/")


def _is_root_match_for_blocklist(prefix_cmp: str, case_insensitive: bool) -> bool:
    """Check if normalized prefix represents a root filesystem for exact-match-only behavior.

    Root filesystems (/, C:, D:) require special handling in blocklists:
    - "/" in blocklist blocks "/" but not "/home"
    - "C:\\" in blocklist blocks "C:\\" but not "C:\\Users"

    This prevents overly broad blocking while still protecting against root mounts.

    Args:
        prefix_cmp: Normalized prefix (forward slashes, casefolded if Windows)
        case_insensitive: True if comparing Windows paths

    Returns:
        True if prefix is a root filesystem
    """
    is_unix_root = prefix_cmp == "/"
    is_windows_root = case_insensitive and bool(re.match(r"^[a-z]:/?$", prefix_cmp))
    return is_unix_root or is_windows_root


def _path_starts_with(
    path: str,
    prefix: str,
    case_insensitive: bool = False,
    exact_root_match_only: bool = False,
) -> bool:
    r"""Check if path starts with prefix, accounting for path separators.

    Special case for blocklists: When exact_root_match_only=True, root paths
    (/, C:\\, D:\\) only match exactly, not subdirectories. This allows blocking
    root filesystem mounts without blocking all subdirectories. For example,
    "/" in blocklist blocks "/" but allows "/home", and "C:\\" blocks "C:\\"
    but allows "C:\\Users".

    For allowlists: When exact_root_match_only=False, root paths match
    subdirectories normally. An allowlist entry of "/" permits all paths,
    and "C:\\" permits all paths on the C: drive.

    Args:
        path: Path to check
        prefix: Prefix to match against
        case_insensitive: If True, perform case-insensitive comparison (for Windows)
        exact_root_match_only: If True, root paths only match exactly (for blocklists)

    Returns:
        True if path starts with prefix
    """
    # For Windows paths (case_insensitive=True), normalize separators to forward slash
    # This ensures C:\Windows and C:/Windows both match
    if case_insensitive:
        path_cmp = path.replace("\\", "/").casefold()
        prefix_cmp = prefix.replace("\\", "/").casefold()
    else:
        path_cmp = path
        prefix_cmp = prefix

    # Exact match always returns True, no match returns False
    if path_cmp == prefix_cmp:
        return True
    if not path_cmp.startswith(prefix_cmp):
        return False

    # Special handling for root filesystems in blocklists - only exact match, no subdirectories
    # This allows "/" in blocklist to block mounting "/" without blocking "/home", etc.
    # Same for Windows drive roots (C:\, D:\, etc.) - block only the root, not subdirs
    # For allowlists (exact_root_match_only=False), treat roots as normal prefixes
    if exact_root_match_only and _is_root_match_for_blocklist(prefix_cmp, case_insensitive):
        return False

    # If prefix ends with a separator, any path starting with it matches
    ends_with_sep = (
        prefix_cmp.endswith("/") if case_insensitive else prefix_cmp.endswith(("/", "\\"))
    )
    if ends_with_sep:
        return True

    # Otherwise, check if the next character after prefix is a path separator
    # For Windows (normalized), check "/". For Unix, check both "/" and "\"
    if len(path_cmp) > len(prefix_cmp):
        next_char = path_cmp[len(prefix_cmp)]
        return next_char == "/" if case_insensitive else next_char in ("/", "\\")

    return False


def _is_root_filesystem(normalized_blocked: str, is_windows: bool) -> bool:
    """Check if a normalized path represents a root filesystem.

    Args:
        normalized_blocked: Normalized blocklist path to check
        is_windows: Whether this is a Windows path

    Returns:
        True if path is a root filesystem (/, C:, D:, etc.)
    """
    if normalized_blocked == "/":
        return True
    return is_windows and bool(re.match(r"^[A-Za-z]:$", normalized_blocked))


def _normalize_blocklist_entry(blocked: str) -> str:
    """Normalize a blocklist entry path.

    Args:
        blocked: Blocklist path to normalize

    Returns:
        Normalized blocklist path
    """
    if _is_windows_absolute_path(blocked):
        return _normalize_windows_path(blocked)
    return os.path.normpath(blocked)


def _convert_unc_admin_share_to_drive_letter(path: str) -> str:
    r"""Convert Windows UNC administrative shares to drive letter format.

    Windows UNC administrative shares provide direct access to drive roots:
    - \\localhost\C$ → C:\
    - \\127.0.0.1\D$ → D:\
    - \\hostname\C$ → C:\ (localhost only for security)

    This conversion is CRITICAL for security - without it, attackers can bypass
    the blocklist by using UNC admin share syntax instead of drive letters.

    Args:
        path: Path that may be a UNC admin share (with forward slashes after normalization)

    Returns:
        Drive letter path if UNC admin share to localhost, original path otherwise

    Examples:
        >>> _convert_unc_admin_share_to_drive_letter("//localhost/C$/Windows")
        'C:\\Windows'
        >>> _convert_unc_admin_share_to_drive_letter("//127.0.0.1/D$/data")
        'D:\\data'
        >>> _convert_unc_admin_share_to_drive_letter("//remotehost/C$/Windows")
        '//remotehost/C$/Windows'  # Not converted - remote host
    """
    # Match UNC admin share pattern: //localhost/C$ or //127.0.0.1/C$
    # After path normalization, UNC paths use forward slashes: //server/share/path
    # Only convert localhost/127.0.0.1 for security (prevent remote host access)
    match = re.match(r"^//([^/]+)/([A-Za-z])\$(/.*)?$", path, re.IGNORECASE)
    if not match:
        return path

    hostname = match.group(1).lower()
    drive_letter = match.group(2).upper()
    remaining_path = match.group(3) or ""

    # Only convert localhost references for security
    # Don't convert remote UNC paths like //server/C$ (different security domain)
    localhost_names = {"localhost", "127.0.0.1", "::1", socket.gethostname().lower()}
    if hostname not in localhost_names:
        return path

    # Convert to drive letter format: C:\Windows
    drive_path = f"{drive_letter}:{remaining_path}"
    return drive_path.replace("/", "\\")


def _raise_root_filesystem_error(path: str, blocked: str) -> None:
    """Raise error for blocked root filesystem mount.

    Args:
        path: Original path (for error message)
        blocked: Blocked path that matched

    Raises:
        UnsafeOperationError: Always raised with root filesystem message
    """
    raise UnsafeOperationError(
        f"Mount path '{path}' is blocked. "
        f"Mounting the root filesystem ({blocked}) could enable container escape. "
        "Enable SAFETY_YOLO_MODE=true to bypass."
    )


def _raise_blocklist_error(path: str, blocked: str) -> None:
    """Raise error for blocked path.

    Args:
        path: Original path (for error message)
        blocked: Blocked path that matched

    Raises:
        UnsafeOperationError: Always raised with standard blocklist message
    """
    raise UnsafeOperationError(
        f"Mount path '{path}' is blocked. "
        f"This path matches blocklist entry: {blocked}. "
        "Enable SAFETY_YOLO_MODE=true to bypass."
    )


def _check_blocklist(path: str, normalized: str, blocked_paths: list[str]) -> None:
    """Check if path is in blocklist and raise error if it is.

    Args:
        path: Original path (for error messages)
        normalized: Normalized and symlink-resolved path to check
        blocked_paths: List of blocked path prefixes

    Raises:
        UnsafeOperationError: If path is blocked
    """
    # SECURITY: Convert UNC admin shares to drive letters BEFORE blocklist check
    # This prevents bypass via \\localhost\C$\Windows when C:\Windows is blocked
    normalized = _convert_unc_admin_share_to_drive_letter(normalized)

    # Windows paths need case-insensitive comparison
    is_windows = _is_windows_absolute_path(normalized)

    for blocked in blocked_paths:
        # SECURITY: Normalize and resolve symlinks in blocklist entries
        # This prevents bypass when /var/run -> /run and blocklist has /var/run/docker.sock
        normalized_blocked = _normalize_blocklist_entry(blocked)
        resolved_blocked = _resolve_symlinks(normalized_blocked)

        if _path_starts_with(
            normalized, resolved_blocked, case_insensitive=is_windows, exact_root_match_only=True
        ):
            # Use casefold for comparison if Windows
            normalized_cmp = normalized.casefold() if is_windows else normalized
            blocked_cmp = resolved_blocked.casefold() if is_windows else resolved_blocked

            # Check if this is a root filesystem and exact match
            is_root = _is_root_filesystem(resolved_blocked, is_windows)
            if is_root and normalized_cmp == blocked_cmp:
                _raise_root_filesystem_error(path, blocked)

            # Standard blocklist error message
            _raise_blocklist_error(path, blocked)


def _check_allowlist(path: str, normalized: str, allowed_paths: list[str]) -> None:
    """Check if path is in allowlist and raise error if not.

    Args:
        path: Original path (for error messages)
        normalized: Normalized and symlink-resolved path to check
        allowed_paths: List of allowed path prefixes

    Raises:
        UnsafeOperationError: If path is not in allowlist
    """
    # SECURITY: Convert UNC admin shares to drive letters for consistent checking
    # This ensures \\localhost\C$\Users matches allowlist entry C:\Users
    normalized = _convert_unc_admin_share_to_drive_letter(normalized)

    # Windows paths need case-insensitive comparison
    is_windows = _is_windows_absolute_path(normalized)

    # SECURITY: Normalize and resolve symlinks in allowlist entries
    # This ensures consistent symlink handling between mount path and allowlist
    normalized_allowed = []
    for allowed in allowed_paths:
        if _is_windows_absolute_path(allowed):
            norm = _normalize_windows_path(allowed)
        else:
            norm = os.path.normpath(allowed)
        resolved = _resolve_symlinks(norm)
        normalized_allowed.append(resolved)

    # Note: exact_root_match_only=False (default) for allowlists
    # This allows "/" or "C:\" in allowlist to permit entire filesystems
    if not any(
        _path_starts_with(normalized, p, case_insensitive=is_windows) for p in normalized_allowed
    ):
        raise UnsafeOperationError(
            f"Mount path '{path}' is not in the allowed paths list. "
            "Configure SAFETY_VOLUME_MOUNT_ALLOWLIST to permit this path."
        )


def _check_sensitive_directories(path: str, normalized: str) -> None:
    """Check if path contains sensitive credential directories.

    Args:
        path: Original path (for error messages)
        normalized: Normalized path to check

    Raises:
        UnsafeOperationError: If path contains sensitive directories
    """
    normalized_lower = normalized.lower().replace("\\", "/")

    for sensitive in SENSITIVE_CREDENTIAL_DIRECTORIES:
        # Check for sensitive dir as path component (e.g., /home/user/.ssh or C:\Users\alice\.ssh)
        if f"/{sensitive}/" in normalized_lower or normalized_lower.endswith(f"/{sensitive}"):
            raise UnsafeOperationError(
                f"Mount path '{path}' contains sensitive directory '{sensitive}'. "
                f"Mounting credential directories could expose SSH keys, GPG keys, "
                f"cloud credentials, or Docker configs. Enable SAFETY_YOLO_MODE=true to bypass."
            )


def _convert_forward_slash_windows_prefix(path: str) -> str:
    r"""Convert Windows path with forward-slash prefix to backslash prefix.

    Handles Windows device namespace and extended-length prefixes that use
    forward slashes instead of backslashes.

    Args:
        path: Windows path with forward slash prefix (e.g., //./pipe or //?/C:/)

    Returns:
        Path with backslash prefix (e.g., \\.\pipe or \\?\C:\)
    """
    # Replace // prefix with \\, then convert all remaining / to \
    path = "\\\\" + path[2:]  # //./pipe → \\./pipe
    return path.replace("/", "\\")  # \\./pipe → \\.\pipe


def _normalize_mount_path(path: str) -> str:
    """Normalize a mount path using appropriate normalization for the path type.

    SECURITY: Handles both Unix path collapse and Windows forward-slash normalization
    to prevent blocklist bypass via alternative path separators.

    Args:
        path: Path to normalize

    Returns:
        Normalized path

    Raises:
        ValidationError: If path format is invalid
    """
    try:
        # SECURITY: Windows accepts forward slashes as path separators, so we must
        # normalize Windows-style paths with forward slashes BEFORE the Unix collapse.
        # Otherwise paths like //./pipe/docker_engine bypass the blocklist.

        # SECURITY: Windows UNC/device paths with forward slashes must be normalized
        # CRITICAL: Only recognize Windows-specific patterns to avoid misclassifying Unix paths
        # Real Windows UNC paths use backslashes: \\server\share
        # Forward-slash variants like //server/share are treated as Unix (POSIX allows //)
        if path.startswith("//"):
            # Windows device namespace: //./ or //./pipe/name → \\.\pipe\name
            if path.startswith("//./") or path.startswith("//?/"):
                path = _convert_forward_slash_windows_prefix(path)
            # Windows UNC admin share: //localhost/C$ or //127.0.0.1/C$
            # Preserve these for later conversion to drive letters
            elif re.match(r"^//[^/]+/[A-Za-z]\$", path):
                # Keep UNC admin shares as-is with forward slashes
                # Converted to drive letters by _convert_unc_admin_share_to_drive_letter()
                pass
            else:
                # All other //path forms are Unix duplicate slashes (POSIX-compliant)
                # Examples: //etc/passwd, //var/run, //server/share
                # On Unix, these resolve to /etc/passwd, /var/run, /server/share
                path = "/" + path.lstrip("/")
        # Check for Windows drive paths with forward slashes: C:/Windows → C:\Windows
        elif re.match(r"^[A-Za-z]:/", path):
            # Windows drive letter with forward slashes - convert to backslashes
            path = path.replace("/", "\\")

        if _is_windows_absolute_path(path):
            return _normalize_windows_path(path)
        return os.path.normpath(path)
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid path format: {path}") from e


def _resolve_symlinks(path: str) -> str:
    """Resolve symlinks in a path to get the real target path.

    SECURITY: Prevents symlink bypass attacks where an attacker creates a symlink
    pointing to a blocked path (e.g., /safe/link -> /etc/passwd) and mounts it.
    Without resolution, the symlink path passes validation but Docker mounts the
    real target, bypassing blocklist checks.

    Args:
        path: Normalized path to resolve

    Returns:
        Resolved path with symlinks followed, or original path if resolution fails

    Note:
        - Only resolves if path exists (Docker creates non-existent mount paths)
        - Returns original path on errors (permission denied, broken symlinks, etc.)
        - Preserves path format (Windows paths stay Windows, Unix stay Unix)
    """
    try:
        path_obj = Path(path)
        # Only resolve if path exists - Docker can mount non-existent paths
        # and will create them, so we shouldn't block them
        if path_obj.exists():
            # resolve() follows all symlinks and returns absolute path
            resolved = path_obj.resolve(strict=True)
            return str(resolved)
        # Path doesn't exist - return normalized path unchanged
        return path
    except (OSError, RuntimeError, ValueError):
        # Permission denied, broken symlink, infinite loop, etc.
        # Return original path - better to validate the literal path than fail
        return path


def validate_mount_path(
    path: str,
    allowed_paths: list[str] | None = None,
    blocked_paths: list[str] | None = None,
    yolo_mode: bool = False,
) -> None:
    r"""Validate that a mount path is safe.

    Implements volume mount security controls aligned with:
    - CIS Docker Benchmark v1.7.0 Section 5.5: Ensure sensitive host system
      directories are not mounted on containers
      https://www.cisecurity.org/benchmark/docker
    - OWASP Docker Security Cheat Sheet: Volume mount best practices
      https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

    Validates bind mount paths against security policies:
    - Blocklist: Prevents mounting dangerous paths (e.g., /var/run/docker.sock, /, /etc)
    - Allowlist: If set, only allows paths starting with specified prefixes
    - Windows support: Recognizes Windows absolute paths (C:\, D:\, etc.)
    - Symlink resolution: Follows symlinks to prevent bypass attacks
    - Path normalization: Prevents traversal attacks (../../etc/passwd)

    Security controls:
    1. Blocks sensitive system directories (/, /etc, /proc, /sys, /dev, /boot)
    2. Blocks Docker/containerd runtime directories (container escape prevention)
    3. Blocks credential directories (.ssh, .aws, .kube, .gnupg, .docker)
    4. Resolves symlinks to prevent bypassing blocklist via symbolic links
    5. Normalizes paths to prevent traversal attacks on both Unix and Windows

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
    # SECURITY: Use Windows-aware normalization for Windows paths to prevent
    # path traversal attacks. os.path.normpath uses host OS semantics, which
    # fails to normalize Windows paths on Linux (e.g., C:\safe\..\Windows
    # stays as C:\safe\..\Windows, bypassing blocklist checks).
    normalized = _normalize_mount_path(path)

    # SECURITY: Resolve symlinks to prevent bypass attacks
    # An attacker could create /safe/link -> /etc/passwd and mount it,
    # bypassing blocklist checks. Resolution ensures we validate the real target.
    resolved = _resolve_symlinks(normalized)

    # Check for sensitive directories anywhere in path (substring check)
    # These contain credentials/keys and should never be mounted
    _check_sensitive_directories(path, resolved)

    # Check blocklist (if provided)
    if blocked_paths is not None:
        _check_blocklist(path, resolved, blocked_paths)

    # Check allowlist (if provided)
    if allowed_paths is not None:
        _check_allowlist(path, resolved, allowed_paths)


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
