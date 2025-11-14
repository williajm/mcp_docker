"""Input validation utilities for Docker operations."""

import re
import shlex
from typing import Any

from mcp_docker.utils.errors import ValidationError

# Docker naming patterns based on Docker documentation
CONTAINER_NAME_PATTERN = re.compile(r"^/?[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")
IMAGE_NAME_PATTERN = re.compile(
    # optional registry (hostname[:port])
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[0-9]{1,5})?/)?"
    # optional namespace/repository
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    # name
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    # optional tag
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?\Z"
)
LABEL_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+\Z")

# Docker length limits
MAX_CONTAINER_NAME_LENGTH = 255  # Maximum container name length in Docker
MAX_IMAGE_NAME_LENGTH = 255  # Maximum image name length in Docker

# Input size limits (security: prevent resource exhaustion)
MAX_COMMAND_LENGTH = 65536  # 64 KB - maximum command string length
MAX_ENV_VAR_VALUE_LENGTH = 32768  # 32 KB - maximum environment variable value
MAX_PATH_LENGTH = 4096  # 4 KB - maximum file path length
MAX_LABEL_VALUE_LENGTH = 4096  # 4 KB - maximum label value

# Network port range
MIN_PORT = 1  # Minimum valid TCP/UDP port number
MAX_PORT = 65535  # Maximum valid TCP/UDP port number


def validate_container_name(name: str) -> str:
    """Validate Docker container name.

    Args:
        name: Container name to validate

    Returns:
        Validated container name

    Raises:
        ValidationError: If name is invalid

    """
    if not name:
        raise ValidationError("Container name cannot be empty")

    if len(name) > MAX_CONTAINER_NAME_LENGTH:
        raise ValidationError(
            f"Container name cannot exceed {MAX_CONTAINER_NAME_LENGTH} characters"
        )

    if not CONTAINER_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid container name: {name}. "
            "Must contain only alphanumeric characters, underscores, periods, and hyphens. "
            "Cannot start with a hyphen or period."
        )

    return name


def validate_image_name(name: str) -> str:
    """Validate Docker image name.

    Args:
        name: Image name to validate

    Returns:
        Validated image name

    Raises:
        ValidationError: If name is invalid

    """
    if not name:
        raise ValidationError("Image name cannot be empty")

    if len(name) > MAX_IMAGE_NAME_LENGTH:
        raise ValidationError(f"Image name cannot exceed {MAX_IMAGE_NAME_LENGTH} characters")

    if not IMAGE_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid image name: {name}. "
            "Must follow Docker image naming conventions (e.g., 'ubuntu', 'ubuntu:22.04', "
            "'registry.example.com/namespace/image:tag')."
        )

    return name


def validate_label(key: str, value: Any) -> tuple[str, str]:
    """Validate Docker label key-value pair.

    Args:
        key: Label key
        value: Label value

    Returns:
        Tuple of (validated_key, validated_value)

    Raises:
        ValidationError: If label is invalid

    """
    if not key:
        raise ValidationError("Label key cannot be empty")

    if not LABEL_KEY_PATTERN.match(key):
        raise ValidationError(
            f"Invalid label key: {key}. "
            "Must contain only alphanumeric characters, underscores, periods, and hyphens."
        )

    # Convert value to string
    value_str = str(value)

    return key, value_str


def validate_port(port: int | str) -> int:
    """Validate port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number as integer

    Raises:
        ValidationError: If port is invalid

    """
    try:
        port_int = int(port)
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid port: {port}. Must be an integer.") from e

    if not MIN_PORT <= port_int <= MAX_PORT:
        raise ValidationError(f"Invalid port: {port}. Must be between {MIN_PORT} and {MAX_PORT}.")

    return port_int


def validate_memory_string(memory: str) -> str:
    """Validate memory limit string.

    Args:
        memory: Memory limit (e.g., "512m", "2g")

    Returns:
        Validated memory string

    Raises:
        ValidationError: If memory format is invalid

    """
    if not memory:
        raise ValidationError("Memory limit cannot be empty")

    # Pattern: number followed by optional unit (b, k, m, g)
    pattern = re.compile(r"^\d+[bkmg]?\Z", re.IGNORECASE)

    if not pattern.match(memory):
        raise ValidationError(
            f"Invalid memory format: {memory}. "
            "Must be a number optionally followed by b, k, m, or g (e.g., '512m', '2g')."
        )

    return memory.lower()


def _validate_command_structure(command: str | list[str]) -> str | list[str]:
    """Validate command structure (string or list) without sanitization.

    This is a shared helper for command validation logic used by both
    sanitize_command and validate_command.

    Args:
        command: Command string or list

    Returns:
        Validated command (same type as input)

    Raises:
        ValidationError: If command structure is invalid

    """
    if isinstance(command, str):
        if not command.strip():
            raise ValidationError("Command cannot be empty")
        return command

    if isinstance(command, list):
        if not command:
            raise ValidationError("Command list cannot be empty")
        if not all(isinstance(item, str) for item in command):
            raise ValidationError("All command items must be strings")
        return command

    raise ValidationError("Command must be a string or list of strings")


def sanitize_command(command: str | list[str]) -> list[str]:
    """Sanitize command for Docker execution.

    Args:
        command: Command string or list

    Returns:
        Sanitized command as list

    Raises:
        ValidationError: If command is invalid

    """
    validated = _validate_command_structure(command)
    # Always return as list for Docker API
    return [validated] if isinstance(validated, str) else validated


def validate_command(command: str | list[str]) -> str | list[str]:
    """Validate command for Docker execution with security checks.

    Args:
        command: Command string or list

    Returns:
        Validated command (same type as input)

    Raises:
        ValidationError: If command is invalid or contains dangerous patterns

    """
    # Check command length to prevent resource exhaustion
    if isinstance(command, str):
        if len(command) > MAX_COMMAND_LENGTH:
            raise ValidationError(
                f"Command too long: {len(command)} bytes (max: {MAX_COMMAND_LENGTH})"
            )
    elif isinstance(command, list):
        total_length = sum(len(str(part)) for part in command)
        if total_length > MAX_COMMAND_LENGTH:
            raise ValidationError(
                f"Command too long: {total_length} bytes (max: {MAX_COMMAND_LENGTH})"
            )

    validated = _validate_command_structure(command)

    # Additional security checks for string commands
    if isinstance(validated, str):
        # Check for dangerous shell patterns
        dangerous_patterns = [";", "&&", "||", "|", "`", "$("]
        if any(pattern in validated for pattern in dangerous_patterns):
            raise ValidationError(
                "Command contains potentially dangerous patterns. "
                "Use list format for commands with special characters."
            )

        # SECURITY: Use stdlib shlex to verify command can be safely parsed
        # This catches malformed quotes, unterminated strings, etc.
        try:
            shlex.split(validated)
        except ValueError as e:
            raise ValidationError(f"Command has invalid shell syntax: {e}") from e

    return validated


def validate_memory(memory: str) -> str:
    """Validate memory limit string.

    Args:
        memory: Memory limit (e.g., "512m", "2g")

    Returns:
        Validated memory string

    Raises:
        ValidationError: If memory format is invalid

    """
    return validate_memory_string(memory)


def validate_port_mapping(container_port: str | int, host_port: int) -> tuple[str, int]:
    """Validate port mapping.

    Args:
        container_port: Container port (can include protocol like "80/tcp")
        host_port: Host port number

    Returns:
        Tuple of (validated_container_port, validated_host_port)

    Raises:
        ValidationError: If port mapping is invalid

    """
    # Validate host port
    validated_host_port = validate_port(host_port)

    # Validate container port
    if isinstance(container_port, str):
        # Could be "80" or "80/tcp"
        if "/" in container_port:
            port_str, protocol = container_port.split("/", 1)
            if protocol not in ["tcp", "udp", "sctp"]:
                raise ValidationError(
                    f"Invalid protocol: {protocol}. Must be 'tcp', 'udp', or 'sctp'."
                )
            validate_port(port_str)
            validated_container_port = container_port
        else:
            validate_port(container_port)
            validated_container_port = container_port
    else:
        validated_container_port = str(validate_port(container_port))

    return validated_container_port, validated_host_port
