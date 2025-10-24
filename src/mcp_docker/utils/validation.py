"""Input validation utilities for Docker operations."""

import re
from typing import Any

from mcp_docker.utils.errors import ValidationError

# Docker naming patterns based on Docker documentation
CONTAINER_NAME_PATTERN = re.compile(r"^/?[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
IMAGE_NAME_PATTERN = re.compile(
    # optional registry (hostname[:port])
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[0-9]{1,5})?/)?"
    # optional namespace/repository
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    # name
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    # optional tag
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?$"
)
LABEL_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")


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

    if len(name) > 255:
        raise ValidationError("Container name cannot exceed 255 characters")

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

    if len(name) > 255:
        raise ValidationError("Image name cannot exceed 255 characters")

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

    if not 1 <= port_int <= 65535:
        raise ValidationError(f"Invalid port: {port}. Must be between 1 and 65535.")

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
    pattern = re.compile(r"^\d+[bkmg]?$", re.IGNORECASE)

    if not pattern.match(memory):
        raise ValidationError(
            f"Invalid memory format: {memory}. "
            "Must be a number optionally followed by b, k, m, or g (e.g., '512m', '2g')."
        )

    return memory.lower()


def sanitize_command(command: str | list[str]) -> list[str]:
    """Sanitize command for Docker execution.

    Args:
        command: Command string or list

    Returns:
        Sanitized command as list

    Raises:
        ValidationError: If command is invalid

    """
    if isinstance(command, str):
        # Basic shell command splitting (not perfect, but safe)
        if not command.strip():
            raise ValidationError("Command cannot be empty")
        return [command]

    if isinstance(command, list):
        if not command:
            raise ValidationError("Command list cannot be empty")
        if not all(isinstance(item, str) for item in command):
            raise ValidationError("All command items must be strings")
        return command

    raise ValidationError("Command must be a string or list of strings")
