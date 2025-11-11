"""Error message sanitization to prevent information disclosure.

This module provides utilities to sanitize error messages before sending them to clients,
preventing leakage of sensitive information such as file paths, internal details,
container IDs, and system architecture.
"""

from pydantic import ValidationError

from mcp_docker.utils.errors import (
    DockerConnectionError,
    DockerOperationError,
    UnsafeOperationError,
)


def sanitize_error_for_client(error: Exception, operation: str) -> tuple[str, str]:
    """Sanitize error messages to prevent information disclosure.

    Args:
        error: The exception that occurred
        operation: The operation that failed (tool name or operation description)

    Returns:
        Tuple of (sanitized_error_message, error_type_for_client)
    """
    # Check known safe exception types FIRST (before string-based matching)
    # These errors have user-facing messages that are safe to expose
    if isinstance(error, UnsafeOperationError):
        # UnsafeOperationError messages are designed for users
        return str(error), "PermissionDenied"

    if isinstance(error, ValidationError):
        # ValidationError messages are safe (no internal details)
        return str(error), "ValidationError"

    if isinstance(error, DockerConnectionError):
        return "Docker daemon is unavailable or unreachable", "ServiceUnavailable"

    if isinstance(error, DockerOperationError):
        return f"Operation '{operation}' failed", "OperationFailed"

    # Now check string-based mappings for other error types
    error_type = type(error).__name__

    # Map internal errors to safe, generic messages
    # These reveal minimal information while still being useful to clients
    safe_error_mappings = {
        "DockerConnectionError": (
            "Docker daemon is unavailable or unreachable",
            "ServiceUnavailable",
        ),
        "ContainerNotFound": (
            "The specified container was not found",
            "ResourceNotFound",
        ),
        "ImageNotFound": (
            "The specified image was not found",
            "ResourceNotFound",
        ),
        "NetworkNotFound": (
            "The specified network was not found",
            "ResourceNotFound",
        ),
        "VolumeNotFound": (
            "The specified volume was not found",
            "ResourceNotFound",
        ),
        "DockerOperationError": (
            f"Operation '{operation}' failed",
            "OperationFailed",
        ),
        "UnsafeOperationError": (
            str(error),  # These messages are safe to expose (designed for users)
            "OperationBlocked",
        ),
        "ValidationError": (
            str(error),  # Pydantic validation errors are safe (no internal details)
            "ValidationError",
        ),
        "ValueError": (
            # Generic message to prevent info disclosure
            f"Invalid input parameter for operation '{operation}'",
            "InvalidInput",
        ),
        "KeyError": (
            f"Required parameter missing for operation '{operation}'",
            "InvalidInput",
        ),
        "TypeError": (
            f"Invalid parameter type for operation '{operation}'",
            "InvalidInput",
        ),
        "PermissionError": (
            "Permission denied for this operation",
            "PermissionDenied",
        ),
        "TimeoutError": (
            f"Operation '{operation}' timed out",
            "Timeout",
        ),
        "RateLimitExceeded": (
            str(error),  # Rate limit messages are safe to expose
            "RateLimitExceeded",
        ),
    }

    # Check if we have a safe mapping for this error type
    if error_type in safe_error_mappings:
        return safe_error_mappings[error_type]

    # For unknown/unexpected errors, return completely generic message
    # The full error details are logged server-side for debugging
    return f"An unexpected error occurred during '{operation}'", "InternalError"


def is_error_safe_to_expose(error: Exception) -> bool:
    """Check if an error message is safe to expose to clients.

    Args:
        error: The exception to check

    Returns:
        True if the error message can be safely shown to clients
    """
    # These error types are designed with user-facing messages
    safe_types = (
        UnsafeOperationError,
        ValidationError,
    )

    return isinstance(error, safe_types)
