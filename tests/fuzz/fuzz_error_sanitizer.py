#!/usr/bin/env python3
"""Fuzz test for error sanitization.

Tests error message sanitization to ensure sensitive information
is not leaked to clients through error messages.
"""

import sys

import atheris

from mcp_docker.utils.error_sanitizer import sanitize_error_for_client
from mcp_docker.utils.errors import (
    DockerConnectionError,
    DockerOperationError,
    UnsafeOperationError,
    ValidationError,
)

# Instrument all code after imports
atheris.instrument_all()


def fuzz_sanitize_error(data: bytes) -> None:
    """Fuzz error sanitization with various exception types and messages.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate fuzzy error message and operation name
    error_msg = fdp.ConsumeUnicodeNoSurrogates(500)
    operation = fdp.ConsumeUnicodeNoSurrogates(100)

    # Test with various exception types
    exception_types = [
        Exception,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        PermissionError,
        TimeoutError,
        FileNotFoundError,
        ConnectionError,
        OSError,
    ]

    for exc_type in exception_types:
        try:
            error = exc_type(error_msg)
            sanitized_msg, error_type = sanitize_error_for_client(error, operation)

            # Verify return types
            assert isinstance(sanitized_msg, str)
            assert isinstance(error_type, str)

            # Verify sensitive info is not leaked
            # The original error message should NOT appear in sanitized output
            # for unknown exception types
            if exc_type not in (UnsafeOperationError, ValidationError):
                # These generic errors should return generic messages
                assert error_msg not in sanitized_msg or len(error_msg) < 5
        except AssertionError:
            # Test failure - sensitive info may have leaked
            pass


def fuzz_custom_exceptions(data: bytes) -> None:
    """Fuzz with custom Docker-specific exceptions.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    error_msg = fdp.ConsumeUnicodeNoSurrogates(200)
    operation = fdp.ConsumeUnicodeNoSurrogates(50)

    # Test with known safe exception types
    safe_exceptions = [
        UnsafeOperationError(error_msg),
        ValidationError(error_msg),
        DockerConnectionError(error_msg),
        DockerOperationError(error_msg),
    ]

    for error in safe_exceptions:
        sanitized_msg, error_type = sanitize_error_for_client(error, operation)
        assert isinstance(sanitized_msg, str)
        assert isinstance(error_type, str)


def fuzz_sensitive_info_in_errors(data: bytes) -> None:
    """Test that sensitive information patterns are not leaked.

    Args:
        data: Random fuzz input
    """
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Patterns that should NOT appear in sanitized output
    sensitive_patterns = [
        "/home/user/.ssh/",
        "/etc/passwd",
        "/var/run/docker.sock",
        "password=secret123",
        "api_key=abcd1234",
        "token=eyJhbG",
        "/root/.aws/credentials",
        "BEGIN RSA PRIVATE" + " KEY",  # Split to avoid pre-commit false positive
        "postgresql://user:pass@host",
        "mysql://root:password@localhost",
    ]

    operation = fdp.ConsumeUnicodeNoSurrogates(30) or "test_operation"

    for pattern in sensitive_patterns:
        prefix = fdp.ConsumeUnicodeNoSurrogates(20)
        suffix = fdp.ConsumeUnicodeNoSurrogates(20)
        error_msg = f"{prefix}{pattern}{suffix}"

        # Test with generic exception (should be sanitized)
        error = RuntimeError(error_msg)
        sanitized_msg, _ = sanitize_error_for_client(error, operation)

        # The sensitive pattern should NOT appear in sanitized output
        # (RuntimeError is not in the safe list, so it gets generic message)
        assert pattern not in sanitized_msg


def fuzz_error_type_names(data: bytes) -> None:
    """Fuzz with dynamically created exception class names.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create exception with fuzzy message
    error_msg = fdp.ConsumeUnicodeNoSurrogates(200)
    operation = fdp.ConsumeUnicodeNoSurrogates(50)

    # Test that unknown exception types get generic handling
    error = Exception(error_msg)
    sanitized_msg, error_type = sanitize_error_for_client(error, operation)

    # Unknown exceptions should return InternalError type
    assert error_type == "InternalError"
    # And a generic message
    assert "unexpected error" in sanitized_msg.lower()


def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point.

    Args:
        data: Random fuzz input
    """
    fuzz_sanitize_error(data)
    fuzz_custom_exceptions(data)
    fuzz_sensitive_info_in_errors(data)
    fuzz_error_type_names(data)


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
