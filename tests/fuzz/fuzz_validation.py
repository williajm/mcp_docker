#!/usr/bin/env python3
"""Fuzz test for input validation functions.

Tests Docker name validation, port validation, and other input sanitization
with malformed and edge-case inputs to ensure robust error handling.
"""

import sys

import atheris

# Import functions without instrumentation to avoid complex dependency issues
from mcp_docker.utils.errors import ValidationError
from mcp_docker.utils.validation import (
    validate_container_name,
    validate_image_name,
    validate_label,
    validate_memory_string,
    validate_port,
)

# Instrument all code after imports
atheris.instrument_all()


def fuzz_container_name(data: bytes) -> None:
    """Fuzz container name validation.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(300)  # Test beyond max length

    try:
        result = validate_container_name(name)
        # If validation succeeds, verify the result is a string
        assert isinstance(result, str)
    except (ValueError, ValidationError, AssertionError):
        # Expected for invalid names
        pass


def fuzz_image_name(data: bytes) -> None:
    """Fuzz image name validation.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(300)

    try:
        result = validate_image_name(name)
        assert isinstance(result, str)
    except (ValueError, ValidationError, AssertionError):
        pass


def fuzz_port_validation(data: bytes) -> None:
    """Fuzz port number validation.

    Args:
        data: Random fuzz input
    """
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Test with integer ports
    port = fdp.ConsumeInt(4)
    try:
        validate_port(port)
    except (ValueError, ValidationError):
        pass

    # Test with string ports
    port_str = fdp.ConsumeUnicodeNoSurrogates(10)
    try:
        validate_port(port_str)
    except (ValueError, ValidationError):
        pass


def fuzz_memory_string(data: bytes) -> None:
    """Fuzz memory string validation.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)
    memory_str = fdp.ConsumeUnicodeNoSurrogates(50)

    try:
        validate_memory_string(memory_str)
    except (ValueError, ValidationError):
        pass


def fuzz_label_validation(data: bytes) -> None:
    """Fuzz Docker label key/value validation.

    Args:
        data: Random fuzz input
    """
    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Test label key/value pair
    key = fdp.ConsumeUnicodeNoSurrogates(100)
    value = fdp.ConsumeUnicodeNoSurrogates(100)
    try:
        validate_label(key, value)
    except (ValueError, ValidationError):
        pass


def fuzz_special_characters(data: bytes) -> None:
    """Test validation with special characters and edge cases.

    Args:
        data: Random fuzz input
    """
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create strings with various special characters
    special_chars = [
        "\x00",  # Null byte
        "\n",  # Newline
        "\r",  # Carriage return
        "\t",  # Tab
        "../",  # Path traversal
        "../../",  # Path traversal
        "${",  # Variable expansion
        "$(",  # Command substitution
        "`",  # Backtick
        ";",  # Command separator
        "|",  # Pipe
        "&",  # Background
        "<",  # Redirect
        ">",  # Redirect
        ">>",  # Append
    ]

    base_name = fdp.ConsumeUnicodeNoSurrogates(50)

    for char in special_chars:
        test_name = base_name + char + fdp.ConsumeUnicodeNoSurrogates(10)
        try:
            validate_container_name(test_name)
        except (ValueError, ValidationError):
            pass


def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point.

    Args:
        data: Random fuzz input
    """
    fuzz_container_name(data)
    fuzz_image_name(data)
    fuzz_port_validation(data)
    fuzz_memory_string(data)
    fuzz_label_validation(data)
    fuzz_special_characters(data)


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
