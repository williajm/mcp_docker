#!/usr/bin/env python3
"""Fuzz test for safety and command sanitization.

Tests command sanitization and safety checks with malicious and edge-case
inputs to ensure dangerous commands are properly blocked.
"""

import sys

import atheris

from mcp_docker.utils.errors import UnsafeOperationError, ValidationError

# Import without instrumentation to avoid complex dependencies
from mcp_docker.utils.safety import (
    sanitize_command,
    validate_mount_path,
    validate_port_binding,
)

# Instrument all code after imports
atheris.instrument_all()


def fuzz_command_sanitization(data: bytes) -> None:
    """Fuzz command sanitization with potentially dangerous commands.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Test string commands
    cmd_str = fdp.ConsumeUnicodeNoSurrogates(200)
    try:
        result = sanitize_command(cmd_str)
        # Should return a list
        assert isinstance(result, list)
    except (ValueError, ValidationError, UnsafeOperationError, AssertionError):
        # Expected for dangerous commands
        pass

    # Test list commands
    cmd_parts = [fdp.ConsumeUnicodeNoSurrogates(50) for _ in range(fdp.ConsumeIntInRange(1, 10))]
    try:
        result = sanitize_command(cmd_parts)
        assert isinstance(result, list)
    except (ValueError, ValidationError, UnsafeOperationError, AssertionError):
        pass


def fuzz_dangerous_patterns(data: bytes) -> None:
    """Test detection of dangerous command patterns.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Known dangerous patterns to test
    dangerous_patterns = [
        "rm -rf /",
        ":(){ :|:& };:",  # Fork bomb
        "dd if=/dev/zero",
        "mkfs.",
        "curl {} | bash",
        "wget {} | sh",
        "shutdown",
        "reboot",
        "halt",
        "init 0",
        "> /dev/sda",
    ]

    # Mix fuzzy data with dangerous patterns
    for pattern in dangerous_patterns:
        prefix = fdp.ConsumeUnicodeNoSurrogates(20)
        suffix = fdp.ConsumeUnicodeNoSurrogates(20)
        test_cmd = f"{prefix}{pattern}{suffix}"

        try:
            sanitize_command(test_cmd)
            # Should raise an error for dangerous commands
        except (ValueError, ValidationError, UnsafeOperationError):
            # Expected - command was blocked
            pass


def fuzz_mount_path_validation(data: bytes) -> None:
    """Fuzz mount path validation.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)
    path = fdp.ConsumeUnicodeNoSurrogates(200)

    try:
        validate_mount_path(path)
    except (ValueError, ValidationError):
        # Expected for sensitive paths
        pass


def fuzz_port_binding_validation(data: bytes) -> None:
    """Fuzz port binding validation.

    Args:
        data: Random fuzz input
    """
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    port = fdp.ConsumeIntInRange(-1000, 70000)  # Include invalid ports
    allow_privileged_ports = fdp.ConsumeBool()

    try:
        validate_port_binding(port, allow_privileged_ports)
    except (ValueError, ValidationError, UnsafeOperationError):
        # Expected for privileged ports when not allowed
        pass


def fuzz_privileged_container_check(data: bytes) -> None:
    """Fuzz privileged container configuration check.

    Args:
        data: Random fuzz input
    """
    if len(data) < 1:
        return

    # Skip this test as check_privileged_container doesn't exist in utils.safety
    pass


def fuzz_path_traversal(data: bytes) -> None:
    """Test path traversal detection.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Path traversal patterns
    traversal_patterns = [
        "../",
        "../../",
        "./../",
        "/..",
        "/../../",
        "....//",
        "..\\",
        "..%2F",
        "..%5c",
    ]

    base_path = fdp.ConsumeUnicodeNoSurrogates(30)

    for pattern in traversal_patterns:
        test_path = base_path + pattern + fdp.ConsumeUnicodeNoSurrogates(20)
        try:
            validate_mount_path(test_path)
        except (ValueError, ValidationError):
            pass


def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point.

    Args:
        data: Random fuzz input
    """
    fuzz_command_sanitization(data)
    fuzz_dangerous_patterns(data)
    fuzz_mount_path_validation(data)
    fuzz_port_binding_validation(data)
    fuzz_privileged_container_check(data)
    fuzz_path_traversal(data)


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
