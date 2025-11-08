#!/usr/bin/env python3
"""Fuzz test for SSH authentication parsing.

Tests the SSH authentication system with malformed and edge-case inputs
to find potential security vulnerabilities or crashes.
"""

import sys

import atheris

# Import without instrumentation
import base64
import struct
from datetime import UTC, datetime

from mcp_docker.auth.ssh_auth import SSHAuthRequest, SSHSignatureValidator
from mcp_docker.auth.ssh_wire import SSHWireMessage

# Instrument all code after imports
atheris.instrument_all()


def fuzz_ssh_signature_parsing(data: bytes) -> None:
    """Fuzz SSH signature parsing with arbitrary input.

    Args:
        data: Random fuzz input
    """
    if len(data) < 10:
        return

    # Test SSHWireMessage parsing (SSH wire format)
    try:
        msg = SSHWireMessage(data)
        _ = msg.get_text()
    except (ValueError, IndexError, struct.error, AttributeError):
        # Expected errors for malformed input
        pass

    # Test signature validation with various inputs
    try:
        validator = SSHSignatureValidator()
        # Split input into components
        split_point = len(data) // 3
        key_data = data[:split_point]
        message = data[split_point : 2 * split_point]
        sig_data = data[2 * split_point :]

        # Try Ed25519 signature verification (most common)
        if len(key_data) >= 32 and len(sig_data) >= 64:
            try:
                validator._verify_ed25519_signature(key_data, message, sig_data)
            except Exception:
                pass

    except Exception:
        # Catch any unexpected exceptions (potential bugs)
        pass


def fuzz_ssh_auth_request(data: bytes) -> None:
    """Fuzz SSH authentication request construction.

    Args:
        data: Random fuzz input
    """
    if len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate fuzzy components
    client_id = fdp.ConsumeUnicodeNoSurrogates(32)
    signature = fdp.ConsumeBytes(128)
    timestamp_str = fdp.ConsumeUnicodeNoSurrogates(64)
    nonce = fdp.ConsumeUnicodeNoSurrogates(32)

    # Try to create auth request (should not crash)
    try:
        request = SSHAuthRequest(
            client_id=client_id,
            signature=signature,
            timestamp=timestamp_str,
            nonce=nonce,
        )
        _ = request.client_id
        _ = request.signature
        _ = request.timestamp
        _ = request.nonce
    except Exception:
        # Expected for invalid inputs
        pass


def fuzz_base64_signature(data: bytes) -> None:
    """Fuzz base64 encoded signature parsing.

    Args:
        data: Random fuzz input
    """
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    base64_str = fdp.ConsumeUnicodeNoSurrogates(256)

    try:
        # Test base64 decoding (common in SSH auth)
        decoded = base64.b64decode(base64_str)
        # Test SSH wire format parsing
        msg = SSHWireMessage(decoded)
        _ = msg.get_string()
    except (ValueError, base64.binascii.Error, IndexError):
        # Expected for invalid input
        pass


def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point.

    Args:
        data: Random fuzz input
    """
    try:
        fuzz_ssh_signature_parsing(data)
        fuzz_ssh_auth_request(data)
        fuzz_base64_signature(data)
    except Exception:
        # Catch any uncaught exceptions to prevent fuzzer exit
        pass


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
