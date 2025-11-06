#!/usr/bin/env python3
"""Example: Authenticating with MCP Docker using SSH keys.

This example demonstrates how to:
1. Generate an SSH key pair
2. Sign an authentication challenge
3. Send SSH authentication request to MCP server
4. Execute Docker operations after authentication

Usage:
    python examples/ssh_auth_client.py
"""

import base64
import secrets
from datetime import UTC, datetime
from pathlib import Path

from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
)


def generate_ssh_keypair(key_path: Path) -> tuple[Path, Path]:
    """Generate SSH Ed25519 key pair.

    Args:
        key_path: Path to save private key

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    print(f"Generating SSH Ed25519 key pair...")

    # Generate Ed25519 key using cryptography library
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    crypto_key = ed25519.Ed25519PrivateKey.generate()

    # Save private key in OpenSSH format
    private_pem = crypto_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(private_pem)
    print(f"  Private key: {key_path}")

    # Get public key in SSH format
    key_type, private_key = load_private_key_from_file(key_path)
    pub_key_type, pub_key_b64 = get_public_key_string(private_key)

    # Save public key
    public_key_path = key_path.with_suffix(".pub")
    with public_key_path.open("w") as f:
        f.write(f"{pub_key_type} {pub_key_b64} my-client:example-key\n")
    print(f"  Public key:  {public_key_path}")

    return key_path, public_key_path


def sign_ssh_challenge(private_key_path: Path, client_id: str) -> dict[str, str]:
    """Sign authentication challenge with SSH private key.

    Args:
        private_key_path: Path to SSH private key
        client_id: Client identifier

    Returns:
        Dict with auth data: client_id, timestamp, nonce, signature
    """
    print(f"\nSigning authentication challenge...")

    # Load private key
    key_type, private_key = load_private_key_from_file(private_key_path)
    print(f"  Key type: {key_type}")

    # Generate challenge components
    timestamp = datetime.now(UTC).isoformat()
    nonce = secrets.token_urlsafe(32)  # 256 bits of entropy

    # Create message to sign: "client_id|timestamp|nonce"
    message = f"{client_id}|{timestamp}|{nonce}".encode("utf-8")
    print(f"  Message: {message.decode()}")

    # Sign message using our SSH signing module
    signature = sign_message(private_key, message)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    print(f"  Signature: {signature_b64[:50]}...")

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64,
    }


def demonstrate_ssh_auth():
    """Demonstrate complete SSH authentication flow."""
    print("=== MCP Docker SSH Authentication Example ===\n")

    # Step 1: Generate SSH key pair
    key_path = Path("/tmp/mcp_test_key")
    if key_path.exists():
        print(f"Using existing key: {key_path}")
    else:
        private_key, public_key = generate_ssh_keypair(key_path)

    # Step 2: Sign authentication challenge
    client_id = "my-client"
    auth_data = sign_ssh_challenge(key_path, client_id)

    # Step 3: Display authentication data
    print("\n=== Authentication Data ===")
    print(f"Client ID:  {auth_data['client_id']}")
    print(f"Timestamp:  {auth_data['timestamp']}")
    print(f"Nonce:      {auth_data['nonce'][:32]}...")
    print(f"Signature:  {auth_data['signature'][:50]}...")

    # Step 4: Instructions for server setup
    print("\n=== Server Setup Instructions ===")
    print("1. Add public key to authorized_keys:")
    print(f"   cat {key_path}.pub >> ~/.ssh/mcp_authorized_keys")
    print()
    print("2. Enable SSH authentication in .env:")
    print("   SECURITY_AUTH_ENABLED=true")
    print("   SECURITY_SSH_AUTH_ENABLED=true")
    print("   SECURITY_SSH_AUTHORIZED_KEYS_FILE=~/.ssh/mcp_authorized_keys")
    print()
    print("3. Send authentication request to MCP server:")
    print("   POST /authenticate")
    print("   Body:", auth_data)

    # Step 5: Example of sending request (pseudo-code)
    print("\n=== Example Request (pseudo-code) ===")
    print(
        """
    import httpx

    response = httpx.post(
        "http://localhost:8000/authenticate",
        json={
            "method": "ssh",
            "client_id": "%s",
            "timestamp": "%s",
            "nonce": "%s",
            "signature": "%s"
        }
    )

    if response.status_code == 200:
        print("Authentication successful!")
        # Now you can make Docker operations
    else:
        print(f"Authentication failed: {response.text}")
    """
        % (
            auth_data["client_id"],
            auth_data["timestamp"],
            auth_data["nonce"][:30] + "...",
            auth_data["signature"][:30] + "...",
        )
    )


if __name__ == "__main__":
    demonstrate_ssh_auth()
