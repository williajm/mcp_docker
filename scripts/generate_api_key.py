#!/usr/bin/env python3
"""Generate a secure API key for MCP Docker server.

This script generates a cryptographically secure API key that can be used
in the .mcp_keys.json configuration file.
"""

import secrets


def generate_api_key() -> str:
    """Generate a cryptographically secure API key.

    Returns:
        A URL-safe base64-encoded key (32 bytes = 43 characters)
    """
    return secrets.token_urlsafe(32)


def main() -> None:
    """Generate and print an API key."""
    key = generate_api_key()
    print("Generated API Key:")
    print("=" * 60)
    print(key)
    print("=" * 60)
    print()
    print("Add this to your .mcp_keys.json file:")
    print()
    print('{')
    print('  "api_key": "' + key + '",')
    print('  "client_id": "your-client-id",')
    print('  "description": "Description of this client",')
    print('  "enabled": true')
    print('}')
    print()
    print("IMPORTANT: Keep this key secure and never commit it to version control!")


if __name__ == "__main__":
    main()
