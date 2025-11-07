#!/usr/bin/env python3
"""Example: Using SSH authentication with MCP Docker client.

This example demonstrates how to authenticate with MCP Docker using SSH keys
when calling tools through the MCP protocol.

Usage:
    python examples/ssh_auth_mcp_client.py

Requirements:
    pip install mcp
"""

import asyncio
import base64
import secrets
from datetime import UTC, datetime
from pathlib import Path

from mcp_docker.auth.ssh_signing import load_private_key_from_file, sign_message


def create_ssh_auth_data(client_id: str, private_key_path: Path) -> dict:
    """Create SSH authentication data for MCP tool calls.

    Args:
        client_id: Client identifier (must match authorized_keys)
        private_key_path: Path to SSH private key

    Returns:
        Dict with SSH auth data ready to include in tool calls
    """
    # Load private key
    _, private_key = load_private_key_from_file(private_key_path)

    # Generate challenge components
    timestamp = datetime.now(UTC).isoformat()
    nonce = secrets.token_urlsafe(32)  # 256 bits of entropy

    # Create message to sign: "client_id|timestamp|nonce"
    message = f"{client_id}|{timestamp}|{nonce}".encode("utf-8")

    # Sign message
    signature = sign_message(private_key, message)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64,
    }


async def main():
    """Demonstrate SSH authentication with MCP Docker."""
    print("=== MCP Docker SSH Authentication Example ===\n")

    # Configuration
    client_id = "my-client"
    private_key_path = Path.home() / ".ssh" / "mcp_client_key"

    if not private_key_path.exists():
        print(f"Error: Private key not found at {private_key_path}")
        print("\nRun this first:")
        print("  ./scripts/setup_ssh_auth.sh my-client")
        return

    # Create SSH authentication data
    print("Creating SSH authentication data...")
    ssh_auth = create_ssh_auth_data(client_id, private_key_path)
    print(f"  Client ID:  {ssh_auth['client_id']}")
    print(f"  Timestamp:  {ssh_auth['timestamp']}")
    print(f"  Nonce:      {ssh_auth['nonce'][:32]}...")
    print(f"  Signature:  {ssh_auth['signature'][:50]}...")

    print("\n=== Example MCP Tool Calls with SSH Auth ===\n")

    # Example 1: List containers with SSH auth
    print("1. List containers:")
    list_containers_call = {
        "_auth": {
            "ssh": ssh_auth  # Include SSH auth
        },
        "all": True,  # Actual tool argument
    }
    print("   Tool: list_containers")
    print("   Arguments:", list_containers_call)
    print()

    # Example 2: Inspect container with SSH auth
    print("2. Inspect container:")
    inspect_call = {
        "_auth": {
            "ssh": ssh_auth  # Include SSH auth
        },
        "container_id": "my-container",  # Actual tool argument
    }
    print("   Tool: inspect_container")
    print("   Arguments:", inspect_call)
    print()

    # Example 3: Pull image with SSH auth
    print("3. Pull image:")
    pull_call = {
        "_auth": {
            "ssh": ssh_auth  # Include SSH auth
        },
        "image": "nginx:latest",  # Actual tool argument
    }
    print("   Tool: pull_image")
    print("   Arguments:", pull_call)
    print()

    print("=== How to Use with MCP Client ===\n")
    print("Using stdio transport:")
    print("""
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="mcp-docker",
    args=["--transport", "stdio"],
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # Create auth data
        ssh_auth = create_ssh_auth_data("my-client", Path("~/.ssh/mcp_client_key"))

        # Call tool with auth
        result = await session.call_tool(
            "list_containers",
            arguments={
                "_auth": {"ssh": ssh_auth},
                "all": True
            }
        )
        print(result)
""")

    print("\nUsing SSE transport:")
    print("""
from mcp import ClientSession
from mcp.client.sse import sse_client

async with sse_client("http://localhost:8000/sse") as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # Create auth data
        ssh_auth = create_ssh_auth_data("my-client", Path("~/.ssh/mcp_client_key"))

        # Call tool with auth
        result = await session.call_tool(
            "list_containers",
            arguments={
                "_auth": {"ssh": ssh_auth},
                "all": True
            }
        )
        print(result)
""")

    print("\n=== Important Notes ===")
    print("1. Generate new auth data for EACH tool call (fresh timestamp & nonce)")
    print("2. The '_auth' argument is removed before passing to the tool")
    print("3. Nonces are tracked to prevent replay attacks (5-minute window)")
    print("4. You can also use API key auth instead:")
    print('   {"_auth": {"api_key": "your-api-key"}, "actual_arg": "value"}')


if __name__ == "__main__":
    asyncio.run(main())
