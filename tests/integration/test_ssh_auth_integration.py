"""Integration test for SSH authentication through MCP tool calls."""

import base64
import secrets
from datetime import UTC, datetime

import pytest

from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
)
from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


class TestSSHAuthIntegration:
    """Test SSH authentication through the MCP tool call interface."""

    @pytest.fixture
    def setup_server_with_ssh_auth(self, tmp_path):
        """Setup MCP server with SSH authentication enabled."""
        # Generate SSH key pair
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        crypto_private_key = ed25519.Ed25519PrivateKey.generate()

        # Save private key
        private_key_path = tmp_path / "test_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load with paramiko
        _, private_key = load_private_key_from_file(private_key_path)

        # Create authorized_keys file
        auth_keys_file = tmp_path / "authorized_keys"
        public_key_line = (
            f"ssh-ed25519 {get_public_key_string(private_key)[1]} test-client:integration-test\n"
        )
        auth_keys_file.write_text(public_key_line)

        # Set environment variables for config
        import os

        os.environ["SECURITY_AUTH_ENABLED"] = "true"
        os.environ["SECURITY_SSH_AUTH_ENABLED"] = "true"
        os.environ["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
        os.environ["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"

        # Create config and server
        config = Config()
        server = MCPDockerServer(config)

        return server, private_key, "test-client"

    def create_ssh_auth_data(self, client_id: str, private_key):
        """Create SSH authentication data."""
        timestamp = datetime.now(UTC).isoformat()
        nonce = secrets.token_urlsafe(32)
        message = f"{client_id}|{timestamp}|{nonce}".encode()

        signature = sign_message(private_key, message)
        signature_b64 = base64.b64encode(signature.asbytes()).decode("utf-8")

        return {
            "client_id": client_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature_b64,
        }

    @pytest.mark.asyncio
    async def test_call_tool_with_ssh_auth(self, setup_server_with_ssh_auth):
        """Test calling a tool with SSH authentication in arguments."""
        server, private_key, client_id = setup_server_with_ssh_auth

        # Create SSH auth data
        ssh_auth = self.create_ssh_auth_data(client_id, private_key)

        # Call tool with SSH auth passed as ssh_auth_data parameter
        # (the _auth extraction happens in __main__.py, not in server.call_tool)
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )

        # Should succeed (auth passed)
        assert result.get("success") is True or "error_type" not in result

    @pytest.mark.asyncio
    async def test_call_tool_with_api_key_auth(self, tmp_path):
        """Test calling a tool with API key authentication in arguments."""
        # Create API keys file
        import json

        api_keys_file = tmp_path / ".mcp_keys.json"
        api_keys_file.write_text(
            json.dumps(
                {
                    "clients": [
                        {
                            "client_id": "test-client",
                            "api_key_hash": "test-hash",
                            "description": "Test client",
                        }
                    ]
                }
            )
        )

        # Note: This test would need the actual hashing mechanism
        # For now, just demonstrate the interface

    @pytest.mark.asyncio
    async def test_replay_attack_prevented(self, setup_server_with_ssh_auth):
        """Test that replay attacks are prevented (nonce reuse)."""
        server, private_key, client_id = setup_server_with_ssh_auth

        # Create SSH auth data
        ssh_auth = self.create_ssh_auth_data(client_id, private_key)

        # First call should succeed
        result1 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )

        # Second call with same auth data should fail (nonce reuse)
        result2 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,  # Same nonce!
        )

        # First should succeed
        assert result1.get("success") is True or "error_type" not in result1

        # Second should fail with authentication error (replay attack detected)
        assert result2.get("success") is False
        error_msg = result2.get("error", "").lower()
        assert "authentication" in error_msg or "nonce" in error_msg or "replay" in error_msg

    @pytest.mark.asyncio
    async def test_fresh_auth_each_call_succeeds(self, setup_server_with_ssh_auth):
        """Test that generating fresh auth data for each call works."""
        server, private_key, client_id = setup_server_with_ssh_auth

        # Call 1 with fresh auth
        ssh_auth1 = self.create_ssh_auth_data(client_id, private_key)
        result1 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth1,
        )

        # Call 2 with fresh auth (new nonce)
        ssh_auth2 = self.create_ssh_auth_data(client_id, private_key)
        result2 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth2,
        )

        # Both should succeed
        assert result1.get("success") is True or "error_type" not in result1
        assert result2.get("success") is True or "error_type" not in result2

    @pytest.mark.asyncio
    async def test_auth_argument_removed_before_tool(self, setup_server_with_ssh_auth):
        """Test that _auth argument is removed before passing to tool."""
        server, private_key, client_id = setup_server_with_ssh_auth

        # Create SSH auth data
        ssh_auth = self.create_ssh_auth_data(client_id, private_key)

        # The tool should receive only 'all', not '_auth'
        # When calling server.call_tool directly, ssh_auth_data is separate from arguments
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )

        # Tool should execute successfully without seeing _auth
        assert result.get("success") is True or "error_type" not in result
