"""Integration tests for API key authentication through MCP server.

These tests validate API key authentication at the server level by calling
server.call_tool() directly with API key auth, bypassing the MCP transport layer.
"""

import json
from typing import Any

import pytest

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def api_key_test_env(tmp_path: Any) -> Any:
    """Setup API key authentication environment for testing.

    Returns:
        Tuple of (server, api_key, client_id)
    """
    # Create API keys file
    api_keys_file = tmp_path / ".mcp_keys.json"
    api_key = "test-api-key-12345-secure"
    client_id = "test-client"

    keys_data = {
        "clients": [
            {
                "api_key": api_key,
                "client_id": client_id,
                "description": "Test client for integration testing",
                "enabled": True,
            }
        ]
    }
    api_keys_file.write_text(json.dumps(keys_data, indent=2))

    # Create config with API key auth enabled
    config = Config()
    config.security.auth_enabled = True
    config.security.api_keys_file = api_keys_file
    config.security.ssh_auth_enabled = False  # Only API key auth
    config.docker.base_url = "unix:///var/run/docker.sock"

    # Create server
    server = MCPDockerServer(config)

    return server, api_key, client_id


@pytest.fixture
def skip_if_no_docker() -> Any:
    """Fail test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.fail(f"Docker is required for integration tests but is not available: {e}")


class TestAPIKeyAuthIntegration:
    """Integration tests for API key authentication."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_valid_api_key_authentication(
        self, api_key_test_env: Any, skip_if_no_docker: Any
    ) -> None:
        """Integration test: Valid API key authenticates successfully.

        Scenario:
        1. Setup server with API key auth enabled
        2. Call tool with valid API key
        3. Verify operation succeeds
        """
        server, api_key, client_id = api_key_test_env

        # Call tool with valid API key
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key,
        )

        # Should succeed
        assert result.get("success") is True, f"Failed with valid API key: {result.get('error')}"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_invalid_api_key_authentication(
        self, api_key_test_env: Any, skip_if_no_docker: Any
    ) -> None:
        """Integration test: Invalid API key is rejected.

        Scenario:
        1. Setup server with API key auth enabled
        2. Call tool with invalid API key
        3. Verify operation fails with authentication error
        """
        server, api_key, client_id = api_key_test_env

        # Call tool with WRONG API key
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key="wrong-api-key-invalid",
        )

        # Should fail
        assert result.get("success") is False, "Invalid API key should be rejected"
        error_msg = result.get("error", "").lower()
        assert "authentication" in error_msg or "api key" in error_msg or "invalid" in error_msg, (
            f"Expected authentication error, got: {result.get('error')}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_missing_api_key_authentication(
        self, api_key_test_env: Any, skip_if_no_docker: Any
    ) -> None:
        """Integration test: Missing API key is rejected.

        Scenario:
        1. Setup server with API key auth enabled
        2. Call tool without providing API key
        3. Verify operation fails with authentication error
        """
        server, api_key, client_id = api_key_test_env

        # Call tool with NO API key
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=None,  # No key provided
        )

        # Should fail
        assert result.get("success") is False, "Missing API key should be rejected"
        error_msg = result.get("error", "").lower()
        assert "authentication" in error_msg or "api key" in error_msg or "required" in error_msg, (
            f"Expected authentication error, got: {result.get('error')}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_disabled_api_key_authentication(
        self, tmp_path: Any, skip_if_no_docker: Any
    ) -> None:
        """Integration test: Disabled API key is rejected.

        Scenario:
        1. Setup server with a disabled API key
        2. Call tool with the disabled key
        3. Verify operation fails
        """
        # Create API keys file with disabled key
        api_keys_file = tmp_path / ".mcp_keys.json"
        api_key = "disabled-key-12345"

        keys_data = {
            "clients": [
                {
                    "api_key": api_key,
                    "client_id": "disabled-client",
                    "description": "Disabled client",
                    "enabled": False,  # Disabled!
                }
            ]
        }
        api_keys_file.write_text(json.dumps(keys_data, indent=2))

        # Create config
        config = Config()
        config.security.auth_enabled = True
        config.security.api_keys_file = api_keys_file
        config.docker.base_url = "unix:///var/run/docker.sock"

        server = MCPDockerServer(config)

        # Call tool with disabled key
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key,
        )

        # Should fail
        assert result.get("success") is False, "Disabled API key should be rejected"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_multiple_api_keys(self, tmp_path: Any, skip_if_no_docker: Any) -> None:
        """Integration test: Multiple API keys work independently.

        Scenario:
        1. Setup server with multiple API keys
        2. Call tools with different keys
        3. Verify all valid keys work
        """
        # Create API keys file with multiple keys
        api_keys_file = tmp_path / ".mcp_keys.json"
        api_key1 = "client1-api-key"
        api_key2 = "client2-api-key"

        keys_data = {
            "clients": [
                {
                    "api_key": api_key1,
                    "client_id": "client1",
                    "description": "Client 1",
                    "enabled": True,
                },
                {
                    "api_key": api_key2,
                    "client_id": "client2",
                    "description": "Client 2",
                    "enabled": True,
                },
            ]
        }
        api_keys_file.write_text(json.dumps(keys_data, indent=2))

        # Create config
        config = Config()
        config.security.auth_enabled = True
        config.security.api_keys_file = api_keys_file
        config.docker.base_url = "unix:///var/run/docker.sock"

        server = MCPDockerServer(config)

        # Test with client1's key
        result1 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key1,
        )
        assert result1.get("success") is True, "Client 1 key should work"

        # Test with client2's key
        result2 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key2,
        )
        assert result2.get("success") is True, "Client 2 key should work"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_api_key_reload(self, tmp_path: Any, skip_if_no_docker: Any) -> None:
        """Integration test: API keys can be reloaded without restart.

        Scenario:
        1. Setup server with one API key
        2. Verify key works
        3. Add new key to file
        4. Reload keys
        5. Verify new key works
        """
        # Create API keys file
        api_keys_file = tmp_path / ".mcp_keys.json"
        api_key1 = "initial-api-key"

        keys_data = {
            "clients": [
                {
                    "api_key": api_key1,
                    "client_id": "client1",
                    "description": "Initial client",
                    "enabled": True,
                }
            ]
        }
        api_keys_file.write_text(json.dumps(keys_data, indent=2))

        # Create config and server
        config = Config()
        config.security.auth_enabled = True
        config.security.api_keys_file = api_keys_file
        config.docker.base_url = "unix:///var/run/docker.sock"

        server = MCPDockerServer(config)

        # Test initial key works
        result1 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key1,
        )
        assert result1.get("success") is True, "Initial key should work"

        # Add new key to file
        api_key2 = "new-api-key"
        keys_data["clients"].append(
            {
                "api_key": api_key2,
                "client_id": "client2",
                "description": "New client",
                "enabled": True,
            }
        )
        api_keys_file.write_text(json.dumps(keys_data, indent=2))

        # Reload keys
        server.auth_middleware.reload_keys()

        # Test new key works
        result2 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key2,
        )
        assert result2.get("success") is True, "New key should work after reload"

        # Verify old key still works
        result3 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key1,
        )
        assert result3.get("success") is True, "Old key should still work after reload"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_api_key_docker_operations(
        self, api_key_test_env: Any, skip_if_no_docker: Any
    ) -> None:
        """Integration test: API key auth works for multiple Docker operations.

        Scenario:
        1. Authenticate with API key
        2. Perform multiple Docker operations
        3. Verify all succeed with same API key
        """
        server, api_key, client_id = api_key_test_env

        # List containers
        result1 = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            api_key=api_key,
        )
        assert result1.get("success") is True, "List containers should work"

        # System info
        result2 = await server.call_tool(
            tool_name="docker_system_info",
            arguments={},
            api_key=api_key,
        )
        assert result2.get("success") is True, "System info should work"

        # Healthcheck
        result3 = await server.call_tool(
            tool_name="docker_healthcheck",
            arguments={},
            api_key=api_key,
        )
        assert result3.get("success") is True, "Healthcheck should work"

        # List images
        result4 = await server.call_tool(
            tool_name="docker_list_images",
            arguments={},
            api_key=api_key,
        )
        assert result4.get("success") is True, "List images should work"
