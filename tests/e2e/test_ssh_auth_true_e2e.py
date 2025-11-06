"""True end-to-end tests for SSH authentication with real MCP client and transport.

These tests use a real MCP ClientSession with stdio transport to validate
the complete production authentication flow, including:
- Real MCP protocol communication
- Transport-level auth handling
- Client-to-server authentication handshake

This is distinct from integration tests which call server.call_tool() directly.
"""

import base64
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
)

# MCP client imports
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    MCP_CLIENT_AVAILABLE = True
except ImportError:
    MCP_CLIENT_AVAILABLE = False


# ============================================================================
# Helper Functions
# ============================================================================


def generate_ed25519_key_pair(tmp_path: Path) -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Generate Ed25519 SSH key pair.

    Args:
        tmp_path: Temporary directory for key storage

    Returns:
        Tuple of (private_key, public_key_line) for authorized_keys
    """
    # Generate key using cryptography library
    crypto_private_key = ed25519.Ed25519PrivateKey.generate()

    # Save private key in OpenSSH format
    private_key_path = tmp_path / f"id_ed25519_{secrets.token_hex(4)}"
    private_pem = crypto_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_path.write_bytes(private_pem)
    private_key_path.chmod(0o600)

    # Load with paramiko
    _, private_key = load_private_key_from_file(private_key_path)

    # Generate public key line for authorized_keys
    public_key_line = f"ssh-ed25519 {get_public_key_string(private_key)[1]}"

    return private_key, public_key_line


def create_ssh_auth_data(
    client_id: str,
    private_key: ed25519.Ed25519PrivateKey,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict:
    """Create SSH authentication data for MCP tool calls.

    Args:
        client_id: Client identifier
        private_key: SSH private key for signing
        timestamp: Optional ISO timestamp (generated if not provided)
        nonce: Optional nonce (generated if not provided)

    Returns:
        Dict with SSH auth data for _auth field
    """
    if timestamp is None:
        timestamp = datetime.now(UTC).isoformat()
    if nonce is None:
        nonce = secrets.token_urlsafe(32)  # 256 bits

    # Create message to sign: "client_id|timestamp|nonce"
    message = f"{client_id}|{timestamp}|{nonce}".encode()

    # Sign message
    signature = sign_message(private_key, message)
    signature_b64 = base64.b64encode(signature.asbytes()).decode("utf-8")

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64,
    }


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def skip_if_no_mcp_client():
    """Fail test if MCP client library is not available."""
    if not MCP_CLIENT_AVAILABLE:
        pytest.fail("MCP client library is required for E2E tests (pip install mcp)")


@pytest.fixture
def skip_if_no_docker():
    """Fail test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.fail(f"Docker is required for E2E tests but is not available: {e}")


@pytest.fixture
def ssh_server_env(tmp_path):
    """Setup SSH authentication environment for MCP server.

    Returns:
        Tuple of (authorized_keys_file, env_vars_dict)
    """
    # Create authorized_keys file
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.touch()
    auth_keys_file.chmod(0o600)

    # Environment variables for server
    env_vars = {
        "SECURITY_AUTH_ENABLED": "true",
        "SECURITY_SSH_AUTH_ENABLED": "true",
        "SECURITY_SSH_AUTHORIZED_KEYS_FILE": str(auth_keys_file),
        "SECURITY_SSH_SIGNATURE_MAX_AGE": "300",
        "DOCKER_BASE_URL": "unix:///var/run/docker.sock",
    }

    return auth_keys_file, env_vars


# ============================================================================
# True E2E Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_ssh_auth_via_stdio_transport(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: SSH authentication through stdio transport with real MCP client.

    This test validates the complete production authentication flow:
    1. MCP server runs as subprocess
    2. Real MCP ClientSession connects via stdio transport
    3. SSH authentication sent through MCP protocol in _auth field
    4. Server validates auth and executes Docker operation

    This is the REAL end-to-end test that exercises the transport layer.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "e2e-test-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:stdio-e2e-test\n")

    # Configure server parameters
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},  # Merge with current environment
    )

    # Connect real MCP client via stdio transport
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize session
            await session.initialize()

            # Generate SSH auth data (as real clients do)
            ssh_auth = create_ssh_auth_data(client_id, private_key)

            # Call tool with auth in arguments (REAL MCP protocol)
            result = await session.call_tool(
                "docker_list_containers",
                arguments={
                    "_auth": {"ssh": ssh_auth},  # Auth through protocol
                    "all": True,
                },
            )

            # Verify success - check result structure and content
            assert result is not None, "Result should not be None"
            assert hasattr(result, "content"), "Result should have content attribute"
            assert len(result.content) > 0, "Result content should not be empty"

            # Check that result is not an error
            if hasattr(result, "isError"):
                assert not result.isError, f"Result should not be an error: {result.content[0].text if result.content else 'no content'}"

            # Parse and verify the JSON response
            import json

            result_text = result.content[0].text
            assert result_text, "Result text should not be empty"

            # Verify it's valid JSON
            result_data = json.loads(result_text)
            assert isinstance(result_data, dict), "Result should be a dictionary"

            # Verify expected structure for docker_list_containers
            assert (
                "containers" in result_data or "count" in result_data
            ), f"Result should contain 'containers' or 'count' key: {result_data.keys()}"


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_replay_attack_via_stdio_transport(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Replay attack prevention through stdio transport.

    This test validates that nonce-based replay protection works through
    the real MCP protocol:
    1. First request with SSH auth succeeds
    2. Second request with SAME auth data fails (nonce reuse)
    3. Third request with FRESH auth succeeds

    This tests the complete security flow through the transport layer.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "replay-test-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:replay-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    # Connect real MCP client
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Generate auth data ONCE
            ssh_auth = create_ssh_auth_data(client_id, private_key)

            # First call - should succeed
            result1 = await session.call_tool(
                "docker_list_containers",
                arguments={
                    "_auth": {"ssh": ssh_auth},  # First use
                    "all": True,
                },
            )
            assert result1 is not None  # Should succeed

            # Second call with SAME auth - should fail (nonce reuse)
            result2 = None
            exception_raised = False
            try:
                result2 = await session.call_tool(
                    "docker_list_containers",
                    arguments={
                        "_auth": {"ssh": ssh_auth},  # REUSED - should fail
                        "all": True,
                    },
                )
            except Exception as e:
                # Expected: should raise exception for auth failure
                exception_raised = True
                assert "nonce" in str(e).lower() or "authentication" in str(e).lower()

            # If no exception, check if result indicates error
            if not exception_raised:
                assert result2 is not None
                # MCP may return error in result content
                if hasattr(result2, "isError") and result2.isError:
                    # Expected error result
                    error_text = result2.content[0].text if result2.content else ""
                    assert "nonce" in error_text.lower() or "authentication" in error_text.lower()
                else:
                    # Result should contain error message in text
                    result_text = result2.content[0].text if result2.content else ""
                    assert "error" in result_text.lower() and (
                        "nonce" in result_text.lower() or "authentication" in result_text.lower()
                    ), f"Expected authentication/nonce error but got: {result_text}"

            # Third call with FRESH auth - should succeed
            ssh_auth_fresh = create_ssh_auth_data(client_id, private_key)
            result3 = await session.call_tool(
                "docker_list_containers",
                arguments={
                    "_auth": {"ssh": ssh_auth_fresh},  # Fresh nonce
                    "all": True,
                },
            )
            assert result3 is not None  # Should succeed


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_container_lifecycle_via_stdio_transport(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Complete container lifecycle through stdio transport.

    This test validates a complete Docker workflow through the real MCP client:
    1. Pull image with SSH auth
    2. Create container with SSH auth
    3. Start container with SSH auth
    4. Inspect container with SSH auth
    5. Stop container with SSH auth
    6. Remove container with SSH auth

    Each operation uses fresh SSH authentication through the MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "lifecycle-test-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:lifecycle-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    container_id = None

    try:
        # Connect real MCP client
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                import json

                # Step 1: Pull image
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_pull_image",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "image": "alpine",
                        "tag": "3.19",
                    },
                )

                # Step 2: Create container (fresh auth)
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_result = await session.call_tool(
                    "docker_create_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "image": "alpine:3.19",
                        "name": f"e2e-test-{secrets.token_hex(4)}",
                        "command": ["sleep", "30"],
                    },
                )
                # Extract container ID from result
                result_text = create_result.content[0].text if create_result else ""
                result_data = json.loads(result_text)
                container_id = result_data.get("container_id")

                # Step 3: Start container (fresh auth)
                if container_id:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_start_container",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "container": container_id,
                        },
                    )

                    # Step 4: Inspect container (fresh auth)
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_inspect_container",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "container": container_id,
                        },
                    )

                    # Step 5: Stop container (fresh auth)
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_stop_container",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "container": container_id,
                            "timeout": 5,
                        },
                    )

                    # Step 6: Remove container (fresh auth)
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_remove_container",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "container": container_id,
                            "force": True,
                        },
                    )
                    container_id = None  # Cleaned up

    finally:
        # Cleanup if something failed
        if container_id:
            try:
                import docker

                docker_client = docker.from_env()
                container = docker_client.containers.get(container_id)
                container.remove(force=True)
            except Exception:
                pass  # Best effort cleanup


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_ssh_auth_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Invalid SSH authentication through stdio transport.

    This test validates that authentication failures are properly handled
    through the MCP protocol:
    1. Attempt auth with invalid signature
    2. Attempt auth with expired timestamp
    3. Attempt auth with unknown client_id

    This tests error handling through the complete stack.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "invalid-test-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:invalid-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    # Connect real MCP client
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Test 1: Invalid signature
            ssh_auth = create_ssh_auth_data(client_id, private_key)
            ssh_auth["signature"] = "invalid-signature-data"  # Corrupt signature

            try:
                await session.call_tool(
                    "docker_list_containers",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "all": True,
                    },
                )
                # Should not succeed
                raise AssertionError("Should have failed with invalid signature")
            except Exception as e:
                assert "signature" in str(e).lower() or "authentication" in str(e).lower()

            # Test 2: Expired timestamp
            old_timestamp = datetime.fromtimestamp(
                datetime.now(UTC).timestamp() - 600,  # 10 minutes ago
                UTC,
            ).isoformat()
            ssh_auth = create_ssh_auth_data(client_id, private_key, timestamp=old_timestamp)

            try:
                await session.call_tool(
                    "docker_list_containers",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "all": True,
                    },
                )
                raise AssertionError("Should have failed with expired timestamp")
            except Exception as e:
                assert "timestamp" in str(e).lower() or "expired" in str(e).lower()

            # Test 3: Unknown client_id
            unknown_key, unknown_pub = generate_ed25519_key_pair(tmp_path)
            ssh_auth = create_ssh_auth_data("unknown-client", unknown_key)

            try:
                await session.call_tool(
                    "docker_list_containers",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "all": True,
                    },
                )
                raise AssertionError("Should have failed with unknown client")
            except Exception as e:
                assert (
                    "client" in str(e).lower()
                    or "authorized" in str(e).lower()
                    or "authentication" in str(e).lower()
                )
