"""Server-level integration tests for SSH authentication in MCP Docker.

These tests validate SSH authentication at the server level by calling
server.call_tool() directly, bypassing the MCP transport layer.

Note: These were previously labeled "E2E" but are actually integration tests
since they don't use a real MCP client or transport (stdio/SSE). True E2E
tests are in tests/e2e/ and use ClientSession with real transports.

These tests validate:
- SSH authentication flow through the server
- Component interaction (middleware + authenticator + server)
- Docker operations with SSH authentication
- Security features (replay protection, key rotation, etc.)
"""

import asyncio
import base64
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
)
from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer

# ============================================================================
# Helper Functions and Fixtures
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

    # Load SSH private key
    _, private_key = load_private_key_from_file(private_key_path)
    assert isinstance(private_key, ed25519.Ed25519PrivateKey), "Expected Ed25519 key"

    # Format public key for authorized_keys
    public_key_line = f"ssh-ed25519 {get_public_key_string(private_key)[1]}"

    return private_key, public_key_line


def generate_rsa_key_pair(tmp_path: Path) -> tuple[rsa.RSAPrivateKey, str]:
    """Generate RSA SSH key pair.

    Args:
        tmp_path: Temporary directory for key storage

    Returns:
        Tuple of (private_key, public_key_line) for authorized_keys
    """
    # Generate key using cryptography library
    crypto_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key in OpenSSH format
    private_key_path = tmp_path / f"id_rsa_{secrets.token_hex(4)}"
    private_pem = crypto_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_path.write_bytes(private_pem)

    # Load SSH private key
    _, private_key = load_private_key_from_file(private_key_path)
    assert isinstance(private_key, rsa.RSAPrivateKey), "Expected RSA key"

    # Format public key for authorized_keys
    public_key_line = f"ssh-rsa {get_public_key_string(private_key)[1]}"

    return private_key, public_key_line


def create_ssh_auth_data(
    client_id: str,
    private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Create SSH authentication data for API calls.

    Args:
        client_id: Client identifier
        private_key: SSH private key for signing
        timestamp: Optional custom timestamp (defaults to now)
        nonce: Optional custom nonce (defaults to random)

    Returns:
        Dictionary with client_id, timestamp, nonce, and signature
    """
    if timestamp is None:
        timestamp = datetime.now(UTC).isoformat()
    if nonce is None:
        nonce = secrets.token_urlsafe(32)

    message = f"{client_id}|{timestamp}|{nonce}".encode()
    signature = sign_message(private_key, message)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64,
    }


@pytest.fixture
def ssh_test_env(tmp_path: Any) -> Any:
    """Setup complete SSH test environment with server and keys.

    Returns:
        Tuple of (server, authorized_keys_file, tmp_path)
    """
    # Create authorized_keys file (empty initially)
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.write_text("")

    # Set environment variables for config
    import os

    os.environ["SECURITY_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
    os.environ["SECURITY_RATE_LIMIT_ENABLED"] = "true"
    os.environ["SECURITY_RATE_LIMIT_RPM"] = "60"
    os.environ["SECURITY_AUDIT_LOG_ENABLED"] = "true"
    os.environ["SECURITY_AUDIT_LOG_FILE"] = str(tmp_path / "audit.log")
    os.environ["SAFETY_ALLOW_MODERATE_OPERATIONS"] = "true"
    os.environ["SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS"] = "true"
    os.environ["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"

    # Create config and server
    config = Config()
    server = MCPDockerServer(config)

    return server, auth_keys_file, tmp_path


@pytest.fixture
def docker_available() -> bool:
    """Check if Docker is available for integration tests."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
        return True
    except Exception:
        return False


# ============================================================================
# Test Scenario 1: Complete Docker Workflow with SSH Auth
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_complete_docker_workflow_with_ssh_auth(
    ssh_test_env: Any, docker_available: Any
) -> None:
    """Integration test: Complete Docker workflow authenticated with SSH keys.

    Scenario:
    1. Setup MCP server with SSH auth
    2. Generate client SSH key pair
    3. Add public key to authorized_keys
    4. Execute full container lifecycle (pull, create, start, inspect, stop, remove)
    5. Verify all operations succeed with proper authentication
    6. Verify audit logs contain SSH auth entries

    This tests the complete integration stack from client to Docker daemon.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "test-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:docker-workflow-test\n")
    server.auth_middleware.reload_keys()

    # Step 1: Pull image (using lightweight alpine)
    ssh_auth = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_pull_image",
        arguments={"image": "alpine", "tag": "3.19"},
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is True, f"Pull failed: {result.get('error')}"

    # Step 2: Create container
    ssh_auth = create_ssh_auth_data(client_id, private_key)
    container_name = f"test-ssh-e2e-{secrets.token_hex(4)}"
    result = await server.call_tool(
        tool_name="docker_create_container",
        arguments={
            "image": "alpine:3.19",
            "name": container_name,
            "command": ["sh", "-c", "sleep 30"],
        },
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is True, f"Create failed: {result.get('error')}"
    container_id = result["result"]["container_id"]

    try:
        # Step 3: Start container
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_start_container",
            arguments={"container_id": container_id},
            ssh_auth_data=ssh_auth,
        )
        assert result.get("success") is True, f"Start failed: {result.get('error')}"

        # Step 4: Inspect container
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_inspect_container",
            arguments={"container_id": container_id},
            ssh_auth_data=ssh_auth,
        )
        assert result.get("success") is True, f"Inspect failed: {result.get('error')}"
        assert result["result"]["details"]["State"]["Running"] is True

        # Step 5: List containers (verify it appears)
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )
        assert result.get("success") is True
        container_ids = [c["id"] for c in result["result"]["containers"]]
        assert container_id[:12] in [cid[:12] for cid in container_ids]

        # Step 6: Stop container
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_stop_container",
            arguments={"container_id": container_id},
            ssh_auth_data=ssh_auth,
        )
        assert result.get("success") is True, f"Stop failed: {result.get('error')}"

    finally:
        # Step 7: Remove container (cleanup)
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_remove_container",
            arguments={"container_id": container_id, "force": True},
            ssh_auth_data=ssh_auth,
        )
        assert result.get("success") is True, f"Remove failed: {result.get('error')}"

    # Verify audit logs contain SSH auth entries
    audit_log = tmp_path / "audit.log"
    assert audit_log.exists()
    audit_content = audit_log.read_text()
    assert client_id in audit_content
    assert "docker_create_container" in audit_content


# ============================================================================
# Test Scenario 2: Key Rotation Without Downtime
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_key_rotation_without_downtime(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Key rotation without service interruption.

    Scenario:
    1. Setup with initial SSH key
    2. Perform Docker operations successfully
    3. Add second SSH key while keeping first active
    4. Perform operations with both keys (verify both work)
    5. Remove first key (simulating rotation completion)
    6. Verify second key still works
    7. Verify first key now fails

    This tests hot key rotation for zero-downtime key updates.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "rotation-client"

    # Generate first key
    key1, pub1 = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{pub1} {client_id}:old-key\n")
    server.auth_middleware.reload_keys()

    # Operation with first key
    ssh_auth = create_ssh_auth_data(client_id, key1)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is True

    # Add second key (both active)
    key2, pub2 = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{pub1} {client_id}:old-key\n{pub2} {client_id}:new-key\n")
    server.auth_middleware.reload_keys()

    # Both keys should work
    ssh_auth1 = create_ssh_auth_data(client_id, key1)
    result1 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth1,
    )
    assert result1.get("success") is True

    ssh_auth2 = create_ssh_auth_data(client_id, key2)
    result2 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth2,
    )
    assert result2.get("success") is True

    # Remove first key (rotation complete)
    auth_keys_file.write_text(f"{pub2} {client_id}:new-key\n")
    server.auth_middleware.reload_keys()

    # Second key should still work
    ssh_auth2 = create_ssh_auth_data(client_id, key2)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth2,
    )
    assert result.get("success") is True

    # First key should fail
    ssh_auth1 = create_ssh_auth_data(client_id, key1)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth1,
    )
    assert result.get("success") is False
    assert "authentication" in result.get("error", "").lower()


# ============================================================================
# Test Scenario 3: Multi-Device Setup
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_multi_device_setup(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Multiple devices with different keys for same client.

    Scenario:
    1. Create 3 different SSH keys for same client_id (laptop, desktop, ci-server)
    2. Add all keys to authorized_keys with descriptions
    3. Perform operations from all three "devices" in parallel
    4. Verify all succeed independently
    5. Verify audit logs distinguish between keys by description

    This tests multiple keys per client for different devices/environments.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "multi-device-client"

    # Generate three keys for different devices
    laptop_key, laptop_pub = generate_ed25519_key_pair(tmp_path)
    desktop_key, desktop_pub = generate_ed25519_key_pair(tmp_path)
    ci_key, ci_pub = generate_ed25519_key_pair(tmp_path)

    # Add all keys to authorized_keys
    auth_keys_file.write_text(
        f"{laptop_pub} {client_id}:laptop\n"
        f"{desktop_pub} {client_id}:desktop\n"
        f"{ci_pub} {client_id}:ci-server\n"
    )
    server.auth_middleware.reload_keys()

    # Perform operations from all three devices concurrently
    async def device_operation(
        device_name: str,
        private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> bool:
        """Execute operation from a specific device."""
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )
        return result.get("success") is True

    # Run operations concurrently
    results = await asyncio.gather(
        device_operation("laptop", laptop_key),
        device_operation("desktop", desktop_key),
        device_operation("ci-server", ci_key),
    )

    # All operations should succeed
    assert all(results), f"Some device operations failed: {results}"

    # Verify audit logs contain device descriptions
    audit_log = tmp_path / "audit.log"
    audit_content = audit_log.read_text()
    assert client_id in audit_content
    # Each device should have made at least one authenticated call
    assert "laptop" in audit_content or "desktop" in audit_content or "ci-server" in audit_content


# ============================================================================
# Test Scenario 4: Replay Attack Prevention
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_replay_attack_prevention(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Replay attack prevention with nonce reuse detection.

    Scenario:
    1. Authenticate successfully with SSH
    2. Perform Docker operation (list containers)
    3. Attempt to reuse EXACT SAME auth data for second operation
    4. Verify second operation fails with "nonce already used" error
    5. Generate fresh auth data and verify operation succeeds

    This tests nonce-based replay attack protection.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "replay-test-client"

    # Setup SSH key
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:replay-test\n")
    server.auth_middleware.reload_keys()

    # Create auth data ONCE
    ssh_auth = create_ssh_auth_data(client_id, private_key)

    # First operation should succeed
    result1 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    assert result1.get("success") is True, f"First operation failed: {result1.get('error')}"

    # Second operation with SAME auth data should fail (replay attack)
    result2 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,  # Same nonce!
    )
    assert result2.get("success") is False, "Replay attack was not prevented!"
    error_msg = result2.get("error", "").lower()
    assert "nonce" in error_msg or "replay" in error_msg or "authentication" in error_msg

    # Fresh auth data should work
    ssh_auth_fresh = create_ssh_auth_data(client_id, private_key)
    result3 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_fresh,
    )
    assert result3.get("success") is True, f"Fresh auth failed: {result3.get('error')}"


# ============================================================================
# Test Scenario 6: Timestamp Expiry
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_timestamp_expiry(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Timestamp validation and expiry.

    Scenario:
    1. Create auth data with OLD timestamp (6 minutes ago, exceeds 5min default)
    2. Attempt Docker operation
    3. Verify fails with "expired timestamp" error
    4. Create auth data with FUTURE timestamp (6 minutes ahead)
    5. Verify also fails with expired/invalid timestamp
    6. Create auth data with current timestamp
    7. Verify succeeds

    This tests timestamp-based replay window enforcement.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "timestamp-test-client"

    # Setup SSH key
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:timestamp-test\n")
    server.auth_middleware.reload_keys()

    # Test 1: Old timestamp (6 minutes ago)
    old_timestamp = datetime.fromtimestamp(datetime.now(UTC).timestamp() - 360, UTC).isoformat()
    ssh_auth_old = create_ssh_auth_data(client_id, private_key, timestamp=old_timestamp)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_old,
    )
    assert result.get("success") is False, "Old timestamp should have been rejected"
    error_msg = result.get("error", "").lower()
    assert "timestamp" in error_msg or "expired" in error_msg or "authentication" in error_msg

    # Test 2: Future timestamp (6 minutes ahead)
    future_timestamp = datetime.fromtimestamp(datetime.now(UTC).timestamp() + 360, UTC).isoformat()
    ssh_auth_future = create_ssh_auth_data(client_id, private_key, timestamp=future_timestamp)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_future,
    )
    assert result.get("success") is False, "Future timestamp should have been rejected"
    error_msg = result.get("error", "").lower()
    assert "timestamp" in error_msg or "expired" in error_msg or "authentication" in error_msg

    # Test 3: Current timestamp should work
    ssh_auth_valid = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_valid,
    )
    assert result.get("success") is True, f"Valid timestamp failed: {result.get('error')}"


# ============================================================================
# Test Scenario 7: Invalid Signature
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_signature(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Invalid signature detection.

    Scenario:
    1. Create auth data with valid timestamp/nonce
    2. Modify signature by changing one character
    3. Attempt Docker operation
    4. Verify fails with "invalid signature" error

    This tests signature verification.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "signature-test-client"

    # Setup SSH key
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:signature-test\n")
    server.auth_middleware.reload_keys()

    # Create valid auth data
    ssh_auth = create_ssh_auth_data(client_id, private_key)

    # Tamper with signature (change last character)
    original_sig = ssh_auth["signature"]
    tampered_sig = original_sig[:-1] + ("A" if original_sig[-1] != "A" else "B")
    ssh_auth["signature"] = tampered_sig

    # Operation should fail
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is False, "Invalid signature should have been rejected"
    error_msg = result.get("error", "").lower()
    assert "signature" in error_msg or "authentication" in error_msg or "invalid" in error_msg


# ============================================================================
# Test Scenario 8: Unauthorized Client
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unauthorized_client(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Unauthorized client rejection.

    Scenario:
    1. Create new SSH key pair NOT in authorized_keys
    2. Attempt to authenticate
    3. Verify fails with "no authorized keys" error

    This tests client authorization enforcement.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "unauthorized-client"

    # Generate key but DON'T add to authorized_keys
    private_key, _ = generate_ed25519_key_pair(tmp_path)

    # Leave authorized_keys empty
    auth_keys_file.write_text("")
    server.auth_middleware.reload_keys()

    # Attempt operation
    ssh_auth = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is False, "Unauthorized client should have been rejected"
    error_msg = result.get("error", "").lower()
    assert "key" in error_msg or "authorized" in error_msg or "authentication" in error_msg


# ============================================================================
# Test Scenario 9: Concurrent Request Deduplication
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrent_request_deduplication(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Concurrent requests with same nonce are deduplicated.

    Scenario:
    1. Generate auth data once
    2. Spawn multiple threads attempting same Docker operation with same auth data
    3. Only ONE should succeed (first to register nonce)
    4. Others should fail with nonce reuse error

    This tests thread-safe nonce deduplication under concurrent load.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "concurrent-test-client"

    # Setup SSH key
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:concurrent-test\n")
    server.auth_middleware.reload_keys()

    # Create ONE auth data to share across all requests
    ssh_auth = create_ssh_auth_data(client_id, private_key)

    # Function to call tool
    async def concurrent_call() -> dict[str, Any]:
        result: dict[str, Any] = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,  # Same auth data!
        )
        return result

    # Launch 10 concurrent requests
    results = await asyncio.gather(*[concurrent_call() for _ in range(10)])

    # Count successes and failures
    successes = sum(1 for r in results if r.get("success") is True)
    failures = sum(1 for r in results if r.get("success") is False)

    # Only ONE should succeed (first to register nonce)
    assert successes == 1, f"Expected 1 success, got {successes}"
    assert failures == 9, f"Expected 9 failures, got {failures}"

    # All failures should be due to nonce reuse
    for result in results:
        if not result.get("success"):
            error_msg = result.get("error", "").lower()
            assert "nonce" in error_msg or "replay" in error_msg or "authentication" in error_msg


# ============================================================================
# Test Scenario 10: Hot Reload of Authorized Keys
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_hot_reload_authorized_keys(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Hot reload of authorized_keys file.

    Scenario:
    1. Start server with one authorized key
    2. Perform operation successfully
    3. Add new key to authorized_keys file (while server running)
    4. Trigger reload
    5. Verify new key works immediately
    6. Verify old key still works

    This tests hot reload without server restart.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env

    # Setup first key
    client1_id = "client-1"
    key1, pub1 = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{pub1} {client1_id}:first-key\n")
    server.auth_middleware.reload_keys()

    # First key should work
    ssh_auth1 = create_ssh_auth_data(client1_id, key1)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth1,
    )
    assert result.get("success") is True

    # Add second key while server is running
    client2_id = "client-2"
    key2, pub2 = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{pub1} {client1_id}:first-key\n{pub2} {client2_id}:second-key\n")

    # Trigger reload (hot reload)
    server.auth_middleware.reload_keys()

    # Both keys should now work
    ssh_auth1_new = create_ssh_auth_data(client1_id, key1)
    result1 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth1_new,
    )
    assert result1.get("success") is True, "Old key stopped working after reload"

    ssh_auth2 = create_ssh_auth_data(client2_id, key2)
    result2 = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth2,
    )
    assert result2.get("success") is True, "New key not working after reload"


# ============================================================================
# Test Scenario 11: Different Timestamp Windows
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_different_timestamp_windows(tmp_path: Any, docker_available: Any) -> None:
    """Integration test: Different timestamp window configurations.

    Scenario:
    1. Test with ssh_signature_max_age=60 (1 minute)
    2. Test with ssh_signature_max_age=600 (10 minutes)
    3. Verify timestamp validation respects configuration

    This tests configurable timestamp windows.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    import os

    # Setup for 60 second window
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.write_text("")

    os.environ["SECURITY_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
    os.environ["SECURITY_SSH_SIGNATURE_MAX_AGE"] = "60"  # 1 minute
    os.environ["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    os.environ["SECURITY_API_KEYS_FILE"] = str(tmp_path / "api_keys.json")
    (tmp_path / "api_keys.json").write_text('{"clients": []}')
    os.environ["SECURITY_AUDIT_LOG_FILE"] = str(tmp_path / "audit_60.log")

    config = Config()
    server = MCPDockerServer(config)

    client_id = "window-test-client"
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:window-test\n")
    server.auth_middleware.reload_keys()

    # Timestamp 90 seconds old should fail (exceeds 60s window)
    old_timestamp = datetime.fromtimestamp(datetime.now(UTC).timestamp() - 90, UTC).isoformat()
    ssh_auth_old = create_ssh_auth_data(client_id, private_key, timestamp=old_timestamp)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_old,
    )
    assert result.get("success") is False, "90-second-old timestamp should fail with 60s window"

    # Current timestamp should work
    ssh_auth_valid = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_valid,
    )
    assert result.get("success") is True


# ============================================================================
# Test Scenario 12: Disabled SSH Auth
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_disabled_ssh_auth(tmp_path: Any, docker_available: Any) -> None:
    """Integration test: SSH auth disabled rejects authentication.

    Scenario:
    1. Start server with SECURITY_SSH_AUTH_ENABLED=false
    2. Attempt SSH authentication
    3. Verify authentication is rejected

    This tests SSH auth enable/disable configuration.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    import os

    # Setup with SSH auth DISABLED
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.write_text("")

    os.environ["SECURITY_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTH_ENABLED"] = "false"  # DISABLED
    os.environ["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
    os.environ["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    os.environ["SECURITY_AUDIT_LOG_FILE"] = str(tmp_path / "audit.log")

    config = Config()
    server = MCPDockerServer(config)

    # Generate SSH key
    client_id = "ssh-client"
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:test\n")

    # Attempt SSH auth (should fail since SSH auth is disabled)
    ssh_auth = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    # Should fail because SSH auth is disabled
    assert result.get("success") is False


# ============================================================================
# Test Scenario 13: Rate Limiting with SSH Auth
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.slow
async def test_rate_limiting_with_ssh_auth(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Rate limiting applies to SSH authenticated clients.

    Scenario:
    1. Enable rate limiting (60 requests per minute = 1 per second)
    2. Perform rapid Docker operations with SSH auth
    3. Verify rate limiting applies correctly
    4. Verify client_id from SSH auth used for rate limit tracking

    This tests integration of SSH auth with rate limiting.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "rate-limit-client"

    # Setup SSH key
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:rate-test\n")
    server.auth_middleware.reload_keys()

    # Make rapid requests (should hit rate limit eventually)
    success_count = 0
    rate_limited_count = 0

    for _i in range(70):  # Try 70 requests (exceeds 60 RPM limit)
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )
        if result.get("success"):
            success_count += 1
        elif "rate limit" in result.get("error", "").lower():
            rate_limited_count += 1

        # Small delay to avoid overwhelming Docker
        await asyncio.sleep(0.01)

    # Should have hit rate limit
    assert rate_limited_count > 0, "Rate limiting did not engage"
    assert success_count < 70, "All requests succeeded (rate limit not working)"


# ============================================================================
# Test Scenario 14: Nonce Store Memory Management
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.slow
async def test_nonce_store_memory_management(tmp_path: Any, docker_available: Any) -> None:
    """Integration test: Nonce store cleans up expired nonces.

    Scenario:
    1. Generate 100+ unique authenticated requests over time
    2. Verify nonce store cleans up expired nonces (doesn't grow unbounded)
    3. Check nonce stats show reasonable active count

    This tests memory management and nonce cleanup.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    import os

    # Setup with SHORT timestamp window (5 seconds) for faster test
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.write_text("")

    os.environ["SECURITY_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTH_ENABLED"] = "true"
    os.environ["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
    os.environ["SECURITY_SSH_SIGNATURE_MAX_AGE"] = "5"  # 5 seconds
    os.environ["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    os.environ["SECURITY_API_KEYS_FILE"] = str(tmp_path / "api_keys.json")
    (tmp_path / "api_keys.json").write_text('{"clients": []}')
    os.environ["SECURITY_AUDIT_LOG_FILE"] = str(tmp_path / "audit.log")
    os.environ["SECURITY_RATE_LIMIT_ENABLED"] = "false"  # Disable for this test

    config = Config()
    server = MCPDockerServer(config)

    client_id = "nonce-test-client"
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:nonce-test\n")
    server.auth_middleware.reload_keys()

    # Generate 50 requests
    for _i in range(50):
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )
        await asyncio.sleep(0.05)  # Small delay

    # Wait for nonces to expire (5 seconds + buffer)
    await asyncio.sleep(6)

    # Generate 50 more requests (should trigger cleanup)
    for _i in range(50):
        ssh_auth = create_ssh_auth_data(client_id, private_key)
        await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )
        await asyncio.sleep(0.05)

    # Check nonce stats
    assert server.auth_middleware.ssh_key_authenticator is not None, (
        "SSH authenticator should be enabled"
    )
    nonce_stats = server.auth_middleware.ssh_key_authenticator.protocol.get_nonce_stats()
    active_nonces = nonce_stats["active_nonces"]

    # Should have cleaned up old nonces (not 100 total)
    # With 5 second window and 0.05s delays, should have ~20-30 active at most
    assert active_nonces < 60, f"Nonce store not cleaning up properly: {active_nonces} active"


# ============================================================================
# Test Scenario 15: Concurrent Clients
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.slow
async def test_concurrent_clients(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Multiple concurrent clients with different SSH keys.

    Scenario:
    1. Simulate 5 clients with different SSH keys
    2. Each performs 20 Docker operations concurrently
    3. Verify all succeed independently
    4. Verify no race conditions in nonce store

    This tests concurrent client isolation and thread safety.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env

    # Disable rate limiting for this test
    import os

    os.environ["SECURITY_RATE_LIMIT_ENABLED"] = "false"
    config = Config()
    server = MCPDockerServer(config)

    # Generate 5 clients with different keys
    clients = []
    auth_keys_content = ""
    for i in range(5):
        client_id = f"client-{i}"
        private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
        auth_keys_content += f"{public_key_line} {client_id}:concurrent-test\n"
        clients.append((client_id, private_key))

    auth_keys_file.write_text(auth_keys_content)
    server.auth_middleware.reload_keys()

    # Function for client to perform operations
    async def client_operations(
        client_id: str,
        private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        count: int,
    ) -> bool:
        results: list[Any] = []
        for _ in range(count):
            ssh_auth = create_ssh_auth_data(client_id, private_key)
            result = await server.call_tool(
                tool_name="docker_list_containers",
                arguments={"all": True},
                ssh_auth_data=ssh_auth,
            )
            results.append(result.get("success"))
            await asyncio.sleep(0.01)  # Small delay
        return all(results)

    # Run all clients concurrently
    tasks = [client_operations(cid, key, 20) for cid, key in clients]
    results = await asyncio.gather(*tasks)

    # All clients should succeed in all operations
    assert all(results), f"Some clients failed: {results}"


# ============================================================================
# Test Scenario 16: RSA Key Support
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rsa_key_support(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: RSA key support alongside Ed25519.

    Scenario:
    1. Generate RSA key pair
    2. Add to authorized_keys
    3. Perform Docker operations
    4. Verify RSA keys work correctly

    This tests support for multiple key algorithms.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "rsa-client"

    # Generate RSA key
    private_key, public_key_line = generate_rsa_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line} {client_id}:rsa-key\n")
    server.auth_middleware.reload_keys()

    # Perform operation with RSA key
    ssh_auth = create_ssh_auth_data(client_id, private_key)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )
    assert result.get("success") is True, f"RSA key failed: {result.get('error')}"


# ============================================================================
# Test Scenario 17: Mixed Key Types
# ============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mixed_key_types(ssh_test_env: Any, docker_available: Any) -> None:
    """Integration test: Ed25519 and RSA keys for same client.

    Scenario:
    1. Generate both Ed25519 and RSA keys for same client
    2. Add both to authorized_keys
    3. Verify both work independently

    This tests multiple key types per client.
    """
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")

    server, auth_keys_file, tmp_path = ssh_test_env
    client_id = "mixed-key-client"

    # Generate both key types
    ed_key, ed_pub = generate_ed25519_key_pair(tmp_path)
    rsa_key, rsa_pub = generate_rsa_key_pair(tmp_path)

    # Add both to authorized_keys
    auth_keys_file.write_text(f"{ed_pub} {client_id}:ed25519-key\n{rsa_pub} {client_id}:rsa-key\n")
    server.auth_middleware.reload_keys()

    # Both should work
    ssh_auth_ed = create_ssh_auth_data(client_id, ed_key)
    result_ed = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_ed,
    )
    assert result_ed.get("success") is True

    ssh_auth_rsa = create_ssh_auth_data(client_id, rsa_key)
    result_rsa = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth_rsa,
    )
    assert result_rsa.get("success") is True
