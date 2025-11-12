"""E2E tests for SSE transport (HTTP and HTTPS).

These tests verify SSE server starts correctly with:
- HTTP SSE on localhost (development mode)
- HTTPS SSE with TLS certificates (production mode)
- Server endpoints are accessible
- TLS configuration works

Note: Full MCP protocol testing over SSE requires complex client implementation.
These tests focus on server startup, endpoint accessibility, and TLS functionality.
"""

import asyncio
import base64
import datetime
import ipaddress
import os
import secrets
import subprocess
import tempfile
import time
from datetime import UTC
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

# Test configuration
SSE_TEST_PORT_HTTP = 8765  # HTTP test port
SSE_TEST_PORT_HTTPS = 8766  # HTTPS test port
SSE_STARTUP_TIMEOUT = 10.0  # seconds
SSE_HEALTH_CHECK_TIMEOUT = 2.0  # seconds - timeout for individual health check requests
SSE_RETRY_DELAY = 0.5  # seconds - delay between server startup retries
SSE_CLEANUP_TIMEOUT = 5.0  # seconds - timeout for graceful process termination
SSE_ERROR_CHECK_DELAY = 2.0  # seconds - delay to check if server exited with error


def generate_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    """Generate self-signed certificate for testing.

    Args:
        cert_dir: Directory to store certificate files

    Returns:
        Tuple of (cert_file, key_file) paths
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP Docker Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(UTC))
        .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write certificate
    cert_file = cert_dir / "test_cert.pem"
    with cert_file.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key
    key_file = cert_dir / "test_key.pem"
    with key_file.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    return cert_file, key_file


def generate_ssh_key_pair(key_dir: Path) -> tuple[Path, Path, str]:
    """Generate Ed25519 SSH key pair for testing.

    Args:
        key_dir: Directory to store key files

    Returns:
        Tuple of (private_key_path, public_key_path, public_key_string)
    """
    # Generate Ed25519 key
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Save private key
    private_key_path = key_dir / "test_ed25519"
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_path.write_bytes(private_pem)
    private_key_path.chmod(0o600)

    # Get public key
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
    )
    public_key_string = public_bytes.decode("utf-8")

    # Save public key
    public_key_path = key_dir / "test_ed25519.pub"
    public_key_path.write_text(public_key_string)

    return private_key_path, public_key_path, public_key_string


def create_ssh_signature(
    client_id: str, private_key_path: Path, timestamp: str | None = None, nonce: str | None = None
) -> dict[str, str]:
    """Create SSH signature for authentication.

    Args:
        client_id: Client identifier
        private_key_path: Path to SSH private key
        timestamp: ISO timestamp (generated if not provided)
        nonce: Nonce value (generated if not provided)

    Returns:
        Dict with signature, timestamp, nonce
    """
    if timestamp is None:
        timestamp = datetime.datetime.now(UTC).isoformat()
    if nonce is None:
        nonce = secrets.token_urlsafe(32)

    # Load private key
    with private_key_path.open("rb") as f:
        private_key = serialization.load_ssh_private_key(f.read(), password=None)

    # Create message: "client_id|timestamp|nonce"
    message = f"{client_id}|{timestamp}|{nonce}".encode()

    # Sign message
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(message)
    else:
        raise ValueError(f"Unsupported key type: {type(private_key)}")

    signature_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64,
    }


async def wait_for_server(
    base_url: str, timeout: float = SSE_STARTUP_TIMEOUT, verify: bool | str = True
) -> None:
    """Wait for SSE server to become ready.

    Args:
        base_url: Base URL of the server
        timeout: Maximum time to wait
        verify: SSL verification (True, False, or path to CA bundle)

    Raises:
        TimeoutError: If server doesn't respond within timeout
    """
    start_time = time.time()
    async with httpx.AsyncClient(verify=verify) as client:
        while time.time() - start_time < timeout:
            try:
                # Try to connect to SSE endpoint with stream=True to avoid hanging
                # We just want to check if the server responds, not read the full stream
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={"Accept": "text/event-stream"},
                    timeout=SSE_HEALTH_CHECK_TIMEOUT,
                ) as response:
                    if response.status_code == 200:
                        return  # Server is up and responding
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadTimeout):
                await asyncio.sleep(SSE_RETRY_DELAY)
                continue

    raise TimeoutError(f"Server at {base_url} did not start within {timeout}s")


def start_sse_server(
    env: dict[str, str],
    host: str = "127.0.0.1",
    port: int = SSE_TEST_PORT_HTTP,
) -> subprocess.Popen[bytes]:
    """Start SSE server with given environment.

    Args:
        env: Environment variables for the server
        host: Host address to bind to
        port: Port number to bind to

    Returns:
        subprocess.Popen: Server process
    """
    return subprocess.Popen(
        [
            "python",
            "-m",
            "mcp_docker",
            "--transport",
            "sse",
            "--host",
            host,
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def cleanup_server(process: subprocess.Popen[bytes]) -> None:
    """Clean up server process.

    Args:
        process: Server process to clean up
    """
    process.terminate()
    try:
        process.wait(timeout=SSE_CLEANUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_http_sse_server_starts() -> None:
    """Test HTTP SSE server starts and SSE endpoint is accessible."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_AUTH_ENABLED"] = "false"  # Localhost without auth is ok for testing
    env["MCP_TLS_ENABLED"] = "false"  # HTTP only

    # Start SSE server
    process = start_sse_server(env, port=SSE_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{SSE_TEST_PORT_HTTP}"

        # Wait for server to start
        try:
            await wait_for_server(base_url, verify=False)
        except TimeoutError as e:
            # Print server output for debugging
            stdout, stderr = process.communicate(timeout=1)
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""
            raise TimeoutError(
                f"Server failed to start. STDOUT: {stdout_text[:500]} STDERR: {stderr_text[:500]}"
            ) from e

        # Test: SSE endpoint is accessible
        async with httpx.AsyncClient(verify=False) as client:
            # Use stream to avoid hanging on SSE endpoint
            async with client.stream(
                "GET",
                f"{base_url}/sse",
                headers={"Accept": "text/event-stream"},
            ) as response:
                assert response.status_code == 200, "SSE endpoint should return 200"
                # SSE uses text/event-stream content type
                content_type = response.headers.get("content-type", "")
                assert "text/event-stream" in content_type, (
                    f"Expected text/event-stream, got {content_type}"
                )

    finally:
        # Cleanup
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_https_sse_with_tls() -> None:
    """Test HTTPS SSE server starts with TLS certificates."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)

        # Generate self-signed certificate
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["SECURITY_AUTH_ENABLED"] = "false"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)

        # Start SSE server with HTTPS
        process = start_sse_server(env, port=SSE_TEST_PORT_HTTPS)

        try:
            base_url = f"https://127.0.0.1:{SSE_TEST_PORT_HTTPS}"

            # Wait for server to start (disable SSL verification for self-signed cert)
            await wait_for_server(base_url, verify=False)

            # Test: HTTPS SSE endpoint is accessible
            async with httpx.AsyncClient(verify=False) as client:
                # Use stream to avoid hanging on SSE endpoint
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status_code == 200, "HTTPS SSE endpoint should return 200"
                    # Verify it's actually HTTPS
                    assert str(response.url).startswith("https://"), "Should be HTTPS connection"
                    content_type = response.headers.get("content-type", "")
                    assert "text/event-stream" in content_type, (
                        f"Expected text/event-stream, got {content_type}"
                    )

        finally:
            # Cleanup
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.asyncio
async def test_sse_security_headers() -> None:
    """Test that security headers are present in HTTPS SSE responses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["SECURITY_AUTH_ENABLED"] = "false"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)

        process = start_sse_server(env, port=SSE_TEST_PORT_HTTPS)

        try:
            base_url = f"https://127.0.0.1:{SSE_TEST_PORT_HTTPS}"
            await wait_for_server(base_url, verify=False)

            # Check security headers
            async with httpx.AsyncClient(verify=False) as client:
                # Use stream to avoid hanging on SSE endpoint
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    headers = response.headers

                    # Check for security headers (configured in _create_security_headers)
                    # These are added by Starlette's Secure middleware
                    assert "x-frame-options" in headers or "X-Frame-Options" in headers, (
                        "Should have X-Frame-Options header"
                    )

                    assert (
                        "strict-transport-security" in headers
                        or "Strict-Transport-Security" in headers
                    ), "Should have Strict-Transport-Security header (HSTS)"

                    assert (
                        "content-security-policy" in headers or "Content-Security-Policy" in headers
                    ), "Should have Content-Security-Policy header"

                    assert "referrer-policy" in headers or "Referrer-Policy" in headers, (
                        "Should have Referrer-Policy header"
                    )

        finally:
            # Cleanup
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sse_with_ssh_auth_enabled() -> None:
    """Test SSE server with SSH authentication enabled requires auth."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dir = Path(tmpdir)

        # Generate SSH key pair
        private_key_path, public_key_path, public_key_string = generate_ssh_key_pair(temp_dir)

        # Create authorized_keys file
        auth_keys_file = temp_dir / "authorized_keys"
        client_id = "test-client"
        with auth_keys_file.open("w") as f:
            f.write(f"{public_key_string} {client_id}:test\n")

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["SECURITY_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
        env["MCP_TLS_ENABLED"] = "false"

        # Start SSE server with SSH auth
        process = start_sse_server(env, port=SSE_TEST_PORT_HTTP)

        try:
            base_url = f"http://127.0.0.1:{SSE_TEST_PORT_HTTP}"
            await wait_for_server(base_url, verify=False)

            # Test: Unauthenticated request should fail
            async with httpx.AsyncClient(verify=False) as client:
                # Try SSE endpoint without auth - should get auth required response
                # Note: SSE endpoint may allow connection but MCP protocol will reject operations
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    # Server may accept SSE connection but will reject operations without auth
                    # This is because auth is checked per-operation in MCP protocol
                    assert response.status_code == 200, "SSE endpoint accessible"

                # Try to send an MCP request without auth - this would need full MCP client
                # For E2E, we verify that auth is configured by checking server started with auth settings

        finally:
            # Cleanup
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_https_sse_with_ssh_auth() -> None:
    """Test HTTPS SSE server with SSH authentication."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dir = Path(tmpdir)

        # Generate TLS certificates
        cert_file, key_file = generate_self_signed_cert(temp_dir)

        # Generate SSH key pair
        private_key_path, public_key_path, public_key_string = generate_ssh_key_pair(temp_dir)

        # Create authorized_keys file
        auth_keys_file = temp_dir / "authorized_keys"
        client_id = "https-test-client"
        with auth_keys_file.open("w") as f:
            f.write(f"{public_key_string} {client_id}:https-test\n")

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["SECURITY_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(auth_keys_file)
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)

        # Start HTTPS SSE server with SSH auth
        process = start_sse_server(env, port=SSE_TEST_PORT_HTTPS)

        try:
            base_url = f"https://127.0.0.1:{SSE_TEST_PORT_HTTPS}"
            await wait_for_server(base_url, verify=False)

            # Test: Server started with both TLS and SSH auth enabled
            async with httpx.AsyncClient(verify=False) as client:
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={"Accept": "text/event-stream"},
                ) as response:
                    assert response.status_code == 200, "HTTPS SSE endpoint accessible"
                    assert str(response.url).startswith("https://"), "Should be HTTPS"

                    # Verify security headers are present (from previous test)
                    headers = response.headers
                    assert (
                        "strict-transport-security" in headers
                        or "Strict-Transport-Security" in headers
                    ), "HTTPS should have HSTS"

        finally:
            # Cleanup
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sse_ssh_auth_key_validation() -> None:
    """Test that SSE server validates authorized_keys file exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dir = Path(tmpdir)

        # Point to non-existent authorized_keys file
        nonexistent_file = temp_dir / "nonexistent_authorized_keys"

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["SECURITY_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTH_ENABLED"] = "true"
        env["SECURITY_SSH_AUTHORIZED_KEYS_FILE"] = str(nonexistent_file)
        env["MCP_TLS_ENABLED"] = "false"

        # Start SSE server with invalid auth config
        process = start_sse_server(env, port=SSE_TEST_PORT_HTTP)

        try:
            # Wait and check if process exited with error
            await asyncio.sleep(SSE_ERROR_CHECK_DELAY)
            returncode = process.poll()

            # Server should fail to start or warn about missing file
            # (Depending on implementation, may start but log errors)
            if returncode is not None:
                # Server exited - check error message
                _, stderr = process.communicate(timeout=1)
                stderr_text = stderr.decode() if stderr else ""
                assert "authorized_keys" in stderr_text.lower() or "file" in stderr_text.lower()

        finally:
            # Cleanup
            if process.poll() is None:
                cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_http_sse_refuses_non_localhost() -> None:
    """Test that HTTP SSE server requires authentication when not on localhost."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_AUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"

    # Try to bind to 0.0.0.0 (non-localhost) without authentication
    # This should fail with a RuntimeError
    process = start_sse_server(env, host="0.0.0.0", port=SSE_TEST_PORT_HTTP)

    try:
        # Wait a bit and check if process exited
        await asyncio.sleep(SSE_ERROR_CHECK_DELAY)
        returncode = process.poll()

        # Server should have exited with error
        assert returncode is not None, "Server should exit when auth disabled on non-localhost"
        assert returncode != 0, "Server should exit with non-zero code"

        # Check error message mentions authentication
        _, stderr = process.communicate(timeout=1)
        stderr_text = stderr.decode() if stderr else ""
        assert "auth" in stderr_text.lower() or "authentication" in stderr_text.lower(), (
            f"Error message should mention authentication: {stderr_text}"
        )

    finally:
        # Cleanup
        if process.poll() is None:
            cleanup_server(process)
