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
import datetime
import http.server
import ipaddress
import json
import os
import socketserver
import subprocess
import tempfile
import threading
import time
from datetime import UTC, timedelta
from pathlib import Path

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Test configuration
SSE_TEST_PORT_HTTP = 8765  # HTTP test port
SSE_TEST_PORT_HTTPS = 8766  # HTTPS test port
MOCK_JWKS_PORT = 9876  # Port for mock JWKS server
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
                    # Server is up if it responds with 200 (no auth) or 401 (auth required)
                    if response.status_code in [200, 401]:
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
    env["SECURITY_OAUTH_ENABLED"] = "false"  # Localhost without auth is ok for testing
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
        env["SECURITY_OAUTH_ENABLED"] = "false"
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
        env["SECURITY_OAUTH_ENABLED"] = "false"
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
async def test_http_sse_refuses_non_localhost() -> None:
    """Test that HTTP SSE server requires explicit allowed hosts when binding to wildcard."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["MCP_TLS_ENABLED"] = "false"
    # Don't set HTTPSTREAM_ALLOWED_HOSTS - should fail to start

    # Try to bind to 0.0.0.0 (wildcard) without HTTPSTREAM_ALLOWED_HOSTS
    # Server should fail to start with fail-secure policy
    process = start_sse_server(env, host="0.0.0.0", port=SSE_TEST_PORT_HTTP)

    try:
        # Wait for server to exit
        await asyncio.sleep(SSE_ERROR_CHECK_DELAY)
        returncode = process.poll()

        # Server should exit with error (fail-secure)
        assert returncode is not None, (
            "Server should fail to start without HTTPSTREAM_ALLOWED_HOSTS for wildcard bind"
        )
        assert returncode != 0, "Server should exit with error code"

    finally:
        # Cleanup
        cleanup_server(process)


# ============================================================================
# OAuth E2E Test Fixtures and Helpers
# ============================================================================


@pytest.fixture
def oauth_test_key_pair() -> tuple[dict, dict]:
    """Generate a test RSA key pair for OAuth JWT signing.

    Returns:
        Tuple of (private_key, public_key) as JWK dicts
    """
    # Generate RSA key pair using cryptography
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Convert to JWK format using authlib
    private_jwk = JsonWebKey.import_key(private_key_obj, {"kty": "RSA"})
    public_jwk = JsonWebKey.import_key(private_key_obj.public_key(), {"kty": "RSA"})

    private_key = private_jwk.as_dict(is_private=True)
    public_key = public_jwk.as_dict(is_private=False)

    # Add kid (key ID) for JWKS lookup
    key_id = "test-key-oauth-e2e"
    private_key["kid"] = key_id
    public_key["kid"] = key_id

    return private_key, public_key


@pytest.fixture
def oauth_jwks_response(oauth_test_key_pair: tuple[dict, dict]) -> dict:
    """Create mock JWKS response.

    Args:
        oauth_test_key_pair: Test key pair fixture

    Returns:
        JWKS response dict
    """
    _, public_key = oauth_test_key_pair
    return {"keys": [public_key]}


@pytest.fixture
def mock_jwks_server(oauth_jwks_response: dict) -> str:
    """Start a mock JWKS HTTP server for E2E testing.

    This server serves the JWKS response at /.well-known/jwks.json
    so that the SSE server subprocess can fetch it.

    Args:
        oauth_jwks_response: JWKS response to serve

    Returns:
        Base URL of the mock JWKS server

    Yields:
        Base URL while server is running
    """

    class JWKSHandler(http.server.BaseHTTPRequestHandler):
        """Simple HTTP handler that serves JWKS responses."""

        def do_GET(self) -> None:  # noqa: N802
            """Handle GET requests."""
            if self.path == "/.well-known/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(oauth_jwks_response).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: tuple) -> None:  # noqa: ARG002, A002
            """Suppress log messages."""
            pass

    # Start server in background thread (allow port reuse for rapid test execution)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", MOCK_JWKS_PORT), JWKSHandler) as httpd:
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Give server time to start
            time.sleep(0.5)
            yield f"http://127.0.0.1:{MOCK_JWKS_PORT}"
        finally:
            # Shutdown server
            httpd.shutdown()


def create_oauth_test_jwt(  # noqa: PLR0913
    private_key: dict,
    issuer: str = "https://auth.example.com/",  # Trailing slash to match Pydantic HttpUrl
    audience: str = "mcp-docker-api",
    subject: str = "test-user-e2e",
    scopes: list[str] | None = None,
    exp_minutes: int = 60,
    **extra_claims: str,
) -> str:
    """Create a test JWT token for OAuth E2E tests.

    Args:
        private_key: Private key JWK dict
        issuer: JWT issuer
        audience: JWT audience
        subject: JWT subject (user ID)
        scopes: OAuth scopes
        exp_minutes: Token expiration in minutes
        extra_claims: Additional JWT claims

    Returns:
        Encoded JWT token string
    """
    now = datetime.datetime.now(UTC)
    header = {"alg": "RS256", "kid": private_key["kid"]}

    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
        "scope": " ".join(scopes) if scopes else "",
        **extra_claims,
    }

    # Sign the JWT
    token = jwt.encode(header, payload, private_key)
    return token.decode("utf-8") if isinstance(token, bytes) else token


# ============================================================================
# OAuth E2E Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sse_oauth_authentication_success(
    oauth_test_key_pair: tuple[dict, dict], mock_jwks_server: str
) -> None:
    """Test SSE server with OAuth - successful authentication with valid token."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        private_key, _ = oauth_test_key_pair

        # Create valid JWT token (issuer must match mock server URL)
        token = create_oauth_test_jwt(
            private_key,
            issuer=f"{mock_jwks_server}/",  # Trailing slash for Pydantic HttpUrl
            scopes=["docker.read", "docker.write"],
            email="test@example.com",
        )

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)
        # Enable OAuth with mock JWKS server
        env["SECURITY_OAUTH_ENABLED"] = "true"
        env["SECURITY_OAUTH_ISSUER"] = f"{mock_jwks_server}/"
        env["SECURITY_OAUTH_JWKS_URL"] = f"{mock_jwks_server}/.well-known/jwks.json"
        env["SECURITY_OAUTH_AUDIENCE"] = "mcp-docker-api"
        env["SECURITY_OAUTH_REQUIRED_SCOPES"] = "docker.read"

        # Start SSE server with OAuth
        port = SSE_TEST_PORT_HTTPS + 10  # Use different port to avoid conflicts
        process = start_sse_server(env, port=port)

        try:
            base_url = f"https://127.0.0.1:{port}"

            # Wait for server to start
            await wait_for_server(base_url, verify=False)

            # Test: SSE endpoint with valid OAuth token
            async with httpx.AsyncClient(verify=False) as client:
                async with client.stream(
                    "GET",
                    f"{base_url}/sse",
                    headers={
                        "Accept": "text/event-stream",
                        "Authorization": f"Bearer {token}",
                    },
                ) as response:
                    assert response.status_code == 200, (
                        f"Should authenticate with valid token, got {response.status_code}"
                    )

        finally:
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sse_oauth_authentication_missing_token(mock_jwks_server: str) -> None:
    """Test SSE server with OAuth - rejects request without token."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)
        # Enable OAuth with mock JWKS server
        env["SECURITY_OAUTH_ENABLED"] = "true"
        env["SECURITY_OAUTH_ISSUER"] = f"{mock_jwks_server}/"
        env["SECURITY_OAUTH_JWKS_URL"] = f"{mock_jwks_server}/.well-known/jwks.json"
        env["SECURITY_OAUTH_AUDIENCE"] = "mcp-docker-api"
        env["SECURITY_OAUTH_REQUIRED_SCOPES"] = "docker.read"

        # Start SSE server with OAuth
        port = SSE_TEST_PORT_HTTPS + 11  # Use different port
        process = start_sse_server(env, port=port)

        try:
            base_url = f"https://127.0.0.1:{port}"

            # Wait for server to start
            await wait_for_server(base_url, verify=False)

            # Test: SSE endpoint without token should fail
            async with httpx.AsyncClient(verify=False) as client:
                try:
                    async with client.stream(
                        "GET",
                        f"{base_url}/sse",
                        headers={"Accept": "text/event-stream"},
                        # No Authorization header
                    ) as response:
                        # Should get 401 or 403
                        assert response.status_code in [
                            401,
                            403,
                        ], f"Should reject request without token, got {response.status_code}"
                except httpx.HTTPStatusError as e:
                    # Also acceptable if httpx raises on error status
                    assert e.response.status_code in [401, 403]

        finally:
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sse_oauth_authentication_invalid_token(
    oauth_test_key_pair: tuple[dict, dict], mock_jwks_server: str
) -> None:
    """Test SSE server with OAuth - rejects request with invalid token."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        private_key, _ = oauth_test_key_pair

        # Create JWT with invalid signature (issuer must match mock server URL)
        token = create_oauth_test_jwt(
            private_key, issuer=f"{mock_jwks_server}/", scopes=["docker.read"]
        )
        invalid_token = token[:-10] + "0000000000"  # Tamper with signature

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)
        # Enable OAuth with mock JWKS server
        env["SECURITY_OAUTH_ENABLED"] = "true"
        env["SECURITY_OAUTH_ISSUER"] = f"{mock_jwks_server}/"
        env["SECURITY_OAUTH_JWKS_URL"] = f"{mock_jwks_server}/.well-known/jwks.json"
        env["SECURITY_OAUTH_AUDIENCE"] = "mcp-docker-api"
        env["SECURITY_OAUTH_REQUIRED_SCOPES"] = "docker.read"

        # Start SSE server with OAuth
        port = SSE_TEST_PORT_HTTPS + 12  # Use different port
        process = start_sse_server(env, port=port)

        try:
            base_url = f"https://127.0.0.1:{port}"

            # Wait for server to start
            await wait_for_server(base_url, verify=False)

            # Test: SSE endpoint with invalid token should fail
            async with httpx.AsyncClient(verify=False) as client:
                try:
                    async with client.stream(
                        "GET",
                        f"{base_url}/sse",
                        headers={
                            "Accept": "text/event-stream",
                            "Authorization": f"Bearer {invalid_token}",
                        },
                    ) as response:
                        # Should get 401 or 403
                        assert response.status_code in [
                            401,
                            403,
                        ], f"Should reject invalid token, got {response.status_code}"
                except httpx.HTTPStatusError as e:
                    # Also acceptable if httpx raises on error status
                    assert e.response.status_code in [401, 403]

        finally:
            cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.asyncio
async def test_sse_oauth_authentication_expired_token(
    oauth_test_key_pair: tuple[dict, dict], mock_jwks_server: str
) -> None:
    """Test SSE server with OAuth - rejects expired token."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir)
        cert_file, key_file = generate_self_signed_cert(cert_dir)

        private_key, _ = oauth_test_key_pair

        # Create expired JWT (expired 5 minutes ago, beyond clock skew, issuer must match mock server URL)
        token = create_oauth_test_jwt(
            private_key, issuer=f"{mock_jwks_server}/", scopes=["docker.read"], exp_minutes=-5
        )

        env = os.environ.copy()
        env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
        env["MCP_TLS_ENABLED"] = "true"
        env["MCP_TLS_CERT_FILE"] = str(cert_file)
        env["MCP_TLS_KEY_FILE"] = str(key_file)
        # Enable OAuth with mock JWKS server
        env["SECURITY_OAUTH_ENABLED"] = "true"
        env["SECURITY_OAUTH_ISSUER"] = f"{mock_jwks_server}/"
        env["SECURITY_OAUTH_JWKS_URL"] = f"{mock_jwks_server}/.well-known/jwks.json"
        env["SECURITY_OAUTH_AUDIENCE"] = "mcp-docker-api"
        env["SECURITY_OAUTH_REQUIRED_SCOPES"] = "docker.read"

        # Start SSE server with OAuth
        port = SSE_TEST_PORT_HTTPS + 13  # Use different port
        process = start_sse_server(env, port=port)

        try:
            base_url = f"https://127.0.0.1:{port}"

            # Wait for server to start
            await wait_for_server(base_url, verify=False)

            # Test: SSE endpoint with expired token should fail
            async with httpx.AsyncClient(verify=False) as client:
                try:
                    async with client.stream(
                        "GET",
                        f"{base_url}/sse",
                        headers={
                            "Accept": "text/event-stream",
                            "Authorization": f"Bearer {token}",
                        },
                    ) as response:
                        # Should get 401 or 403
                        assert response.status_code in [
                            401,
                            403,
                        ], f"Should reject expired token, got {response.status_code}"
                except httpx.HTTPStatusError as e:
                    # Also acceptable if httpx raises on error status
                    assert e.response.status_code in [401, 403]

        finally:
            cleanup_server(process)
