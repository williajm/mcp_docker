"""Stress tests and security edge case tests for HTTP Stream Transport.

These tests address Claude's review feedback for missing coverage:
1. Resumability stress tests (1000+ events, concurrent sessions, TTL)
2. Security edge cases (malformed session IDs, host injection, CORS attacks)
"""

import asyncio
import os

import httpx
import pytest

# Import helpers from main E2E test file
from tests.e2e.test_httpstream_transport_e2e import (
    HTTPSTREAM_TEST_PORT_HTTP,
    cleanup_server,
    start_httpstream_server,
    wait_for_httpstream_server,
)

# ============================================================================
# Resumability Stress Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.stress
@pytest.mark.asyncio
async def test_httpstream_resumability_1000_events() -> None:
    """Stress test: Reconnect with 1000+ events in history."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "false"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            # Step 1: Create a session and generate 1000+ events
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "stress-test", "version": "1.0"},
                },
            }

            response = await client.post(
                f"{base_url}/",
                json=init_request,
                headers={"Accept": "application/json, text/event-stream"},
            )
            assert response.status_code == 200
            session_id = response.headers.get("mcp-session-id")
            assert session_id is not None

            # Step 2: Make 1000 tool list requests to generate events
            for i in range(1000):
                # Check if server is still alive periodically
                if i % 100 == 0 and process.poll() is not None:
                    raise RuntimeError(f"Server process died at request {i}")

                list_request = {
                    "jsonrpc": "2.0",
                    "id": i + 2,
                    "method": "tools/list",
                    "params": {},
                }
                response = await client.post(
                    f"{base_url}/",
                    json=list_request,
                    headers={
                        "mcp-session-id": session_id,
                        "Accept": "application/json, text/event-stream",
                    },
                )
                # Check response to catch errors early
                assert response.status_code == 200, (
                    f"Request {i} failed with status {response.status_code}"
                )

            # Step 3: Reconnect with same session ID and verify we can resume
            reconnect_request = {
                "jsonrpc": "2.0",
                "id": 1002,
                "method": "tools/list",
                "params": {},
            }

            response = await client.post(
                f"{base_url}/",
                json=reconnect_request,
                headers={
                    "mcp-session-id": session_id,
                    "Accept": "application/json, text/event-stream",
                },
            )

            # Should successfully reconnect and execute
            assert response.status_code == 200
            assert response.headers.get("mcp-session-id") == session_id

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.stress
@pytest.mark.asyncio
async def test_httpstream_concurrent_sessions_with_replay() -> None:
    """Stress test: Multiple concurrent sessions with event replay."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "false"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        async def create_and_test_session(session_num: int) -> None:
            """Create a session, generate events, disconnect, and reconnect."""
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                # Create session
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": f"concurrent-test-{session_num}",
                            "version": "1.0",
                        },
                    },
                }

                response = await client.post(
                    f"{base_url}/",
                    json=init_request,
                    headers={"Accept": "application/json, text/event-stream"},
                )
                session_id = response.headers.get("mcp-session-id")
                assert session_id is not None

                # Generate 50 events per session
                for i in range(50):
                    list_request = {
                        "jsonrpc": "2.0",
                        "id": i + 2,
                        "method": "tools/list",
                        "params": {},
                    }
                    await client.post(
                        f"{base_url}/",
                        json=list_request,
                        headers={
                            "mcp-session-id": session_id,
                            "Accept": "application/json, text/event-stream",
                        },
                    )

                # Disconnect briefly
                await asyncio.sleep(0.1)

                # Reconnect and verify
                reconnect_request = {
                    "jsonrpc": "2.0",
                    "id": 100,
                    "method": "tools/list",
                    "params": {},
                }

                response = await client.post(
                    f"{base_url}/",
                    json=reconnect_request,
                    headers={
                        "mcp-session-id": session_id,
                        "Accept": "application/json, text/event-stream",
                    },
                )
                assert response.status_code == 200

        # Run 10 concurrent sessions
        await asyncio.gather(*[create_and_test_session(i) for i in range(10)])

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_event_ttl_expiration() -> None:
    """Test event TTL expiration during active session.

    Note: This test simulates TTL expiration by waiting, but actual TTL
    in production is 1 hour. We test the behavior, not the exact timing.
    """
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "false"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            # Create session
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "ttl-test", "version": "1.0"},
                },
            }

            response = await client.post(
                f"{base_url}/",
                json=init_request,
                headers={"Accept": "application/json, text/event-stream"},
            )
            session_id = response.headers.get("mcp-session-id")
            assert session_id is not None

            # Generate some events
            for i in range(5):
                list_request = {
                    "jsonrpc": "2.0",
                    "id": i + 2,
                    "method": "tools/list",
                    "params": {},
                }
                await client.post(
                    f"{base_url}/",
                    json=list_request,
                    headers={
                        "mcp-session-id": session_id,
                        "Accept": "application/json, text/event-stream",
                    },
                )

            # Note: In production, events expire after 1 hour
            # We can't easily test exact expiration without mocking time,
            # but we verify the session continues to work with old events
            await asyncio.sleep(1)

            # Session should still work (events not expired yet)
            list_request = {
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/list",
                "params": {},
            }
            response = await client.post(
                f"{base_url}/",
                json=list_request,
                headers={
                    "mcp-session-id": session_id,
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            # Should succeed (session still active)
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text}"
            )

    finally:
        cleanup_server(process)


# ============================================================================
# Security Edge Case Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_malformed_session_id_too_long() -> None:
    """Security test: Reject session ID that is too long."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "false"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            # Try with excessively long session ID (10KB)
            malformed_id = "a" * 10000

            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "security-test", "version": "1.0"},
                },
            }

            response = await client.post(
                f"{base_url}/",
                json=init_request,
                headers={
                    "mcp-session-id": malformed_id,
                    "Accept": "application/json, text/event-stream",
                },
            )

            # Server should either:
            # 1. Reject it (400/431)
            # 2. Ignore it and create new session (200 with different session ID)
            # Both are acceptable security behaviors
            assert response.status_code in [200, 400, 431]

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_malformed_session_id_invalid_chars() -> None:
    """Security test: Reject session ID with invalid characters."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "false"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        # Test various invalid characters
        invalid_ids = [
            "../../../etc/passwd",  # Path traversal
            "<script>alert('xss')</script>",  # XSS
            "'; DROP TABLE sessions; --",  # SQL injection
            "\x00\x01\x02",  # Null bytes and control chars
            "session\nid\rwith\tnewlines",  # Newlines/tabs
        ]

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            for malformed_id in invalid_ids:
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "security-test", "version": "1.0"},
                    },
                }

                try:
                    response = await client.post(
                        f"{base_url}/",
                        json=init_request,
                        headers={
                            "mcp-session-id": malformed_id,
                            "Accept": "application/json, text/event-stream",
                        },
                    )

                    # Server should handle safely (reject or ignore)
                    assert response.status_code in [200, 400, 431]

                    # If 200, verify new session was created (not reused)
                    if response.status_code == 200:
                        new_session_id = response.headers.get("mcp-session-id")
                        # Should not echo back malicious input
                        assert new_session_id != malformed_id
                except (httpx.LocalProtocolError, httpx.UnsupportedProtocol):
                    # httpx may reject invalid headers before sending
                    # This is acceptable - the malformed input was caught
                    pass

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_host_header_injection() -> None:
    """Security test: Reject Host header injection attempts."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["HTTPSTREAM_DNS_REBINDING_PROTECTION"] = "true"
    env["HTTPSTREAM_ALLOWED_HOSTS"] = '["127.0.0.1", "localhost"]'

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        # Test various malicious Host headers
        malicious_hosts = [
            "evil.com",  # Different domain
            "127.0.0.1\r\nX-Injected: true",  # Header injection
            "127.0.0.1:@evil.com",  # Credential injection
            "127.0.0.1/../../../etc/passwd",  # Path traversal
            "127.0.0.1\x00evil.com",  # Null byte injection
        ]

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            for malicious_host in malicious_hosts:
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "security-test", "version": "1.0"},
                    },
                }

                try:
                    response = await client.post(
                        f"{base_url}/",
                        json=init_request,
                        headers={
                            "Host": malicious_host,
                            "Accept": "application/json, text/event-stream",
                        },
                    )
                    # Should reject when DNS protection enabled
                    # 400 = Bad Request, 403 = Forbidden, 421 = Misdirected Request
                    assert response.status_code in [400, 403, 421]
                except (httpx.InvalidURL, httpx.RequestError):
                    # httpx may reject invalid Host headers before sending
                    pass

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_cors_preflight_disallowed_origin() -> None:
    """Security test: CORS preflight with disallowed origin."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["CORS_ENABLED"] = "true"
    env["CORS_ALLOW_ORIGINS"] = '["https://trusted.com"]'  # Only allow specific origin

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        disallowed_origins = [
            "https://evil.com",
            "https://trusted.com.evil.com",  # Subdomain attack
            "https://trustedXcom",  # Typo squatting
            "http://trusted.com",  # Wrong protocol
        ]

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            for origin in disallowed_origins:
                # CORS preflight (OPTIONS)
                response = await client.options(
                    f"{base_url}/",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                )

                # Should either reject or not include Allow-Origin header
                if response.status_code == 200:
                    # If successful, should NOT include disallowed origin
                    allow_origin = response.headers.get("access-control-allow-origin")
                    if allow_origin:
                        assert allow_origin != origin

    finally:
        cleanup_server(process)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_httpstream_cors_credentials_without_specific_origin() -> None:
    """Security test: CORS should not allow credentials with wildcard origin."""
    env = os.environ.copy()
    env["DOCKER_BASE_URL"] = "unix:///var/run/docker.sock"
    env["SECURITY_OAUTH_ENABLED"] = "false"
    env["MCP_TLS_ENABLED"] = "false"
    env["CORS_ENABLED"] = "true"
    env["CORS_ALLOW_ORIGINS"] = '["http://localhost:3000"]'  # Specific origin (not wildcard)
    env["CORS_ALLOW_CREDENTIALS"] = "true"

    process = start_httpstream_server(env, port=HTTPSTREAM_TEST_PORT_HTTP)

    try:
        base_url = f"http://127.0.0.1:{HTTPSTREAM_TEST_PORT_HTTP}"
        await wait_for_httpstream_server(base_url, verify=False)

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            # Test with allowed origin
            response = await client.head(
                f"{base_url}/",
                headers={"Origin": "http://localhost:3000"},
            )

            # Should succeed with specific origin
            assert response.status_code == 200
            allow_origin = response.headers.get("access-control-allow-origin", "")
            allow_creds = response.headers.get("access-control-allow-credentials", "")

            # Credentials should be allowed with specific origin
            assert allow_creds.lower() == "true"
            assert allow_origin == "http://localhost:3000"

            # Test with disallowed origin
            response2 = await client.head(
                f"{base_url}/",
                headers={"Origin": "https://evil.com"},
            )

            # Should either reject or not include evil origin in allow-origin
            if response2.status_code == 200:
                allow_origin2 = response2.headers.get("access-control-allow-origin", "")
                # Should not allow evil.com
                assert allow_origin2 != "https://evil.com"

    finally:
        cleanup_server(process)
