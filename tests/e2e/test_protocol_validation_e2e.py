"""End-to-end tests for JSON-RPC protocol validation.

These tests validate that the MCP server properly handles malformed
JSON-RPC requests without crashing.

NOTE: The MCP SDK catches protocol-level errors and sends notification messages
instead of proper JSON-RPC error responses. These tests verify that:
1. The server doesn't crash or hang
2. Some form of error response is returned
3. No sensitive information is leaked in error messages

Tests cover the security issues found by mcp-testbench:
- Fuzzing: Empty payloads, invalid JSON, null bytes, deeply nested objects
- Prompt Injection: Malformed requests that shouldn't trigger crashes
"""

import asyncio
import json
import os
import subprocess
from typing import Any

import pytest

# ============================================================================
# Helper Functions
# ============================================================================


async def send_raw_jsonrpc_request(request_data: str | dict[str, Any]) -> tuple[bool, str, bool]:
    """Send a raw JSON-RPC request to the MCP server via stdio.

    Args:
        request_data: Either a JSON string or dict to send

    Returns:
        Tuple of (crashed, response_text, has_error_indication)
        crashed: True if server crashed/hung/returned non-JSON
        response_text: The response from the server
        has_error_indication: True if response indicates an error
    """
    # Start the server process
    proc = subprocess.Popen(
        ["python", "-m", "mcp_docker", "--transport", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "SECURITY_OAUTH_ENABLED": "false"},
    )

    try:
        # Convert request_data to string
        if isinstance(request_data, (dict, list)):
            request_str = json.dumps(request_data)
        else:
            request_str = request_data

        # Send request and close stdin
        # Wait for response with timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.to_thread(proc.communicate, input=f"{request_str}\n"), timeout=5.0
            )
        except TimeoutError:
            proc.kill()
            return True, "Timeout - server hung", False

        # Parse response to determine if server crashed and if error was indicated
        if not stdout or not stdout.strip():
            # Empty response indicates crash
            return True, stderr if stderr else "Empty response", False

        try:
            response = json.loads(stdout.strip())

            # Check for error indications
            has_error = False
            if "error" in response:
                has_error = True
            elif "params" in response and isinstance(response["params"], dict):
                # Check for error notification (like Internal Server Error)
                params = response["params"]
                if params.get("level") == "error" or "error" in str(params.get("data", "")).lower():
                    has_error = True

            # Server responded with valid JSON - not crashed
            return False, stdout, has_error

        except json.JSONDecodeError:
            # Response is not valid JSON - indicates server crash
            return True, stdout, False

    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


# ============================================================================
# Assertion Helpers
# ============================================================================


def assert_no_crash(crashed: bool, response: str, has_error: bool, test_name: str) -> None:
    """Assert that server did not crash and handled error gracefully.

    Args:
        crashed: Whether server crashed
        response: Server response
        has_error: Whether response indicates an error
        test_name: Name of the test for error messages
    """
    assert not crashed, f"{test_name}: Server crashed or hung. Response: {response[:200]}"
    assert has_error, f"{test_name}: Expected error indication but got: {response[:200]}"

    # Verify no sensitive info leaked
    response_lower = response.lower()
    assert "traceback" not in response_lower, f"{test_name}: Traceback leaked in error"
    assert "/home/" not in response_lower, f"{test_name}: File paths leaked in error"
    assert "password" not in response_lower, f"{test_name}: Sensitive data leaked in error"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def skip_if_no_docker() -> Any:
    """Fail test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.fail(f"Docker is required for E2E tests but is not available: {e}")


# ============================================================================
# Fuzzing Tests (from mcp-testbench)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_empty_payload(skip_if_no_docker: Any) -> None:
    """Test that empty payload doesn't crash the server."""
    crashed, response, has_error = await send_raw_jsonrpc_request("")
    assert_no_crash(crashed, response, has_error, "empty_payload")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_invalid_json(skip_if_no_docker: Any) -> None:
    """Test that invalid JSON doesn't crash the server."""
    crashed, response, has_error = await send_raw_jsonrpc_request("{invalid json")
    assert_no_crash(crashed, response, has_error, "invalid_json")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_null_payload(skip_if_no_docker: Any) -> None:
    """Test that null payload doesn't crash the server."""
    crashed, response, has_error = await send_raw_jsonrpc_request("null")
    assert_no_crash(crashed, response, has_error, "null_payload")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_array_instead_of_object(skip_if_no_docker: Any) -> None:
    """Test that array payload doesn't crash the server."""
    crashed, response, has_error = await send_raw_jsonrpc_request("[]")
    assert_no_crash(crashed, response, has_error, "array_payload")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_missing_method(skip_if_no_docker: Any) -> None:
    """Test that request without method doesn't crash the server."""
    request = {"jsonrpc": "2.0", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert_no_crash(crashed, response, has_error, "missing_method")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_invalid_method_type(skip_if_no_docker: Any) -> None:
    """Test that numeric method type doesn't crash the server."""
    request = {"jsonrpc": "2.0", "method": 123, "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert_no_crash(crashed, response, has_error, "invalid_method_type")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_missing_jsonrpc_version(skip_if_no_docker: Any) -> None:
    """Test that request without jsonrpc version doesn't crash the server."""
    request = {"method": "test", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert_no_crash(crashed, response, has_error, "missing_jsonrpc_version")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_invalid_jsonrpc_version(skip_if_no_docker: Any) -> None:
    """Test that invalid jsonrpc version doesn't crash the server."""
    request = {"jsonrpc": "1.0", "method": "test", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert_no_crash(crashed, response, has_error, "invalid_jsonrpc_version")


@pytest.mark.e2e
@pytest.mark.asyncio
@pytest.mark.slow
async def test_deeply_nested_objects(skip_if_no_docker: Any) -> None:
    """Test that deeply nested objects don't cause crash or DoS.

    This tests protection against billion laughs / nested object attacks.
    """
    # Create deeply nested object (100 levels - more realistic for actual attacks)
    nested: dict[str, Any] = {"a": "value"}
    for _ in range(100):
        nested = {"nested": nested}

    request = {"jsonrpc": "2.0", "method": "test", "params": nested, "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)

    # Should not crash - verify graceful handling
    assert not crashed, f"deeply_nested: Server crashed. Response: {response[:200]}"
    # Error indication is optional - deep nesting might be handled


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_null_bytes(skip_if_no_docker: Any) -> None:
    """Test that null bytes in input are handled without crash."""
    request_with_null = '{"jsonrpc": "2.0", "method": "test\\x00", "id": 1}'
    crashed, response, has_error = await send_raw_jsonrpc_request(request_with_null)
    assert not crashed, f"null_bytes: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_params_as_string(skip_if_no_docker: Any) -> None:
    """Test that params as string (not object/array) doesn't crash server."""
    request = {"jsonrpc": "2.0", "method": "test", "params": "invalid", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert_no_crash(crashed, response, has_error, "params_as_string")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_huge_string(skip_if_no_docker: Any) -> None:
    """Test that extremely large strings are rejected gracefully.

    This tests DoS protection against memory exhaustion attacks.
    """
    huge_string = "x" * (10 * 1024 * 1024)  # 10 MB string
    request = {"jsonrpc": "2.0", "method": "test", "params": {"data": huge_string}, "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)

    # Should not crash - verify graceful handling
    assert not crashed, f"huge_string: Server crashed or hung. Response: {response[:200]}"


# ============================================================================
# Injection Tests (from mcp-testbench prompt injection tests)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_command_injection_attempt(skip_if_no_docker: Any) -> None:
    """Test that command injection attempts in method names don't cause crashes."""
    request = {"jsonrpc": "2.0", "method": "test; rm -rf /", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    # Should not crash - method not found is fine
    assert not crashed, f"command_injection: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_path_traversal_in_method(skip_if_no_docker: Any) -> None:
    """Test that path traversal attempts in method names don't cause crashes."""
    request = {"jsonrpc": "2.0", "method": "../../../etc/passwd", "id": 1}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert not crashed, f"path_traversal: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_sql_injection_in_params(skip_if_no_docker: Any) -> None:
    """Test that SQL injection attempts in params don't cause crashes."""
    request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {"query": "1' OR '1'='1"},
        "id": 1,
    }
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert not crashed, f"sql_injection: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_xss_payload_in_params(skip_if_no_docker: Any) -> None:
    """Test that XSS payloads in params don't cause crashes."""
    request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {"data": "<script>alert('xss')</script>"},
        "id": 1,
    }
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert not crashed, f"xss_payload: Server crashed. Response: {response[:200]}"


# ============================================================================
# Edge Case Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_string_id_instead_of_number(skip_if_no_docker: Any) -> None:
    """Test that string IDs are handled (JSON-RPC allows string or number IDs)."""
    request = {"jsonrpc": "2.0", "method": "tools/list", "id": "string-id"}
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    # String IDs are valid in JSON-RPC 2.0, should not crash
    assert not crashed, f"string_id: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_unicode_exploit(skip_if_no_docker: Any) -> None:
    """Test that Unicode exploits are handled safely."""
    request = {
        "jsonrpc": "2.0",
        "method": "test\u202e\u202d",  # Right-to-left override characters
        "id": 1,
    }
    crashed, response, has_error = await send_raw_jsonrpc_request(request)
    assert not crashed, f"unicode_exploit: Server crashed. Response: {response[:200]}"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_multiple_requests_batch(skip_if_no_docker: Any) -> None:
    """Test that batch requests are handled (or rejected) properly.

    JSON-RPC 2.0 supports batch requests as an array of request objects.
    """
    batch_request = [
        {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        {"jsonrpc": "2.0", "method": "tools/list", "id": 2},
    ]
    crashed, response, has_error = await send_raw_jsonrpc_request(batch_request)
    # Either support batch or reject, but don't crash
    assert not crashed, f"batch_request: Server crashed. Response: {response[:200]}"
