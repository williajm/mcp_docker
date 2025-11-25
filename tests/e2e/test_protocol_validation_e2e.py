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


def assert_no_crash_lenient(crashed: bool, response: str, test_name: str) -> None:
    """Assert that server did not crash (error indication optional).

    Args:
        crashed: Whether server crashed
        response: Server response
        test_name: Name of the test for error messages
    """
    assert not crashed, f"{test_name}: Server crashed or hung. Response: {response[:200]}"


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
# Parameterized Fuzzing Tests
# ============================================================================


class TestProtocolFuzzing:
    """Test that various malformed inputs don't crash the server."""

    @pytest.mark.e2e
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "test_name,request_data",
        [
            ("empty_payload", ""),
            ("invalid_json", "{invalid json"),
            ("null_payload", "null"),
            ("array_payload", "[]"),
            ("missing_method", {"jsonrpc": "2.0", "id": 1}),
            ("invalid_method_type", {"jsonrpc": "2.0", "method": 123, "id": 1}),
            ("missing_jsonrpc_version", {"method": "test", "id": 1}),
            ("invalid_jsonrpc_version", {"jsonrpc": "1.0", "method": "test", "id": 1}),
            (
                "params_as_string",
                {"jsonrpc": "2.0", "method": "test", "params": "invalid", "id": 1},
            ),
        ],
    )
    async def test_malformed_request_no_crash(
        self, skip_if_no_docker: Any, test_name: str, request_data: str | dict
    ) -> None:
        """Test that malformed requests don't crash the server."""
        crashed, response, has_error = await send_raw_jsonrpc_request(request_data)
        assert_no_crash(crashed, response, has_error, test_name)

    @pytest.mark.e2e
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "test_name,request_data",
        [
            ("null_bytes", '{"jsonrpc": "2.0", "method": "test\\x00", "id": 1}'),
            ("string_id", {"jsonrpc": "2.0", "method": "tools/list", "id": "string-id"}),
            ("unicode_exploit", {"jsonrpc": "2.0", "method": "test\u202e\u202d", "id": 1}),
            (
                "batch_request",
                [
                    {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                    {"jsonrpc": "2.0", "method": "tools/list", "id": 2},
                ],
            ),
        ],
    )
    async def test_edge_case_no_crash(
        self, skip_if_no_docker: Any, test_name: str, request_data: str | dict | list
    ) -> None:
        """Test that edge case requests don't crash the server (error optional)."""
        crashed, response, _ = await send_raw_jsonrpc_request(request_data)
        assert_no_crash_lenient(crashed, response, test_name)

    @pytest.mark.e2e
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_deeply_nested_objects(self, skip_if_no_docker: Any) -> None:
        """Test that deeply nested objects don't cause crash or DoS.

        This tests protection against billion laughs / nested object attacks.
        """
        # Create deeply nested object (100 levels - more realistic for actual attacks)
        nested: dict[str, Any] = {"a": "value"}
        for _ in range(100):
            nested = {"nested": nested}

        request = {"jsonrpc": "2.0", "method": "test", "params": nested, "id": 1}
        crashed, response, _ = await send_raw_jsonrpc_request(request)
        assert_no_crash_lenient(crashed, response, "deeply_nested")

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_huge_string(self, skip_if_no_docker: Any) -> None:
        """Test that extremely large strings are rejected gracefully.

        This tests DoS protection against memory exhaustion attacks.
        """
        huge_string = "x" * (10 * 1024 * 1024)  # 10 MB string
        request = {"jsonrpc": "2.0", "method": "test", "params": {"data": huge_string}, "id": 1}
        crashed, response, _ = await send_raw_jsonrpc_request(request)
        assert_no_crash_lenient(crashed, response, "huge_string")


# ============================================================================
# Parameterized Injection Tests
# ============================================================================


class TestInjectionAttempts:
    """Test that injection attempts don't cause crashes."""

    @pytest.mark.e2e
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "test_name,request_data",
        [
            ("command_injection", {"jsonrpc": "2.0", "method": "test; rm -rf /", "id": 1}),
            ("path_traversal", {"jsonrpc": "2.0", "method": "../../../etc/passwd", "id": 1}),
            (
                "sql_injection",
                {
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {"query": "1' OR '1'='1"},
                    "id": 1,
                },
            ),
            (
                "xss_payload",
                {
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {"data": "<script>alert('xss')</script>"},
                    "id": 1,
                },
            ),
        ],
    )
    async def test_injection_no_crash(
        self, skip_if_no_docker: Any, test_name: str, request_data: dict
    ) -> None:
        """Test that injection attempts don't crash the server."""
        crashed, response, _ = await send_raw_jsonrpc_request(request_data)
        assert_no_crash_lenient(crashed, response, test_name)
