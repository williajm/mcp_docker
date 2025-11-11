"""Tests for IP extraction security.

SECURITY NOTE: X-Forwarded-For header processing is now handled by Uvicorn's
battle-tested ProxyHeadersMiddleware. These tests verify that our _extract_client_ip
function correctly reads from the ASGI scope after middleware processing.

The middleware is configured with trusted_hosts in run_sse() and handles all
proxy header validation, CIDR matching, and IP spoofing prevention.
"""

from mcp_docker.__main__ import _extract_client_ip


class TestClientIPExtraction:
    """Test client IP extraction from ASGI scope.

    These tests verify that _extract_client_ip correctly reads from scope['client'],
    which has already been processed by ProxyHeadersMiddleware.
    """

    def test_extract_ip_from_scope_client(self) -> None:
        """Test extracting IP from scope['client'] tuple."""
        scope = {
            "type": "http",
            "client": ("192.168.1.100", 12345),  # (host, port) tuple
        }
        ip = _extract_client_ip(scope)
        assert ip == "192.168.1.100"

    def test_extract_ipv6_from_scope_client(self) -> None:
        """Test extracting IPv6 address from scope['client']."""
        scope = {
            "type": "http",
            "client": ("2001:db8::1", 12345),
            "headers": [],
        }
        ip = _extract_client_ip(scope)
        assert ip == "2001:db8::1"

    def test_extract_ipv6_localhost(self) -> None:
        """Test handling IPv6 localhost."""
        scope = {
            "type": "http",
            "client": ("::1", 12345),
            "headers": [],
        }
        ip = _extract_client_ip(scope)
        assert ip == "::1"

    def test_handles_missing_client_field(self) -> None:
        """Test handling scope without client field."""
        scope: dict[str, object] = {
            "type": "http",
            "headers": [],
        }
        ip = _extract_client_ip(scope)
        assert ip is None

    def test_handles_none_client_field(self) -> None:
        """Test handling scope with None client."""
        scope: dict[str, object] = {
            "type": "http",
            "client": None,
            "headers": [],
        }
        ip = _extract_client_ip(scope)
        assert ip is None

    def test_handles_empty_client_tuple(self) -> None:
        """Test handling empty client tuple."""
        scope: dict[str, object] = {
            "type": "http",
            "client": (),  # Empty tuple
            "headers": [],
        }
        ip = _extract_client_ip(scope)
        assert ip is None


class TestProxyHeadersMiddlewareIntegration:
    """Test notes for ProxyHeadersMiddleware integration.

    SECURITY: ProxyHeadersMiddleware is battle-tested by Uvicorn and handles:
    - X-Forwarded-For header validation with trusted_hosts
    - CIDR notation for trusted proxy networks
    - IP spoofing prevention (ignores headers from untrusted sources)
    - Multiple proxy chain handling (leftmost IP extraction)
    - IPv4 and IPv6 support

    The middleware updates scope['client'] with the real client IP before
    our _extract_client_ip function is called.

    Configuration in run_sse():
        ProxyHeadersMiddleware(
            sse_handler,
            trusted_hosts=config.security.trusted_proxies or ["127.0.0.1"]
        )

    This prevents common attacks:
    1. IP allowlist bypass via header spoofing
    2. Rate limit evasion via rotating fake IPs
    3. Audit log poisoning with fake IPs

    See Uvicorn documentation:
    https://www.uvicorn.org/deployment/#running-behind-nginx
    """

    def test_middleware_integration_note(self) -> None:
        """Document that ProxyHeadersMiddleware handles security.

        This is a documentation test to remind developers that:
        1. We use Uvicorn's ProxyHeadersMiddleware for proxy header processing
        2. The middleware is configured in run_sse() with trusted_hosts
        3. All X-Forwarded-For security is handled by the middleware
        4. Our _extract_client_ip just reads from scope['client']
        """
        # Documentation test - no assertions needed
        pass
