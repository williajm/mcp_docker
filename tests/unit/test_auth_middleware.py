"""Unit tests for authentication middleware."""

import pytest

from mcp_docker.auth.middleware import AuthenticationError, AuthMiddleware
from mcp_docker.config import SecurityConfig


class TestAuthMiddleware:
    """Test authentication middleware functionality."""

    async def test_no_allowlist_allows_all_ips(self) -> None:
        """Test that no allowlist allows all IP addresses."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Should allow any IP
        result = await middleware.authenticate_request(ip_address="192.168.1.1")
        assert result.client_id == "192.168.1.1"
        assert result.ip_address == "192.168.1.1"
        assert result.auth_method == "ip"

        result = await middleware.authenticate_request(ip_address="10.0.0.1")
        assert result.client_id == "10.0.0.1"

    async def test_no_allowlist_allows_none_ip(self) -> None:
        """Test that no allowlist allows None IP (stdio transport)."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Should allow None (stdio)
        result = await middleware.authenticate_request(ip_address=None)
        assert result.client_id == "stdio"
        assert result.ip_address is None
        assert result.auth_method == "stdio"

    async def test_allowlist_blocks_unlisted_ips(self) -> None:
        """Test that allowlist blocks IP addresses not in the list."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100", "10.0.0.50"])
        middleware = AuthMiddleware(config)

        # Should block unlisted IP
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware.authenticate_request(ip_address="192.168.1.200")

        assert "IP address not allowed" in str(exc_info.value)
        assert "192.168.1.200" in str(exc_info.value)

    async def test_allowlist_allows_listed_ips(self) -> None:
        """Test that allowlist allows IP addresses in the list."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100", "10.0.0.50"])
        middleware = AuthMiddleware(config)

        # Should allow listed IPs
        result = await middleware.authenticate_request(ip_address="192.168.1.100")
        assert result.client_id == "192.168.1.100"
        assert result.ip_address == "192.168.1.100"
        assert result.auth_method == "ip"

        result = await middleware.authenticate_request(ip_address="10.0.0.50")
        assert result.client_id == "10.0.0.50"

    async def test_allowlist_allows_none_ip_stdio(self) -> None:
        """Test that allowlist allows None IP (stdio transport) - critical for stdio+SSE config.

        This test validates the fix for the regression where stdio transport was blocked
        when SECURITY_ALLOWED_CLIENT_IPS was configured for SSE deployment security.
        stdio should always bypass IP allowlist since it's local trusted process model.
        """
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Should allow None (stdio) even when allowlist is configured
        # This is the critical fix - stdio must work alongside SSE security
        result = await middleware.authenticate_request(ip_address=None)
        assert result.client_id == "stdio"
        assert result.ip_address is None
        assert result.description == "Local stdio transport"
        assert result.auth_method == "stdio"

    def test_check_ip_allowed_no_allowlist(self) -> None:
        """Test check_ip_allowed with no allowlist."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        assert middleware.check_ip_allowed("192.168.1.1") is True
        assert middleware.check_ip_allowed("10.0.0.1") is True
        assert middleware.check_ip_allowed(None) is True

    def test_check_ip_allowed_with_allowlist(self) -> None:
        """Test check_ip_allowed with allowlist configured."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100", "10.0.0.50"])
        middleware = AuthMiddleware(config)

        # Listed IPs should be allowed
        assert middleware.check_ip_allowed("192.168.1.100") is True
        assert middleware.check_ip_allowed("10.0.0.50") is True

        # Unlisted IPs should be blocked
        assert middleware.check_ip_allowed("192.168.1.200") is False
        assert middleware.check_ip_allowed("10.0.0.100") is False

        # None (stdio) should be allowed
        assert middleware.check_ip_allowed(None) is True

    async def test_client_info_structure(self) -> None:
        """Test that ClientInfo is properly constructed."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Test with IP address
        result = await middleware.authenticate_request(ip_address="192.168.1.100")
        assert result.client_id == "192.168.1.100"
        assert result.api_key_hash == "none"
        assert result.description == "IP-based access"
        assert result.ip_address == "192.168.1.100"
        assert result.auth_method == "ip"

        # Test with None (stdio)
        result = await middleware.authenticate_request(ip_address=None)
        assert result.client_id == "stdio"
        assert result.api_key_hash == "none"
        assert result.description == "Local stdio transport"
        assert result.ip_address is None
        assert result.auth_method == "stdio"

    def test_edge_cases(self) -> None:
        """Test edge cases for IP allowlist."""
        # Empty allowlist (all allowed)
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)
        assert middleware.check_ip_allowed("") is True
        assert middleware.check_ip_allowed("0.0.0.0") is True

        # Single IP in allowlist
        config = SecurityConfig(allowed_client_ips=["127.0.0.1"])
        middleware = AuthMiddleware(config)
        assert middleware.check_ip_allowed("127.0.0.1") is True
        assert middleware.check_ip_allowed("127.0.0.2") is False
        assert middleware.check_ip_allowed(None) is True  # stdio always allowed
