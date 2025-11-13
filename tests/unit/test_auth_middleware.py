"""Unit tests for authentication middleware."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from mcp_docker.auth.middleware import AuthenticationError, AuthMiddleware
from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.oauth_auth import OAuthAuthenticationError
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


class TestAuthMiddlewareOAuth:
    """Test OAuth authentication in middleware."""

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    def test_oauth_authenticator_initialization(self, mock_oauth_class: AsyncMock) -> None:
        """Test OAuth authenticator is initialized when oauth_enabled=True."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        middleware = AuthMiddleware(config)

        # Verify OAuthAuthenticator was instantiated
        mock_oauth_class.assert_called_once_with(config)
        assert middleware.oauth_authenticator is not None

    def test_no_oauth_authenticator_when_disabled(self) -> None:
        """Test OAuth authenticator is not initialized when oauth_enabled=False."""
        config = SecurityConfig(oauth_enabled=False)

        middleware = AuthMiddleware(config)

        # Verify OAuth authenticator is None
        assert middleware.oauth_authenticator is None

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_bearer_token_required(self, mock_oauth_class: AsyncMock) -> None:
        """Test bearer token is required when OAuth is enabled."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        middleware = AuthMiddleware(config)

        # Try to authenticate without bearer token
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware.authenticate_request(ip_address="192.168.1.100", bearer_token=None)

        assert "Bearer token required" in str(exc_info.value)

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_successful_authentication(self, mock_oauth_class: AsyncMock) -> None:
        """Test successful OAuth authentication with valid bearer token."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_required_scopes=["docker.read"],
        )

        # Mock the OAuthAuthenticator instance
        mock_authenticator = AsyncMock()
        mock_oauth_class.return_value = mock_authenticator

        # Mock successful authentication result
        mock_client_info = ClientInfo(
            client_id="user123",
            auth_method="oauth",
            api_key_hash="oauth",
            description="OAuth authenticated client",
            scopes=["docker.read", "docker.write"],
            extra={"email": "user@example.com"},
            authenticated_at=datetime.now(UTC),
        )
        mock_authenticator.authenticate_token.return_value = mock_client_info

        middleware = AuthMiddleware(config)

        # Authenticate with bearer token
        result = await middleware.authenticate_request(
            ip_address="192.168.1.100",
            bearer_token="valid_jwt_token",
        )

        # Verify authentication was successful
        assert result.client_id == "user123"
        assert result.auth_method == "oauth"
        assert result.scopes == ["docker.read", "docker.write"]
        assert result.ip_address == "192.168.1.100"
        assert result.extra == {"email": "user@example.com"}

        # Verify the token was validated
        mock_authenticator.authenticate_token.assert_called_once_with("valid_jwt_token")

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_authentication_failure(self, mock_oauth_class: AsyncMock) -> None:
        """Test OAuth authentication failure with invalid token."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        # Mock the OAuthAuthenticator instance
        mock_authenticator = AsyncMock()
        mock_oauth_class.return_value = mock_authenticator

        # Mock authentication failure
        mock_authenticator.authenticate_token.side_effect = OAuthAuthenticationError(
            "Invalid JWT token: signature verification failed"
        )

        middleware = AuthMiddleware(config)

        # Try to authenticate with invalid token
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware.authenticate_request(
                ip_address="192.168.1.100",
                bearer_token="invalid_jwt_token",
            )

        assert "OAuth authentication failed" in str(exc_info.value)
        assert "signature verification failed" in str(exc_info.value)

        # Verify the token was attempted to be validated
        mock_authenticator.authenticate_token.assert_called_once_with("invalid_jwt_token")

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_stdio_bypass(self, mock_oauth_class: AsyncMock) -> None:
        """Test stdio transport bypasses OAuth authentication."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        middleware = AuthMiddleware(config)

        # Authenticate via stdio (ip_address=None, no bearer token)
        result = await middleware.authenticate_request(ip_address=None, bearer_token=None)

        # Verify stdio bypassed OAuth
        assert result.client_id == "stdio"
        assert result.auth_method == "stdio"
        assert result.ip_address is None

        # Verify OAuth authenticator was never called
        mock_oauth_class.return_value.authenticate_token.assert_not_called()

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_close_cleanup(self, mock_oauth_class: AsyncMock) -> None:
        """Test close() method cleans up OAuth authenticator."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        # Mock the OAuthAuthenticator instance
        mock_authenticator = AsyncMock()
        mock_oauth_class.return_value = mock_authenticator

        middleware = AuthMiddleware(config)

        # Close the middleware
        await middleware.close()

        # Verify the OAuth authenticator close was called
        mock_authenticator.close.assert_called_once()

    async def test_close_without_oauth(self) -> None:
        """Test close() method when OAuth is disabled."""
        config = SecurityConfig(oauth_enabled=False)

        middleware = AuthMiddleware(config)

        # Close should not raise an error
        await middleware.close()

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_authenticator_not_initialized_error(
        self, mock_oauth_class: AsyncMock
    ) -> None:
        """Test error when OAuth enabled but authenticator not initialized (edge case)."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        middleware = AuthMiddleware(config)

        # Manually set authenticator to None to simulate initialization failure
        middleware.oauth_authenticator = None

        # Try to authenticate with bearer token
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware.authenticate_request(
                ip_address="192.168.1.100",
                bearer_token="some_token",
            )

        assert "OAuth authentication not available" in str(exc_info.value)

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_with_ip_allowlist_defense_in_depth(
        self, mock_oauth_class: AsyncMock
    ) -> None:
        """Test defense-in-depth: valid OAuth token but IP not in allowlist is rejected."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            allowed_client_ips=["192.168.1.100", "192.168.1.101"],
        )

        # Mock the OAuthAuthenticator instance
        mock_authenticator = AsyncMock()
        mock_oauth_class.return_value = mock_authenticator

        # Mock successful OAuth authentication
        mock_client_info = ClientInfo(
            client_id="user123",
            auth_method="oauth",
            api_key_hash="oauth",
            description="OAuth authenticated client",
            scopes=["docker.read"],
            authenticated_at=datetime.now(UTC),
        )
        mock_authenticator.authenticate_token.return_value = mock_client_info

        middleware = AuthMiddleware(config)

        # Try to authenticate with valid OAuth token but IP not in allowlist
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware.authenticate_request(
                ip_address="10.0.0.1",  # Not in allowlist
                bearer_token="valid_jwt_token",
            )

        # Should fail due to IP not in allowlist, despite valid OAuth token
        assert "IP address not allowed" in str(exc_info.value)
        assert "10.0.0.1" in str(exc_info.value)

        # OAuth authentication should have been called first
        mock_authenticator.authenticate_token.assert_called_once_with("valid_jwt_token")

    @patch("mcp_docker.auth.middleware.OAuthAuthenticator")
    async def test_oauth_with_ip_in_allowlist_succeeds(self, mock_oauth_class: AsyncMock) -> None:
        """Test defense-in-depth: valid OAuth token with IP in allowlist succeeds."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            allowed_client_ips=["192.168.1.100", "192.168.1.101"],
        )

        # Mock the OAuthAuthenticator instance
        mock_authenticator = AsyncMock()
        mock_oauth_class.return_value = mock_authenticator

        # Mock successful OAuth authentication
        mock_client_info = ClientInfo(
            client_id="user123",
            auth_method="oauth",
            api_key_hash="oauth",
            description="OAuth authenticated client",
            scopes=["docker.read"],
            authenticated_at=datetime.now(UTC),
        )
        mock_authenticator.authenticate_token.return_value = mock_client_info

        middleware = AuthMiddleware(config)

        # Authenticate with valid OAuth token and IP in allowlist
        result = await middleware.authenticate_request(
            ip_address="192.168.1.100",  # In allowlist
            bearer_token="valid_jwt_token",
        )

        # Should succeed - both OAuth and IP allowlist pass
        assert result.client_id == "user123"
        assert result.auth_method == "oauth"
        assert result.ip_address == "192.168.1.100"

        # OAuth authentication should have been called
        mock_authenticator.authenticate_token.assert_called_once_with("valid_jwt_token")
