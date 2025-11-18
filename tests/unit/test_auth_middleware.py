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


class TestAuthMiddlewareCall:
    """Test the __call__ method (FastMCP 2.0 middleware entry point)."""

    async def test_call_with_stdio_context(self) -> None:
        """Test __call__ with stdio context (no IP address)."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context for stdio (no fastmcp_context or IP)
        mock_context = AsyncMock()
        mock_context.fastmcp_context = None

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_ip_address_extraction(self) -> None:
        """Test __call__ extracts IP address from FastMCP context correctly."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Create mock FastMCP context with full request structure
        mock_client = AsyncMock()
        mock_client.host = "192.168.1.100"

        mock_request = AsyncMock()
        mock_request.client = mock_client
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

        # Verify client_info was stored in context
        assert hasattr(mock_fastmcp_context, "client_info")
        assert mock_fastmcp_context.client_info.ip_address == "192.168.1.100"

    async def test_call_with_bearer_token_extraction(self) -> None:
        """Test __call__ extracts bearer token from Authorization header."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        with patch("mcp_docker.auth.middleware.OAuthAuthenticator") as mock_oauth_class:
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

            # Create mock FastMCP context with Authorization header
            mock_client = AsyncMock()
            mock_client.host = "192.168.1.100"

            mock_request = AsyncMock()
            mock_request.client = mock_client
            mock_request.headers = {"authorization": "Bearer test_jwt_token"}

            mock_request_context = AsyncMock()
            mock_request_context.request = mock_request

            mock_fastmcp_context = AsyncMock()
            mock_fastmcp_context.request_context = mock_request_context

            mock_context = AsyncMock()
            mock_context.fastmcp_context = mock_fastmcp_context

            # Mock call_next
            mock_call_next = AsyncMock(return_value="success")

            # Call the middleware
            result = await middleware(mock_context, mock_call_next)

            # Verify it succeeded
            assert result == "success"
            mock_call_next.assert_called_once_with(mock_context)

            # Verify bearer token was extracted and validated
            mock_authenticator.authenticate_token.assert_called_once_with("test_jwt_token")

            # Verify client_info was stored in context
            assert hasattr(mock_fastmcp_context, "client_info")
            assert mock_fastmcp_context.client_info.client_id == "user123"

    async def test_call_with_authorization_header_without_bearer_prefix(self) -> None:
        """Test __call__ ignores Authorization header without 'Bearer ' prefix."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Create mock FastMCP context with Authorization header (no Bearer prefix)
        mock_client = AsyncMock()
        mock_client.host = "192.168.1.100"

        mock_request = AsyncMock()
        mock_request.client = mock_client
        mock_request.headers = {"authorization": "Basic dXNlcjpwYXNz"}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded (falls back to IP-based auth)
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_authentication_error_propagation(self) -> None:
        """Test __call__ propagates AuthenticationError when auth fails."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Create mock FastMCP context with blocked IP
        mock_client = AsyncMock()
        mock_client.host = "10.0.0.1"  # Not in allowlist

        mock_request = AsyncMock()
        mock_request.client = mock_client
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next (should not be called)
        mock_call_next = AsyncMock()

        # Call the middleware - should raise AuthenticationError
        with pytest.raises(AuthenticationError) as exc_info:
            await middleware(mock_context, mock_call_next)

        # Verify error message
        assert "IP address not allowed" in str(exc_info.value)
        assert "10.0.0.1" in str(exc_info.value)

        # Verify call_next was never called
        mock_call_next.assert_not_called()

    async def test_call_with_partial_context_no_request_context(self) -> None:
        """Test __call__ handles missing request_context gracefully."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context without request_context attribute
        mock_fastmcp_context = AsyncMock(spec=[])  # Empty spec, no attributes
        del mock_fastmcp_context.request_context  # Ensure it doesn't have it

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_partial_context_no_request(self) -> None:
        """Test __call__ handles missing request gracefully."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context without request attribute
        mock_request_context = AsyncMock(spec=[])  # Empty spec
        del mock_request_context.request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_partial_context_no_client(self) -> None:
        """Test __call__ handles missing client gracefully."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context without client attribute
        mock_request = AsyncMock(spec=["headers"])
        del mock_request.client
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_partial_context_no_host(self) -> None:
        """Test __call__ handles missing host gracefully."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context without host attribute
        mock_client = AsyncMock(spec=[])
        del mock_client.host

        mock_request = AsyncMock()
        mock_request.client = mock_client
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_partial_context_no_headers(self) -> None:
        """Test __call__ handles missing headers gracefully."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Create mock context without headers attribute
        mock_client = AsyncMock()
        mock_client.host = "192.168.1.100"

        mock_request = AsyncMock(spec=["client"])
        del mock_request.headers
        mock_request.client = mock_client

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_none_request_context(self) -> None:
        """Test __call__ handles None request_context."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context with None request_context
        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = None

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_none_request(self) -> None:
        """Test __call__ handles None request."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context with None request
        mock_request_context = AsyncMock()
        mock_request_context.request = None

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_with_none_client(self) -> None:
        """Test __call__ handles None client."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context with None client
        mock_request = AsyncMock()
        mock_request.client = None
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should treat as stdio)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)

    async def test_call_stores_client_info_in_context(self) -> None:
        """Test __call__ stores client_info in fastmcp_context for downstream middleware."""
        config = SecurityConfig(allowed_client_ips=["192.168.1.100"])
        middleware = AuthMiddleware(config)

        # Create mock FastMCP context
        mock_client = AsyncMock()
        mock_client.host = "192.168.1.100"

        mock_request = AsyncMock()
        mock_request.client = mock_client
        mock_request.headers = {}

        mock_request_context = AsyncMock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = AsyncMock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = AsyncMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware
        await middleware(mock_context, mock_call_next)

        # Verify client_info was stored
        assert hasattr(mock_fastmcp_context, "client_info")
        client_info = mock_fastmcp_context.client_info
        assert client_info.client_id == "192.168.1.100"
        assert client_info.auth_method == "ip"
        assert client_info.ip_address == "192.168.1.100"

    async def test_call_does_not_store_client_info_if_no_fastmcp_context(self) -> None:
        """Test __call__ handles missing fastmcp_context when storing client_info."""
        config = SecurityConfig(allowed_client_ips=[])
        middleware = AuthMiddleware(config)

        # Create mock context without fastmcp_context
        mock_context = AsyncMock()
        mock_context.fastmcp_context = None

        # Mock call_next
        mock_call_next = AsyncMock(return_value="success")

        # Call the middleware (should not crash)
        result = await middleware(mock_context, mock_call_next)

        # Verify it succeeded
        assert result == "success"
        mock_call_next.assert_called_once_with(mock_context)
