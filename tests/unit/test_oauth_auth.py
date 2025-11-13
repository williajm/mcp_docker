"""Unit tests for OAuth authentication."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_docker.auth.oauth_auth import OAuthAuthenticationError, OAuthAuthenticator
from mcp_docker.config import SecurityConfig


@pytest.fixture
def oauth_config() -> SecurityConfig:
    """Create OAuth-enabled security config."""
    return SecurityConfig(
        oauth_enabled=True,
        oauth_issuer="https://auth.example.com",
        oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        oauth_audience=["mcp-docker-api"],
        oauth_required_scopes=["docker.read"],
        oauth_clock_skew_seconds=60,
    )


@pytest.fixture
def test_key_pair() -> tuple[dict, dict]:
    """Generate a test RSA key pair for JWT signing."""
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
    key_id = "test-key-1"
    private_key["kid"] = key_id
    public_key["kid"] = key_id

    return private_key, public_key


@pytest.fixture
def jwks_response(test_key_pair: tuple[dict, dict]) -> dict:
    """Create mock JWKS response."""
    _, public_key = test_key_pair
    return {"keys": [public_key]}


def create_test_jwt(  # noqa: PLR0913
    private_key: dict,
    issuer: str = "https://auth.example.com/",  # Trailing slash to match Pydantic HttpUrl
    audience: str = "mcp-docker-api",
    subject: str = "user123",
    scopes: list[str] | None = None,
    exp_minutes: int = 60,
    **extra_claims: str,
) -> str:
    """Create a test JWT token."""
    now = datetime.now(UTC)
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


class TestOAuthAuthenticator:
    """Test OAuth authenticator functionality."""

    def test_init_without_oauth_enabled_raises_error(self) -> None:
        """Test that initializing authenticator without OAuth enabled raises error."""
        config = SecurityConfig(oauth_enabled=False)

        with pytest.raises(ValueError, match="OAuth authenticator created but oauth_enabled=False"):
            OAuthAuthenticator(config)

    async def test_authenticate_valid_jwt(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test authenticating with a valid JWT token."""
        private_key, _ = test_key_pair

        # Create valid JWT
        token = create_test_jwt(
            private_key,
            scopes=["docker.read", "docker.write"],
            email="user@example.com",
            name="Test User",
        )

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)
            client_info = await authenticator.authenticate_token(token)

            assert client_info.client_id == "user123"
            assert client_info.auth_method == "oauth"
            assert "docker.read" in client_info.scopes
            assert "docker.write" in client_info.scopes
            assert client_info.extra["email"] == "user@example.com"
            assert client_info.extra["name"] == "Test User"

            await authenticator.close()

    async def test_authenticate_invalid_signature_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that invalid JWT signature raises error."""
        private_key, _ = test_key_pair

        # Create JWT with valid signature
        token = create_test_jwt(private_key)

        # Tamper with the token to invalidate signature
        tampered_token = token[:-10] + "0000000000"

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError, match="Invalid JWT token"):
                await authenticator.authenticate_token(tampered_token)

            await authenticator.close()

    async def test_authenticate_expired_token_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that expired JWT raises error."""
        private_key, _ = test_key_pair

        # Create expired JWT (expired 5 minutes ago, beyond clock skew)
        token = create_test_jwt(private_key, exp_minutes=-5)

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token)

            await authenticator.close()

    async def test_authenticate_wrong_issuer_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that wrong issuer raises error."""
        private_key, _ = test_key_pair

        # Create JWT with wrong issuer
        token = create_test_jwt(private_key, issuer="https://wrong-issuer.com")

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token)

            await authenticator.close()

    async def test_authenticate_wrong_audience_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that wrong audience raises error."""
        private_key, _ = test_key_pair

        # Create JWT with wrong audience
        token = create_test_jwt(private_key, audience="wrong-audience")

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token)

            await authenticator.close()

    async def test_authenticate_missing_required_scope_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that missing required scope raises error."""
        private_key, _ = test_key_pair

        # Create JWT without required scope
        token = create_test_jwt(private_key, scopes=["other.scope"])

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError, match="Missing required scopes"):
                await authenticator.authenticate_token(token)

            await authenticator.close()

    async def test_jwks_caching(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that JWKS is cached and reused."""
        private_key, _ = test_key_pair

        # Create valid JWT
        token = create_test_jwt(private_key, scopes=["docker.read"])

        # Mock JWKS fetch
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)

            # First authentication - should fetch JWKS
            await authenticator.authenticate_token(token)
            assert mock_get.call_count == 1

            # Second authentication - should use cached JWKS
            await authenticator.authenticate_token(token)
            assert mock_get.call_count == 1  # No additional fetch

            await authenticator.close()

    async def test_scope_extraction_from_various_formats(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test extracting scopes from different claim formats."""
        private_key, _ = test_key_pair

        # Test space-separated scope string
        token = create_test_jwt(private_key, scopes=["docker.read", "docker.write"])

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(oauth_config)
            client_info = await authenticator.authenticate_token(token)

            assert "docker.read" in client_info.scopes
            assert "docker.write" in client_info.scopes

            await authenticator.close()

    async def test_authenticate_no_required_scopes(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test authentication when no scopes are required."""
        private_key, _ = test_key_pair

        # Config without required scopes
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],  # No required scopes
        )

        # Create JWT with no scopes
        token = create_test_jwt(private_key, scopes=[])

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)
            client_info = await authenticator.authenticate_token(token)

            # Should succeed even without scopes
            assert client_info.client_id == "user123"
            assert client_info.scopes == []

            await authenticator.close()

    async def test_jwks_fetch_failure_raises_error(
        self,
        oauth_config: SecurityConfig,
        test_key_pair: tuple[dict, dict],
    ) -> None:
        """Test that JWKS fetch failure raises error."""
        private_key, _ = test_key_pair
        token = create_test_jwt(private_key, scopes=["docker.read"])

        # Mock JWKS fetch failure
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.side_effect = httpx.HTTPError("Connection failed")

            authenticator = OAuthAuthenticator(oauth_config)

            with pytest.raises(OAuthAuthenticationError, match="Failed to fetch JWKS"):
                await authenticator.authenticate_token(token)

            await authenticator.close()

    async def test_introspection_active_token(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test token introspection for active token (fallback when JWT validation fails)."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=["docker.read"],
            oauth_introspection_url="https://auth.example.com/introspect",
            oauth_client_id="mcp-docker",
            oauth_client_secret="secret123",
        )

        # Create invalid JWT (wrong signature) to force introspection
        token = create_test_jwt(private_key, scopes=["docker.read"])
        invalid_token = token[:-10] + "0000000000"  # Tamper to invalidate signature

        # Mock introspection response
        introspection_response = {
            "active": True,
            "sub": "user456",
            "scope": "docker.read docker.write",
            "client_id": "client-app",
            "email": "user@example.com",
        }

        with (
            patch("httpx.AsyncClient.get") as mock_get,
            patch("httpx.AsyncClient.post") as mock_post,
        ):
            # JWKS fetch succeeds but token validation will fail
            mock_jwks_response = MagicMock()
            mock_jwks_response.json.return_value = jwks_response
            mock_jwks_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_jwks_response

            # Mock successful introspection
            mock_introspect_response = MagicMock()
            mock_introspect_response.json.return_value = introspection_response
            mock_introspect_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_introspect_response

            authenticator = OAuthAuthenticator(config)
            client_info = await authenticator.authenticate_token(invalid_token)

            assert client_info.client_id == "user456"
            assert client_info.auth_method == "oauth"
            assert "docker.read" in client_info.scopes
            assert "docker.write" in client_info.scopes
            assert client_info.extra["client_id"] == "client-app"

            await authenticator.close()

    async def test_introspection_inactive_token_raises_error(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that inactive token from introspection raises error."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
            oauth_introspection_url="https://auth.example.com/introspect",
            oauth_client_id="mcp-docker",
            oauth_client_secret="secret123",
        )

        # Create invalid JWT to force introspection
        token = create_test_jwt(private_key, scopes=[])
        invalid_token = token[:-10] + "0000000000"

        # Mock inactive token response
        introspection_response = {"active": False}

        with (
            patch("httpx.AsyncClient.get") as mock_get,
            patch("httpx.AsyncClient.post") as mock_post,
        ):
            # JWKS fetch succeeds but token validation will fail
            mock_jwks_response = MagicMock()
            mock_jwks_response.json.return_value = jwks_response
            mock_jwks_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_jwks_response

            mock_introspect_response = MagicMock()
            mock_introspect_response.json.return_value = introspection_response
            mock_introspect_response.raise_for_status = MagicMock()
            mock_post.return_value = mock_introspect_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError, match="Token is not active"):
                await authenticator.authenticate_token(invalid_token)

            await authenticator.close()
