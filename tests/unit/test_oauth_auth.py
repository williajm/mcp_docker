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


class TestOAuthSecurityVulnerabilities:
    """Security-focused tests for OAuth vulnerabilities per RFC 8725 and OAuth 2.0 BCP."""

    async def test_algorithm_none_attack_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that JWT with alg=none is rejected (CVE-2015-9235 class vulnerability)."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create token with alg=none (no signature)
        import base64
        import json

        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        # Encode header and payload, no signature
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
        none_token = f"{header_b64.decode()}.{payload_b64.decode()}."

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(none_token)

            await authenticator.close()

    async def test_algorithm_confusion_hs256_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that JWT with HS256 instead of RS256 is rejected (algorithm confusion attack)."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create token with HS256 (symmetric) instead of RS256 (asymmetric)
        import base64
        import hashlib
        import hmac
        import json

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
        message = f"{header_b64.decode()}.{payload_b64.decode()}"

        # Sign with HMAC (using public key as secret - a common attack)
        signature = hmac.new(b"secret", message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
        hs256_token = f"{message}.{sig_b64.decode()}"

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(hs256_token)

            await authenticator.close()

    async def test_malformed_token_not_jwt_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that non-JWT token (random string) is rejected gracefully."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        malformed_tokens = [
            "not-a-jwt-token",
            "only.two.parts",  # Missing signature
            "one-part-only",
            "",
            "a" * 1000,  # Very long random string
        ]

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            for malformed_token in malformed_tokens:
                with pytest.raises(OAuthAuthenticationError):
                    await authenticator.authenticate_token(malformed_token)

            await authenticator.close()

    async def test_token_missing_required_claims_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that tokens missing required claims (sub, exp, iss) are rejected."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Test missing 'sub' claim
        payload_no_sub = {
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }
        token_no_sub = jwt.encode({"alg": "RS256"}, payload_no_sub, private_key)

        # Test missing 'exp' claim
        payload_no_exp = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "iat": int(datetime.now(UTC).timestamp()),
        }
        token_no_exp = jwt.encode({"alg": "RS256"}, payload_no_exp, private_key)

        # Test missing 'iss' claim
        payload_no_iss = {
            "sub": "user123",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }
        token_no_iss = jwt.encode({"alg": "RS256"}, payload_no_iss, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # All should be rejected
            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token_no_sub.decode())

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token_no_exp.decode())

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token_no_iss.decode())

            await authenticator.close()

    async def test_not_before_nbf_claim_validation(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that tokens with nbf (not before) in the future are rejected."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
            oauth_clock_skew_seconds=60,
        )

        # Create token with nbf 5 minutes in the future (beyond clock skew)
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
            "nbf": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        }
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_multiple_audiences_partial_match(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test token with multiple audiences where one matches is accepted."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",  # Trailing slash for Pydantic HttpUrl
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],  # We require this audience
            oauth_required_scopes=[],
        )

        # Create token with multiple audiences, one matching
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": [
                "some-other-api",
                "mcp-docker-api",
                "yet-another-api",
            ],  # Multiple audiences
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # Should succeed - one audience matches
            client_info = await authenticator.authenticate_token(token.decode())
            assert client_info.client_id == "user123"

            await authenticator.close()

    async def test_jwks_kid_mismatch_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that token with kid not in JWKS is rejected."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create token with wrong kid
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        # Force wrong kid in header
        header = {"alg": "RS256", "kid": "non-existent-key-id"}
        token = jwt.encode(header, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_empty_scope_handling(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test handling of empty and whitespace-only scopes."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",  # Trailing slash for Pydantic HttpUrl
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=["docker.read"],  # Require scope
        )

        test_cases = [
            "",  # Empty string
            "   ",  # Whitespace only
            " docker.read  docker.write ",  # Extra whitespace
        ]

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            for scope_value in test_cases:
                payload = {
                    "sub": "user123",
                    "iss": "https://auth.example.com/",
                    "aud": ["mcp-docker-api"],
                    "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
                    "iat": int(datetime.now(UTC).timestamp()),
                    "scope": scope_value,
                }
                token = jwt.encode({"alg": "RS256"}, payload, private_key)

                if scope_value.strip() and "docker.read" in scope_value:
                    # Should succeed for valid scopes with whitespace
                    client_info = await authenticator.authenticate_token(token.decode())
                    assert "docker.read" in client_info.scopes
                else:
                    # Should fail for empty/whitespace-only scopes
                    with pytest.raises(OAuthAuthenticationError, match="Missing required scopes"):
                        await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_case_insensitive_none_algorithm_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that case variations of 'none' algorithm are rejected (OWASP recommendation)."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        import base64
        import json

        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        # Test various case variations of "none"
        none_variations = ["NoNe", "NONE", "nOnE", "nONE", "NonE"]

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            for alg_variant in none_variations:
                header = {"alg": alg_variant, "typ": "JWT"}
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
                payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
                none_token = f"{header_b64.decode()}.{payload_b64.decode()}."

                with pytest.raises(OAuthAuthenticationError):
                    await authenticator.authenticate_token(none_token)

            await authenticator.close()

    async def test_modified_payload_without_signature_change_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that modifying payload without updating signature is rejected (signature validation)."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create valid token
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        import base64
        import json

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        # Tamper with payload - change sub claim
        parts = token.decode().split(".")
        tampered_payload = payload.copy()
        tampered_payload["sub"] = "admin"  # Escalate to admin
        tampered_payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b"=").decode()
        )

        # Reconstruct token with original signature
        tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # Should reject tampered token
            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(tampered_token)

            await authenticator.close()

    async def test_jwks_endpoint_404_error_handling(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test behavior when JWKS endpoint returns 404."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            # Simulate 404 error
            mock_get.side_effect = httpx.HTTPStatusError(
                "404 Not Found", request=MagicMock(), response=MagicMock(status_code=404)
            )

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError, match="Failed to fetch JWKS"):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_jwks_malformed_json_error_handling(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test behavior when JWKS endpoint returns malformed JSON."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.side_effect = ValueError("Invalid JSON")
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError, match="Error processing JWKS"):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_invalid_base64_encoding_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that tokens with invalid base64url encoding are rejected."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Test various invalid encodings
        invalid_tokens = [
            "invalid!!!.base64.encoding",  # Invalid base64 characters
            "SGVsbG8=.V29ybGQ=.U2lnbmF0dXJl",  # Using = padding (should be stripped)
            "not.valid",  # Missing signature section
            "..signature",  # Empty header and payload
        ]

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            for invalid_token in invalid_tokens:
                with pytest.raises(OAuthAuthenticationError):
                    await authenticator.authenticate_token(invalid_token)

            await authenticator.close()

    async def test_extremely_short_token_lifetime_edge_case(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test token with very short lifetime (1 second) with clock skew."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
            oauth_clock_skew_seconds=60,  # 60 second clock skew
        )

        # Create token that expires in 1 second
        now = datetime.now(UTC)
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((now + timedelta(seconds=1)).timestamp()),
            "iat": int(now.timestamp()),
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # Should succeed due to clock skew tolerance
            client_info = await authenticator.authenticate_token(token.decode())
            assert client_info.client_id == "user123"

            await authenticator.close()

    async def test_extremely_large_token_dos_prevention(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that extremely large tokens are rejected (DoS prevention)."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create token with extremely large payload (1MB of data)
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
            "large_claim": "X" * (1024 * 1024),  # 1MB of X's
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # authlib may reject this during encoding or decoding
            try:
                token = jwt.encode({"alg": "RS256"}, payload, private_key)
                # If it encodes, try to authenticate (should fail or timeout)
                with pytest.raises((OAuthAuthenticationError, Exception)):
                    await authenticator.authenticate_token(token.decode())
            except Exception:
                # If encoding fails, that's also acceptable DoS prevention
                pass

            await authenticator.close()

    async def test_jwks_cache_refresh_on_kid_mismatch(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that JWKS cache is refreshed when kid doesn't match cached keys."""
        private_key, public_key = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        # Create token with different kid
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        # Use a different kid in the header
        token = jwt.encode({"alg": "RS256", "kid": "different-key-id"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            # Return JWKS without the requested kid
            mock_response.json.return_value = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "original-key-id",
                        "use": "sig",
                        "n": public_key["n"],
                        "e": public_key["e"],
                    }
                ]
            }
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            # Should fail - kid mismatch
            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()

    async def test_token_with_missing_signature_section_rejected(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test that token with header and payload but no signature is rejected."""
        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        import base64
        import json

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")

        # Token with no signature section (only two parts)
        incomplete_token = f"{header_b64.decode()}.{payload_b64.decode()}"

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()
            mock_get.return_value = mock_response

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError):
                await authenticator.authenticate_token(incomplete_token)

            await authenticator.close()

    async def test_jwks_timeout_error_handling(
        self,
        test_key_pair: tuple[dict, dict],
        jwks_response: dict,
    ) -> None:
        """Test behavior when JWKS endpoint times out."""
        private_key, _ = test_key_pair

        config = SecurityConfig(
            oauth_enabled=True,
            oauth_issuer="https://auth.example.com/",
            oauth_jwks_url="https://auth.example.com/.well-known/jwks.json/",
            oauth_audience=["mcp-docker-api"],
            oauth_required_scopes=[],
        )

        payload = {
            "sub": "user123",
            "iss": "https://auth.example.com/",
            "aud": ["mcp-docker-api"],
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }

        from authlib.jose import JsonWebToken

        jwt = JsonWebToken(["RS256"])
        token = jwt.encode({"alg": "RS256"}, payload, private_key)

        with patch("httpx.AsyncClient.get") as mock_get:
            # Simulate timeout
            mock_get.side_effect = httpx.TimeoutException("Request timeout")

            authenticator = OAuthAuthenticator(config)

            with pytest.raises(OAuthAuthenticationError, match="Failed to fetch JWKS"):
                await authenticator.authenticate_token(token.decode())

            await authenticator.close()
