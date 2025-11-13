"""OAuth/OIDC authentication for MCP Docker server."""

from datetime import UTC, datetime
from typing import Any

import httpx
from authlib.jose import JsonWebKey, JsonWebToken, JWTClaims
from authlib.jose.errors import JoseError
from cachetools import TTLCache

from mcp_docker.auth.models import ClientInfo
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class OAuthAuthenticationError(Exception):
    """Raised when OAuth authentication fails."""

    pass


class OAuthAuthenticator:
    """OAuth/OIDC authenticator with JWT validation and JWKS caching.

    This authenticator validates bearer tokens using JWT signature verification
    against a JWKS endpoint. It supports:
    - JWT signature validation (RS256, ES256, etc.)
    - JWKS caching with automatic refresh
    - Issuer, audience, expiration validation
    - Required scope enforcement
    - Optional token introspection for opaque tokens
    - Clock skew tolerance

    Attributes:
        config: Security configuration with OAuth settings
        jwks_cache: TTL cache for JWKS keys (15 minute TTL)
        http_client: HTTP client for fetching JWKS and introspection
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize OAuth authenticator.

        Args:
            config: Security configuration with OAuth settings

        Raises:
            ValueError: If OAuth is enabled but required config is missing
        """
        self.config = config

        if not self.config.oauth_enabled:
            raise ValueError("OAuth authenticator created but oauth_enabled=False")

        # Initialize JWKS cache (15 minute TTL, max 10 keys)
        self.jwks_cache: TTLCache[str, Any] = TTLCache(maxsize=10, ttl=900)

        # Initialize HTTP client for JWKS fetching
        self.http_client = httpx.AsyncClient(timeout=10.0)

        logger.info(
            f"OAuth authenticator initialized: issuer={self.config.oauth_issuer}, "
            f"jwks_url={self.config.oauth_jwks_url}"
        )

    async def authenticate_token(self, token: str) -> ClientInfo:
        """Authenticate a bearer token and return client information.

        Args:
            token: Bearer token (JWT or opaque token)

        Returns:
            ClientInfo with OAuth details

        Raises:
            OAuthAuthenticationError: If authentication fails
        """
        try:
            # First, try JWT validation with cached JWKS
            claims = await self._validate_jwt(token, bypass_cache=False)
            return self._build_client_info_from_claims(claims)

        except JoseError as e:
            # JWT validation failed - could be due to key rotation
            logger.debug(f"JWT validation failed, refreshing JWKS and retrying: {e}")
            return await self._retry_jwt_with_fresh_jwks(token)

        except Exception as e:
            logger.error(f"OAuth authentication error: {e}")
            raise OAuthAuthenticationError(f"Authentication failed: {e}") from e

    def _build_client_info_from_claims(self, claims: JWTClaims) -> ClientInfo:
        """Build ClientInfo from validated JWT claims.

        Args:
            claims: Validated JWT claims

        Returns:
            ClientInfo with OAuth details
        """
        # Extract client info from claims
        client_id = claims.get("sub") or claims.get("client_id") or "unknown"
        scopes = self._extract_scopes(claims)

        # Validate required scopes
        if self.config.oauth_required_scopes:
            self._validate_scopes(scopes)

        # Build extra metadata from claims
        extra: dict[str, str] = {}
        for claim_key in ["client_id", "email", "name", "preferred_username"]:
            if claim_key in claims and claims[claim_key]:
                extra[claim_key] = str(claims[claim_key])

        logger.info(f"OAuth authentication successful: client_id={client_id}, scopes={scopes}")

        return ClientInfo(
            client_id=client_id,
            auth_method="oauth",
            api_key_hash="oauth",
            description="OAuth authenticated client",
            scopes=scopes,
            extra=extra,
            authenticated_at=datetime.now(UTC),
        )

    async def _retry_jwt_with_fresh_jwks(self, token: str) -> ClientInfo:
        """Retry JWT validation with fresh JWKS after clearing cache.

        Args:
            token: Bearer token to validate

        Returns:
            ClientInfo if validation succeeds

        Raises:
            OAuthAuthenticationError: If validation still fails
        """
        try:
            # Clear the cache and retry with fresh JWKS
            self.jwks_cache.clear()
            claims = await self._validate_jwt(token, bypass_cache=True)

            logger.info("OAuth authentication successful after JWKS refresh")
            return self._build_client_info_from_claims(claims)

        except JoseError as retry_error:
            # Still failed after refresh, try introspection if configured
            return await self._handle_jwt_failure_with_introspection(token, retry_error)

    async def _handle_jwt_failure_with_introspection(
        self, token: str, retry_error: JoseError
    ) -> ClientInfo:
        """Handle JWT validation failure by attempting token introspection.

        Args:
            token: Bearer token to introspect
            retry_error: The JoseError from JWT validation retry

        Returns:
            ClientInfo from introspection

        Raises:
            OAuthAuthenticationError: If introspection not configured or fails
        """
        if self.config.oauth_introspection_url:
            logger.debug(
                f"JWT validation failed after refresh, trying introspection: {retry_error}"
            )
            return await self._introspect_token(token)

        logger.warning(
            f"JWT validation failed after JWKS refresh "
            f"and no introspection configured: {retry_error}"
        )
        raise OAuthAuthenticationError(f"Invalid JWT token: {retry_error}") from retry_error

    async def _validate_jwt(self, token: str, bypass_cache: bool = False) -> JWTClaims:
        """Validate JWT token signature and claims.

        Args:
            token: JWT token string
            bypass_cache: If True, fetch fresh JWKS bypassing cache

        Returns:
            Validated JWT claims

        Raises:
            JoseError: If validation fails
        """
        # Fetch JWKS (cached or fresh based on bypass_cache)
        jwks = await self._fetch_jwks(bypass_cache=bypass_cache)

        # Create JWT validator with supported algorithms
        jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])

        # Decode and validate token
        claims = jwt.decode(
            token,
            key=jwks,
            claims_options={
                "iss": {
                    "essential": True,
                    "value": str(self.config.oauth_issuer),
                },
                "aud": {
                    "essential": bool(self.config.oauth_audience),
                    "values": self.config.oauth_audience if self.config.oauth_audience else None,
                },
                "exp": {
                    "essential": True,
                    "leeway": self.config.oauth_clock_skew_seconds,
                },
                "nbf": {
                    "essential": False,
                    "leeway": self.config.oauth_clock_skew_seconds,
                },
            },
        )

        # Validate claims
        claims.validate()

        return claims

    async def _fetch_jwks(self, bypass_cache: bool = False) -> JsonWebKey:
        """Fetch JWKS from the configured URL with caching.

        Args:
            bypass_cache: If True, fetch fresh JWKS ignoring cache

        Returns:
            JsonWebKey object for validation

        Raises:
            OAuthAuthenticationError: If JWKS fetch fails
        """
        # Check cache first (unless bypassing)
        cache_key = "jwks"
        if not bypass_cache and cache_key in self.jwks_cache:
            logger.debug("Using cached JWKS")
            return self.jwks_cache[cache_key]

        # Fetch JWKS from endpoint
        try:
            logger.debug(f"Fetching JWKS from {self.config.oauth_jwks_url}")
            response = await self.http_client.get(str(self.config.oauth_jwks_url))
            response.raise_for_status()

            jwks_data = response.json()

            # Create JsonWebKey from JWKS
            jwks = JsonWebKey.import_key_set(jwks_data)

            # Cache the JWKS
            self.jwks_cache[cache_key] = jwks

            logger.info("JWKS fetched and cached successfully")
            return jwks

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise OAuthAuthenticationError(f"Failed to fetch JWKS: {e}") from e
        except Exception as e:
            logger.error(f"Error processing JWKS: {e}")
            raise OAuthAuthenticationError(f"Error processing JWKS: {e}") from e

    async def _introspect_token(self, token: str) -> ClientInfo:
        """Introspect an opaque token using the introspection endpoint.

        Args:
            token: Opaque token string

        Returns:
            ClientInfo with introspection results

        Raises:
            OAuthAuthenticationError: If introspection fails
        """
        if not self.config.oauth_introspection_url:
            raise OAuthAuthenticationError("Token introspection not configured")

        if not (self.config.oauth_client_id and self.config.oauth_client_secret):
            raise OAuthAuthenticationError("Client credentials required for token introspection")

        try:
            logger.debug("Introspecting opaque token")

            # Call introspection endpoint
            response = await self.http_client.post(
                str(self.config.oauth_introspection_url),
                auth=(self.config.oauth_client_id, self.config.oauth_client_secret),
                data={"token": token},
            )
            response.raise_for_status()

            introspection = response.json()

            # Check if token is active
            if not introspection.get("active"):
                raise OAuthAuthenticationError("Token is not active")

            # Extract client info
            client_id = introspection.get("sub") or introspection.get("client_id") or "unknown"
            scopes_str = introspection.get("scope", "")
            scopes = scopes_str.split() if scopes_str else []

            # Validate required scopes
            if self.config.oauth_required_scopes:
                self._validate_scopes(scopes)

            # Build extra metadata
            extra: dict[str, str] = {}
            for key in ["client_id", "username", "email"]:
                if key in introspection and introspection[key]:
                    extra[key] = str(introspection[key])

            logger.info(f"Token introspection successful: client_id={client_id}, scopes={scopes}")

            return ClientInfo(
                client_id=client_id,
                auth_method="oauth",
                api_key_hash="oauth",
                description="OAuth authenticated client (introspected)",
                scopes=scopes,
                extra=extra,
                authenticated_at=datetime.now(UTC),
            )

        except httpx.HTTPError as e:
            logger.error(f"Token introspection failed: {e}")
            raise OAuthAuthenticationError(f"Token introspection failed: {e}") from e
        except Exception as e:
            logger.error(f"Error during token introspection: {e}")
            raise OAuthAuthenticationError(f"Token introspection error: {e}") from e

    def _extract_scopes(self, claims: JWTClaims) -> list[str]:
        """Extract scopes from JWT claims.

        OAuth providers may use different claim names for scopes:
        - 'scope' (space-separated string) - standard OAuth2
        - 'scopes' (array) - some providers
        - 'scp' (array) - Azure AD

        Args:
            claims: JWT claims

        Returns:
            List of scopes
        """
        # Try 'scope' (space-separated string)
        if "scope" in claims:
            scope_str = claims["scope"]
            if isinstance(scope_str, str):
                return scope_str.split()

        # Try 'scopes' (array)
        if "scopes" in claims:
            scopes = claims["scopes"]
            if isinstance(scopes, list):
                return [str(s) for s in scopes]

        # Try 'scp' (Azure AD)
        if "scp" in claims:
            scp = claims["scp"]
            if isinstance(scp, str):
                return scp.split()
            if isinstance(scp, list):
                return [str(s) for s in scp]

        return []

    def _validate_scopes(self, token_scopes: list[str]) -> None:
        """Validate that token has required scopes.

        Args:
            token_scopes: Scopes from the token

        Raises:
            OAuthAuthenticationError: If required scopes are missing
        """
        required = set(self.config.oauth_required_scopes)
        granted = set(token_scopes)

        missing = required - granted
        if missing:
            raise OAuthAuthenticationError(f"Missing required scopes: {', '.join(sorted(missing))}")

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        await self.http_client.aclose()
        logger.debug("OAuth authenticator closed")
