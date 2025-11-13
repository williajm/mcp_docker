"""Authentication middleware for MCP Docker server."""

from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.oauth_auth import OAuthAuthenticationError, OAuthAuthenticator
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthMiddleware:
    """Middleware that handles authentication for MCP server requests.

    This middleware supports multiple authentication methods:
    - OAuth/OIDC (for network transports when enabled)
    - IP allowlist (defense-in-depth with OAuth, or standalone)
    - No authentication (stdio transport)

    Authentication flow:
    1. stdio transport (ip_address=None) always bypasses authentication
    2. Network transports (ip_address provided):
       - If OAuth enabled: require and validate bearer token, then check IP allowlist
       - If OAuth disabled: check IP allowlist (if configured)

    Note: When OAuth is enabled, BOTH the OAuth token AND IP allowlist (if configured)
    must pass for defense-in-depth security.
    """

    def __init__(self, security_config: SecurityConfig) -> None:
        """Initialize authentication middleware.

        Args:
            security_config: Security configuration
        """
        self.config = security_config
        self.oauth_authenticator: OAuthAuthenticator | None = None

        # Initialize OAuth authenticator if enabled
        if self.config.oauth_enabled:
            self.oauth_authenticator = OAuthAuthenticator(self.config)
            logger.info(
                f"OAuth authentication enabled: issuer={self.config.oauth_issuer}, "
                f"required_scopes={self.config.oauth_required_scopes}"
            )
        else:
            logger.info("OAuth authentication disabled")

        # Log IP allowlist status
        if self.config.allowed_client_ips:
            logger.info(
                f"IP allowlist enabled with {len(self.config.allowed_client_ips)} allowed IPs"
            )
        else:
            logger.info("IP allowlist disabled - all IPs allowed")

    async def authenticate_request(
        self,
        ip_address: str | None = None,
        bearer_token: str | None = None,
    ) -> ClientInfo:
        """Authenticate an incoming request.

        Authentication flow:
        1. stdio transport (ip_address=None): Always allowed, no authentication
        2. Network transport with OAuth enabled: Require and validate bearer token,
           then check IP allowlist (if configured) for defense-in-depth
        3. Network transport with OAuth disabled: Check IP allowlist

        Args:
            ip_address: IP address of the client (None for stdio transport)
            bearer_token: Bearer token from Authorization header (network transports only)

        Returns:
            ClientInfo for the authenticated client

        Raises:
            AuthenticationError: If authentication fails (invalid token or blocked IP)
        """
        # stdio transport always bypasses authentication
        if ip_address is None:
            logger.debug("Request from stdio transport, bypassing authentication")
            return ClientInfo(
                client_id="stdio",
                auth_method="stdio",
                api_key_hash="none",
                description="Local stdio transport",
                ip_address=None,
            )

        # Network transport - check OAuth if enabled
        if self.config.oauth_enabled:
            if not bearer_token:
                logger.warning(f"OAuth enabled but no bearer token provided from IP {ip_address}")
                raise AuthenticationError("Bearer token required for network access")

            if not self.oauth_authenticator:
                logger.error("OAuth enabled but authenticator not initialized")
                raise AuthenticationError("OAuth authentication not available")

            try:
                # Validate OAuth token
                client_info = await self.oauth_authenticator.authenticate_token(bearer_token)

                # Add IP address to client info
                client_info.ip_address = ip_address

                # Defense in depth: Check IP allowlist even after successful OAuth auth
                if (
                    self.config.allowed_client_ips
                    and ip_address not in self.config.allowed_client_ips
                ):
                    logger.warning(
                        f"OAuth authentication succeeded but IP {ip_address} not in allowlist. "
                        f"Client: {client_info.client_id}"
                    )
                    raise AuthenticationError(
                        f"Valid OAuth token but IP address not allowed: {ip_address}"
                    )

                logger.info(
                    f"OAuth authentication successful: client_id={client_info.client_id}, "
                    f"ip={ip_address}, scopes={client_info.scopes}"
                )
                return client_info

            except OAuthAuthenticationError as e:
                logger.warning(f"OAuth authentication failed from IP {ip_address}: {e}")
                raise AuthenticationError(f"OAuth authentication failed: {e}") from e

        # OAuth not enabled - fall back to IP allowlist
        if self.config.allowed_client_ips and ip_address not in self.config.allowed_client_ips:
            logger.warning(f"Request blocked: IP {ip_address} not in allowlist")
            raise AuthenticationError(f"IP address not allowed: {ip_address}")

        # IP allowed or no allowlist configured
        logger.debug(f"Request allowed from IP: {ip_address}")
        return ClientInfo(
            client_id=ip_address,
            auth_method="ip",
            api_key_hash="none",
            description="IP-based access",
            ip_address=ip_address,
        )

    def check_ip_allowed(self, ip_address: str | None) -> bool:
        """Check if an IP address is allowed.

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is allowed, no allowlist is configured, or ip_address is None (stdio)
        """
        if not self.config.allowed_client_ips:
            return True

        # stdio transport (ip_address=None) bypasses the allowlist
        if not ip_address:
            return True

        return ip_address in self.config.allowed_client_ips

    async def close(self) -> None:
        """Close OAuth authenticator and cleanup resources."""
        if self.oauth_authenticator:
            await self.oauth_authenticator.close()
            logger.debug("Auth middleware closed")
