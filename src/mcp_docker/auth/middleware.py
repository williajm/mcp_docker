"""Authentication middleware for MCP Docker server."""

from mcp_docker.auth.api_key import APIKeyAuthenticator, ClientInfo
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthMiddleware:
    """Middleware that handles authentication for MCP server requests.

    This middleware intercepts requests and validates API keys before
    allowing them to proceed to the Docker server.
    """

    def __init__(self, security_config: SecurityConfig) -> None:
        """Initialize authentication middleware.

        Args:
            security_config: Security configuration
        """
        self.config = security_config
        self.authenticator: APIKeyAuthenticator | None = None

        if self.config.auth_enabled:
            self.authenticator = APIKeyAuthenticator(self.config.api_keys_file)
            logger.info("Authentication middleware enabled")
        else:
            logger.warning("Authentication middleware DISABLED - all requests will be allowed")

    def authenticate_request(
        self, api_key: str | None, ip_address: str | None = None
    ) -> ClientInfo:
        """Authenticate an incoming request.

        Args:
            api_key: API key from the request
            ip_address: IP address of the client

        Returns:
            ClientInfo for the authenticated client

        Raises:
            AuthenticationError: If authentication fails
        """
        # If auth is disabled, create a default client info
        if not self.config.auth_enabled:
            logger.debug("Authentication bypassed (auth disabled)")
            return ClientInfo(
                client_id="unauthenticated",
                api_key_hash="none",
                description="Authentication disabled",
                ip_address=ip_address,
            )

        # Check IP allowlist if configured
        if self.config.allowed_client_ips and (
            not ip_address or ip_address not in self.config.allowed_client_ips
        ):
            logger.warning(f"Request blocked: IP {ip_address} not in allowlist")
            raise AuthenticationError(f"IP address not allowed: {ip_address}")

        # Validate API key
        if not api_key:
            logger.warning("Authentication failed: no API key provided")
            raise AuthenticationError("API key required")

        if not self.authenticator:
            logger.error("Authenticator not initialized but auth is enabled")
            raise AuthenticationError("Authentication system error")

        client_info = self.authenticator.authenticate(api_key, ip_address)
        if not client_info:
            logger.warning("Authentication failed: invalid API key")
            raise AuthenticationError("Invalid API key")

        return client_info

    def check_ip_allowed(self, ip_address: str | None) -> bool:
        """Check if an IP address is allowed.

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is allowed or no allowlist is configured
        """
        if not self.config.allowed_client_ips:
            return True

        if not ip_address:
            return False

        return ip_address in self.config.allowed_client_ips

    def reload_keys(self) -> None:
        """Reload API keys from file.

        This allows updating keys without restarting the server.
        """
        if self.authenticator:
            self.authenticator.reload_keys()
            logger.info("API keys reloaded")
        else:
            logger.warning("Cannot reload keys: authenticator not initialized")
