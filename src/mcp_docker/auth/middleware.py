"""Authentication middleware for MCP Docker server."""

from mcp_docker.auth.models import ClientInfo
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthMiddleware:
    """Middleware that handles IP filtering for MCP server requests.

    This middleware intercepts requests and validates client IPs before
    allowing them to proceed to the Docker server.
    """

    def __init__(self, security_config: SecurityConfig) -> None:
        """Initialize authentication middleware.

        Args:
            security_config: Security configuration
        """
        self.config = security_config

        if self.config.allowed_client_ips:
            logger.info(
                f"IP allowlist enabled with {len(self.config.allowed_client_ips)} allowed IPs"
            )
        else:
            logger.info("IP allowlist disabled - all IPs allowed")

    def authenticate_request(
        self,
        ip_address: str | None = None,
    ) -> ClientInfo:
        """Authenticate an incoming request using IP allowlist.

        Args:
            ip_address: IP address of the client

        Returns:
            ClientInfo for the authenticated client

        Raises:
            AuthenticationError: If IP is not allowed
        """
        # Check IP allowlist if configured (only for network transports)
        # stdio transport (ip_address=None) bypasses the allowlist
        if (
            self.config.allowed_client_ips
            and ip_address
            and ip_address not in self.config.allowed_client_ips
        ):
            logger.warning(f"Request blocked: IP {ip_address} not in allowlist")
            raise AuthenticationError(f"IP address not allowed: {ip_address}")

        # Create client info for allowed request
        logger.debug(f"Request allowed from IP: {ip_address}")
        return ClientInfo(
            client_id=ip_address or "unknown",
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
