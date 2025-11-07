"""Authentication middleware for MCP Docker server."""

import base64
from typing import Any

from mcp_docker.auth.api_key import APIKeyAuthenticator, ClientInfo
from mcp_docker.auth.ssh_auth import SSHAuthRequest, SSHKeyAuthenticator
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.errors import SSHAuthenticationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthMiddleware:
    """Middleware that handles authentication for MCP server requests.

    Supports two authentication methods:
    - API Key authentication (existing)
    - SSH key-based authentication (new)

    This middleware intercepts requests and validates credentials before
    allowing them to proceed to the Docker server.
    """

    def __init__(self, security_config: SecurityConfig) -> None:
        """Initialize authentication middleware.

        Args:
            security_config: Security configuration
        """
        self.config = security_config
        self.api_key_authenticator: APIKeyAuthenticator | None = None
        self.ssh_key_authenticator: SSHKeyAuthenticator | None = None

        if self.config.auth_enabled:
            # Initialize API key authenticator
            self.api_key_authenticator = APIKeyAuthenticator(self.config.api_keys_file)
            logger.info("API key authentication enabled")

            # Initialize SSH key authenticator if enabled
            if self.config.ssh_auth_enabled:
                self.ssh_key_authenticator = SSHKeyAuthenticator(
                    self.config.ssh_authorized_keys_file,
                    self.config,  # Pass full config for ssh_signature_max_age
                )
                logger.info(
                    f"SSH authentication enabled "
                    f"(authorized_keys: {self.config.ssh_authorized_keys_file})"
                )
        else:
            logger.warning("Authentication middleware DISABLED - all requests will be allowed")

    @property
    def authenticator(self) -> APIKeyAuthenticator | None:
        """Backward-compatible property for accessing API key authenticator.

        Deprecated: Use api_key_authenticator instead.
        """
        return self.api_key_authenticator

    def authenticate_request(
        self,
        api_key: str | None = None,
        ip_address: str | None = None,
        ssh_auth_data: dict[str, Any] | None = None,
    ) -> ClientInfo:
        """Authenticate an incoming request using API key or SSH key.

        Args:
            api_key: API key from the request (optional)
            ip_address: IP address of the client
            ssh_auth_data: SSH authentication data (optional)
                Format: {
                    "client_id": str,
                    "signature": base64-encoded bytes,
                    "timestamp": str,
                    "nonce": str,
                }

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

        # Try SSH authentication first if provided
        if ssh_auth_data is not None:
            if self.ssh_key_authenticator is None:
                logger.error("SSH auth data provided but SSH authentication is disabled")
                raise AuthenticationError("SSH authentication is not enabled")

            try:
                return self._authenticate_ssh(ssh_auth_data, ip_address)
            except SSHAuthenticationError as e:
                logger.warning(f"SSH authentication failed: {e}")
                raise AuthenticationError(f"SSH authentication failed: {e}") from e

        # Try API key authentication
        if api_key is not None and api_key.strip():
            if not self.api_key_authenticator:
                logger.error("API key authenticator not initialized but auth is enabled")
                raise AuthenticationError("Authentication system error")

            client_info = self.api_key_authenticator.authenticate(api_key, ip_address)
            if not client_info:
                logger.warning("Authentication failed: invalid API key")
                raise AuthenticationError("Invalid API key")

            return client_info

        # No credentials provided (None or empty/whitespace API key, no SSH data)
        logger.warning("Authentication failed: no credentials provided")
        raise AuthenticationError("API key required")

    def _authenticate_ssh(
        self, ssh_auth_data: dict[str, Any], ip_address: str | None
    ) -> ClientInfo:
        """Authenticate using SSH key signature.

        Args:
            ssh_auth_data: SSH authentication data
            ip_address: Client IP address

        Returns:
            ClientInfo if authentication succeeds

        Raises:
            SSHAuthenticationError: If authentication fails
        """
        # Ensure SSH authenticator is initialized
        if self.ssh_key_authenticator is None:
            raise SSHAuthenticationError("SSH authentication is not enabled")

        try:
            # Extract authentication data
            client_id = ssh_auth_data.get("client_id")
            signature_b64 = ssh_auth_data.get("signature")
            timestamp = ssh_auth_data.get("timestamp")
            nonce = ssh_auth_data.get("nonce", "")

            if not all([client_id, signature_b64, timestamp, nonce]):
                raise SSHAuthenticationError(
                    "Incomplete SSH auth data. Required: client_id, signature, timestamp, nonce"
                )

            # Type narrowing: after all() check, these are guaranteed to be non-None strings
            assert isinstance(client_id, str)
            assert isinstance(signature_b64, str)
            assert isinstance(timestamp, str)
            assert isinstance(nonce, str)

            # Decode signature
            signature = base64.b64decode(signature_b64)

            # Create authentication request
            auth_request = SSHAuthRequest(
                client_id=client_id,
                signature=signature,
                timestamp=timestamp,
                nonce=nonce,
            )

            # Authenticate (raises SSHAuthenticationError on failure)
            client_info = self.ssh_key_authenticator.authenticate(auth_request)

            # Add IP address
            client_info.ip_address = ip_address
            return client_info

        except Exception as e:
            logger.error(f"SSH authentication error: {e}")
            raise SSHAuthenticationError(f"SSH authentication error: {e}") from e

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
        """Reload API keys and SSH authorized keys from files.

        This allows updating keys without restarting the server.
        """
        if self.api_key_authenticator:
            self.api_key_authenticator.reload_keys()
            logger.info("API keys reloaded")

        if self.ssh_key_authenticator:
            self.ssh_key_authenticator.key_manager.reload_keys()
            logger.info("SSH authorized keys reloaded")

        if not self.api_key_authenticator and not self.ssh_key_authenticator:
            logger.warning("Cannot reload keys: no authenticators initialized")
