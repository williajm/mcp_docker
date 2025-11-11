"""Authentication middleware for MCP Docker server."""

import base64
from typing import Any

from limits import storage
from limits.strategies import MovingWindowRateLimiter

from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.ssh_auth import SSHAuthRequest, SSHKeyAuthenticator
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.errors import SSHAuthenticationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthRateLimitExceededError(AuthenticationError):
    """Raised when authentication rate limit is exceeded."""

    pass


class AuthRateLimiter:
    """Rate limiter for authentication attempts using the `limits` library.

    SECURITY: Uses battle-tested limits library with:
    - Automatic expiration via MovingWindowRateLimiter
    - Memory-bounded storage
    - Thread-safe operations
    - No custom security code
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        """Initialize authentication rate limiter using limits library.

        Args:
            max_attempts: Maximum failed auth attempts allowed within window
            window_seconds: Time window in seconds for rate limiting (default: 5 minutes)
        """
        from limits import parse

        self.max_attempts = max_attempts
        self.window = window_seconds

        # Create rate limit: "5 per 300 seconds"
        self.limit = parse(f"{max_attempts} per {window_seconds} seconds")

        # Use in-memory storage (thread-safe, bounded)
        # SECURITY: Uses library's built-in storage, not custom dict
        self.storage = storage.MemoryStorage()

        # MovingWindowRateLimiter: more accurate than fixed window
        self.limiter = MovingWindowRateLimiter(self.storage)

    def check_and_record_attempt(self, identifier: str) -> None:
        """Check if authentication attempts are within limits and record attempt.

        Uses limits library for thread-safe, memory-bounded rate limiting.

        Args:
            identifier: Unique identifier (e.g., client_id or IP address)

        Raises:
            AuthRateLimitExceeded: If too many failed attempts
        """
        # Test and increment in one operation (thread-safe)
        if not self.limiter.hit(self.limit, identifier):
            # Limit exceeded
            raise AuthRateLimitExceededError(
                f"Too many authentication failures. Try again in {self.window} seconds."
            )
        # Limit not exceeded, attempt recorded

    def clear_attempts(self, identifier: str) -> None:
        """Clear failed attempts for an identifier (on successful auth).

        Args:
            identifier: Unique identifier to clear
        """
        # Clear the rate limit for this identifier using limiter's clear method
        self.limiter.clear(self.limit, identifier)


class AuthMiddleware:
    """Middleware that handles authentication for MCP server requests.

    Supports SSH key-based authentication only.

    This middleware intercepts requests and validates credentials before
    allowing them to proceed to the Docker server.
    """

    def __init__(self, security_config: SecurityConfig) -> None:
        """Initialize authentication middleware.

        Args:
            security_config: Security configuration
        """
        self.config = security_config
        self.ssh_key_authenticator: SSHKeyAuthenticator | None = None
        # Initialize authentication rate limiter (5 attempts per 5 minutes)
        self.auth_rate_limiter = AuthRateLimiter(max_attempts=5, window_seconds=300)

        if self.config.auth_enabled:
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
                logger.warning(
                    "Authentication enabled but no SSH auth configured - all requests will fail"
                )
        else:
            logger.warning("Authentication middleware DISABLED - all requests will be allowed")

    def authenticate_request(
        self,
        ip_address: str | None = None,
        ssh_auth_data: dict[str, Any] | None = None,
    ) -> ClientInfo:
        """Authenticate an incoming request using SSH key.

        Args:
            ip_address: IP address of the client
            ssh_auth_data: SSH authentication data (required if auth enabled)
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

        # Try SSH authentication if provided
        if ssh_auth_data is not None:
            if self.ssh_key_authenticator is None:
                logger.error("SSH auth data provided but SSH authentication is disabled")
                raise AuthenticationError("SSH authentication is not enabled")

            try:
                client_info, rate_limit_identifier = self._authenticate_ssh(
                    ssh_auth_data, ip_address
                )
                # Clear rate limit attempts on successful auth (use same identifier)
                self.auth_rate_limiter.clear_attempts(rate_limit_identifier)
                return client_info
            except (SSHAuthenticationError, AuthRateLimitExceededError) as e:
                logger.warning(f"SSH authentication failed: {e}")
                raise AuthenticationError(f"SSH authentication failed: {e}") from e

        # No credentials provided
        logger.warning("Authentication failed: no SSH credentials provided")
        raise AuthenticationError("SSH authentication required")

    def _authenticate_ssh(
        self, ssh_auth_data: dict[str, Any], ip_address: str | None
    ) -> tuple[ClientInfo, str]:
        """Authenticate using SSH key signature.

        Args:
            ssh_auth_data: SSH authentication data
            ip_address: Client IP address

        Returns:
            Tuple of (ClientInfo, rate_limit_identifier) if authentication succeeds

        Raises:
            SSHAuthenticationError: If authentication fails
            AuthRateLimitExceeded: If too many failed attempts
        """
        # Ensure SSH authenticator is initialized
        if self.ssh_key_authenticator is None:
            raise SSHAuthenticationError("SSH authentication is not enabled")

        # Extract client_id for rate limiting
        client_id = ssh_auth_data.get("client_id", "unknown")
        identifier = f"{client_id}:{ip_address}" if ip_address else client_id

        # Check rate limit BEFORE attempting authentication
        self.auth_rate_limiter.check_and_record_attempt(identifier)

        try:
            # Extract authentication data
            signature_b64 = ssh_auth_data.get("signature")
            timestamp = ssh_auth_data.get("timestamp")
            nonce = ssh_auth_data.get("nonce", "")

            if not all([client_id, signature_b64, timestamp, nonce]):
                raise SSHAuthenticationError(
                    "Incomplete SSH auth data. Required: client_id, signature, timestamp, nonce"
                )

            # Type narrowing using isinstance checks instead of assertions
            if not isinstance(client_id, str):
                raise SSHAuthenticationError("client_id must be a string")
            if not isinstance(signature_b64, str):
                raise SSHAuthenticationError("signature must be a base64-encoded string")
            if not isinstance(timestamp, str):
                raise SSHAuthenticationError("timestamp must be a string")
            if not isinstance(nonce, str):
                raise SSHAuthenticationError("nonce must be a string")

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
            return client_info, identifier

        except SSHAuthenticationError:
            # Re-raise SSH auth errors without wrapping
            raise
        except (KeyError, ValueError) as e:
            # Catch only expected exceptions during parsing
            logger.error(f"SSH authentication parsing error: {e}")
            raise SSHAuthenticationError(f"Invalid SSH authentication data: {e}") from e

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
        """Reload SSH authorized keys from files.

        This allows updating keys without restarting the server.
        """
        if self.ssh_key_authenticator:
            self.ssh_key_authenticator.key_manager.reload_keys()
            logger.info("SSH authorized keys reloaded")
        else:
            logger.warning("Cannot reload keys: SSH authenticator not initialized")
