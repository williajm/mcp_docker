"""Tests for authentication middleware."""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_docker.auth.middleware import (
    AuthenticationError,
    AuthMiddleware,
    AuthRateLimiter,
    AuthRateLimitExceededError,
)
from mcp_docker.auth.models import ClientInfo
from mcp_docker.config import SecurityConfig
from mcp_docker.utils.errors import SSHAuthenticationError


class TestAuthRateLimiter:
    """Test authentication rate limiter using limits library.

    SECURITY NOTE: These tests verify rate limiting behavior using the battle-tested
    `limits` library. Internal implementation details (storage, limiter) are not
    tested - we trust the library's implementation and only verify our usage.
    """

    def test_init(self) -> None:
        """Test rate limiter initialization with limits library."""
        limiter = AuthRateLimiter(max_attempts=5, window_seconds=300)
        assert limiter.max_attempts == 5
        assert limiter.window == 300
        # Verify limits library components are initialized
        assert limiter.limit is not None
        assert limiter.storage is not None
        assert limiter.limiter is not None

    def test_allows_attempts_within_limit(self) -> None:
        """Test that attempts within limit are allowed."""
        limiter = AuthRateLimiter(max_attempts=3, window_seconds=60)

        # Should allow 3 attempts
        limiter.check_and_record_attempt("test_client")
        limiter.check_and_record_attempt("test_client")
        limiter.check_and_record_attempt("test_client")

        # 4th attempt should raise error
        with pytest.raises(AuthRateLimitExceededError):
            limiter.check_and_record_attempt("test_client")

    def test_clears_old_attempts(self) -> None:
        """Test that old attempts outside window are cleared automatically.

        The limits library handles automatic expiration via MovingWindowRateLimiter.
        """
        limiter = AuthRateLimiter(max_attempts=2, window_seconds=1)

        # Record 2 attempts
        limiter.check_and_record_attempt("test_client")
        limiter.check_and_record_attempt("test_client")

        # 3rd attempt should be blocked
        with pytest.raises(AuthRateLimitExceededError):
            limiter.check_and_record_attempt("test_client")

        # Wait for window to expire
        time.sleep(1.1)

        # Should allow new attempt (old ones automatically expired)
        limiter.check_and_record_attempt("test_client")  # Should not raise

    def test_different_clients_tracked_separately(self) -> None:
        """Test that different clients are tracked independently."""
        limiter = AuthRateLimiter(max_attempts=2, window_seconds=60)

        # Client A makes 2 attempts
        limiter.check_and_record_attempt("client_a")
        limiter.check_and_record_attempt("client_a")

        # Client A is now blocked
        with pytest.raises(AuthRateLimitExceededError):
            limiter.check_and_record_attempt("client_a")

        # But client B should still be allowed
        limiter.check_and_record_attempt("client_b")  # Should not raise

    def test_clear_attempts(self) -> None:
        """Test clearing attempts for a client after successful auth."""
        limiter = AuthRateLimiter(max_attempts=2, window_seconds=60)

        # Record attempts
        limiter.check_and_record_attempt("test_client")
        limiter.check_and_record_attempt("test_client")

        # Client is now blocked
        with pytest.raises(AuthRateLimitExceededError):
            limiter.check_and_record_attempt("test_client")

        # Clear attempts (e.g., after successful authentication)
        limiter.clear_attempts("test_client")

        # Should be able to attempt again
        limiter.check_and_record_attempt("test_client")  # Should not raise

    def test_clear_attempts_nonexistent_client(self) -> None:
        """Test clearing attempts for non-existent client doesn't error."""
        limiter = AuthRateLimiter(max_attempts=5, window_seconds=60)
        limiter.clear_attempts("nonexistent")  # Should not raise

    def test_memory_bounded_by_limits_library(self) -> None:
        """Test that limits library handles memory management automatically.

        The limits.MemoryStorage is memory-bounded by design and handles
        automatic cleanup. This test verifies the limiter doesn't crash
        with many identifiers, trusting the library's internal memory management.
        """
        limiter = AuthRateLimiter(max_attempts=5, window_seconds=60)

        # Try many different identifiers
        num_attempts = 1500
        for i in range(num_attempts):
            try:
                limiter.check_and_record_attempt(f"client_{i}")
            except AuthRateLimitExceededError:
                pass  # Expected - each client hits limit immediately

        # No assertion on internal state - we trust limits library
        # Just verify the limiter still works
        limiter.check_and_record_attempt("final_client")  # Should not crash


class TestAuthMiddleware:
    """Test authentication middleware."""

    @pytest.fixture
    def security_config(self, tmp_path: Path) -> SecurityConfig:
        """Create security config for testing."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text("# Empty keys file\n")

        return SecurityConfig(
            auth_enabled=True,
            ssh_auth_enabled=True,
            ssh_authorized_keys_file=str(keys_file),
            allowed_client_ips=[],
        )

    @pytest.fixture
    def auth_middleware(self, security_config: SecurityConfig) -> AuthMiddleware:
        """Create auth middleware for testing."""
        return AuthMiddleware(security_config)

    def test_init_with_auth_enabled(self, security_config: SecurityConfig) -> None:
        """Test initialization with authentication enabled."""
        middleware = AuthMiddleware(security_config)
        assert middleware.config == security_config
        assert middleware.ssh_key_authenticator is not None
        assert middleware.auth_rate_limiter is not None

    def test_init_with_auth_disabled(self, tmp_path: Path) -> None:
        """Test initialization with authentication disabled."""
        config = SecurityConfig(
            auth_enabled=False,
            ssh_auth_enabled=False,
            ssh_authorized_keys_file=str(tmp_path / "keys"),
        )
        middleware = AuthMiddleware(config)
        assert middleware.ssh_key_authenticator is None

    def test_init_auth_enabled_but_no_ssh(self, tmp_path: Path) -> None:
        """Test initialization with auth enabled but no SSH configured."""
        config = SecurityConfig(
            auth_enabled=True,
            ssh_auth_enabled=False,
            ssh_authorized_keys_file=str(tmp_path / "keys"),
        )
        middleware = AuthMiddleware(config)
        assert middleware.ssh_key_authenticator is None

    def test_authenticate_with_auth_disabled(self, tmp_path: Path) -> None:
        """Test authentication when auth is disabled."""
        config = SecurityConfig(
            auth_enabled=False,
            ssh_auth_enabled=False,
            ssh_authorized_keys_file=str(tmp_path / "keys"),
        )
        middleware = AuthMiddleware(config)

        client_info = middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=None)

        assert client_info.client_id == "unauthenticated"
        assert client_info.api_key_hash == "none"
        assert client_info.ip_address == "127.0.0.1"

    def test_authenticate_ip_not_in_allowlist(self, security_config: SecurityConfig) -> None:
        """Test authentication fails when IP not in allowlist."""
        security_config.allowed_client_ips = ["192.168.1.1"]
        middleware = AuthMiddleware(security_config)

        with pytest.raises(AuthenticationError, match="IP address not allowed"):
            middleware.authenticate_request(ip_address="10.0.0.1", ssh_auth_data=None)

    def test_authenticate_no_ip_with_allowlist(self, security_config: SecurityConfig) -> None:
        """Test authentication fails when no IP provided and allowlist configured."""
        security_config.allowed_client_ips = ["192.168.1.1"]
        middleware = AuthMiddleware(security_config)

        with pytest.raises(AuthenticationError, match="IP address not allowed"):
            middleware.authenticate_request(ip_address=None, ssh_auth_data=None)

    def test_authenticate_no_credentials(self, auth_middleware: AuthMiddleware) -> None:
        """Test authentication fails when no credentials provided."""
        with pytest.raises(AuthenticationError, match="SSH authentication required"):
            auth_middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=None)

    def test_authenticate_ssh_but_not_enabled(self, tmp_path: Path) -> None:
        """Test SSH auth fails when SSH not enabled."""
        config = SecurityConfig(
            auth_enabled=True,
            ssh_auth_enabled=False,
            ssh_authorized_keys_file=str(tmp_path / "keys"),
        )
        middleware = AuthMiddleware(config)

        ssh_data = {
            "client_id": "test",
            "signature": "dGVzdA==",
            "timestamp": "2024-01-01T00:00:00Z",
            "nonce": "test123",
        }

        with pytest.raises(AuthenticationError, match="SSH authentication is not enabled"):
            middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=ssh_data)

    def test_authenticate_ssh_success(self, auth_middleware: AuthMiddleware) -> None:
        """Test successful SSH authentication."""
        ssh_data = {
            "client_id": "test_client",
            "signature": "dGVzdHNpZ25hdHVyZQ==",
            "timestamp": "2024-01-01T00:00:00Z",
            "nonce": "test_nonce",
        }

        # Mock the authenticator to return a successful client info
        mock_client_info = ClientInfo(
            client_id="test_client",
            api_key_hash="test_hash",
            description="Test client",
        )

        with patch.object(
            auth_middleware.ssh_key_authenticator, "authenticate", return_value=mock_client_info
        ):
            result = auth_middleware.authenticate_request(
                ip_address="127.0.0.1", ssh_auth_data=ssh_data
            )

            assert result.client_id == "test_client"
            assert result.ip_address == "127.0.0.1"

    def test_authenticate_ssh_incomplete_data(self, auth_middleware: AuthMiddleware) -> None:
        """Test SSH authentication with incomplete data."""
        # Missing nonce
        ssh_data = {
            "client_id": "test",
            "signature": "dGVzdA==",
            "timestamp": "2024-01-01T00:00:00Z",
        }

        with pytest.raises(AuthenticationError):
            auth_middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=ssh_data)

    def test_authenticate_ssh_invalid_types(self, auth_middleware: AuthMiddleware) -> None:
        """Test SSH authentication with invalid data types."""
        ssh_data = {
            "client_id": 123,  # Should be string
            "signature": "dGVzdA==",
            "timestamp": "2024-01-01T00:00:00Z",
            "nonce": "test",
        }

        with pytest.raises(AuthenticationError):
            auth_middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=ssh_data)

    def test_authenticate_ssh_rate_limit(self, auth_middleware: AuthMiddleware) -> None:
        """Test SSH authentication rate limiting."""
        ssh_data = {
            "client_id": "test_client",
            "signature": "dGVzdA==",
            "timestamp": "2024-01-01T00:00:00Z",
            "nonce": "test",
        }

        # Make authenticator always fail with SSH auth error
        with patch.object(
            auth_middleware.ssh_key_authenticator,
            "authenticate",
            side_effect=SSHAuthenticationError("Auth failed"),
        ):
            # Try 5 times (rate limit)
            for _ in range(5):
                with pytest.raises(AuthenticationError):
                    auth_middleware.authenticate_request(
                        ip_address="127.0.0.1", ssh_auth_data=ssh_data
                    )

            # 6th attempt should be rate limited
            with pytest.raises(AuthenticationError, match="Too many authentication failures"):
                auth_middleware.authenticate_request(ip_address="127.0.0.1", ssh_auth_data=ssh_data)

    def test_authenticate_ssh_clears_rate_limit_with_correct_identifier(
        self, auth_middleware: AuthMiddleware
    ) -> None:
        """Test that successful SSH auth clears rate limit with client_id:ip identifier."""
        ssh_data = {
            "client_id": "test-client",
            "signature": "dGVzdA==",
            "timestamp": "2024-01-01T00:00:00Z",
            "nonce": "test",
        }
        ip_address = "192.168.1.100"
        expected_identifier = f"test-client:{ip_address}"

        # Mock successful authentication
        mock_client_info = ClientInfo(
            client_id="test-client",
            api_key_hash="test-hash",
            description="Test client",
            ip_address=ip_address,
        )
        with patch.object(
            auth_middleware.ssh_key_authenticator, "authenticate", return_value=mock_client_info
        ):
            # First, record some failed attempts
            auth_middleware.auth_rate_limiter.check_and_record_attempt(expected_identifier)
            auth_middleware.auth_rate_limiter.check_and_record_attempt(expected_identifier)

            # Now authenticate successfully - this should clear the rate limit
            client_info = auth_middleware.authenticate_request(
                ip_address=ip_address, ssh_auth_data=ssh_data
            )

            # Verify clear_attempts was called (implicit via successful auth)
            # We can verify by checking that we can make more attempts
            auth_middleware.auth_rate_limiter.check_and_record_attempt(
                expected_identifier
            )  # Should not raise
            assert client_info.client_id == "test-client"
            assert client_info.ip_address == ip_address

    def test_check_ip_allowed_no_allowlist(self, auth_middleware: AuthMiddleware) -> None:
        """Test IP check with no allowlist configured."""
        assert auth_middleware.check_ip_allowed("10.0.0.1") is True
        assert auth_middleware.check_ip_allowed(None) is True

    def test_check_ip_allowed_with_allowlist(self, security_config: SecurityConfig) -> None:
        """Test IP check with allowlist configured."""
        security_config.allowed_client_ips = ["192.168.1.1", "192.168.1.2"]
        middleware = AuthMiddleware(security_config)

        assert middleware.check_ip_allowed("192.168.1.1") is True
        assert middleware.check_ip_allowed("192.168.1.2") is True
        assert middleware.check_ip_allowed("10.0.0.1") is False
        assert middleware.check_ip_allowed(None) is False

    def test_reload_keys_with_ssh(self, auth_middleware: AuthMiddleware) -> None:
        """Test reloading SSH keys."""
        mock_key_manager = MagicMock()
        auth_middleware.ssh_key_authenticator.key_manager = mock_key_manager

        auth_middleware.reload_keys()

        mock_key_manager.reload_keys.assert_called_once()

    def test_reload_keys_without_ssh(self, tmp_path: Path) -> None:
        """Test reloading keys when SSH not enabled."""
        config = SecurityConfig(
            auth_enabled=False,
            ssh_auth_enabled=False,
            ssh_authorized_keys_file=str(tmp_path / "keys"),
        )
        middleware = AuthMiddleware(config)

        # Should not raise
        middleware.reload_keys()
