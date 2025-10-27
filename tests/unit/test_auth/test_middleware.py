"""Unit tests for authentication middleware."""

import json
from pathlib import Path

import pytest

from mcp_docker.auth.middleware import AuthenticationError, AuthMiddleware
from mcp_docker.config import SecurityConfig


class TestAuthMiddleware:
    """Tests for AuthMiddleware."""

    @pytest.fixture
    def security_config_auth_disabled(self, tmp_path: Path) -> SecurityConfig:
        """Create a security config with auth disabled."""
        return SecurityConfig(
            auth_enabled=False,
            api_keys_file=tmp_path / ".mcp_keys.json",
            rate_limit_enabled=False,
            audit_log_enabled=False,
            audit_log_file=tmp_path / "audit.log",
        )

    @pytest.fixture
    def security_config_auth_enabled(self, tmp_path: Path) -> SecurityConfig:
        """Create a security config with auth enabled."""
        # Create a keys file
        keys_file = tmp_path / ".mcp_keys.json"
        keys_data = {
            "clients": [
                {
                    "api_key": "valid-key-123",
                    "client_id": "test-client",
                    "description": "Test client",
                    "enabled": True,
                }
            ]
        }
        keys_file.write_text(json.dumps(keys_data))

        return SecurityConfig(
            auth_enabled=True,
            api_keys_file=keys_file,
            rate_limit_enabled=False,
            audit_log_enabled=False,
            audit_log_file=tmp_path / "audit.log",
        )

    @pytest.fixture
    def security_config_with_ip_allowlist(self, tmp_path: Path) -> SecurityConfig:
        """Create a security config with IP allowlist."""
        # Create a keys file
        keys_file = tmp_path / ".mcp_keys.json"
        keys_data = {
            "clients": [
                {
                    "api_key": "valid-key-123",
                    "client_id": "test-client",
                    "description": "Test client",
                    "enabled": True,
                }
            ]
        }
        keys_file.write_text(json.dumps(keys_data))

        return SecurityConfig(
            auth_enabled=True,
            api_keys_file=keys_file,
            allowed_client_ips=["127.0.0.1", "192.168.1.100"],
            rate_limit_enabled=False,
            audit_log_enabled=False,
            audit_log_file=tmp_path / "audit.log",
        )

    def test_init_auth_disabled(self, security_config_auth_disabled: SecurityConfig) -> None:
        """Test initializing middleware with auth disabled."""
        middleware = AuthMiddleware(security_config_auth_disabled)

        assert middleware.config.auth_enabled is False
        assert middleware.authenticator is None

    def test_init_auth_enabled(self, security_config_auth_enabled: SecurityConfig) -> None:
        """Test initializing middleware with auth enabled."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        assert middleware.config.auth_enabled is True
        assert middleware.authenticator is not None

    def test_authenticate_request_auth_disabled(
        self, security_config_auth_disabled: SecurityConfig
    ) -> None:
        """Test authenticating a request when auth is disabled."""
        middleware = AuthMiddleware(security_config_auth_disabled)

        # Should succeed without API key
        client_info = middleware.authenticate_request(None, "127.0.0.1")

        assert client_info.client_id == "unauthenticated"
        assert client_info.api_key_hash == "none"
        assert client_info.ip_address == "127.0.0.1"

    def test_authenticate_request_valid_key(
        self, security_config_auth_enabled: SecurityConfig
    ) -> None:
        """Test authenticating a request with a valid API key."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        client_info = middleware.authenticate_request("valid-key-123", "127.0.0.1")

        assert client_info.client_id == "test-client"
        assert client_info.description == "Test client"
        assert client_info.ip_address == "127.0.0.1"

    def test_authenticate_request_invalid_key(
        self, security_config_auth_enabled: SecurityConfig
    ) -> None:
        """Test authenticating a request with an invalid API key."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        with pytest.raises(AuthenticationError, match="Invalid API key"):
            middleware.authenticate_request("invalid-key", "127.0.0.1")

    def test_authenticate_request_missing_key(
        self, security_config_auth_enabled: SecurityConfig
    ) -> None:
        """Test authenticating a request without an API key."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        with pytest.raises(AuthenticationError, match="API key required"):
            middleware.authenticate_request(None, "127.0.0.1")

    def test_authenticate_request_empty_key(
        self, security_config_auth_enabled: SecurityConfig
    ) -> None:
        """Test authenticating a request with an empty API key."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        with pytest.raises(AuthenticationError, match="API key required"):
            middleware.authenticate_request("", "127.0.0.1")

    def test_authenticate_request_ip_allowlist_valid(
        self, security_config_with_ip_allowlist: SecurityConfig
    ) -> None:
        """Test authenticating a request from an allowed IP."""
        middleware = AuthMiddleware(security_config_with_ip_allowlist)

        # Should succeed with valid key from allowed IP
        client_info = middleware.authenticate_request("valid-key-123", "127.0.0.1")

        assert client_info.client_id == "test-client"
        assert client_info.ip_address == "127.0.0.1"

    def test_authenticate_request_ip_allowlist_invalid(
        self, security_config_with_ip_allowlist: SecurityConfig
    ) -> None:
        """Test authenticating a request from a disallowed IP."""
        middleware = AuthMiddleware(security_config_with_ip_allowlist)

        # Should fail even with valid key from disallowed IP
        with pytest.raises(AuthenticationError, match="IP address not allowed"):
            middleware.authenticate_request("valid-key-123", "192.168.1.200")

    def test_authenticate_request_ip_allowlist_missing_ip(
        self, security_config_with_ip_allowlist: SecurityConfig
    ) -> None:
        """Test authenticating a request without IP when allowlist is configured."""
        middleware = AuthMiddleware(security_config_with_ip_allowlist)

        # Should fail if IP is not provided
        with pytest.raises(AuthenticationError, match="IP address not allowed"):
            middleware.authenticate_request("valid-key-123", None)

    def test_check_ip_allowed_no_allowlist(
        self, security_config_auth_enabled: SecurityConfig
    ) -> None:
        """Test checking IP when no allowlist is configured."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        # All IPs should be allowed
        assert middleware.check_ip_allowed("127.0.0.1") is True
        assert middleware.check_ip_allowed("192.168.1.1") is True
        assert middleware.check_ip_allowed(None) is True

    def test_check_ip_allowed_with_allowlist(
        self, security_config_with_ip_allowlist: SecurityConfig
    ) -> None:
        """Test checking IP when allowlist is configured."""
        middleware = AuthMiddleware(security_config_with_ip_allowlist)

        # Only allowed IPs should pass
        assert middleware.check_ip_allowed("127.0.0.1") is True
        assert middleware.check_ip_allowed("192.168.1.100") is True
        assert middleware.check_ip_allowed("192.168.1.200") is False
        assert middleware.check_ip_allowed(None) is False

    def test_reload_keys(self, security_config_auth_enabled: SecurityConfig) -> None:
        """Test reloading API keys."""
        middleware = AuthMiddleware(security_config_auth_enabled)

        # Update the keys file
        keys_data = {
            "clients": [
                {
                    "api_key": "new-key-456",
                    "client_id": "new-client",
                    "description": "New client",
                    "enabled": True,
                }
            ]
        }
        security_config_auth_enabled.api_keys_file.write_text(json.dumps(keys_data))

        # Reload keys
        middleware.reload_keys()

        # Old key should not work
        with pytest.raises(AuthenticationError):
            middleware.authenticate_request("valid-key-123", "127.0.0.1")

        # New key should work
        client_info = middleware.authenticate_request("new-key-456", "127.0.0.1")
        assert client_info.client_id == "new-client"

    def test_reload_keys_auth_disabled(self, security_config_auth_disabled: SecurityConfig) -> None:
        """Test reloading keys when auth is disabled."""
        middleware = AuthMiddleware(security_config_auth_disabled)

        # Should not raise error
        middleware.reload_keys()
