"""Unit tests for HTTP Stream Transport configuration."""

import pytest
from pydantic import ValidationError

from mcp_docker.config import CORSConfig, HttpStreamConfig


class TestHttpStreamConfig:
    """Test HTTP Stream Transport configuration."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = HttpStreamConfig()
        assert config.json_response_default is False
        assert config.stateless_mode is False
        assert config.resumability_enabled is True
        assert config.event_store_max_events == 1000
        assert config.event_store_ttl_seconds == 300
        assert config.dns_rebinding_protection is True

    def test_environment_variable_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test configuration from environment variables."""
        monkeypatch.setenv("HTTPSTREAM_JSON_RESPONSE_DEFAULT", "true")
        monkeypatch.setenv("HTTPSTREAM_STATELESS_MODE", "true")
        monkeypatch.setenv("HTTPSTREAM_RESUMABILITY_ENABLED", "false")
        monkeypatch.setenv("HTTPSTREAM_DNS_REBINDING_PROTECTION", "false")

        config = HttpStreamConfig()
        assert config.json_response_default is True
        assert config.stateless_mode is True
        assert config.resumability_enabled is False
        assert config.dns_rebinding_protection is False

    def test_json_response_mode_streaming(self) -> None:
        """Test streaming mode (default)."""
        config = HttpStreamConfig(json_response_default=False)
        assert config.json_response_default is False

    def test_json_response_mode_batch(self) -> None:
        """Test batch mode."""
        config = HttpStreamConfig(json_response_default=True)
        assert config.json_response_default is True

    def test_event_store_max_events_custom(self) -> None:
        """Test custom max_events configuration."""
        config = HttpStreamConfig(event_store_max_events=500)
        assert config.event_store_max_events == 500

    def test_event_store_ttl_seconds_custom(self) -> None:
        """Test custom TTL configuration."""
        config = HttpStreamConfig(event_store_ttl_seconds=180)
        assert config.event_store_ttl_seconds == 180

    def test_event_store_max_events_validation_min(self) -> None:
        """Test that max_events must be >= 1."""
        with pytest.raises(ValidationError):
            HttpStreamConfig(event_store_max_events=0)

    def test_event_store_max_events_validation_max(self) -> None:
        """Test that max_events must be <= 10000."""
        with pytest.raises(ValidationError):
            HttpStreamConfig(event_store_max_events=10001)

    def test_event_store_ttl_validation_min(self) -> None:
        """Test that TTL must be >= 60 seconds."""
        with pytest.raises(ValidationError):
            HttpStreamConfig(event_store_ttl_seconds=59)

    def test_event_store_ttl_validation_max(self) -> None:
        """Test that TTL must be <= 3600 seconds."""
        with pytest.raises(ValidationError):
            HttpStreamConfig(event_store_ttl_seconds=3601)

    def test_event_store_environment_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test EventStore configuration from environment variables."""
        monkeypatch.setenv("HTTPSTREAM_RESUMABILITY_ENABLED", "true")
        monkeypatch.setenv("HTTPSTREAM_EVENT_STORE_MAX_EVENTS", "750")
        monkeypatch.setenv("HTTPSTREAM_EVENT_STORE_TTL_SECONDS", "240")

        config = HttpStreamConfig()
        assert config.resumability_enabled is True
        assert config.event_store_max_events == 750
        assert config.event_store_ttl_seconds == 240

    def test_allowed_hosts_default_empty(self) -> None:
        """Test that allowed_hosts defaults to empty list."""
        config = HttpStreamConfig()
        assert config.allowed_hosts == []

    def test_allowed_hosts_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test parsing allowed_hosts from JSON array string."""
        monkeypatch.setenv("HTTPSTREAM_ALLOWED_HOSTS", '["api.example.com", "192.0.2.1"]')

        config = HttpStreamConfig()
        assert len(config.allowed_hosts) == 2
        assert "api.example.com" in config.allowed_hosts
        assert "192.0.2.1" in config.allowed_hosts

    def test_allowed_hosts_list(self) -> None:
        """Test allowed_hosts as a list."""
        config = HttpStreamConfig(allowed_hosts=["api.example.com", "192.0.2.1"])
        assert len(config.allowed_hosts) == 2
        assert "api.example.com" in config.allowed_hosts
        assert "192.0.2.1" in config.allowed_hosts

    def test_allowed_hosts_multiple(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test multiple production hostnames."""
        monkeypatch.setenv(
            "HTTPSTREAM_ALLOWED_HOSTS",
            '["api.example.com", "my-api.company.com", "192.0.2.1", "203.0.113.50"]',
        )

        config = HttpStreamConfig()
        assert len(config.allowed_hosts) == 4
        assert "api.example.com" in config.allowed_hosts
        assert "my-api.company.com" in config.allowed_hosts
        assert "192.0.2.1" in config.allowed_hosts
        assert "203.0.113.50" in config.allowed_hosts


class TestCORSConfig:
    """Test CORS configuration and validation."""

    def test_cors_disabled_by_default(self) -> None:
        """Test CORS is disabled by default."""
        config = CORSConfig()
        assert config.enabled is False
        assert config.allow_origins == []

    def test_cors_wildcard_with_credentials_raises_error(self) -> None:
        """Test that wildcard origin with credentials is rejected."""
        with pytest.raises(ValidationError, match="Cannot use wildcard origin"):
            CORSConfig(
                enabled=True,
                allow_origins=["*"],
                allow_credentials=True,
            )

    def test_cors_empty_origins_with_credentials_raises_error(self) -> None:
        """Test that empty origins with credentials is rejected."""
        with pytest.raises(ValidationError, match="Must specify explicit allow_origins"):
            CORSConfig(
                enabled=True,
                allow_origins=[],
                allow_credentials=True,
            )

    def test_cors_explicit_origins_with_credentials_accepted(self) -> None:
        """Test that explicit origins with credentials is accepted."""
        config = CORSConfig(
            enabled=True,
            allow_origins=["https://app.example.com"],
            allow_credentials=True,
        )
        assert config.enabled is True
        assert config.allow_origins == ["https://app.example.com"]
        assert config.allow_credentials is True

    def test_cors_wildcard_without_credentials_accepted(self) -> None:
        """Test that wildcard without credentials is accepted."""
        config = CORSConfig(
            enabled=True,
            allow_origins=["*"],
            allow_credentials=False,
        )
        assert config.allow_origins == ["*"]
        assert config.allow_credentials is False

    def test_cors_multiple_origins(self) -> None:
        """Test multiple explicit origins."""
        config = CORSConfig(
            enabled=True,
            allow_origins=["https://app.example.com", "https://admin.example.com"],
            allow_credentials=True,
        )
        assert len(config.allow_origins) == 2
        assert "https://app.example.com" in config.allow_origins
        assert "https://admin.example.com" in config.allow_origins

    def test_cors_disabled_allows_any_config(self) -> None:
        """Test that disabled CORS allows any configuration."""
        # When disabled, validation doesn't apply
        config = CORSConfig(
            enabled=False,
            allow_origins=["*"],
            allow_credentials=True,
        )
        assert config.enabled is False

    def test_cors_default_methods(self) -> None:
        """Test default allowed methods."""
        config = CORSConfig()
        assert "GET" in config.allow_methods
        assert "POST" in config.allow_methods
        assert "OPTIONS" in config.allow_methods

    def test_cors_default_headers(self) -> None:
        """Test default allowed headers."""
        config = CORSConfig()
        assert "Content-Type" in config.allow_headers
        assert "Authorization" in config.allow_headers
        assert "mcp-session-id" in config.allow_headers
        assert "last-event-id" in config.allow_headers

    def test_cors_default_expose_headers(self) -> None:
        """Test default exposed headers."""
        config = CORSConfig()
        assert "mcp-session-id" in config.expose_headers

    def test_cors_default_max_age(self) -> None:
        """Test default max age."""
        config = CORSConfig()
        assert config.max_age == 3600

    def test_cors_parse_origins_from_json_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test parsing origins from JSON array string."""
        monkeypatch.setenv(
            "CORS_ALLOW_ORIGINS", '["https://app.example.com","https://api.example.com"]'
        )
        config = CORSConfig()
        assert len(config.allow_origins) == 2
        assert "https://app.example.com" in config.allow_origins
        assert "https://api.example.com" in config.allow_origins

    def test_cors_environment_variable_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test CORS configuration from environment variables."""
        monkeypatch.setenv("CORS_ENABLED", "true")
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", '["https://app.example.com"]')
        monkeypatch.setenv("CORS_ALLOW_CREDENTIALS", "true")
        monkeypatch.setenv("CORS_MAX_AGE", "7200")

        config = CORSConfig()
        assert config.enabled is True
        assert config.allow_origins == ["https://app.example.com"]
        assert config.allow_credentials is True
        assert config.max_age == 7200
