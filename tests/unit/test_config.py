"""Tests for configuration module."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_docker.config import (
    Config,
    DockerConfig,
    SafetyConfig,
    SecurityConfig,
    ServerConfig,
    _parse_comma_separated_list,
)
from mcp_docker.version import __version__


class TestDockerConfig:
    """Tests for DockerConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        import os
        import platform

        # Clear DOCKER_BASE_URL env var if set
        old_base_url = os.environ.pop("DOCKER_BASE_URL", None)
        try:
            config = DockerConfig()
            # Check that base_url is auto-detected based on OS
            expected_socket = (
                "npipe:////./pipe/docker_engine"
                if platform.system().lower() == "windows"
                else "unix:///var/run/docker.sock"
            )
            assert config.base_url == expected_socket
            assert config.timeout == 60
            assert config.tls_verify is False
            assert config.tls_ca_cert is None
        finally:
            # Restore original value
            if old_base_url:
                os.environ["DOCKER_BASE_URL"] = old_base_url

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = DockerConfig(
            base_url="tcp://localhost:2375",
            timeout=30,
        )
        assert config.base_url == "tcp://localhost:2375"
        assert config.timeout == 30

    def test_timeout_validation(self) -> None:
        """Test timeout must be positive."""
        with pytest.raises(ValidationError):
            DockerConfig(timeout=0)

        with pytest.raises(ValidationError):
            DockerConfig(timeout=-1)

    def test_tls_verify_without_ca_cert_uses_system_bundle(self) -> None:
        """Test that TLS verification can use system CA bundle when no custom CA provided.

        This is a legitimate use case for connecting to Docker daemons with publicly
        trusted certificates or certificates trusted by the system CA store.
        """
        # Should allow TLS verification without custom CA cert (uses system CA bundle)
        config = DockerConfig(
            base_url="tcp://docker.example.com:2376",
            tls_verify=True,
            tls_ca_cert=None,  # No custom CA - will use system bundle
        )
        assert config.tls_verify is True
        assert config.tls_ca_cert is None

    def test_tls_verify_with_custom_ca_cert(self, tmp_path: Path) -> None:
        """Test TLS verification with custom CA certificate."""
        ca_cert = tmp_path / "ca.pem"
        ca_cert.touch()

        config = DockerConfig(
            base_url="tcp://docker.example.com:2376",
            tls_verify=True,
            tls_ca_cert=ca_cert,
        )
        assert config.tls_verify is True
        assert config.tls_ca_cert == ca_cert

    def test_tls_verify_rejects_nonexistent_ca_cert(self, tmp_path: Path) -> None:
        """Test that TLS verification rejects non-existent CA certificate files."""
        nonexistent_cert = tmp_path / "nonexistent.pem"

        with pytest.raises(ValidationError, match="Certificate file not found"):
            DockerConfig(
                base_url="tcp://docker.example.com:2376",
                tls_verify=True,
                tls_ca_cert=nonexistent_cert,
            )


class TestSafetyConfig:
    """Tests for SafetyConfig."""

    def test_default_values(self) -> None:
        """Test default safety configuration."""
        import os

        # Clear any environment variables that might override defaults
        old_destructive = os.environ.pop("SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS", None)
        try:
            config = SafetyConfig()
            assert config.allow_moderate_operations is True
            assert config.allow_destructive_operations is False
            assert config.allow_privileged_containers is False
            assert config.require_confirmation_for_destructive is True
            assert config.max_concurrent_operations == 10
        finally:
            # Restore original value
            if old_destructive:
                os.environ["SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS"] = old_destructive

    def test_custom_values(self) -> None:
        """Test custom safety configuration."""
        config = SafetyConfig(
            allow_destructive_operations=True,
            max_concurrent_operations=20,
        )
        assert config.allow_destructive_operations is True
        assert config.max_concurrent_operations == 20

    def test_max_concurrent_validation(self) -> None:
        """Test max_concurrent_operations validation."""
        with pytest.raises(ValidationError):
            SafetyConfig(max_concurrent_operations=0)

        with pytest.raises(ValidationError):
            SafetyConfig(max_concurrent_operations=101)

    def test_parse_tool_list_from_string(self) -> None:
        """Test parsing tool list from comma-separated string."""
        config = SafetyConfig(
            allowed_tools="docker_list_containers,docker_inspect_container, docker_version"
        )
        assert config.allowed_tools == [
            "docker_list_containers",
            "docker_inspect_container",
            "docker_version",
        ]

    def test_parse_tool_list_from_list(self) -> None:
        """Test parsing tool list from list."""
        config = SafetyConfig(allowed_tools=["docker_list_containers", "docker_inspect_container"])
        assert config.allowed_tools == ["docker_list_containers", "docker_inspect_container"]

    def test_parse_tool_list_empty_string(self) -> None:
        """Test parsing empty string returns empty list."""
        config = SafetyConfig(allowed_tools="")
        assert config.allowed_tools == []

    def test_parse_tool_list_none(self) -> None:
        """Test parsing None returns empty list."""
        config = SafetyConfig()
        assert config.allowed_tools == []
        assert config.denied_tools == []

    def test_parse_tool_list_strips_whitespace(self) -> None:
        """Test that whitespace around tool names is stripped."""
        config = SafetyConfig(
            denied_tools="  docker_remove_container  , docker_prune_images  ,  docker_system_prune  "
        )
        assert config.denied_tools == [
            "docker_remove_container",
            "docker_prune_images",
            "docker_system_prune",
        ]

    def test_parse_tool_list_filters_empty_strings(self) -> None:
        """Test that empty strings and extra commas are filtered out."""
        config = SafetyConfig(allowed_tools="docker_list_containers,,docker_version,")
        assert config.allowed_tools == ["docker_list_containers", "docker_version"]

    def test_parse_tool_list_with_list_containing_empty_strings(self) -> None:
        """Test that empty strings in lists are filtered out."""
        config = SafetyConfig(
            denied_tools=["docker_remove_container", "", "  ", "docker_prune_images"]
        )
        assert config.denied_tools == ["docker_remove_container", "docker_prune_images"]

    def test_allowed_and_denied_tools_independent(self) -> None:
        """Test that allowed_tools and denied_tools can be set independently."""
        config = SafetyConfig(
            allowed_tools="docker_list_containers,docker_version",
            denied_tools="docker_remove_container,docker_prune_images",
        )
        assert config.allowed_tools == ["docker_list_containers", "docker_version"]
        assert config.denied_tools == ["docker_remove_container", "docker_prune_images"]


class TestServerConfig:
    """Tests for ServerConfig."""

    def test_default_values(self) -> None:
        """Test default server configuration."""
        config = ServerConfig()
        assert config.server_name == "mcp-docker"
        assert config.server_version == __version__
        assert config.log_level == "INFO"

    def test_log_level_validation(self) -> None:
        """Test log level validation."""
        config = ServerConfig(log_level="DEBUG")
        assert config.log_level == "DEBUG"

        config = ServerConfig(log_level="debug")
        assert config.log_level == "DEBUG"

        with pytest.raises(ValidationError):
            ServerConfig(log_level="INVALID")


class TestConfig:
    """Tests for main Config class."""

    def test_initialization(self) -> None:
        """Test Config initialization."""
        config = Config()
        assert isinstance(config.docker, DockerConfig)
        assert isinstance(config.safety, SafetyConfig)
        assert isinstance(config.server, ServerConfig)

    def test_repr(self) -> None:
        """Test Config string representation."""
        config = Config()
        repr_str = repr(config)
        assert "Config" in repr_str
        assert "docker=" in repr_str
        assert "safety=" in repr_str
        assert "server=" in repr_str


class TestSecurityConfig:
    """Tests for SecurityConfig."""

    def test_audit_log_path_validator_creates_parent_directory(self, tmp_path: Path) -> None:
        """Test that audit log validator creates parent directory if it doesn't exist."""
        # Create a path where parent doesn't exist yet
        audit_log_path = tmp_path / "new_dir" / "subdir" / "audit.log"
        assert not audit_log_path.parent.exists()

        # Create config with non-existent parent directory
        config = SecurityConfig(audit_log_file=audit_log_path)

        # Validator should have created the parent directory
        assert audit_log_path.parent.exists()
        assert config.audit_log_file == audit_log_path

    def test_audit_log_path_validator_accepts_existing_directory(self, tmp_path: Path) -> None:
        """Test that audit log validator works with existing parent directory."""
        audit_log_path = tmp_path / "audit.log"
        assert audit_log_path.parent.exists()

        # Should work fine with existing directory
        config = SecurityConfig(audit_log_file=audit_log_path)
        assert config.audit_log_file == audit_log_path


class TestParseCommaSeparatedList:
    """Test _parse_comma_separated_list helper function."""

    def test_parse_json_array_compact(self):
        """Test parsing compact JSON array format."""
        result = _parse_comma_separated_list('["docker.read","docker.write"]')
        assert result == ["docker.read", "docker.write"]

    def test_parse_json_array_spaced(self):
        """Test parsing spaced JSON array format."""
        result = _parse_comma_separated_list('["docker.read", "docker.write"]')
        assert result == ["docker.read", "docker.write"]

    def test_parse_comma_separated(self):
        """Test parsing comma-separated string."""
        result = _parse_comma_separated_list("docker.read,docker.write")
        assert result == ["docker.read", "docker.write"]

    def test_parse_comma_separated_with_spaces(self):
        """Test parsing comma-separated string with spaces."""
        result = _parse_comma_separated_list("docker.read, docker.write, docker.admin")
        assert result == ["docker.read", "docker.write", "docker.admin"]

    def test_parse_single_value(self):
        """Test parsing single value."""
        result = _parse_comma_separated_list("mcp-docker-api")
        assert result == ["mcp-docker-api"]

    def test_parse_already_list(self):
        """Test parsing when already a list."""
        result = _parse_comma_separated_list(["docker.read", "docker.write"])
        assert result == ["docker.read", "docker.write"]

    def test_parse_none(self):
        """Test parsing None."""
        result = _parse_comma_separated_list(None)
        assert result == []

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = _parse_comma_separated_list("")
        assert result == []

    def test_parse_json_array_with_whitespace(self):
        """Test parsing JSON array with extra whitespace."""
        result = _parse_comma_separated_list('  ["docker.read", "docker.write"]  ')
        assert result == ["docker.read", "docker.write"]

    def test_parse_malformed_json_falls_back(self):
        """Test that malformed JSON falls back to comma-separated parsing."""
        # This looks like JSON but has syntax error, should fall back
        result = _parse_comma_separated_list('["docker.read",docker.write"]')
        # Falls back to comma-separated, treating brackets as part of values
        assert len(result) > 0  # Just verify it doesn't crash


class TestSecurityConfigOAuthParsing:
    """Test SecurityConfig OAuth field parsing with environment variable formats."""

    def test_oauth_audience_json_array(self):
        """Test oauth_audience with JSON array format."""
        config = SecurityConfig(oauth_audience='["mcp-docker-api", "api.example.com"]')
        assert config.oauth_audience == ["mcp-docker-api", "api.example.com"]

    def test_oauth_audience_comma_separated(self):
        """Test oauth_audience with comma-separated format."""
        config = SecurityConfig(oauth_audience="mcp-docker-api,api.example.com")
        assert config.oauth_audience == ["mcp-docker-api", "api.example.com"]

    def test_oauth_required_scopes_json_array(self):
        """Test oauth_required_scopes with JSON array format."""
        config = SecurityConfig(oauth_required_scopes='["docker.read", "docker.write"]')
        assert config.oauth_required_scopes == ["docker.read", "docker.write"]

    def test_oauth_required_scopes_comma_separated(self):
        """Test oauth_required_scopes with comma-separated format."""
        config = SecurityConfig(oauth_required_scopes="docker.read,docker.write")
        assert config.oauth_required_scopes == ["docker.read", "docker.write"]

    def test_oauth_fields_default_empty_list(self):
        """Test that OAuth fields default to empty lists."""
        config = SecurityConfig()
        assert config.oauth_audience == []
        assert config.oauth_required_scopes == []
