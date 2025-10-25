"""Tests for configuration module."""

import pytest
from pydantic import ValidationError

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig


class TestDockerConfig:
    """Tests for DockerConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        import os

        # Clear DOCKER_BASE_URL env var if set
        old_base_url = os.environ.pop("DOCKER_BASE_URL", None)
        try:
            config = DockerConfig()
            assert config.base_url == "unix:///var/run/docker.sock"
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


class TestSafetyConfig:
    """Tests for SafetyConfig."""

    def test_default_values(self) -> None:
        """Test default safety configuration."""
        config = SafetyConfig()
        assert config.allow_destructive_operations is False
        assert config.allow_privileged_containers is False
        assert config.require_confirmation_for_destructive is True
        assert config.max_concurrent_operations == 10

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


class TestServerConfig:
    """Tests for ServerConfig."""

    def test_default_values(self) -> None:
        """Test default server configuration."""
        config = ServerConfig()
        assert config.server_name == "mcp-docker"
        assert config.server_version == "0.1.0"
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
