"""Tests for configuration module."""

import os
import platform

import pytest
from pydantic import ValidationError

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.version import __version__


class TestDockerConfig:
    """Tests for DockerConfig."""

    def test_default_values(self) -> None:
        """Test default Docker configuration values."""
        old_base_url = os.environ.pop("DOCKER_BASE_URL", None)
        try:
            config = DockerConfig()
            expected_socket = (
                "npipe:////./pipe/docker_engine"
                if platform.system().lower() == "windows"
                else "unix:///var/run/docker.sock"
            )
            assert config.base_url == expected_socket
            assert config.timeout == 60
        finally:
            if old_base_url:
                os.environ["DOCKER_BASE_URL"] = old_base_url

    def test_custom_values(self) -> None:
        """Test custom Docker configuration values."""
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

    def test_rejects_insecure_http_socket(self) -> None:
        """Test insecure HTTP Docker socket URLs are rejected."""
        with pytest.raises(ValidationError, match="Insecure HTTP Docker socket"):
            DockerConfig(base_url="http://docker.example.com")


class TestSafetyConfig:
    """Tests for SafetyConfig."""

    def test_default_values(self) -> None:
        """Test default safety configuration."""
        config = SafetyConfig()
        assert config.allow_moderate_operations is True
        assert config.default_tool_timeout == 30.0
        assert config.max_response_bytes == 1048576

    def test_read_only_mode(self) -> None:
        """Test read-only safety mode."""
        config = SafetyConfig(allow_moderate_operations=False)
        assert config.allow_moderate_operations is False

    def test_tool_timeout_bounds(self) -> None:
        """Test tool timeout bounds."""
        assert SafetyConfig(default_tool_timeout=0).default_tool_timeout == 0
        assert SafetyConfig(default_tool_timeout=3600).default_tool_timeout == 3600

        with pytest.raises(ValidationError):
            SafetyConfig(default_tool_timeout=-1)

        with pytest.raises(ValidationError):
            SafetyConfig(default_tool_timeout=3601)

    def test_response_size_bounds(self) -> None:
        """Test response size bounds."""
        assert SafetyConfig(max_response_bytes=0).max_response_bytes == 0
        assert SafetyConfig(max_response_bytes=10485760).max_response_bytes == 10485760

        with pytest.raises(ValidationError):
            SafetyConfig(max_response_bytes=-1)

        with pytest.raises(ValidationError):
            SafetyConfig(max_response_bytes=10485761)


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
