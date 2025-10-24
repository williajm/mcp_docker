"""Pytest configuration and shared fixtures."""

from collections.abc import Generator
from unittest.mock import MagicMock, Mock

import pytest
from docker import DockerClient

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker.client import DockerClientWrapper


@pytest.fixture
def docker_config() -> DockerConfig:
    """Create test Docker configuration."""
    return DockerConfig(
        base_url="unix:///var/run/docker.sock",
        timeout=30,
    )


@pytest.fixture
def safety_config() -> SafetyConfig:
    """Create test safety configuration."""
    return SafetyConfig(
        allow_destructive_operations=True,
        allow_privileged_containers=False,
        require_confirmation_for_destructive=False,
    )


@pytest.fixture
def server_config() -> ServerConfig:
    """Create test server configuration."""
    return ServerConfig(
        server_name="mcp-docker-test",
        server_version="0.1.0",
        log_level="DEBUG",
    )


@pytest.fixture
def config(
    docker_config: DockerConfig,
    safety_config: SafetyConfig,
    server_config: ServerConfig,
) -> Config:
    """Create complete test configuration."""
    cfg = Config.__new__(Config)
    cfg.docker = docker_config
    cfg.safety = safety_config
    cfg.server = server_config
    return cfg


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create mock Docker client."""
    mock_client = MagicMock(spec=DockerClient)
    mock_client.ping.return_value = True
    mock_client.info.return_value = {
        "Name": "test-docker",
        "Containers": 5,
        "ContainersRunning": 2,
        "ContainersPaused": 0,
        "ContainersStopped": 3,
        "Images": 10,
        "OperatingSystem": "Linux",
        "Architecture": "x86_64",
        "MemTotal": 8589934592,
        "NCPU": 4,
    }
    mock_client.version.return_value = {
        "Version": "24.0.0",
        "ApiVersion": "1.43",
    }
    return mock_client


@pytest.fixture
def docker_client_wrapper(
    docker_config: DockerConfig,
    mock_docker_client: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[DockerClientWrapper, None, None]:
    """Create Docker client wrapper with mocked client."""

    def mock_docker_client_init(*args: tuple, **kwargs: dict) -> Mock:
        return mock_docker_client

    monkeypatch.setattr("docker.DockerClient", mock_docker_client_init)

    wrapper = DockerClientWrapper(docker_config)
    yield wrapper
    wrapper.close()
