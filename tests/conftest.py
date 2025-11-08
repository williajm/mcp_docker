"""Pytest configuration and shared fixtures."""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from docker import DockerClient

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.version import __version__


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
        allow_moderate_operations=True,
        allow_destructive_operations=True,
        allow_privileged_containers=False,
        require_confirmation_for_destructive=False,
    )


@pytest.fixture
def read_only_safety_config() -> SafetyConfig:
    """Create read-only mode safety configuration (blocks MODERATE operations)."""
    return SafetyConfig(
        allow_moderate_operations=False,
        allow_destructive_operations=False,
        allow_privileged_containers=False,
        require_confirmation_for_destructive=True,
    )


@pytest.fixture
def server_config() -> ServerConfig:
    """Create test server configuration."""
    return ServerConfig(
        server_name="mcp-docker-test",
        server_version=__version__,
        log_level="DEBUG",
    )


@pytest.fixture
def config(
    docker_config: DockerConfig,
    safety_config: SafetyConfig,
    server_config: ServerConfig,
) -> Config:
    """Create complete test configuration."""
    test_config = Config.__new__(Config)
    test_config.docker = docker_config
    test_config.safety = safety_config
    test_config.server = server_config
    return test_config


@pytest.fixture
def read_only_config(
    docker_config: DockerConfig,
    read_only_safety_config: SafetyConfig,
    server_config: ServerConfig,
) -> Config:
    """Create read-only mode configuration (blocks MODERATE operations)."""
    test_config = Config.__new__(Config)
    test_config.docker = docker_config
    test_config.safety = read_only_safety_config
    test_config.server = server_config
    return test_config


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

    def mock_docker_client_init(*args: Any, **kwargs: Any) -> Mock:
        return mock_docker_client

    monkeypatch.setattr("docker.DockerClient", mock_docker_client_init)

    wrapper = DockerClientWrapper(docker_config)
    yield wrapper
    wrapper.close()


# Integration test fixtures
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "integration: Integration tests requiring Docker")
    config.addinivalue_line("markers", "slow: Slow running tests")


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Check if Docker is available for integration tests."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
        return True
    except Exception:
        return False


@pytest.fixture
def skip_if_no_docker(docker_available: bool) -> None:
    """Fail test if Docker is not available."""
    if not docker_available:
        pytest.fail("Docker is required for integration tests but is not available")


@pytest.fixture
def integration_test_config() -> Config:
    """Create configuration for integration tests."""
    test_config = Config()
    # Override settings for integration tests
    test_config.safety.allow_moderate_operations = True
    test_config.safety.allow_destructive_operations = True
    test_config.safety.allow_privileged_containers = True
    test_config.safety.require_confirmation_for_destructive = False
    return test_config
