"""Unit tests for FastMCP tool registration."""

from unittest.mock import MagicMock, Mock

import pytest
from fastmcp import FastMCP

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.registration import register_all_tools


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create a mock Docker client wrapper."""
    mock = Mock(spec=DockerClientWrapper)
    mock.client = MagicMock()
    return mock


@pytest.fixture
def safety_config() -> SafetyConfig:
    """Create a basic safety config."""
    return SafetyConfig()


@pytest.fixture
def fastmcp_app() -> FastMCP:
    """Create a FastMCP application instance."""
    return FastMCP(name="test-mcp-docker", version="1.0.0")


def test_register_all_tools_slim_surface(
    fastmcp_app: FastMCP,
    mock_docker_client: Mock,
    safety_config: SafetyConfig,
) -> None:
    """Test that the slim local tool surface is registered successfully."""
    registered = register_all_tools(fastmcp_app, mock_docker_client, safety_config)

    assert registered == {
        "container_inspection": [
            "docker_list_containers",
            "docker_inspect_container",
            "docker_container_logs",
            "docker_container_stats",
        ],
        "container_lifecycle": [
            "docker_start_container",
            "docker_stop_container",
            "docker_restart_container",
        ],
        "image": [
            "docker_list_images",
            "docker_inspect_image",
        ],
        "network": ["docker_list_networks"],
        "volume": ["docker_list_volumes"],
        "system": ["docker_version"],
    }

    total_tools = sum(len(tools) for tools in registered.values())
    assert total_tools == 12


def test_registration_with_custom_safety_config(
    fastmcp_app: FastMCP,
    mock_docker_client: Mock,
) -> None:
    """Test registration with custom safety configuration."""
    custom_config = SafetyConfig(allow_moderate_operations=False)

    registered = register_all_tools(fastmcp_app, mock_docker_client, custom_config)

    total_tools = sum(len(tools) for tools in registered.values())
    assert total_tools == 12
