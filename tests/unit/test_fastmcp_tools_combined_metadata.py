"""Unit tests for tool metadata across container_lifecycle, image, and network modules."""

from unittest.mock import Mock

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper

# Container lifecycle imports
from mcp_docker.fastmcp_tools.container_lifecycle import (
    create_create_container_tool,
    create_remove_container_tool,
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)

# Image imports
from mcp_docker.fastmcp_tools.image import (
    create_build_image_tool,
    create_image_history_tool,
    create_inspect_image_tool,
    create_list_images_tool,
    create_prune_images_tool,
    create_pull_image_tool,
    create_push_image_tool,
    create_remove_image_tool,
    create_tag_image_tool,
)

# Network imports
from mcp_docker.fastmcp_tools.network import (
    create_connect_container_tool,
    create_create_network_tool,
    create_disconnect_container_tool,
    create_inspect_network_tool,
    create_list_networks_tool,
    create_remove_network_tool,
)
from mcp_docker.utils.safety import OperationSafety


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    return client


@pytest.fixture
def safety_config():
    """Create safety config."""
    return SafetyConfig()


# Container Lifecycle Tool Metadata Tests


def test_create_container_tool_metadata(mock_docker_client):
    """Test docker_create_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_create_container_tool(
        mock_docker_client, safety_config
    )
    assert name == "docker_create_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_start_container_tool_metadata(mock_docker_client):
    """Test docker_start_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_start_container_tool(
        mock_docker_client
    )
    assert name == "docker_start_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_stop_container_tool_metadata(mock_docker_client):
    """Test docker_stop_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_stop_container_tool(
        mock_docker_client
    )
    assert name == "docker_stop_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_restart_container_tool_metadata(mock_docker_client):
    """Test docker_restart_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_restart_container_tool(
        mock_docker_client
    )
    assert name == "docker_restart_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_remove_container_tool_metadata(mock_docker_client):
    """Test docker_remove_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_remove_container_tool(
        mock_docker_client
    )
    assert name == "docker_remove_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.DESTRUCTIVE
    assert callable(func)


# Image Tool Metadata Tests


def test_list_images_tool_metadata(mock_docker_client):
    """Test docker_list_images tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_list_images_tool(
        mock_docker_client, safety_config
    )
    assert name == "docker_list_images"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.SAFE
    assert callable(func)


def test_inspect_image_tool_metadata(mock_docker_client):
    """Test docker_inspect_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_inspect_image_tool(
        mock_docker_client
    )
    assert name == "docker_inspect_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.SAFE
    assert callable(func)


def test_image_history_tool_metadata(mock_docker_client):
    """Test docker_image_history tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_image_history_tool(
        mock_docker_client, safety_config
    )
    assert name == "docker_image_history"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.SAFE
    assert callable(func)


def test_pull_image_tool_metadata(mock_docker_client):
    """Test docker_pull_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_pull_image_tool(
        mock_docker_client
    )
    assert name == "docker_pull_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_build_image_tool_metadata(mock_docker_client):
    """Test docker_build_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_build_image_tool(
        mock_docker_client
    )
    assert name == "docker_build_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_push_image_tool_metadata(mock_docker_client):
    """Test docker_push_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_push_image_tool(
        mock_docker_client
    )
    assert name == "docker_push_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_tag_image_tool_metadata(mock_docker_client):
    """Test docker_tag_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_tag_image_tool(
        mock_docker_client
    )
    assert name == "docker_tag_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_remove_image_tool_metadata(mock_docker_client):
    """Test docker_remove_image tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_remove_image_tool(
        mock_docker_client
    )
    assert name == "docker_remove_image"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.DESTRUCTIVE
    assert callable(func)


def test_prune_images_tool_metadata(mock_docker_client):
    """Test docker_prune_images tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_prune_images_tool(
        mock_docker_client
    )
    assert name == "docker_prune_images"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.DESTRUCTIVE
    assert callable(func)


# Network Tool Metadata Tests


def test_list_networks_tool_metadata(mock_docker_client):
    """Test docker_list_networks tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_list_networks_tool(
        mock_docker_client, safety_config
    )
    assert name == "docker_list_networks"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.SAFE
    assert callable(func)


def test_inspect_network_tool_metadata(mock_docker_client):
    """Test docker_inspect_network tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_inspect_network_tool(
        mock_docker_client
    )
    assert name == "docker_inspect_network"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.SAFE
    assert callable(func)


def test_create_network_tool_metadata(mock_docker_client):
    """Test docker_create_network tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_create_network_tool(
        mock_docker_client
    )
    assert name == "docker_create_network"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_connect_container_tool_metadata(mock_docker_client):
    """Test docker_connect_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_connect_container_tool(
        mock_docker_client
    )
    assert name == "docker_connect_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_disconnect_container_tool_metadata(mock_docker_client):
    """Test docker_disconnect_container tool metadata."""
    name, description, safety_level, idempotent, open_world, func = (
        create_disconnect_container_tool(mock_docker_client)
    )
    assert name == "docker_disconnect_container"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.MODERATE
    assert callable(func)


def test_remove_network_tool_metadata(mock_docker_client):
    """Test docker_remove_network tool metadata."""
    name, description, safety_level, idempotent, open_world, func = create_remove_network_tool(
        mock_docker_client
    )
    assert name == "docker_remove_network"
    assert isinstance(description, str) and len(description) > 0
    assert safety_level == OperationSafety.DESTRUCTIVE
    assert callable(func)
