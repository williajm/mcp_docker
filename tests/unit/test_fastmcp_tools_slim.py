"""Unit tests for the exposed slim tool surface."""

from unittest.mock import Mock

import pytest

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.container_inspection import (
    create_container_logs_tool,
    create_container_stats_tool,
    create_inspect_container_tool,
    create_list_containers_tool,
)
from mcp_docker.tools.container_lifecycle import (
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)
from mcp_docker.tools.image import create_inspect_image_tool, create_list_images_tool
from mcp_docker.tools.network import create_list_networks_tool
from mcp_docker.tools.system import create_version_tool
from mcp_docker.tools.volume import create_list_volumes_tool


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    return client


@pytest.mark.parametrize(
    "tool_creator,expected_name,expected_safety",
    [
        (create_list_containers_tool, "docker_list_containers", OperationSafety.SAFE),
        (create_inspect_container_tool, "docker_inspect_container", OperationSafety.SAFE),
        (create_container_logs_tool, "docker_container_logs", OperationSafety.SAFE),
        (create_container_stats_tool, "docker_container_stats", OperationSafety.SAFE),
        (create_start_container_tool, "docker_start_container", OperationSafety.MODERATE),
        (create_stop_container_tool, "docker_stop_container", OperationSafety.MODERATE),
        (create_restart_container_tool, "docker_restart_container", OperationSafety.MODERATE),
        (create_list_images_tool, "docker_list_images", OperationSafety.SAFE),
        (create_inspect_image_tool, "docker_inspect_image", OperationSafety.SAFE),
        (create_list_networks_tool, "docker_list_networks", OperationSafety.SAFE),
        (create_list_volumes_tool, "docker_list_volumes", OperationSafety.SAFE),
        (create_version_tool, "docker_version", OperationSafety.SAFE),
    ],
)
def test_exposed_tool_metadata(
    mock_docker_client: Mock,
    tool_creator: Mock,
    expected_name: str,
    expected_safety: OperationSafety,
) -> None:
    """Test metadata for each exposed tool."""
    spec = tool_creator(mock_docker_client)

    assert spec.name == expected_name
    assert spec.safety == expected_safety
    assert isinstance(spec.description, str) and spec.description
    assert callable(spec.func)
