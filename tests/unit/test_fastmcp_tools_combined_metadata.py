"""Unit tests for exposed tool metadata."""

from unittest.mock import Mock

import pytest

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.container_lifecycle import (
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)
from mcp_docker.tools.image import create_inspect_image_tool, create_list_images_tool
from mcp_docker.tools.network import create_list_networks_tool


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    return client


class TestToolMetadata:
    """Test metadata for exposed tools."""

    @pytest.mark.parametrize(
        "tool_creator,expected_name,expected_safety",
        [
            (create_start_container_tool, "docker_start_container", OperationSafety.MODERATE),
            (create_stop_container_tool, "docker_stop_container", OperationSafety.MODERATE),
            (create_restart_container_tool, "docker_restart_container", OperationSafety.MODERATE),
            (create_list_images_tool, "docker_list_images", OperationSafety.SAFE),
            (create_inspect_image_tool, "docker_inspect_image", OperationSafety.SAFE),
            (create_list_networks_tool, "docker_list_networks", OperationSafety.SAFE),
        ],
    )
    def test_tool_metadata(
        self,
        mock_docker_client: Mock,
        tool_creator: Mock,
        expected_name: str,
        expected_safety: OperationSafety,
    ) -> None:
        """Test exposed tool metadata."""
        spec = tool_creator(mock_docker_client)

        assert spec.name == expected_name
        assert isinstance(spec.description, str) and len(spec.description) > 0
        assert spec.safety == expected_safety
        assert callable(spec.func)
