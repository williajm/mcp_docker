"""Unit tests for tool metadata across container_lifecycle, image, and network modules."""

from unittest.mock import Mock

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety

# Container lifecycle imports
from mcp_docker.tools.container_lifecycle import (
    create_create_container_tool,
    create_remove_container_tool,
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)

# Image imports
from mcp_docker.tools.image import (
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
from mcp_docker.tools.network import (
    create_connect_container_tool,
    create_create_network_tool,
    create_disconnect_container_tool,
    create_inspect_network_tool,
    create_list_networks_tool,
    create_remove_network_tool,
)


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


class TestToolMetadata:
    """Test tool metadata for all tool modules."""

    @pytest.mark.parametrize(
        "tool_creator,expected_name,expected_safety,needs_safety_config,expected_supports_task",
        [
            # Container lifecycle tools (none support background tasks)
            (
                create_create_container_tool,
                "docker_create_container",
                OperationSafety.MODERATE,
                True,
                False,
            ),
            (
                create_start_container_tool,
                "docker_start_container",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_stop_container_tool,
                "docker_stop_container",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_restart_container_tool,
                "docker_restart_container",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_remove_container_tool,
                "docker_remove_container",
                OperationSafety.DESTRUCTIVE,
                False,
                False,
            ),
            # Image tools (pull, build, push support background tasks)
            (
                create_list_images_tool,
                "docker_list_images",
                OperationSafety.SAFE,
                True,
                False,
            ),
            (
                create_inspect_image_tool,
                "docker_inspect_image",
                OperationSafety.SAFE,
                False,
                False,
            ),
            (
                create_image_history_tool,
                "docker_image_history",
                OperationSafety.SAFE,
                True,
                False,
            ),
            (
                create_pull_image_tool,
                "docker_pull_image",
                OperationSafety.MODERATE,
                False,
                True,  # supports_task=True for pull
            ),
            (
                create_build_image_tool,
                "docker_build_image",
                OperationSafety.MODERATE,
                False,
                True,  # supports_task=True for build
            ),
            (
                create_push_image_tool,
                "docker_push_image",
                OperationSafety.MODERATE,
                False,
                True,  # supports_task=True for push
            ),
            (
                create_tag_image_tool,
                "docker_tag_image",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_remove_image_tool,
                "docker_remove_image",
                OperationSafety.DESTRUCTIVE,
                False,
                False,
            ),
            (
                create_prune_images_tool,
                "docker_prune_images",
                OperationSafety.DESTRUCTIVE,
                False,
                False,
            ),
            # Network tools (none support background tasks)
            (
                create_list_networks_tool,
                "docker_list_networks",
                OperationSafety.SAFE,
                True,
                False,
            ),
            (
                create_inspect_network_tool,
                "docker_inspect_network",
                OperationSafety.SAFE,
                False,
                False,
            ),
            (
                create_create_network_tool,
                "docker_create_network",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_connect_container_tool,
                "docker_connect_container",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_disconnect_container_tool,
                "docker_disconnect_container",
                OperationSafety.MODERATE,
                False,
                False,
            ),
            (
                create_remove_network_tool,
                "docker_remove_network",
                OperationSafety.DESTRUCTIVE,
                False,
                False,
            ),
        ],
    )
    def test_tool_metadata(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        expected_name,
        expected_safety,
        needs_safety_config,
        expected_supports_task,
    ):
        """Test tool metadata for container lifecycle, image, and network tools."""
        if needs_safety_config:
            name, description, safety_level, idempotent, open_world, supports_task, func = (
                tool_creator(mock_docker_client, safety_config)
            )
        else:
            name, description, safety_level, idempotent, open_world, supports_task, func = (
                tool_creator(mock_docker_client)
            )

        assert name == expected_name
        assert isinstance(description, str) and len(description) > 0
        assert safety_level == expected_safety
        assert supports_task == expected_supports_task, (
            f"Tool {expected_name} has supports_task={supports_task}, "
            f"expected {expected_supports_task}"
        )
        assert callable(func)
