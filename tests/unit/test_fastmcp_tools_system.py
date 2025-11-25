"""Unit tests for fastmcp_tools/system.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.system import create_prune_system_tool
from mcp_docker.utils.errors import DockerOperationError


# Module-level fixtures
@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    client.client.api = Mock()
    client.client.images = Mock()
    client.client.volumes = Mock()
    return client


class TestPruneSystemTool:
    """Test docker_prune_system tool."""

    @pytest.mark.parametrize(
        "volumes,expected_volumes_deleted,expected_space,volumes_call_expected",
        [
            (False, [], 6100, False),
            (True, ["volume1", "volume2"], 8100, True),
        ],
    )
    def test_prune_system_success(
        self,
        mock_docker_client,
        volumes,
        expected_volumes_deleted,
        expected_space,
        volumes_call_expected,
    ):
        """Test successful system prune with and without volumes."""
        mock_docker_client.client.api.prune_containers.return_value = {
            "ContainersDeleted": ["container1", "container2"],
            "SpaceReclaimed": 1000,
        }
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:abc123"}],
            "SpaceReclaimed": 5000,
        }
        mock_docker_client.client.api.prune_networks.return_value = {
            "NetworksDeleted": ["network1"],
            "SpaceReclaimed": 100,
        }
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 2000,
        }

        *_, prune_func = create_prune_system_tool(mock_docker_client)
        result = prune_func(volumes=volumes)

        assert result["containers_deleted"] == ["container1", "container2"]
        assert result["images_deleted"] == [{"Deleted": "sha256:abc123"}]
        assert result["networks_deleted"] == ["network1"]
        assert result["volumes_deleted"] == expected_volumes_deleted
        assert result["space_reclaimed"] == expected_space

        mock_docker_client.client.api.prune_containers.assert_called_once_with(filters=None)
        mock_docker_client.client.images.prune.assert_called_once_with(filters=None)
        mock_docker_client.client.api.prune_networks.assert_called_once_with(filters=None)

        if volumes_call_expected:
            mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)
        else:
            mock_docker_client.client.volumes.prune.assert_not_called()

    def test_prune_system_with_filters(self, mock_docker_client):
        """Test system prune with filters."""
        mock_docker_client.client.api.prune_containers.return_value = {
            "ContainersDeleted": [],
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [],
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.api.prune_networks.return_value = {
            "NetworksDeleted": [],
            "SpaceReclaimed": 0,
        }

        *_, prune_func = create_prune_system_tool(mock_docker_client)
        filters = {"until": "24h"}
        result = prune_func(filters=filters)

        mock_docker_client.client.api.prune_containers.assert_called_once_with(filters=filters)
        mock_docker_client.client.images.prune.assert_called_once_with(filters=filters)
        mock_docker_client.client.api.prune_networks.assert_called_once_with(filters=filters)
        assert result["space_reclaimed"] == 0

    def test_prune_system_empty_results(self, mock_docker_client):
        """Test system prune with no resources to delete (None values)."""
        mock_docker_client.client.api.prune_containers.return_value = {
            "ContainersDeleted": None,
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": None,
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.api.prune_networks.return_value = {
            "NetworksDeleted": None,
            "SpaceReclaimed": 0,
        }

        *_, prune_func = create_prune_system_tool(mock_docker_client)
        result = prune_func()

        assert result["containers_deleted"] == []
        assert result["images_deleted"] == []
        assert result["networks_deleted"] == []
        assert result["volumes_deleted"] == []
        assert result["space_reclaimed"] == 0

    def test_prune_system_api_error(self, mock_docker_client):
        """Test system prune with Docker API error."""
        mock_docker_client.client.api.prune_containers.side_effect = APIError("Prune failed")

        *_, prune_func = create_prune_system_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to prune system"):
            prune_func()

    def test_create_prune_system_tool_metadata(self, mock_docker_client):
        """Test tool metadata is correct."""
        name, description, safety_level, idempotent, open_world, func = create_prune_system_tool(
            mock_docker_client
        )

        assert name == "docker_prune_system"
        assert "Prune all unused Docker resources" in description
        assert safety_level.value == "destructive"
        assert idempotent is False
        assert open_world is False
        assert callable(func)
