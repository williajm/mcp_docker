"""Unit tests for fastmcp_tools/system.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.system import (
    create_events_tool,
    create_prune_system_tool,
    create_version_tool,
)
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
        (
            name,
            description,
            safety_level,
            idempotent,
            open_world,
            supports_task,
            func,
        ) = create_prune_system_tool(mock_docker_client)

        assert name == "docker_prune_system"
        assert "Prune all unused Docker resources" in description
        assert safety_level.value == "destructive"
        assert idempotent is False
        assert open_world is False
        assert callable(func)


class TestVersionTool:
    """Test docker_version tool."""

    def test_version_success(self, mock_docker_client):
        """Test successful version retrieval."""
        mock_docker_client.client.version.return_value = {
            "Version": "24.0.7",
            "ApiVersion": "1.43",
            "Platform": {"Name": "Docker Desktop"},
            "Os": "linux",
            "Arch": "amd64",
            "KernelVersion": "5.15.0-91-generic",
            "Components": [
                {"Name": "Engine", "Version": "24.0.7"},
                {"Name": "containerd", "Version": "1.6.26"},
            ],
        }

        *_, version_func = create_version_tool(mock_docker_client)
        result = version_func()

        assert result["version"] == "24.0.7"
        assert result["api_version"] == "1.43"
        assert result["platform"]["name"] == "Docker Desktop"
        assert result["platform"]["os"] == "linux"
        assert result["platform"]["arch"] == "amd64"
        assert result["platform"]["kernel"] == "5.15.0-91-generic"
        assert len(result["components"]) == 2
        mock_docker_client.client.version.assert_called_once()

    def test_version_partial_data(self, mock_docker_client):
        """Test version with partial/missing data returns defaults."""
        mock_docker_client.client.version.return_value = {
            "Version": "24.0.7",
        }

        *_, version_func = create_version_tool(mock_docker_client)
        result = version_func()

        assert result["version"] == "24.0.7"
        assert result["api_version"] == "unknown"
        assert result["platform"]["name"] == "unknown"
        assert result["platform"]["os"] == "unknown"
        assert result["components"] == []

    def test_version_api_error(self, mock_docker_client):
        """Test version with Docker API error."""
        mock_docker_client.client.version.side_effect = APIError("Connection refused")

        *_, version_func = create_version_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to get Docker version"):
            version_func()

    def test_create_version_tool_metadata(self, mock_docker_client):
        """Test tool metadata is correct."""
        (
            name,
            description,
            safety_level,
            idempotent,
            open_world,
            supports_task,
            func,
        ) = create_version_tool(mock_docker_client)

        assert name == "docker_version"
        assert "Docker version" in description
        assert safety_level.value == "safe"
        assert idempotent is True
        assert open_world is False
        assert callable(func)


class TestEventsTool:
    """Test docker_events tool."""

    def test_events_success(self, mock_docker_client):
        """Test successful events retrieval."""
        mock_events = [
            {"Type": "container", "Action": "start", "time": 1704067200},
            {"Type": "container", "Action": "stop", "time": 1704067260},
        ]
        mock_docker_client.client.events.return_value = iter(mock_events)

        *_, events_func = create_events_tool(mock_docker_client)
        result = events_func(until="2024-01-01T12:00:00", since="2024-01-01T11:00:00")

        assert result["count"] == 2
        assert len(result["events"]) == 2
        assert result["events"][0]["Type"] == "container"
        assert result["events"][0]["Action"] == "start"
        mock_docker_client.client.events.assert_called_once_with(
            since="2024-01-01T11:00:00",
            until="2024-01-01T12:00:00",
            filters=None,
            decode=True,
        )

    def test_events_with_filters(self, mock_docker_client):
        """Test events with filters."""
        mock_events = [{"Type": "container", "Action": "start", "time": 1704067200}]
        mock_docker_client.client.events.return_value = iter(mock_events)

        *_, events_func = create_events_tool(mock_docker_client)
        filters = {"type": "container", "event": ["start", "stop"]}
        result = events_func(until="2024-01-01T12:00:00", filters=filters)

        assert result["count"] == 1
        mock_docker_client.client.events.assert_called_once_with(
            since=None,
            until="2024-01-01T12:00:00",
            filters=filters,
            decode=True,
        )

    def test_events_empty(self, mock_docker_client):
        """Test events with no results."""
        mock_docker_client.client.events.return_value = iter([])

        *_, events_func = create_events_tool(mock_docker_client)
        result = events_func(until="2024-01-01T12:00:00")

        assert result["count"] == 0
        assert result["events"] == []

    def test_events_max_limit(self, mock_docker_client):
        """Test events stops at max limit (1000)."""
        # Create more than 1000 events
        mock_events = [{"Type": "container", "Action": "start", "time": i} for i in range(1500)]
        mock_docker_client.client.events.return_value = iter(mock_events)

        *_, events_func = create_events_tool(mock_docker_client)
        result = events_func(until="2024-01-01T12:00:00")

        assert result["count"] == 1000
        assert len(result["events"]) == 1000

    def test_events_api_error(self, mock_docker_client):
        """Test events with Docker API error."""
        mock_docker_client.client.events.side_effect = APIError("Connection refused")

        *_, events_func = create_events_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to get Docker events"):
            events_func(until="2024-01-01T12:00:00")

    def test_create_events_tool_metadata(self, mock_docker_client):
        """Test tool metadata is correct."""
        (
            name,
            description,
            safety_level,
            idempotent,
            open_world,
            supports_task,
            func,
        ) = create_events_tool(mock_docker_client)

        assert name == "docker_events"
        assert "events" in description.lower()
        assert safety_level.value == "safe"
        assert idempotent is False  # Events change over time
        assert open_world is False
        assert callable(func)
