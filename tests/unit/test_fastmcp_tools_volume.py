"""Unit tests for fastmcp_tools/volume.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.volume import (
    create_create_volume_tool,
    create_inspect_volume_tool,
    create_list_volumes_tool,
    create_prune_volumes_tool,
    create_remove_volume_tool,
)
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound


class TestListVolumesTool:
    """Test docker_list_volumes tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.volumes = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_list_volumes_success(self, mock_docker_client, safety_config):
        """Test successful volume listing."""
        # Mock volume objects
        vol1 = Mock()
        vol1.name = "volume1"
        vol1.attrs = {
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/volume1/_data",
            "Labels": {"env": "test"},
            "Scope": "local",
        }

        vol2 = Mock()
        vol2.name = "volume2"
        vol2.attrs = {
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/volume2/_data",
            "Labels": {},
            "Scope": "local",
        }

        mock_docker_client.client.volumes.list.return_value = [vol1, vol2]

        # Get the list function
        _, _, _, _, _, list_func = create_list_volumes_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify
        assert result["count"] == 2
        assert len(result["volumes"]) == 2
        assert result["volumes"][0]["name"] == "volume1"
        assert result["volumes"][0]["driver"] == "local"
        assert result["volumes"][0]["labels"] == {"env": "test"}
        assert result["volumes"][1]["name"] == "volume2"

    def test_list_volumes_with_filters(self, mock_docker_client, safety_config):
        """Test volume listing with filters."""
        mock_docker_client.client.volumes.list.return_value = []

        # Get the list function
        _, _, _, _, _, list_func = create_list_volumes_tool(mock_docker_client, safety_config)

        # Execute with filters
        filters = {"dangling": ["true"]}
        result = list_func(filters=filters)

        # Verify filters were passed
        mock_docker_client.client.volumes.list.assert_called_once_with(filters=filters)
        assert result["count"] == 0

    def test_list_volumes_api_error(self, mock_docker_client, safety_config):
        """Test volume listing with API error."""
        mock_docker_client.client.volumes.list.side_effect = APIError("List failed")

        # Get the list function
        _, _, _, _, _, list_func = create_list_volumes_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to list volumes"):
            list_func()


class TestInspectVolumeTool:
    """Test docker_inspect_volume tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.volumes = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_inspect_volume_success(self, mock_docker_client, safety_config):
        """Test successful volume inspection."""
        # Mock volume object
        volume = Mock()
        volume.attrs = {
            "Name": "test-volume",
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/test-volume/_data",
            "CreatedAt": "2024-01-01T00:00:00Z",
            "Labels": {"env": "prod"},
        }

        mock_docker_client.client.volumes.get.return_value = volume

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_volume_tool(mock_docker_client)

        # Execute
        result = inspect_func(volume_name="test-volume")

        # Verify
        assert result["details"]["Name"] == "test-volume"
        assert result["details"]["Driver"] == "local"
        assert result["details"]["Labels"] == {"env": "prod"}
        mock_docker_client.client.volumes.get.assert_called_once_with("test-volume")

    def test_inspect_volume_not_found(self, mock_docker_client, safety_config):
        """Test inspecting non-existent volume."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_volume_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(VolumeNotFound, match="Volume not found"):
            inspect_func(volume_name="nonexistent")

    def test_inspect_volume_api_error(self, mock_docker_client, safety_config):
        """Test volume inspection with API error."""
        mock_docker_client.client.volumes.get.side_effect = APIError("Inspect failed")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_volume_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to inspect volume"):
            inspect_func(volume_name="test-volume")


class TestCreateVolumeTool:
    """Test docker_create_volume tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.volumes = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_create_volume_success(self, mock_docker_client, safety_config):
        """Test successful volume creation."""
        # Mock volume object
        volume = Mock()
        volume.name = "test-volume"
        volume.attrs = {
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/test-volume/_data",
        }

        mock_docker_client.client.volumes.create.return_value = volume

        # Get the create function
        _, _, _, _, _, create_func = create_create_volume_tool(mock_docker_client)

        # Execute
        result = create_func(name="test-volume")

        # Verify
        assert result["name"] == "test-volume"
        assert result["driver"] == "local"
        mock_docker_client.client.volumes.create.assert_called_once()

    def test_create_volume_with_options(self, mock_docker_client, safety_config):
        """Test volume creation with driver options and labels."""
        # Mock volume object
        volume = Mock()
        volume.name = "nfs-volume"
        volume.attrs = {
            "Driver": "nfs",
            "Mountpoint": "/mnt/nfs",
        }

        mock_docker_client.client.volumes.create.return_value = volume

        # Get the create function
        _, _, _, _, _, create_func = create_create_volume_tool(mock_docker_client)

        # Execute with options
        create_func(
            name="nfs-volume",
            driver="nfs",
            driver_opts={"type": "nfs", "device": ":/path"},
            labels={"env": "prod"},
        )

        # Verify options were passed
        call_args = mock_docker_client.client.volumes.create.call_args
        assert call_args.kwargs["name"] == "nfs-volume"
        assert call_args.kwargs["driver"] == "nfs"
        assert call_args.kwargs["driver_opts"] == {"type": "nfs", "device": ":/path"}
        assert call_args.kwargs["labels"] == {"env": "prod"}

    def test_create_volume_auto_name(self, mock_docker_client, safety_config):
        """Test volume creation with auto-generated name."""
        # Mock volume object
        volume = Mock()
        volume.name = "auto-generated-123"
        volume.attrs = {"Driver": "local", "Mountpoint": "/var/lib/docker/volumes/..."}

        mock_docker_client.client.volumes.create.return_value = volume

        # Get the create function
        _, _, _, _, _, create_func = create_create_volume_tool(mock_docker_client)

        # Execute without name
        result = create_func()

        # Verify auto-generated name was used
        assert result["name"] == "auto-generated-123"

    def test_create_volume_api_error(self, mock_docker_client, safety_config):
        """Test volume creation with API error."""
        mock_docker_client.client.volumes.create.side_effect = APIError("Create failed")

        # Get the create function
        _, _, _, _, _, create_func = create_create_volume_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to create volume"):
            create_func(name="test-volume")


class TestRemoveVolumeTool:
    """Test docker_remove_volume tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.volumes = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_remove_volume_success(self, mock_docker_client, safety_config):
        """Test successful volume removal."""
        # Mock volume object
        volume = Mock()
        volume.remove = Mock()

        mock_docker_client.client.volumes.get.return_value = volume

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_volume_tool(mock_docker_client)

        # Execute
        result = remove_func(volume_name="test-volume")

        # Verify
        assert result["volume_name"] == "test-volume"
        mock_docker_client.client.volumes.get.assert_called_once_with("test-volume")
        volume.remove.assert_called_once_with(force=False)

    def test_remove_volume_with_force(self, mock_docker_client, safety_config):
        """Test volume removal with force flag."""
        # Mock volume object
        volume = Mock()
        volume.remove = Mock()

        mock_docker_client.client.volumes.get.return_value = volume

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_volume_tool(mock_docker_client)

        # Execute with force
        remove_func(volume_name="test-volume", force=True)

        # Verify force was used
        volume.remove.assert_called_once_with(force=True)

    def test_remove_volume_not_found(self, mock_docker_client, safety_config):
        """Test removing non-existent volume."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_volume_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(VolumeNotFound, match="Volume not found"):
            remove_func(volume_name="nonexistent")

    def test_remove_volume_api_error(self, mock_docker_client, safety_config):
        """Test volume removal with API error."""
        volume = Mock()
        volume.remove.side_effect = APIError("Remove failed")

        mock_docker_client.client.volumes.get.return_value = volume

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_volume_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to remove volume"):
            remove_func(volume_name="test-volume")


class TestPruneVolumesTool:
    """Test docker_prune_volumes tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.volumes = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_prune_volumes_standard(self, mock_docker_client, safety_config):
        """Test standard volume prune (unused only)."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 5000,
        }

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_volumes_tool(mock_docker_client)

        # Execute standard prune
        result = prune_func(force_all=False)

        # Verify
        assert result["deleted"] == ["volume1", "volume2"]
        assert result["space_reclaimed"] == 5000
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)

    def test_prune_volumes_with_filters(self, mock_docker_client, safety_config):
        """Test volume prune with filters."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": [],
            "SpaceReclaimed": 0,
        }

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_volumes_tool(mock_docker_client)

        # Execute with filters
        filters = {"label": ["env=test"]}
        prune_func(filters=filters, force_all=False)

        # Verify filters were passed
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=filters)

    def test_prune_volumes_api_error(self, mock_docker_client, safety_config):
        """Test volume prune with API error."""
        mock_docker_client.client.volumes.prune.side_effect = APIError("Prune failed")

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_volumes_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to prune volumes"):
            prune_func(force_all=False)
