"""Unit tests for fastmcp_tools/volume.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.volume import (
    create_create_volume_tool,
    create_inspect_volume_tool,
    create_list_volumes_tool,
    create_prune_volumes_tool,
    create_remove_volume_tool,
)
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound


# Module-level fixtures to avoid duplication across test classes
@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    client.client.volumes = Mock()
    return client


@pytest.fixture
def safety_config():
    """Create safety config."""
    return SafetyConfig()


class TestVolumeNotFoundErrors:
    """Test volume not found error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,call_kwargs",
        [
            (create_inspect_volume_tool, {"volume_name": "nonexistent"}),
            (create_remove_volume_tool, {"volume_name": "nonexistent"}),
        ],
    )
    def test_volume_not_found(self, mock_docker_client, tool_creator, call_kwargs):
        """Test that VolumeNotFound is raised when volume doesn't exist."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        *_, func = tool_creator(mock_docker_client)

        with pytest.raises(VolumeNotFound, match="Volume not found"):
            func(**call_kwargs)


class TestAPIErrors:
    """Test API error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs,error_match,setup_error_on",
        [
            (create_list_volumes_tool, True, {}, "Failed to list volumes", "volumes.list"),
            (
                create_inspect_volume_tool,
                False,
                {"volume_name": "test"},
                "Failed to inspect volume",
                "volumes.get",
            ),
            (
                create_create_volume_tool,
                False,
                {"name": "test"},
                "Failed to create volume",
                "volumes.create",
            ),
            (
                create_prune_volumes_tool,
                False,
                {"force_all": False},
                "Failed to prune volumes",
                "volumes.prune",
            ),
        ],
    )
    def test_api_error(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        call_kwargs,
        error_match,
        setup_error_on,
    ):
        """Test that DockerOperationError is raised on API errors."""
        method_mapping = {
            "volumes.list": mock_docker_client.client.volumes.list,
            "volumes.get": mock_docker_client.client.volumes.get,
            "volumes.create": mock_docker_client.client.volumes.create,
            "volumes.prune": mock_docker_client.client.volumes.prune,
        }
        method_mapping[setup_error_on].side_effect = APIError("API failed")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(DockerOperationError, match=error_match):
            func(**call_kwargs)

    def test_remove_volume_api_error(self, mock_docker_client):
        """Test volume removal with API error."""
        volume = Mock()
        volume.remove.side_effect = APIError("Remove failed")
        mock_docker_client.client.volumes.get.return_value = volume

        *_, remove_func = create_remove_volume_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to remove volume"):
            remove_func(volume_name="test-volume")


class TestListVolumesTool:
    """Test docker_list_volumes tool."""

    def test_list_volumes_success(self, mock_docker_client, safety_config):
        """Test successful volume listing."""
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

        *_, list_func = create_list_volumes_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 2
        assert len(result["volumes"]) == 2
        assert result["volumes"][0]["name"] == "volume1"
        assert result["volumes"][0]["driver"] == "local"
        assert result["volumes"][0]["labels"] == {"env": "test"}
        assert result["volumes"][1]["name"] == "volume2"

    def test_list_volumes_with_filters(self, mock_docker_client, safety_config):
        """Test volume listing with filters."""
        mock_docker_client.client.volumes.list.return_value = []

        *_, list_func = create_list_volumes_tool(mock_docker_client, safety_config)
        filters = {"dangling": ["true"]}
        result = list_func(filters=filters)

        mock_docker_client.client.volumes.list.assert_called_once_with(filters=filters)
        assert result["count"] == 0


class TestInspectVolumeTool:
    """Test docker_inspect_volume tool."""

    def test_inspect_volume_success(self, mock_docker_client):
        """Test successful volume inspection."""
        volume = Mock()
        volume.attrs = {
            "Name": "test-volume",
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/test-volume/_data",
            "CreatedAt": "2024-01-01T00:00:00Z",
            "Labels": {"env": "prod"},
        }
        mock_docker_client.client.volumes.get.return_value = volume

        *_, inspect_func = create_inspect_volume_tool(mock_docker_client)
        result = inspect_func(volume_name="test-volume")

        assert result["details"]["Name"] == "test-volume"
        assert result["details"]["Driver"] == "local"
        assert result["details"]["Labels"] == {"env": "prod"}
        mock_docker_client.client.volumes.get.assert_called_once_with("test-volume")


class TestCreateVolumeTool:
    """Test docker_create_volume tool."""

    def test_create_volume_success(self, mock_docker_client):
        """Test successful volume creation."""
        volume = Mock()
        volume.name = "test-volume"
        volume.attrs = {
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/test-volume/_data",
        }
        mock_docker_client.client.volumes.create.return_value = volume

        *_, create_func = create_create_volume_tool(mock_docker_client)
        result = create_func(name="test-volume")

        assert result["name"] == "test-volume"
        assert result["driver"] == "local"
        mock_docker_client.client.volumes.create.assert_called_once()

    def test_create_volume_with_options(self, mock_docker_client):
        """Test volume creation with driver options and labels."""
        volume = Mock()
        volume.name = "nfs-volume"
        volume.attrs = {"Driver": "nfs", "Mountpoint": "/mnt/nfs"}
        mock_docker_client.client.volumes.create.return_value = volume

        *_, create_func = create_create_volume_tool(mock_docker_client)
        create_func(
            name="nfs-volume",
            driver="nfs",
            driver_opts={"type": "nfs", "device": ":/path"},
            labels={"env": "prod"},
        )

        call_args = mock_docker_client.client.volumes.create.call_args
        assert call_args.kwargs["name"] == "nfs-volume"
        assert call_args.kwargs["driver"] == "nfs"
        assert call_args.kwargs["driver_opts"] == {"type": "nfs", "device": ":/path"}
        assert call_args.kwargs["labels"] == {"env": "prod"}

    def test_create_volume_auto_name(self, mock_docker_client):
        """Test volume creation with auto-generated name."""
        volume = Mock()
        volume.name = "auto-generated-123"
        volume.attrs = {"Driver": "local", "Mountpoint": "/var/lib/docker/volumes/..."}
        mock_docker_client.client.volumes.create.return_value = volume

        *_, create_func = create_create_volume_tool(mock_docker_client)
        result = create_func()

        assert result["name"] == "auto-generated-123"


class TestRemoveVolumeTool:
    """Test docker_remove_volume tool."""

    @pytest.mark.parametrize(
        "force,expected_force",
        [
            (False, False),
            (True, True),
        ],
    )
    def test_remove_volume(self, mock_docker_client, force, expected_force):
        """Test volume removal with and without force flag."""
        volume = Mock()
        volume.remove = Mock()
        mock_docker_client.client.volumes.get.return_value = volume

        *_, remove_func = create_remove_volume_tool(mock_docker_client)
        result = remove_func(volume_name="test-volume", force=force)

        assert result["volume_name"] == "test-volume"
        mock_docker_client.client.volumes.get.assert_called_once_with("test-volume")
        volume.remove.assert_called_once_with(force=expected_force)


class TestPruneVolumesTool:
    """Test docker_prune_volumes tool."""

    def test_prune_volumes_standard(self, mock_docker_client):
        """Test standard volume prune (unused only)."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 5000,
        }

        *_, prune_func = create_prune_volumes_tool(mock_docker_client)
        result = prune_func(force_all=False)

        assert result["deleted"] == ["volume1", "volume2"]
        assert result["space_reclaimed"] == 5000
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)

    def test_prune_volumes_with_filters(self, mock_docker_client):
        """Test volume prune with filters."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": [],
            "SpaceReclaimed": 0,
        }

        *_, prune_func = create_prune_volumes_tool(mock_docker_client)
        filters = {"label": ["env=test"]}
        prune_func(filters=filters, force_all=False)

        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=filters)

    def test_prune_volumes_force_all(self, mock_docker_client):
        """Test force removing all volumes."""
        volume1 = Mock()
        volume1.name = "test-vol-1"

        volume2 = Mock()
        volume2.name = "test-vol-2"

        mock_docker_client.client.volumes.list.return_value = [volume1, volume2]

        def get_side_effect(name):
            vol = Mock()
            vol.remove = Mock()
            return vol

        mock_docker_client.client.volumes.get.side_effect = get_side_effect

        *_, prune_func = create_prune_volumes_tool(mock_docker_client)
        result = prune_func(force_all=True)

        assert len(result["deleted"]) == 2
        assert "test-vol-1" in result["deleted"]
        assert "test-vol-2" in result["deleted"]
        assert result["space_reclaimed"] == 0
        assert mock_docker_client.client.volumes.get.call_count == 2

    def test_prune_volumes_force_all_with_errors(self, mock_docker_client):
        """Test force removing all volumes with some failures."""
        volume1 = Mock()
        volume1.name = "error-vol"

        volume2 = Mock()
        volume2.name = "success-vol"

        mock_docker_client.client.volumes.list.return_value = [volume1, volume2]

        def get_side_effect(name):
            vol = Mock()
            if name == "error-vol":
                vol.remove.side_effect = APIError("Volume in use")
            else:
                vol.remove = Mock()
            return vol

        mock_docker_client.client.volumes.get.side_effect = get_side_effect

        *_, prune_func = create_prune_volumes_tool(mock_docker_client)
        result = prune_func(force_all=True)

        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == "success-vol"
