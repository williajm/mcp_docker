"""Unit tests for volume tools."""

from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.volume_tools import (
    CreateVolumeInput,
    CreateVolumeTool,
    InspectVolumeInput,
    InspectVolumeTool,
    ListVolumesInput,
    ListVolumesTool,
    PruneVolumesInput,
    PruneVolumesTool,
    RemoveVolumeInput,
    RemoveVolumeTool,
)
from mcp_docker.utils.errors import DockerOperationError, VolumeNotFound


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def mock_volume():
    """Create a mock volume."""
    volume = MagicMock()
    volume.name = "my-volume"
    volume.attrs = {
        "Name": "my-volume",
        "Driver": "local",
        "Mountpoint": "/var/lib/docker/volumes/my-volume/_data",
        "Labels": {"env": "test"},
        "Scope": "local",
    }
    return volume


class TestListVolumesTool:
    """Tests for ListVolumesTool."""

    @pytest.mark.asyncio
    async def test_list_volumes_success(self, mock_docker_client, mock_volume):
        """Test successful volume listing."""
        mock_docker_client.client.volumes.list.return_value = [mock_volume]

        tool = ListVolumesTool(mock_docker_client)
        input_data = ListVolumesInput()
        result = await tool.execute(input_data)

        assert result.count == 1
        assert len(result.volumes) == 1
        assert result.volumes[0]["name"] == "my-volume"
        assert result.volumes[0]["driver"] == "local"
        mock_docker_client.client.volumes.list.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_list_volumes_with_filters(self, mock_docker_client, mock_volume):
        """Test listing volumes with filters."""
        mock_docker_client.client.volumes.list.return_value = [mock_volume]

        tool = ListVolumesTool(mock_docker_client)
        input_data = ListVolumesInput(filters={"dangling": ["true"]})
        result = await tool.execute(input_data)

        assert result.count == 1
        mock_docker_client.client.volumes.list.assert_called_once_with(
            filters={"dangling": ["true"]}
        )

    @pytest.mark.asyncio
    async def test_list_volumes_api_error(self, mock_docker_client):
        """Test handling of API errors."""
        mock_docker_client.client.volumes.list.side_effect = APIError("API error")

        tool = ListVolumesTool(mock_docker_client)
        input_data = ListVolumesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestInspectVolumeTool:
    """Tests for InspectVolumeTool."""

    @pytest.mark.asyncio
    async def test_inspect_volume_success(self, mock_docker_client, mock_volume):
        """Test successful volume inspection."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = InspectVolumeTool(mock_docker_client)
        input_data = InspectVolumeInput(volume_name="my-volume")
        result = await tool.execute(input_data)

        assert result.details["Name"] == "my-volume"
        assert result.details["Driver"] == "local"
        mock_docker_client.client.volumes.get.assert_called_once_with("my-volume")

    @pytest.mark.asyncio
    async def test_inspect_volume_not_found(self, mock_docker_client):
        """Test handling of volume not found."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        tool = InspectVolumeTool(mock_docker_client)
        input_data = InspectVolumeInput(volume_name="nonexistent")

        with pytest.raises(VolumeNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_inspect_volume_api_error(self, mock_docker_client):
        """Test handling of API errors."""
        mock_docker_client.client.volumes.get.side_effect = APIError("API error")

        tool = InspectVolumeTool(mock_docker_client)
        input_data = InspectVolumeInput(volume_name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestCreateVolumeTool:
    """Tests for CreateVolumeTool."""

    @pytest.mark.asyncio
    async def test_create_volume_success(self, mock_docker_client, mock_volume):
        """Test successful volume creation."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client)
        input_data = CreateVolumeInput(name="my-volume", driver="local")
        result = await tool.execute(input_data)

        assert result.name == "my-volume"
        assert result.driver == "local"
        mock_docker_client.client.volumes.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_volume_with_options(self, mock_docker_client, mock_volume):
        """Test creating volume with additional options."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client)
        input_data = CreateVolumeInput(
            name="my-volume",
            driver="local",
            driver_opts={"type": "nfs", "device": ":/path/to/dir"},
            labels={"env": "test", "project": "demo"},
        )
        result = await tool.execute(input_data)

        assert result.name == "my-volume"
        call_kwargs = mock_docker_client.client.volumes.create.call_args[1]
        assert call_kwargs["name"] == "my-volume"
        assert call_kwargs["driver_opts"]["type"] == "nfs"
        assert call_kwargs["labels"]["env"] == "test"

    @pytest.mark.asyncio
    async def test_create_volume_auto_name(self, mock_docker_client, mock_volume):
        """Test creating volume with auto-generated name."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client)
        input_data = CreateVolumeInput()
        result = await tool.execute(input_data)

        assert result.name == "my-volume"
        call_kwargs = mock_docker_client.client.volumes.create.call_args[1]
        assert "name" not in call_kwargs  # Name not specified, should be auto-generated

    @pytest.mark.asyncio
    async def test_create_volume_api_error(self, mock_docker_client):
        """Test handling of API errors."""
        mock_docker_client.client.volumes.create.side_effect = APIError("API error")

        tool = CreateVolumeTool(mock_docker_client)
        input_data = CreateVolumeInput(name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestRemoveVolumeTool:
    """Tests for RemoveVolumeTool."""

    @pytest.mark.asyncio
    async def test_remove_volume_success(self, mock_docker_client, mock_volume):
        """Test successful volume removal."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = RemoveVolumeTool(mock_docker_client)
        input_data = RemoveVolumeInput(volume_name="my-volume")
        result = await tool.execute(input_data)

        assert result.volume_name == "my-volume"
        mock_docker_client.client.volumes.get.assert_called_once_with("my-volume")
        mock_volume.remove.assert_called_once_with(force=False)

    @pytest.mark.asyncio
    async def test_remove_volume_with_force(self, mock_docker_client, mock_volume):
        """Test removing volume with force."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = RemoveVolumeTool(mock_docker_client)
        input_data = RemoveVolumeInput(volume_name="my-volume", force=True)
        result = await tool.execute(input_data)

        assert result.volume_name == "my-volume"
        mock_volume.remove.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_remove_volume_not_found(self, mock_docker_client):
        """Test handling of volume not found."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        tool = RemoveVolumeTool(mock_docker_client)
        input_data = RemoveVolumeInput(volume_name="nonexistent")

        with pytest.raises(VolumeNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_remove_volume_api_error(self, mock_docker_client, mock_volume):
        """Test handling of API errors."""
        mock_docker_client.client.volumes.get.return_value = mock_volume
        mock_volume.remove.side_effect = APIError("API error")

        tool = RemoveVolumeTool(mock_docker_client)
        input_data = RemoveVolumeInput(volume_name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestPruneVolumesTool:
    """Tests for PruneVolumesTool."""

    @pytest.mark.asyncio
    async def test_prune_volumes_success(self, mock_docker_client):
        """Test successful volume pruning."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 1048576,
        }

        tool = PruneVolumesTool(mock_docker_client)
        input_data = PruneVolumesInput()
        result = await tool.execute(input_data)

        assert len(result.deleted) == 2
        assert "volume1" in result.deleted
        assert result.space_reclaimed == 1048576
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_prune_volumes_with_filters(self, mock_docker_client):
        """Test pruning volumes with filters."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1"],
            "SpaceReclaimed": 524288,
        }

        tool = PruneVolumesTool(mock_docker_client)
        input_data = PruneVolumesInput(filters={"label": ["env=test"]})
        result = await tool.execute(input_data)

        assert len(result.deleted) == 1
        mock_docker_client.client.volumes.prune.assert_called_once_with(
            filters={"label": ["env=test"]}
        )

    @pytest.mark.asyncio
    async def test_prune_volumes_api_error(self, mock_docker_client):
        """Test handling of API errors."""
        mock_docker_client.client.volumes.prune.side_effect = APIError("API error")

        tool = PruneVolumesTool(mock_docker_client)
        input_data = PruneVolumesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)
