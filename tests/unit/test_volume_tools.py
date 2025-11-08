"""Unit tests for volume tools."""

from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.docker_wrapper.client import DockerClientWrapper
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
def mock_docker_client() -> Any:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def mock_volume() -> Any:
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
    async def test_list_volumes_success(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test successful volume listing."""
        mock_docker_client.client.volumes.list.return_value = [mock_volume]

        tool = ListVolumesTool(mock_docker_client, safety_config)
        input_data = ListVolumesInput()
        result = await tool.execute(input_data)

        assert result.count == 1
        assert len(result.volumes) == 1
        assert result.volumes[0]["name"] == "my-volume"
        assert result.volumes[0]["driver"] == "local"
        mock_docker_client.client.volumes.list.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_list_volumes_with_filters(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test listing volumes with filters."""
        mock_docker_client.client.volumes.list.return_value = [mock_volume]

        tool = ListVolumesTool(mock_docker_client, safety_config)
        input_data = ListVolumesInput(filters={"dangling": ["true"]})
        result = await tool.execute(input_data)

        assert result.count == 1
        mock_docker_client.client.volumes.list.assert_called_once_with(
            filters={"dangling": ["true"]}
        )

    @pytest.mark.asyncio
    async def test_list_volumes_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.volumes.list.side_effect = APIError("API error")

        tool = ListVolumesTool(mock_docker_client, safety_config)
        input_data = ListVolumesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestInspectVolumeTool:
    """Tests for InspectVolumeTool."""

    @pytest.mark.asyncio
    async def test_inspect_volume_success(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test successful volume inspection."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = InspectVolumeTool(mock_docker_client, safety_config)
        input_data = InspectVolumeInput(volume_name="my-volume")
        result = await tool.execute(input_data)

        assert result.details["Name"] == "my-volume"
        assert result.details["Driver"] == "local"
        mock_docker_client.client.volumes.get.assert_called_once_with("my-volume")

    @pytest.mark.asyncio
    async def test_inspect_volume_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of volume not found."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        tool = InspectVolumeTool(mock_docker_client, safety_config)
        input_data = InspectVolumeInput(volume_name="nonexistent")

        with pytest.raises(VolumeNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_inspect_volume_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.volumes.get.side_effect = APIError("API error")

        tool = InspectVolumeTool(mock_docker_client, safety_config)
        input_data = InspectVolumeInput(volume_name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestCreateVolumeTool:
    """Tests for CreateVolumeTool."""

    @pytest.mark.asyncio
    async def test_create_volume_success(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test successful volume creation."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client, safety_config)
        input_data = CreateVolumeInput(name="my-volume", driver="local")
        result = await tool.execute(input_data)

        assert result.name == "my-volume"
        assert result.driver == "local"
        mock_docker_client.client.volumes.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_volume_with_options(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test creating volume with additional options."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client, safety_config)
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
    async def test_create_volume_auto_name(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test creating volume with auto-generated name."""
        mock_docker_client.client.volumes.create.return_value = mock_volume

        tool = CreateVolumeTool(mock_docker_client, safety_config)
        input_data = CreateVolumeInput()
        result = await tool.execute(input_data)

        assert result.name == "my-volume"
        call_kwargs = mock_docker_client.client.volumes.create.call_args[1]
        assert "name" not in call_kwargs  # Name not specified, should be auto-generated

    @pytest.mark.asyncio
    async def test_create_volume_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.volumes.create.side_effect = APIError("API error")

        tool = CreateVolumeTool(mock_docker_client, safety_config)
        input_data = CreateVolumeInput(name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestRemoveVolumeTool:
    """Tests for RemoveVolumeTool."""

    @pytest.mark.asyncio
    async def test_remove_volume_success(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test successful volume removal."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = RemoveVolumeTool(mock_docker_client, safety_config)
        input_data = RemoveVolumeInput(volume_name="my-volume")
        result = await tool.execute(input_data)

        assert result.volume_name == "my-volume"
        mock_docker_client.client.volumes.get.assert_called_once_with("my-volume")
        mock_volume.remove.assert_called_once_with(force=False)

    @pytest.mark.asyncio
    async def test_remove_volume_with_force(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test removing volume with force."""
        mock_docker_client.client.volumes.get.return_value = mock_volume

        tool = RemoveVolumeTool(mock_docker_client, safety_config)
        input_data = RemoveVolumeInput(volume_name="my-volume", force=True)
        result = await tool.execute(input_data)

        assert result.volume_name == "my-volume"
        mock_volume.remove.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_remove_volume_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of volume not found."""
        mock_docker_client.client.volumes.get.side_effect = NotFound("Volume not found")

        tool = RemoveVolumeTool(mock_docker_client, safety_config)
        input_data = RemoveVolumeInput(volume_name="nonexistent")

        with pytest.raises(VolumeNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_remove_volume_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_volume: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.volumes.get.return_value = mock_volume
        mock_volume.remove.side_effect = APIError("API error")

        tool = RemoveVolumeTool(mock_docker_client, safety_config)
        input_data = RemoveVolumeInput(volume_name="my-volume")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestPruneVolumesTool:
    """Tests for PruneVolumesTool."""

    @pytest.mark.asyncio
    async def test_prune_volumes_success(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test successful volume pruning (unused only by default)."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 1048576,
        }

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput()
        result = await tool.execute(input_data)

        assert len(result.deleted) == 2
        assert "volume1" in result.deleted
        assert result.space_reclaimed == 1048576
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_prune_volumes_with_filters(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning volumes with filters."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1"],
            "SpaceReclaimed": 524288,
        }

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput(filters={"label": ["env=test"]})
        result = await tool.execute(input_data)

        assert len(result.deleted) == 1
        mock_docker_client.client.volumes.prune.assert_called_once_with(
            filters={"label": ["env=test"]}
        )

    @pytest.mark.asyncio
    async def test_prune_volumes_force_all(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning volumes with force_all=True removes ALL volumes."""
        # Create mock volumes
        mock_volume1 = MagicMock()
        mock_volume1.name = "volume1"

        mock_volume2 = MagicMock()
        mock_volume2.name = "volume2"

        mock_volume3 = MagicMock()
        mock_volume3.name = "volume3"

        mock_docker_client.client.volumes.list.return_value = [
            mock_volume1,
            mock_volume2,
            mock_volume3,
        ]

        # Mock volume get and remove
        def get_volume(name: Any) -> Any:
            if name == "volume1":
                return mock_volume1
            if name == "volume2":
                return mock_volume2
            return mock_volume3

        mock_docker_client.client.volumes.get.side_effect = get_volume

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput(force_all=True)
        result = await tool.execute(input_data)

        # Should remove ALL volumes with force=True
        assert len(result.deleted) == 3
        assert "volume1" in result.deleted
        assert "volume2" in result.deleted
        assert "volume3" in result.deleted
        # Verify force=True was used
        mock_volume1.remove.assert_called_once_with(force=True)
        mock_volume2.remove.assert_called_once_with(force=True)
        mock_volume3.remove.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_prune_volumes_force_all_handles_errors(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning with force_all=True continues on errors."""
        # Create mock volumes
        mock_volume1 = MagicMock()
        mock_volume1.name = "volume1"

        mock_volume2 = MagicMock()
        mock_volume2.name = "volume2"

        mock_docker_client.client.volumes.list.return_value = [mock_volume1, mock_volume2]

        # Mock volume get
        def get_volume(name: Any) -> Any:
            if name == "volume1":
                return mock_volume1
            return mock_volume2

        mock_docker_client.client.volumes.get.side_effect = get_volume

        # First removal fails, second succeeds
        mock_volume1.remove.side_effect = APIError("Volume in use")
        mock_volume2.remove.return_value = None

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput(force_all=True)
        result = await tool.execute(input_data)

        # Should continue despite error and remove the second volume
        assert len(result.deleted) == 1
        assert "volume2" in result.deleted
        assert "volume1" not in result.deleted

    @pytest.mark.asyncio
    async def test_prune_volumes_force_all_ignores_filters(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test that force_all=True ignores filters and removes all volumes."""
        # Create mock volumes
        mock_volume1 = MagicMock()
        mock_volume1.name = "volume1"

        mock_docker_client.client.volumes.list.return_value = [mock_volume1]

        def get_volume(name: Any) -> Any:
            return mock_volume1

        mock_docker_client.client.volumes.get.side_effect = get_volume

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        # Filters should be ignored when force_all=True
        input_data = PruneVolumesInput(force_all=True, filters={"label": ["env=test"]})
        result = await tool.execute(input_data)

        # Should still remove all volumes, ignoring filters
        assert len(result.deleted) == 1
        # Verify volumes.list was called without filters for force_all
        mock_docker_client.client.volumes.list.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_prune_volumes_empty_list(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning when no volumes exist."""
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": None,  # Docker returns None when nothing deleted
            "SpaceReclaimed": 0,
        }

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput()
        result = await tool.execute(input_data)

        assert len(result.deleted) == 0
        assert result.space_reclaimed == 0

    @pytest.mark.asyncio
    async def test_prune_volumes_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.volumes.prune.side_effect = APIError("API error")

        tool = PruneVolumesTool(mock_docker_client, safety_config)
        input_data = PruneVolumesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)
