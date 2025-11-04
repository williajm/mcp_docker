"""Unit tests for system tools."""

from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.system_tools import (
    EventsInput,
    EventsTool,
    HealthCheckInput,
    HealthCheckTool,
    SystemDfInput,
    SystemDfTool,
    SystemInfoInput,
    SystemInfoTool,
    SystemPruneInput,
    SystemPruneTool,
    VersionInput,
    VersionTool,
)
from mcp_docker.utils.errors import DockerOperationError


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


class TestSystemInfoTool:
    """Tests for SystemInfoTool."""

    @pytest.mark.asyncio
    async def test_system_info_success(self, mock_docker_client, safety_config):
        """Test successful system info retrieval."""
        system_info = {
            "Containers": 10,
            "ContainersRunning": 3,
            "ContainersPaused": 0,
            "ContainersStopped": 7,
            "Images": 25,
            "Driver": "overlay2",
            "MemTotal": 8589934592,
            "Name": "docker-host",
            "ServerVersion": "20.10.0",
        }
        mock_docker_client.client.info.return_value = system_info

        tool = SystemInfoTool(mock_docker_client, safety_config)
        input_data = SystemInfoInput()
        result = await tool.execute(input_data)

        assert result.info["Containers"] == 10
        assert result.info["Images"] == 25
        mock_docker_client.client.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_system_info_api_error(self, mock_docker_client, safety_config):
        """Test handling of API errors."""
        mock_docker_client.client.info.side_effect = APIError("API error")

        tool = SystemInfoTool(mock_docker_client, safety_config)
        input_data = SystemInfoInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestSystemDfTool:
    """Tests for SystemDfTool."""

    @pytest.mark.asyncio
    async def test_system_df_success(self, mock_docker_client, safety_config):
        """Test successful disk usage retrieval."""
        df_info = {
            "LayersSize": 1073741824,
            "Images": [
                {"Size": 536870912, "SharedSize": 268435456},
                {"Size": 536870912, "SharedSize": 268435456},
            ],
            "Containers": [
                {"SizeRw": 52428800},
                {"SizeRw": 52428800},
            ],
            "Volumes": [
                {"UsageData": {"Size": 104857600}},
                {"UsageData": {"Size": 104857600}},
            ],
            "BuildCache": [
                {"Size": 262144000, "Shared": 131072000},
                {"Size": 262144000, "Shared": 131072000},
            ],
        }
        mock_docker_client.client.df.return_value = df_info

        tool = SystemDfTool(mock_docker_client, safety_config)
        input_data = SystemDfInput()
        result = await tool.execute(input_data)

        assert result.usage["Images"]["total_count"] == 2
        assert result.usage["Containers"]["total_count"] == 2
        assert result.usage["Volumes"]["total_count"] == 2
        assert result.usage["BuildCache"]["total_count"] == 2
        assert result.usage["LayersSize"] == 1073741824
        mock_docker_client.client.df.assert_called_once()

    @pytest.mark.asyncio
    async def test_system_df_api_error(self, mock_docker_client, safety_config):
        """Test handling of API errors."""
        mock_docker_client.client.df.side_effect = APIError("API error")

        tool = SystemDfTool(mock_docker_client, safety_config)
        input_data = SystemDfInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestSystemPruneTool:
    """Tests for SystemPruneTool."""

    @pytest.mark.asyncio
    async def test_system_prune_success(self, mock_docker_client, safety_config):
        """Test successful system prune."""
        mock_docker_client.client.api.prune_containers.return_value = {
            "ContainersDeleted": ["container1", "container2"],
            "SpaceReclaimed": 104857600,
        }
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:abc123"}],
            "SpaceReclaimed": 536870912,
        }
        mock_docker_client.client.api.prune_networks.return_value = {
            "NetworksDeleted": ["network1"],
            "SpaceReclaimed": 0,
        }

        tool = SystemPruneTool(mock_docker_client, safety_config)
        input_data = SystemPruneInput()
        result = await tool.execute(input_data)

        assert len(result.containers_deleted) == 2
        assert len(result.images_deleted) == 1
        assert len(result.networks_deleted) == 1
        assert result.space_reclaimed == 104857600 + 536870912 + 0

    @pytest.mark.asyncio
    async def test_system_prune_with_filters(self, mock_docker_client, safety_config):
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

        tool = SystemPruneTool(mock_docker_client, safety_config)
        input_data = SystemPruneInput(filters={"until": ["24h"]})
        result = await tool.execute(input_data)

        assert result.space_reclaimed == 0
        mock_docker_client.client.api.prune_containers.assert_called_once_with(
            filters={"until": ["24h"]}
        )

    @pytest.mark.asyncio
    async def test_system_prune_with_volumes(self, mock_docker_client, safety_config):
        """Test system prune with volumes enabled."""
        mock_docker_client.client.api.prune_containers.return_value = {
            "ContainersDeleted": ["container1"],
            "SpaceReclaimed": 104857600,
        }
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [],
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.api.prune_networks.return_value = {
            "NetworksDeleted": [],
            "SpaceReclaimed": 0,
        }
        mock_docker_client.client.volumes.prune.return_value = {
            "VolumesDeleted": ["volume1", "volume2"],
            "SpaceReclaimed": 536870912,
        }

        tool = SystemPruneTool(mock_docker_client, safety_config)
        input_data = SystemPruneInput(volumes=True)
        result = await tool.execute(input_data)

        assert len(result.volumes_deleted) == 2
        assert result.space_reclaimed == 104857600 + 536870912
        mock_docker_client.client.volumes.prune.assert_called_once_with(filters=None)

    @pytest.mark.asyncio
    async def test_system_prune_api_error(self, mock_docker_client, safety_config):
        """Test handling of API errors."""
        mock_docker_client.client.api.prune_containers.side_effect = APIError("API error")

        tool = SystemPruneTool(mock_docker_client, safety_config)
        input_data = SystemPruneInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestVersionTool:
    """Tests for VersionTool."""

    @pytest.mark.asyncio
    async def test_version_success(self, mock_docker_client, safety_config):
        """Test successful version retrieval."""
        version_info = {
            "Platform": {"Name": "Docker Engine - Community"},
            "Components": [
                {
                    "Name": "Engine",
                    "Version": "20.10.0",
                    "Details": {
                        "ApiVersion": "1.41",
                        "Arch": "amd64",
                        "BuildTime": "2020-12-01T00:00:00.000000000+00:00",
                        "GitCommit": "abc123",
                        "GoVersion": "go1.16",
                        "KernelVersion": "5.10.0",
                        "Os": "linux",
                    },
                }
            ],
            "Version": "20.10.0",
            "ApiVersion": "1.41",
        }
        mock_docker_client.client.version.return_value = version_info

        tool = VersionTool(mock_docker_client, safety_config)
        input_data = VersionInput()
        result = await tool.execute(input_data)

        assert result.version["Version"] == "20.10.0"
        assert result.version["ApiVersion"] == "1.41"
        mock_docker_client.client.version.assert_called_once()

    @pytest.mark.asyncio
    async def test_version_api_error(self, mock_docker_client, safety_config):
        """Test handling of API errors."""
        mock_docker_client.client.version.side_effect = APIError("API error")

        tool = VersionTool(mock_docker_client, safety_config)
        input_data = VersionInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestEventsTool:
    """Tests for EventsTool."""

    @pytest.mark.asyncio
    async def test_events_success(self, mock_docker_client, safety_config):
        """Test successful events retrieval."""
        events = [
            {"status": "start", "id": "container1", "Type": "container"},
            {"status": "stop", "id": "container2", "Type": "container"},
        ]
        mock_docker_client.client.events.return_value = iter(events)

        tool = EventsTool(mock_docker_client, safety_config)
        input_data = EventsInput()
        result = await tool.execute(input_data)

        assert result.count == 2
        assert len(result.events) == 2
        assert result.events[0]["status"] == "start"

    @pytest.mark.asyncio
    async def test_events_with_filters(self, mock_docker_client, safety_config):
        """Test events with filters."""
        events = [{"status": "start", "id": "container1", "Type": "container"}]
        mock_docker_client.client.events.return_value = iter(events)

        tool = EventsTool(mock_docker_client, safety_config)
        input_data = EventsInput(
            filters={"type": ["container"], "event": ["start"]}, since="2023-01-01"
        )
        result = await tool.execute(input_data)

        assert result.count == 1
        call_kwargs = mock_docker_client.client.events.call_args[1]
        assert call_kwargs["filters"] == {"type": ["container"], "event": ["start"]}
        # Since should be parsed to Unix timestamp
        assert call_kwargs["since"] == 1672531200  # 2023-01-01 00:00:00 UTC
        # Until should be auto-set to prevent blocking when since is provided
        assert "until" in call_kwargs

    @pytest.mark.asyncio
    async def test_events_limit(self, mock_docker_client, safety_config):
        """Test events limited to 100."""
        # Create 150 events
        events = [
            {"status": "start", "id": f"container{i}", "Type": "container"} for i in range(150)
        ]
        mock_docker_client.client.events.return_value = iter(events)

        tool = EventsTool(mock_docker_client, safety_config)
        input_data = EventsInput()
        result = await tool.execute(input_data)

        # Should only return 100 events due to limit
        assert result.count == 100

    @pytest.mark.asyncio
    async def test_events_api_error(self, mock_docker_client, safety_config):
        """Test handling of API errors."""
        mock_docker_client.client.events.side_effect = APIError("API error")

        tool = EventsTool(mock_docker_client, safety_config)
        input_data = EventsInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestHealthCheckTool:
    """Tests for HealthCheckTool."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_docker_client, safety_config):
        """Test successful health check with healthy status."""
        health_status = {
            "status": "healthy",
            "daemon_info": {
                "ServerVersion": "20.10.0",
                "OperatingSystem": "Ubuntu 20.04",
            },
            "containers": {"running": 3, "stopped": 2},
            "images": 10,
        }
        mock_docker_client.health_check.return_value = health_status

        tool = HealthCheckTool(mock_docker_client, safety_config)
        input_data = HealthCheckInput()
        result = await tool.execute(input_data)

        assert result.healthy is True
        assert result.message == "Docker daemon is healthy"
        assert result.details["containers"]["running"] == 3
        assert result.details["images"] == 10

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_docker_client, safety_config):
        """Test health check with unhealthy status."""
        health_status = {
            "status": "unhealthy",
            "daemon_info": {},
            "containers": {},
            "images": 0,
        }
        mock_docker_client.health_check.return_value = health_status

        tool = HealthCheckTool(mock_docker_client, safety_config)
        input_data = HealthCheckInput()
        result = await tool.execute(input_data)

        assert result.healthy is False
        assert result.message == "Docker daemon is unhealthy"

    @pytest.mark.asyncio
    async def test_health_check_exception(self, mock_docker_client, safety_config):
        """Test health check with exception."""
        mock_docker_client.health_check.side_effect = Exception("Connection failed")

        tool = HealthCheckTool(mock_docker_client, safety_config)
        input_data = HealthCheckInput()
        result = await tool.execute(input_data)

        assert result.healthy is False
        assert "Health check failed" in result.message
        assert result.details is None
