"""Unit tests for resource providers."""

from unittest.mock import MagicMock, Mock

import pytest

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.resources.providers import (
    ContainerLogsResource,
    ContainerStatsResource,
    ResourceProvider,
)
from mcp_docker.utils.errors import ContainerNotFound, MCPDockerError


@pytest.fixture
def mock_docker_client() -> DockerClientWrapper:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def logs_resource(mock_docker_client: DockerClientWrapper) -> ContainerLogsResource:
    """Create a container logs resource."""
    return ContainerLogsResource(mock_docker_client)


@pytest.fixture
def stats_resource(mock_docker_client: DockerClientWrapper) -> ContainerStatsResource:
    """Create a container stats resource."""
    return ContainerStatsResource(mock_docker_client)


@pytest.fixture
def resource_provider(mock_docker_client: DockerClientWrapper) -> ResourceProvider:
    """Create a resource provider."""
    return ResourceProvider(mock_docker_client)


class TestContainerLogsResource:
    """Test container logs resource."""

    def test_get_uri(self, logs_resource: ContainerLogsResource) -> None:
        """Test getting resource URI."""
        uri = logs_resource.get_uri("abc123")
        assert uri == "container://logs/abc123"

    def test_get_metadata(self, logs_resource: ContainerLogsResource) -> None:
        """Test getting resource metadata."""
        metadata = logs_resource.get_metadata("abc123")
        assert metadata.uri == "container://logs/abc123"
        assert "abc123" in metadata.name
        assert "abc123" in metadata.description
        assert metadata.mime_type == "text/plain"

    @pytest.mark.asyncio
    async def test_read_logs_success(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading container logs successfully."""
        # Mock container
        mock_container = MagicMock()
        mock_container.logs.return_value = b"log line 1\nlog line 2\n"
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read logs
        content = await logs_resource.read("abc123")

        assert content.uri == "container://logs/abc123"
        assert content.mime_type == "text/plain"
        assert content.text == "log line 1\nlog line 2\n"
        assert content.blob is None

        # Verify calls
        mock_docker_client.client.containers.get.assert_called_once_with("abc123")
        mock_container.logs.assert_called_once_with(tail=100, follow=False)

    @pytest.mark.asyncio
    async def test_read_logs_with_tail(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading container logs with custom tail."""
        # Mock container
        mock_container = MagicMock()
        mock_container.logs.return_value = b"recent log\n"
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read logs with custom tail
        await logs_resource.read("abc123", tail=10)

        mock_container.logs.assert_called_once_with(tail=10, follow=False)

    @pytest.mark.asyncio
    async def test_read_logs_container_not_found(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading logs for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = Exception("404")

        with pytest.raises(ContainerNotFound, match="Container not found"):
            await logs_resource.read("nonexistent")

    @pytest.mark.asyncio
    async def test_read_logs_other_error(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading logs with other error."""
        mock_docker_client.client.containers.get.side_effect = Exception("Connection error")

        with pytest.raises(MCPDockerError, match="Failed to get container logs"):
            await logs_resource.read("abc123")

    @pytest.mark.asyncio
    async def test_read_logs_with_follow(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading container logs with follow mode (generator)."""
        # Mock container with generator logs
        mock_container = MagicMock()
        # Simulate generator returning log lines
        mock_container.logs.return_value = iter([b"line 1\n", b"line 2\n", b"line 3\n"])
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read logs with follow mode
        content = await logs_resource.read("abc123", follow=True)

        assert content.uri == "container://logs/abc123"
        assert content.mime_type == "text/plain"
        assert content.text == "line 1\nline 2\nline 3\n"

        # Verify calls
        mock_docker_client.client.containers.get.assert_called_once_with("abc123")
        mock_container.logs.assert_called_once_with(tail=100, follow=True)

    @pytest.mark.asyncio
    async def test_read_logs_with_follow_string_items(
        self, logs_resource: ContainerLogsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading container logs with follow mode returning string items."""
        # Mock container with generator logs as strings
        mock_container = MagicMock()
        # Simulate generator returning string items (non-bytes)
        mock_container.logs.return_value = iter(["string line 1\n", "string line 2\n"])
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read logs with follow mode
        content = await logs_resource.read("abc123", follow=True)

        assert content.text == "string line 1\nstring line 2\n"


class TestContainerStatsResource:
    """Test container stats resource."""

    def test_get_uri(self, stats_resource: ContainerStatsResource) -> None:
        """Test getting resource URI."""
        uri = stats_resource.get_uri("abc123")
        assert uri == "container://stats/abc123"

    def test_get_metadata(self, stats_resource: ContainerStatsResource) -> None:
        """Test getting resource metadata."""
        metadata = stats_resource.get_metadata("abc123")
        assert metadata.uri == "container://stats/abc123"
        assert "abc123" in metadata.name
        assert "abc123" in metadata.description
        assert metadata.mime_type == "application/json"

    @pytest.mark.asyncio
    async def test_read_stats_success(
        self, stats_resource: ContainerStatsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading container stats successfully."""
        # Mock container with stats
        mock_container = MagicMock()
        mock_container.stats.return_value = {
            "cpu_stats": {
                "cpu_usage": {"total_usage": 100000},
                "system_cpu_usage": 1000000,
                "online_cpus": 4,
            },
            "memory_stats": {"usage": 104857600, "limit": 2147483648},  # 100 MB  # 2 GB
            "networks": {
                "eth0": {"rx_bytes": 1024000, "tx_bytes": 2048000}  # 1000 KB  # 2000 KB
            },
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read stats
        content = await stats_resource.read("abc123")

        assert content.uri == "container://stats/abc123"
        assert content.mime_type == "text/plain"
        assert content.text is not None
        assert "abc123" in content.text
        assert "CPU:" in content.text
        assert "Memory:" in content.text
        assert "Network:" in content.text

        # Verify calls
        mock_docker_client.client.containers.get.assert_called_once_with("abc123")
        mock_container.stats.assert_called_once_with(stream=False)

    @pytest.mark.asyncio
    async def test_read_stats_container_not_found(
        self, stats_resource: ContainerStatsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading stats for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = Exception("404")

        with pytest.raises(ContainerNotFound, match="Container not found"):
            await stats_resource.read("nonexistent")

    @pytest.mark.asyncio
    async def test_read_stats_other_error(
        self, stats_resource: ContainerStatsResource, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading stats with other error."""
        mock_docker_client.client.containers.get.side_effect = Exception("Connection error")

        with pytest.raises(MCPDockerError, match="Failed to get container stats"):
            await stats_resource.read("abc123")


class TestResourceProvider:
    """Test resource provider."""

    def test_initialization(self, resource_provider: ResourceProvider) -> None:
        """Test resource provider initialization."""
        assert resource_provider.logs_resource is not None
        assert resource_provider.stats_resource is not None

    def test_list_resources_success(
        self, resource_provider: ResourceProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test listing resources successfully."""
        # Mock containers
        mock_running = MagicMock()
        mock_running.short_id = "abc123"
        mock_running.status = "running"

        mock_stopped = MagicMock()
        mock_stopped.short_id = "def456"
        mock_stopped.status = "exited"

        mock_docker_client.client.containers.list.return_value = [mock_running, mock_stopped]

        # List resources
        resources = resource_provider.list_resources()

        # Should have:
        # - Logs for running container
        # - Stats for running container
        # - Logs for stopped container
        # Total: 3 resources
        assert len(resources) == 3

        uris = [r.uri for r in resources]
        assert "container://logs/abc123" in uris
        assert "container://stats/abc123" in uris
        assert "container://logs/def456" in uris
        assert "container://stats/def456" not in uris  # Stats only for running

    def test_list_resources_error(
        self, resource_provider: ResourceProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test listing resources with error."""
        mock_docker_client.client.containers.list.side_effect = Exception("Connection error")

        # Should return empty list on error
        resources = resource_provider.list_resources()
        assert resources == []

    @pytest.mark.asyncio
    async def test_read_resource_logs(
        self, resource_provider: ResourceProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading logs resource."""
        # Mock container
        mock_container = MagicMock()
        mock_container.logs.return_value = b"log content\n"
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read logs resource
        content = await resource_provider.read_resource("container://logs/abc123")

        assert content.uri == "container://logs/abc123"
        assert content.text == "log content\n"

    @pytest.mark.asyncio
    async def test_read_resource_stats(
        self, resource_provider: ResourceProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test reading stats resource."""
        # Mock container
        mock_container = MagicMock()
        mock_container.stats.return_value = {
            "cpu_stats": {"cpu_usage": {"total_usage": 100000}, "online_cpus": 2},
            "memory_stats": {"usage": 1048576, "limit": 10485760},
            "networks": {},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Read stats resource
        content = await resource_provider.read_resource("container://stats/abc123")

        assert content.uri == "container://stats/abc123"
        assert content.text is not None

    @pytest.mark.asyncio
    async def test_read_resource_unknown_scheme(self, resource_provider: ResourceProvider) -> None:
        """Test reading resource with unknown scheme."""
        with pytest.raises(ValueError, match="Unknown resource URI scheme"):
            await resource_provider.read_resource("unknown://resource")

    def test_get_resource_metadata_logs(self, resource_provider: ResourceProvider) -> None:
        """Test getting metadata for logs resource."""
        metadata = resource_provider.get_resource_metadata("container://logs/abc123")
        assert metadata.uri == "container://logs/abc123"
        assert metadata.mime_type == "text/plain"

    def test_get_resource_metadata_stats(self, resource_provider: ResourceProvider) -> None:
        """Test getting metadata for stats resource."""
        metadata = resource_provider.get_resource_metadata("container://stats/abc123")
        assert metadata.uri == "container://stats/abc123"
        assert metadata.mime_type == "application/json"

    def test_get_resource_metadata_unknown_scheme(
        self, resource_provider: ResourceProvider
    ) -> None:
        """Test getting metadata for unknown resource scheme."""
        with pytest.raises(ValueError, match="Unknown resource URI scheme"):
            resource_provider.get_resource_metadata("unknown://resource")


class TestBaseResourceHelper:
    """Tests for BaseResourceHelper class."""

    def test_fetch_container_blocking(self, mock_docker_client: DockerClientWrapper) -> None:
        """Test fetching container object."""
        from mcp_docker.resources.base import BaseResourceHelper

        # Setup mock container
        mock_container = MagicMock()
        mock_container.id = "test123"
        mock_docker_client.client.containers.get.return_value = mock_container

        # Create helper and fetch container
        helper = BaseResourceHelper(mock_docker_client)
        result = helper._fetch_container_blocking("test123")

        # Verify
        assert result == mock_container
        mock_docker_client.client.containers.get.assert_called_once_with("test123")
