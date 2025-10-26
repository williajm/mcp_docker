"""Unit tests for resource providers."""

from unittest.mock import MagicMock, Mock, patch

import pytest

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.resources.providers import (
    ComposeConfigResource,
    ComposeServiceLogsResource,
    ComposeServicesResource,
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
def mock_compose_client() -> ComposeClient:
    """Create a mock Compose client."""
    return Mock(spec=ComposeClient)


@pytest.fixture
def logs_resource(mock_docker_client: DockerClientWrapper) -> ContainerLogsResource:
    """Create a container logs resource."""
    return ContainerLogsResource(mock_docker_client)


@pytest.fixture
def stats_resource(mock_docker_client: DockerClientWrapper) -> ContainerStatsResource:
    """Create a container stats resource."""
    return ContainerStatsResource(mock_docker_client)


@pytest.fixture
def compose_config_resource(mock_compose_client: ComposeClient) -> ComposeConfigResource:
    """Create a compose config resource."""
    return ComposeConfigResource(mock_compose_client)


@pytest.fixture
def compose_services_resource(mock_compose_client: ComposeClient) -> ComposeServicesResource:
    """Create a compose services resource."""
    return ComposeServicesResource(mock_compose_client)


@pytest.fixture
def compose_logs_resource(mock_compose_client: ComposeClient) -> ComposeServiceLogsResource:
    """Create a compose service logs resource."""
    return ComposeServiceLogsResource(mock_compose_client)


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


class TestComposeConfigResource:
    """Test compose config resource."""

    def test_get_uri(self, compose_config_resource: ComposeConfigResource) -> None:
        """Test getting resource URI."""
        uri = compose_config_resource.get_uri("myproject")
        assert uri == "compose://config/myproject"

    def test_get_metadata(self, compose_config_resource: ComposeConfigResource) -> None:
        """Test getting resource metadata."""
        metadata = compose_config_resource.get_metadata("myproject")
        assert metadata.uri == "compose://config/myproject"
        assert "myproject" in metadata.name
        assert "myproject" in metadata.description
        assert metadata.mime_type == "application/json"

    @pytest.mark.asyncio
    async def test_read_success(
        self, compose_config_resource: ComposeConfigResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose config successfully."""
        mock_compose_client.execute.return_value = {
            "success": True,
            "data": {"version": "3.8", "services": {"web": {"image": "nginx"}}},
        }

        content = await compose_config_resource.read("myproject")

        assert content.uri == "compose://config/myproject"
        assert content.mime_type == "application/json"
        assert "nginx" in content.text
        mock_compose_client.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_failure(
        self, compose_config_resource: ComposeConfigResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose config with failure."""
        mock_compose_client.execute.return_value = {
            "success": False,
            "stderr": "Project not found",
        }

        with pytest.raises(MCPDockerError, match="Failed to get config"):
            await compose_config_resource.read("myproject")

    @pytest.mark.asyncio
    async def test_read_exception(
        self, compose_config_resource: ComposeConfigResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose config with exception."""
        mock_compose_client.execute.side_effect = Exception("Connection error")

        with pytest.raises(MCPDockerError, match="Failed to get compose config"):
            await compose_config_resource.read("myproject")


class TestComposeServicesResource:
    """Test compose services resource."""

    def test_get_uri(self, compose_services_resource: ComposeServicesResource) -> None:
        """Test getting resource URI."""
        uri = compose_services_resource.get_uri("myproject")
        assert uri == "compose://services/myproject"

    def test_get_metadata(self, compose_services_resource: ComposeServicesResource) -> None:
        """Test getting resource metadata."""
        metadata = compose_services_resource.get_metadata("myproject")
        assert metadata.uri == "compose://services/myproject"
        assert "myproject" in metadata.name
        assert metadata.mime_type == "application/json"

    @pytest.mark.asyncio
    async def test_read_success(
        self,
        compose_services_resource: ComposeServicesResource,
        mock_compose_client: ComposeClient,
    ) -> None:
        """Test reading compose services successfully."""
        mock_compose_client.execute.return_value = {
            "success": True,
            "data": [{"Name": "web", "State": "running"}, {"Name": "db", "State": "running"}],
        }

        content = await compose_services_resource.read("myproject")

        assert content.uri == "compose://services/myproject"
        assert content.mime_type == "application/json"
        assert "web" in content.text
        assert "db" in content.text
        mock_compose_client.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_failure(
        self,
        compose_services_resource: ComposeServicesResource,
        mock_compose_client: ComposeClient,
    ) -> None:
        """Test reading compose services with failure."""
        mock_compose_client.execute.return_value = {
            "success": False,
            "stderr": "Project not found",
        }

        with pytest.raises(MCPDockerError, match="Failed to get services"):
            await compose_services_resource.read("myproject")

    @pytest.mark.asyncio
    async def test_read_exception(
        self,
        compose_services_resource: ComposeServicesResource,
        mock_compose_client: ComposeClient,
    ) -> None:
        """Test reading compose services with exception."""
        mock_compose_client.execute.side_effect = Exception("Connection error")

        with pytest.raises(MCPDockerError, match="Failed to get compose services"):
            await compose_services_resource.read("myproject")


class TestComposeServiceLogsResource:
    """Test compose service logs resource."""

    def test_get_uri(self, compose_logs_resource: ComposeServiceLogsResource) -> None:
        """Test getting resource URI."""
        uri = compose_logs_resource.get_uri("myproject", "web")
        assert uri == "compose://logs/myproject/web"

    def test_get_metadata(self, compose_logs_resource: ComposeServiceLogsResource) -> None:
        """Test getting resource metadata."""
        metadata = compose_logs_resource.get_metadata("myproject", "web")
        assert metadata.uri == "compose://logs/myproject/web"
        assert "myproject" in metadata.name
        assert "web" in metadata.name
        assert metadata.mime_type == "text/plain"

    @pytest.mark.asyncio
    async def test_read_success(
        self, compose_logs_resource: ComposeServiceLogsResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose service logs successfully."""
        mock_compose_client.execute.return_value = {
            "success": True,
            "stdout": "log line 1\nlog line 2\n",
        }

        content = await compose_logs_resource.read("myproject", "web")

        assert content.uri == "compose://logs/myproject/web"
        assert content.mime_type == "text/plain"
        assert "log line 1" in content.text
        mock_compose_client.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_with_tail(
        self, compose_logs_resource: ComposeServiceLogsResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose service logs with custom tail."""
        mock_compose_client.execute.return_value = {
            "success": True,
            "stdout": "recent log\n",
        }

        await compose_logs_resource.read("myproject", "web", tail=50)

        # Verify tail was passed in args
        call_args = mock_compose_client.execute.call_args
        assert "--tail" in call_args[1]["args"]
        assert "50" in call_args[1]["args"]

    @pytest.mark.asyncio
    async def test_read_failure(
        self, compose_logs_resource: ComposeServiceLogsResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose service logs with failure."""
        mock_compose_client.execute.return_value = {
            "success": False,
            "stderr": "Service not found",
        }

        with pytest.raises(MCPDockerError, match="Failed to get logs"):
            await compose_logs_resource.read("myproject", "web")

    @pytest.mark.asyncio
    async def test_read_exception(
        self, compose_logs_resource: ComposeServiceLogsResource, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose service logs with exception."""
        mock_compose_client.execute.side_effect = Exception("Connection error")

        with pytest.raises(MCPDockerError, match="Failed to get compose service logs"):
            await compose_logs_resource.read("myproject", "web")


class TestResourceProviderCompose:
    """Test resource provider compose-related methods."""

    @pytest.mark.asyncio
    async def test_read_resource_compose_config(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose config resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        mock_compose_client.execute.return_value = {
            "success": True,
            "data": {"services": {"web": {}}},
        }

        content = await resource_provider.read_resource("compose://config/myproject")

        assert content.uri == "compose://config/myproject"
        assert content.mime_type == "application/json"

    @pytest.mark.asyncio
    async def test_read_resource_compose_services(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose services resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        mock_compose_client.execute.return_value = {
            "success": True,
            "data": [{"Name": "web"}],
        }

        content = await resource_provider.read_resource("compose://services/myproject")

        assert content.uri == "compose://services/myproject"
        assert content.mime_type == "application/json"

    @pytest.mark.asyncio
    async def test_read_resource_compose_logs(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose service logs resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        mock_compose_client.execute.return_value = {
            "success": True,
            "stdout": "service logs",
        }

        content = await resource_provider.read_resource("compose://logs/myproject/web")

        assert content.uri == "compose://logs/myproject/web"
        assert content.text == "service logs"

    @pytest.mark.asyncio
    async def test_read_resource_compose_logs_invalid_uri(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test reading compose logs with invalid URI."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)

        with pytest.raises(ValueError, match="Invalid compose logs URI"):
            await resource_provider.read_resource("compose://logs/myproject")  # Missing service

    def test_get_resource_metadata_compose_config(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test getting metadata for compose config resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        metadata = resource_provider.get_resource_metadata("compose://config/myproject")

        assert metadata.uri == "compose://config/myproject"
        assert metadata.mime_type == "application/json"

    def test_get_resource_metadata_compose_services(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test getting metadata for compose services resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        metadata = resource_provider.get_resource_metadata("compose://services/myproject")

        assert metadata.uri == "compose://services/myproject"
        assert metadata.mime_type == "application/json"

    def test_get_resource_metadata_compose_logs(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test getting metadata for compose service logs resource."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)
        metadata = resource_provider.get_resource_metadata("compose://logs/myproject/web")

        assert metadata.uri == "compose://logs/myproject/web"
        assert metadata.mime_type == "text/plain"

    def test_get_resource_metadata_compose_logs_invalid_uri(
        self, mock_docker_client: DockerClientWrapper, mock_compose_client: ComposeClient
    ) -> None:
        """Test getting metadata for compose logs with invalid URI."""
        resource_provider = ResourceProvider(mock_docker_client, mock_compose_client)

        with pytest.raises(ValueError, match="Invalid compose logs URI"):
            resource_provider.get_resource_metadata("compose://logs/myproject")

    def test_resolve_compose_file_from_query_params(
        self, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test resolving compose file from query parameters."""
        resource_provider = ResourceProvider(mock_docker_client)

        with patch("pathlib.Path.exists", return_value=True):
            compose_file = resource_provider._resolve_compose_file(
                "myproject", {"file": ["/tmp/docker-compose.yml"]}
            )
            assert compose_file == "/tmp/docker-compose.yml"

    def test_resolve_compose_file_from_directory(
        self, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test resolving compose file from compose_files directory."""
        resource_provider = ResourceProvider(mock_docker_client)

        # Mock the file system to simulate finding a compose file
        with patch("pathlib.Path.exists") as mock_exists:
            # First call for compose_dir.exists(), then for exact_match.exists()
            mock_exists.side_effect = [True, True]

            compose_file = resource_provider._resolve_compose_file("myproject", None)

            # Should return the path to user-myproject.yml
            assert compose_file is not None
            assert "user-myproject.yml" in compose_file

    def test_resolve_compose_file_yaml_extension(
        self, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test resolving compose file with .yaml extension."""
        resource_provider = ResourceProvider(mock_docker_client)

        with patch("pathlib.Path.exists") as mock_exists:
            # compose_dir exists, .yml doesn't exist, .yaml exists
            mock_exists.side_effect = [True, False, True]

            compose_file = resource_provider._resolve_compose_file("myproject", None)

            assert compose_file is not None
            assert "user-myproject.yaml" in compose_file

    def test_resolve_compose_file_not_found(
        self, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test resolving compose file when not found."""
        resource_provider = ResourceProvider(mock_docker_client)

        with patch("pathlib.Path.exists", return_value=False):
            compose_file = resource_provider._resolve_compose_file("nonexistent", None)
            assert compose_file is None
