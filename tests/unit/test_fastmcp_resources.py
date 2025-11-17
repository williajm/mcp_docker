"""Unit tests for FastMCP resources."""

from unittest.mock import Mock

import pytest

from mcp_docker.fastmcp_resources import (
    create_container_logs_resource,
    create_container_stats_resource,
    register_all_resources,
)
from mcp_docker.utils.errors import ContainerNotFound, MCPDockerError


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock()
    client.client = Mock()
    return client


@pytest.fixture
def mock_container():
    """Create a mock Docker container."""
    container = Mock()
    container.logs = Mock(return_value=b"Container log line 1\nContainer log line 2\n")
    container.stats = Mock(
        return_value={
            "cpu_stats": {
                "cpu_usage": {"total_usage": 1000000},
                "system_cpu_usage": 10000000,
                "online_cpus": 4,
            },
            "precpu_stats": {
                "cpu_usage": {"total_usage": 900000},
                "system_cpu_usage": 9500000,
            },
            "memory_stats": {
                "usage": 134217728,  # 128 MB
                "limit": 536870912,  # 512 MB
            },
            "networks": {
                "eth0": {
                    "rx_bytes": 1024,
                    "tx_bytes": 2048,
                }
            },
            "blkio_stats": {"io_service_bytes_recursive": []},
        }
    )
    return container


class TestCreateContainerLogsResource:
    """Test create_container_logs_resource."""

    def test_creates_resource_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        uri, func = create_container_logs_resource(mock_docker_client)

        assert uri == "container://logs/{container_id}"
        assert callable(func)

    @pytest.mark.asyncio
    async def test_get_logs_success(self, mock_docker_client, mock_container):
        """Test successful log retrieval."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, logs_func = create_container_logs_resource(mock_docker_client)

        result = await logs_func("test-container")

        assert isinstance(result, str)
        assert "Container log line 1" in result
        assert "Container log line 2" in result
        mock_docker_client.client.containers.get.assert_called_once_with("test-container")

    @pytest.mark.asyncio
    async def test_get_logs_container_not_found(self, mock_docker_client):
        """Test log retrieval when container doesn't exist."""
        error = Exception("404 Client Error: Not Found")
        mock_docker_client.client.containers.get = Mock(side_effect=error)

        _, logs_func = create_container_logs_resource(mock_docker_client)

        with pytest.raises(ContainerNotFound):
            await logs_func("nonexistent")

    @pytest.mark.asyncio
    async def test_get_logs_other_error(self, mock_docker_client):
        """Test log retrieval with unexpected error."""
        error = RuntimeError("Unexpected error")
        mock_docker_client.client.containers.get = Mock(side_effect=error)

        _, logs_func = create_container_logs_resource(mock_docker_client)

        with pytest.raises(MCPDockerError, match="Failed to get container logs"):
            await logs_func("test-container")

    @pytest.mark.asyncio
    async def test_get_logs_handles_generator(self, mock_docker_client):
        """Test log retrieval when logs() returns a generator."""
        mock_container = Mock()
        # Return a generator instead of bytes
        mock_container.logs = Mock(return_value=iter([b"line1\n", b"line2\n"]))
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, logs_func = create_container_logs_resource(mock_docker_client)

        result = await logs_func("test-container")

        assert isinstance(result, str)
        assert "line1" in result
        assert "line2" in result


class TestCreateContainerStatsResource:
    """Test create_container_stats_resource."""

    def test_creates_resource_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        uri, func = create_container_stats_resource(mock_docker_client)

        assert uri == "container://stats/{container_id}"
        assert callable(func)

    @pytest.mark.asyncio
    async def test_get_stats_success(self, mock_docker_client, mock_container):
        """Test successful stats retrieval."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, stats_func = create_container_stats_resource(mock_docker_client)

        result = await stats_func("test-container")

        assert isinstance(result, str)
        assert "Container Statistics" in result
        assert "test-container" in result
        assert "CPU:" in result
        assert "Memory:" in result
        assert "Network:" in result
        mock_docker_client.client.containers.get.assert_called_once_with("test-container")

    @pytest.mark.asyncio
    async def test_get_stats_container_not_found(self, mock_docker_client):
        """Test stats retrieval when container doesn't exist."""
        error = Exception("404 Client Error: Not Found")
        mock_docker_client.client.containers.get = Mock(side_effect=error)

        _, stats_func = create_container_stats_resource(mock_docker_client)

        with pytest.raises(ContainerNotFound):
            await stats_func("nonexistent")

    @pytest.mark.asyncio
    async def test_get_stats_other_error(self, mock_docker_client):
        """Test stats retrieval with unexpected error."""
        error = RuntimeError("Unexpected error")
        mock_docker_client.client.containers.get = Mock(side_effect=error)

        _, stats_func = create_container_stats_resource(mock_docker_client)

        with pytest.raises(MCPDockerError, match="Failed to get container stats"):
            await stats_func("test-container")


class TestRegisterAllResources:
    """Test register_all_resources."""

    def test_registers_all_resources(self, mock_docker_client):
        """Test that all resources are registered."""
        app = Mock()
        app.resource = Mock(return_value=lambda f: f)  # Mock decorator

        registered = register_all_resources(app, mock_docker_client)

        assert "container" in registered
        assert len(registered["container"]) == 2
        assert "container://logs/{container_id}" in registered["container"]
        assert "container://stats/{container_id}" in registered["container"]

        # Verify app.resource was called twice
        assert app.resource.call_count == 2
