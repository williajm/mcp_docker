"""Unit tests for Docker client wrapper."""

from unittest.mock import MagicMock, patch

import pytest
from docker.errors import DockerException

from mcp_docker.config import DockerConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.errors import DockerConnectionError, DockerHealthCheckError


@pytest.fixture
def docker_config() -> DockerConfig:
    """Create a Docker configuration for testing."""
    return DockerConfig(base_url="unix:///var/run/docker.sock", timeout=60)


@pytest.fixture
def mock_docker_client() -> MagicMock:
    """Create a mock Docker client."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.info.return_value = {
        "Name": "test-docker",
        "OperatingSystem": "Linux",
        "Architecture": "x86_64",
        "MemTotal": 8000000000,
        "NCPU": 4,
        "Containers": 5,
        "ContainersRunning": 2,
        "ContainersPaused": 0,
        "ContainersStopped": 3,
        "Images": 10,
    }
    mock.version.return_value = {
        "Version": "24.0.0",
        "ApiVersion": "1.43",
    }
    return mock


class TestDockerClientWrapper:
    """Test Docker client wrapper functionality."""

    def test_initialization(self, docker_config: DockerConfig) -> None:
        """Test Docker client wrapper initialization."""
        wrapper = DockerClientWrapper(docker_config)
        assert wrapper.config == docker_config
        assert wrapper._client is None

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_lazy_connection(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test lazy initialization of Docker client."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        assert wrapper._client is None

        # Access client property to trigger connection
        client = wrapper.client
        assert client is not None
        assert wrapper._client is not None
        mock_docker_class.assert_called_once()
        mock_docker_client.ping.assert_called_once()

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_connection_failure(
        self, mock_docker_class: MagicMock, docker_config: DockerConfig
    ) -> None:
        """Test connection failure handling."""
        mock_docker_class.side_effect = DockerException("Connection failed")

        wrapper = DockerClientWrapper(docker_config)
        with pytest.raises(DockerConnectionError, match="Cannot connect to Docker daemon"):
            _ = wrapper.client

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_health_check_success(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test successful health check."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        health = wrapper.health_check()

        assert health["status"] == "healthy"
        assert health["daemon_info"]["name"] == "test-docker"
        assert health["daemon_info"]["server_version"] == "24.0.0"
        assert health["containers"]["total"] == 5
        assert health["containers"]["running"] == 2

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_health_check_failure(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test health check failure handling."""
        # First ping succeeds for connection, second fails for health check
        mock_docker_client.ping.side_effect = [True, DockerException("Health check failed")]
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        with pytest.raises(DockerHealthCheckError, match="Health check failed"):
            wrapper.health_check()

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_close(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test closing Docker client connection."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        _ = wrapper.client  # Initialize client
        assert wrapper._client is not None

        wrapper.close()
        assert wrapper._client is None
        mock_docker_client.close.assert_called_once()

    def test_close_when_not_connected(self, docker_config: DockerConfig) -> None:
        """Test closing when client is not connected."""
        wrapper = DockerClientWrapper(docker_config)
        wrapper.close()  # Should not raise
        assert wrapper._client is None

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_context_manager(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test using wrapper as context manager."""
        mock_docker_class.return_value = mock_docker_client

        with DockerClientWrapper(docker_config) as wrapper:
            assert isinstance(wrapper, DockerClientWrapper)

        # Client should be closed after exiting context
        assert wrapper._client is None

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_acquire_context_manager(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test acquire context manager for client access."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        with wrapper.acquire() as client:
            assert client is mock_docker_client

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_acquire_handles_docker_exception(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test that acquire properly propagates Docker exceptions."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        with pytest.raises(DockerException), wrapper.acquire():
            raise DockerException("Test error")

    def test_repr(self, docker_config: DockerConfig) -> None:
        """Test string representation."""
        wrapper = DockerClientWrapper(docker_config)
        repr_str = repr(wrapper)
        assert "DockerClientWrapper" in repr_str
        assert "disconnected" in repr_str

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_repr_connected(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test string representation when connected."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        _ = wrapper.client  # Connect
        repr_str = repr(wrapper)
        assert "DockerClientWrapper" in repr_str
        assert "connected" in repr_str

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    @patch("mcp_docker.docker_wrapper.client.docker.tls.TLSConfig")
    def test_tls_connection_with_certs(
        self,
        mock_tls_config: MagicMock,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test TLS connection with client certificates."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            ca_cert = Path(tmpdir) / "ca.pem"
            client_cert = Path(tmpdir) / "cert.pem"
            client_key = Path(tmpdir) / "key.pem"

            ca_cert.touch()
            client_cert.touch()
            client_key.touch()

            docker_config.tls_verify = True
            docker_config.tls_ca_cert = ca_cert
            docker_config.tls_client_cert = client_cert
            docker_config.tls_client_key = client_key

            mock_docker_class.return_value = mock_docker_client

            wrapper = DockerClientWrapper(docker_config)
            _ = wrapper.client

            # Verify TLSConfig was called with certs
            mock_tls_config.assert_called_once()
            call_kwargs = mock_tls_config.call_args[1]
            assert call_kwargs["verify"] is True
            assert call_kwargs["client_cert"] == (str(client_cert), str(client_key))
            assert call_kwargs["ca_cert"] == str(ca_cert)

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_connection_unexpected_error(
        self, mock_docker_class: MagicMock, docker_config: DockerConfig
    ) -> None:
        """Test handling of unexpected errors during connection."""
        mock_docker_class.side_effect = Exception("Unexpected error")

        wrapper = DockerClientWrapper(docker_config)
        with pytest.raises(DockerConnectionError, match="Unexpected error"):
            _ = wrapper.client

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_close_with_error(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test close method when close raises an error."""
        mock_docker_class.return_value = mock_docker_client
        mock_docker_client.close.side_effect = Exception("Close error")

        wrapper = DockerClientWrapper(docker_config)
        _ = wrapper.client  # Connect

        # Should not raise even if close fails
        wrapper.close()
        assert wrapper._client is None

    @patch("mcp_docker.docker_wrapper.client.docker.DockerClient")
    def test_acquire_unexpected_error(
        self,
        mock_docker_class: MagicMock,
        docker_config: DockerConfig,
        mock_docker_client: MagicMock,
    ) -> None:
        """Test that acquire properly propagates unexpected exceptions."""
        mock_docker_class.return_value = mock_docker_client

        wrapper = DockerClientWrapper(docker_config)
        with pytest.raises(Exception, match="Unexpected error"), wrapper.acquire():
            raise Exception("Unexpected error")
