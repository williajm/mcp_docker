"""Unit tests for FastMCPDockerServer."""

from unittest.mock import Mock, patch

import pytest

from mcp_docker.config import Config
from mcp_docker.server.server import FastMCPDockerServer


class TestFastMCPDockerServer:
    """Test FastMCPDockerServer class."""

    @patch("mcp_docker.server.server.create_fastmcp_app")
    @patch("mcp_docker.server.server.DockerClientWrapper")
    @patch("mcp_docker.server.server.SafetyEnforcer")
    @patch("mcp_docker.server.server.register_all_tools")
    def test_init_basic(
        self,
        mock_register_tools: Mock,
        mock_safety_enforcer: Mock,
        mock_docker_wrapper: Mock,
        mock_create_app: Mock,
    ) -> None:
        """Test basic FastMCPDockerServer initialization."""
        mock_app = Mock()
        mock_app.add_middleware = Mock()
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1", "tool2"]}

        config = Config()
        server = FastMCPDockerServer(config)

        assert server.config == config
        assert server.app == mock_app
        mock_docker_wrapper.assert_called_once_with(config.docker)
        mock_safety_enforcer.assert_called_once_with(config.safety)
        mock_register_tools.assert_called_once_with(mock_app, server.docker_client, config.safety)
        assert mock_app.add_middleware.call_count == 3

    @patch("mcp_docker.server.server.create_fastmcp_app")
    @patch("mcp_docker.server.server.DockerClientWrapper")
    @patch("mcp_docker.server.server.SafetyEnforcer")
    @patch("mcp_docker.server.server.register_all_tools")
    @pytest.mark.asyncio
    async def test_start_healthy_docker(
        self,
        mock_register_tools: Mock,
        mock_safety_enforcer: Mock,  # noqa: ARG002
        mock_docker_wrapper: Mock,
        mock_create_app: Mock,
    ) -> None:
        """Test start() with healthy Docker daemon."""
        mock_app = Mock()
        mock_app.add_middleware = Mock()
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}

        mock_docker_client = Mock()
        mock_docker_client.health_check = Mock(return_value={"status": "healthy"})
        mock_docker_wrapper.return_value = mock_docker_client

        server = FastMCPDockerServer(Config())
        await server.start()

        mock_docker_client.health_check.assert_called_once()

    @patch("mcp_docker.server.server.create_fastmcp_app")
    @patch("mcp_docker.server.server.DockerClientWrapper")
    @patch("mcp_docker.server.server.SafetyEnforcer")
    @patch("mcp_docker.server.server.register_all_tools")
    @pytest.mark.asyncio
    async def test_start_docker_error(
        self,
        mock_register_tools: Mock,
        mock_safety_enforcer: Mock,  # noqa: ARG002
        mock_docker_wrapper: Mock,
        mock_create_app: Mock,
    ) -> None:
        """Test start() with Docker health check error."""
        mock_app = Mock()
        mock_app.add_middleware = Mock()
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}

        mock_docker_client = Mock()
        mock_docker_client.health_check = Mock(side_effect=Exception("Connection error"))
        mock_docker_wrapper.return_value = mock_docker_client

        server = FastMCPDockerServer(Config())
        await server.start()

        mock_docker_client.health_check.assert_called_once()

    @patch("mcp_docker.server.server.create_fastmcp_app")
    @patch("mcp_docker.server.server.DockerClientWrapper")
    @patch("mcp_docker.server.server.SafetyEnforcer")
    @patch("mcp_docker.server.server.register_all_tools")
    @pytest.mark.asyncio
    async def test_stop_closes_docker_client(
        self,
        mock_register_tools: Mock,
        mock_safety_enforcer: Mock,  # noqa: ARG002
        mock_docker_wrapper: Mock,
        mock_create_app: Mock,
    ) -> None:
        """Test stop() closes Docker client."""
        mock_app = Mock()
        mock_app.add_middleware = Mock()
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}

        mock_docker_client = Mock()
        mock_docker_wrapper.return_value = mock_docker_client

        server = FastMCPDockerServer(Config())
        await server.stop()

        mock_docker_client.close.assert_called_once()

    @patch("mcp_docker.server.server.create_fastmcp_app")
    def test_get_app(self, mock_create_app: Mock) -> None:
        """Test get_app() returns FastMCP app."""
        mock_app = Mock()
        mock_app.add_middleware = Mock()
        mock_create_app.return_value = mock_app

        with (
            patch("mcp_docker.server.server.DockerClientWrapper"),
            patch("mcp_docker.server.server.SafetyEnforcer"),
            patch("mcp_docker.server.server.register_all_tools", return_value={"container": []}),
        ):
            server = FastMCPDockerServer(Config())

        assert server.get_app() == mock_app
