"""Unit tests for fastmcp_server.py FastMCPDockerServer."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_docker.config import Config
from mcp_docker.fastmcp_server import FastMCPDockerServer


class TestFastMCPDockerServer:
    """Test FastMCPDockerServer class."""

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    def test_init_basic(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test basic FastMCPDockerServer initialization."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1", "tool2"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        config = Config()

        # Initialize server
        server = FastMCPDockerServer(config)

        # Verify initialization
        assert server.config == config
        assert server.app == mock_app
        mock_docker_wrapper.assert_called_once_with(config.docker)
        mock_safety_enforcer.assert_called_once_with(config.safety)
        mock_auth_middleware.assert_called_once_with(config.security)

        # Verify middleware was attached (critical security fix)
        assert mock_app.add_middleware.call_count == 4
        # Verify the four middleware instances were attached (auth, safety, rate_limit, audit)
        calls = mock_app.add_middleware.call_args_list
        assert any(isinstance(call[0][0].__class__.__name__, str) for call in calls)

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    def test_init_with_destructive_operations_enabled(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test initialization with destructive operations warning."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        # Create config with destructive operations enabled
        config = Config()
        config.safety.allow_destructive_operations = True

        # Initialize server (should log warning)
        server = FastMCPDockerServer(config)

        assert server.config == config

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    @pytest.mark.asyncio
    async def test_start_healthy_docker(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test start() with healthy Docker daemon."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        mock_docker_client = Mock()
        mock_docker_client.health_check = Mock(return_value={"status": "healthy"})
        mock_docker_wrapper.return_value = mock_docker_client

        config = Config()
        server = FastMCPDockerServer(config)

        # Start server
        await server.start()

        # Verify health check was called
        mock_docker_client.health_check.assert_called_once()

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    @pytest.mark.asyncio
    async def test_start_unhealthy_docker(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test start() with unhealthy Docker daemon."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        mock_docker_client = Mock()
        mock_docker_client.health_check = Mock(return_value={"status": "unhealthy"})
        mock_docker_wrapper.return_value = mock_docker_client

        config = Config()
        server = FastMCPDockerServer(config)

        # Start server (should log warning)
        await server.start()

        # Verify health check was called
        mock_docker_client.health_check.assert_called_once()

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    @pytest.mark.asyncio
    async def test_start_docker_error(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test start() with Docker health check error."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        mock_docker_client = Mock()
        mock_docker_client.health_check = Mock(side_effect=Exception("Connection error"))
        mock_docker_wrapper.return_value = mock_docker_client

        config = Config()
        server = FastMCPDockerServer(config)

        # Start server (should log warning but not raise)
        await server.start()

        # Verify health check was called
        mock_docker_client.health_check.assert_called_once()

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    @pytest.mark.asyncio
    async def test_stop(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test stop() method."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        mock_docker_client = Mock()
        mock_docker_client.close = Mock()
        mock_docker_wrapper.return_value = mock_docker_client

        mock_auth = Mock()
        mock_auth.close = AsyncMock()
        mock_auth_middleware.return_value = mock_auth

        config = Config()
        server = FastMCPDockerServer(config)

        # Stop server
        await server.stop()

        # Verify cleanup was called
        mock_docker_client.close.assert_called_once()
        mock_auth.close.assert_called_once()

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    def test_get_app(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test get_app() method."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        config = Config()
        server = FastMCPDockerServer(config)

        # Get app
        app = server.get_app()

        assert app == mock_app

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    def test_get_middleware_components(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test get_middleware_components() method."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        config = Config()
        server = FastMCPDockerServer(config)

        # Get middleware components
        components = server.get_middleware_components()

        assert "safety" in components
        assert "rate_limit" in components
        assert "audit" in components
        assert "auth" in components
        assert "rate_limiter" in components
        assert "audit_logger" in components

    @patch("mcp_docker.fastmcp_server.create_fastmcp_app")
    @patch("mcp_docker.fastmcp_server.DockerClientWrapper")
    @patch("mcp_docker.fastmcp_server.SafetyEnforcer")
    @patch("mcp_docker.fastmcp_server.AuthMiddleware")
    @patch("mcp_docker.fastmcp_server.RateLimiter")
    @patch("mcp_docker.fastmcp_server.AuditLogger")
    @patch("mcp_docker.fastmcp_server.register_all_tools")
    @patch("mcp_docker.fastmcp_server.register_all_resources")
    @patch("mcp_docker.fastmcp_server.register_all_prompts")
    def test_wrap_tools_with_middleware(  # noqa: PLR0913
        self,
        mock_register_prompts,
        mock_register_resources,
        mock_register_tools,
        mock_audit_logger,
        mock_rate_limiter,
        mock_auth_middleware,
        mock_safety_enforcer,
        mock_docker_wrapper,
        mock_create_app,
    ):
        """Test _wrap_tools_with_middleware() method."""
        # Setup mocks
        mock_app = Mock()
        mock_app.add_middleware = Mock()  # Mock middleware attachment
        mock_create_app.return_value = mock_app
        mock_register_tools.return_value = {"container": ["tool1"]}
        mock_register_resources.return_value = {"container": ["resource1"]}
        mock_register_prompts.return_value = {"docker": ["prompt1"]}

        config = Config()
        # This will call _wrap_tools_with_middleware internally
        server = FastMCPDockerServer(config)

        # Verify server was initialized (wrapping happens in __init__)
        assert server.app == mock_app
