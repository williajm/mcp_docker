"""Integration tests for FastMCP server implementation.

This module tests the FastMCP server wrapper and integration with the
Docker client, middleware, and feature flag switching.
"""

import pytest

from mcp_docker.config import Config
from mcp_docker.server.server import FastMCPDockerServer


@pytest.fixture
def fastmcp_config() -> Config:
    """Create a test configuration for FastMCP server."""
    config = Config()
    config.safety.allow_moderate_operations = True
    return config


@pytest.mark.integration
def test_fastmcp_server_initialization(fastmcp_config: Config) -> None:
    """Test that FastMCP server initializes successfully."""
    # Create server
    server = FastMCPDockerServer(fastmcp_config)

    # Verify server attributes
    assert server.config == fastmcp_config
    assert server.docker_client is not None
    assert server.app is not None
    assert server.safety_enforcer is not None

    # Verify middleware instances
    assert server.error_handler_middleware is not None
    assert server.safety_middleware is not None


@pytest.mark.integration
def test_fastmcp_server_get_app(fastmcp_config: Config) -> None:
    """Test getting the FastMCP application instance."""
    server = FastMCPDockerServer(fastmcp_config)
    app = server.get_app()

    # Verify we get a FastMCP instance
    assert app is not None
    # FastMCP apps should have these attributes
    assert hasattr(app, "name")
    assert hasattr(app, "version")


@pytest.mark.integration
def test_fastmcp_server_with_read_only_mode(fastmcp_config: Config) -> None:
    """Test FastMCP server with moderate operations disabled."""
    fastmcp_config.safety.allow_moderate_operations = False

    # Create server
    server = FastMCPDockerServer(fastmcp_config)

    # Should still initialize successfully
    assert server.app is not None
    assert server.safety_enforcer is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fastmcp_server_start_stop(fastmcp_config: Config) -> None:
    """Test FastMCP server start and stop lifecycle."""
    server = FastMCPDockerServer(fastmcp_config)

    # Start server (this performs health check)
    try:
        await server.start()
        # If we get here, start succeeded (Docker daemon is available)
        # Now stop the server
        await server.stop()
    except Exception as e:
        # If Docker daemon is not available in test environment, that's OK
        # The test verifies that start/stop methods exist and can be called
        if "Docker daemon" in str(e) or "Cannot connect" in str(e):
            pytest.skip("Docker daemon not available in test environment")
        raise
