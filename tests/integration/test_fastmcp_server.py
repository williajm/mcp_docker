"""Integration tests for FastMCP server implementation.

This module tests the FastMCP server wrapper and integration with the
Docker client, middleware, and feature flag switching.
"""

import pytest

from mcp_docker.config import Config
from mcp_docker.fastmcp_server import FastMCPDockerServer


@pytest.fixture
def fastmcp_config() -> Config:
    """Create a test configuration for FastMCP server."""
    config = Config()
    config.safety.allow_moderate_operations = True
    config.safety.allow_destructive_operations = True
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
    assert server.rate_limiter is not None
    assert server.audit_logger is not None

    # Verify middleware instances
    assert server.safety_middleware is not None
    assert server.rate_limit_middleware is not None
    assert server.audit_middleware is not None
    assert server.auth_middleware is not None


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
def test_fastmcp_server_middleware_components(fastmcp_config: Config) -> None:
    """Test getting middleware components for transport integration."""
    server = FastMCPDockerServer(fastmcp_config)
    components = server.get_middleware_components()

    # Verify all middleware components are present
    assert "safety" in components
    assert "rate_limit" in components
    assert "audit" in components
    assert "auth" in components
    assert "rate_limiter" in components
    assert "audit_logger" in components

    # Verify components are not None
    for key, value in components.items():
        assert value is not None, f"Component '{key}' should not be None"


@pytest.mark.integration
def test_fastmcp_server_with_safety_disabled(fastmcp_config: Config) -> None:
    """Test FastMCP server with destructive operations disabled."""
    # Disable destructive operations
    fastmcp_config.safety.allow_destructive_operations = False

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


@pytest.mark.integration
def test_fastmcp_server_with_destructive_operations_enabled(
    fastmcp_config: Config,
) -> None:
    """Test that server initializes successfully with destructive operations enabled.

    Note: The server logs a warning when destructive operations are enabled,
    which can be verified in the pytest captured output.
    """
    # Enable destructive operations
    fastmcp_config.safety.allow_destructive_operations = True

    # Create server (should succeed and log warning)
    server = FastMCPDockerServer(fastmcp_config)

    # Verify server initialized successfully
    assert server is not None
    assert server.config.safety.allow_destructive_operations is True
    assert server.app is not None
