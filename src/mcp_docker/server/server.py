"""FastMCP server implementation for the local MCP Docker package."""

import asyncio

from fastmcp import FastMCP
from fastmcp.server.middleware.response_limiting import ResponseLimitingMiddleware

from mcp_docker.config import Config
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.middleware import ErrorHandlerMiddleware, SafetyMiddleware
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.tools import register_all_tools
from mcp_docker.utils.fastmcp_helpers import create_fastmcp_app
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class FastMCPDockerServer:
    """Local FastMCP server for Docker operations."""

    def __init__(self, config: Config) -> None:
        """Initialize the FastMCP Docker server.

        Args:
            config: Server configuration
        """
        self.config = config
        self.docker_client = DockerClientWrapper(config.docker)

        logger.info("Initializing FastMCP Docker server")

        # Create FastMCP app
        self.app = create_fastmcp_app(name="mcp-docker")

        # Create safety enforcer
        self.safety_enforcer = SafetyEnforcer(config.safety)

        # Create middleware instances
        self.error_handler_middleware = ErrorHandlerMiddleware(debug_mode=config.server.debug_mode)
        self.safety_middleware = SafetyMiddleware(self.safety_enforcer, self.app)

        # Response limiting middleware (global safety net for oversized tool responses)
        if config.safety.max_response_bytes > 0:
            self.response_limiting_middleware: ResponseLimitingMiddleware | None = (
                ResponseLimitingMiddleware(max_size=config.safety.max_response_bytes)
            )
        else:
            self.response_limiting_middleware = None

        # Middleware execution order: first added = outermost wrapper
        # - ErrorHandlerMiddleware: Sanitizes errors before client sees them (when debug_mode=False)
        # - SafetyMiddleware: Validates operations against safety policies
        # - ResponseLimitingMiddleware: INNERMOST - truncates oversized tool responses
        logger.info("Attaching middleware to FastMCP app")
        # NOTE: Middleware classes are protocol-compatible but don't inherit from base class
        self.app.add_middleware(self.error_handler_middleware)  # type: ignore[arg-type]
        self.app.add_middleware(self.safety_middleware)  # type: ignore[arg-type]
        if self.response_limiting_middleware is not None:
            self.app.add_middleware(self.response_limiting_middleware)
        logger.info("Middleware attached successfully (error_handler, safety, response_limiting)")

        # Register all tools with middleware integration
        registered_tools = register_all_tools(self.app, self.docker_client, config.safety)
        total_tools = sum(len(tools) for tools in registered_tools.values())

        logger.info(f"Registered {total_tools} tools across FastMCP")

    async def start(self) -> None:
        """Start the FastMCP server."""
        logger.info("Starting FastMCP Docker server")

        # Check Docker daemon health
        try:
            health_status = await asyncio.to_thread(self.docker_client.health_check)
            status = health_status.get("status", "unknown")
            if status == "healthy":
                logger.info("Docker daemon is healthy")
            else:
                logger.warning(f"Docker daemon health check failed: {status}")
        except Exception as e:
            logger.warning(f"Docker daemon health check failed: {e}")

    async def stop(self) -> None:
        """Stop the FastMCP server and cleanup resources."""
        logger.info("Stopping FastMCP Docker server")
        await asyncio.to_thread(self.docker_client.close)

    def get_app(self) -> FastMCP:
        """Get the underlying FastMCP application.

        Returns:
            FastMCP application instance
        """
        return self.app
