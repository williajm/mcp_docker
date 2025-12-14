"""FastMCP server implementation for MCP Docker.

This module provides a FastMCP 2.0-based server implementation that wraps
the FastMCP app with middleware and configuration. This is used when the
use_fastmcp feature flag is enabled.
"""

import asyncio

from fastmcp import FastMCP

from mcp_docker.config import Config
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.middleware import (
    AuditMiddleware,
    AuthMiddleware,
    DebugLoggingMiddleware,
    RateLimitMiddleware,
    SafetyMiddleware,
)
from mcp_docker.server.prompts import register_all_prompts
from mcp_docker.server.resources import register_all_resources
from mcp_docker.services.audit import AuditLogger
from mcp_docker.services.rate_limiter import RateLimiter
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.tools import register_all_tools
from mcp_docker.utils.fastmcp_helpers import create_fastmcp_app
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class FastMCPDockerServer:
    """FastMCP 2.0-based MCP server for Docker operations.

    This server wraps a FastMCP application with middleware and configuration,
    providing the same functionality as MCPDockerServer but using FastMCP 2.0.
    """

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

        # Create security components (shared with middleware)
        self.auth_middleware = AuthMiddleware(config.security)
        self.rate_limiter = RateLimiter(
            enabled=config.security.rate_limit_enabled,
            requests_per_minute=config.security.rate_limit_rpm,
            max_concurrent=config.security.rate_limit_concurrent,
        )
        self.audit_logger = AuditLogger(
            audit_log_file=config.security.audit_log_file,
            enabled=config.security.audit_log_enabled,
        )

        # Create middleware instances
        self.debug_middleware = DebugLoggingMiddleware(debug_enabled=config.server.debug_mode)
        self.safety_middleware = SafetyMiddleware(self.safety_enforcer, self.app)
        self.rate_limit_middleware = RateLimitMiddleware(self.rate_limiter)
        self.audit_middleware = AuditMiddleware(self.audit_logger)

        # CRITICAL: Attach middleware to FastMCP app
        # Middleware execution order: first added = outermost wrapper
        # - DebugLoggingMiddleware: OUTERMOST - logs MCP requests/responses at DEBUG level
        # - AuditMiddleware: Logs all requests (including blocked ones) for audit trail
        # - AuthMiddleware: Validates OAuth/IP allowlist before tool execution
        # - SafetyMiddleware: Validates operations against safety policies
        # - RateLimitMiddleware: INNERMOST - prevents abuse via request throttling
        logger.info("Attaching middleware to FastMCP app")
        # NOTE: Middleware classes are protocol-compatible but don't inherit from base class
        self.app.add_middleware(self.debug_middleware)  # type: ignore[arg-type]
        self.app.add_middleware(self.audit_middleware)  # type: ignore[arg-type]
        self.app.add_middleware(self.auth_middleware)  # type: ignore[arg-type]
        self.app.add_middleware(self.safety_middleware)  # type: ignore[arg-type]
        self.app.add_middleware(self.rate_limit_middleware)  # type: ignore[arg-type]
        logger.info("Middleware attached successfully (debug, audit, auth, safety, rate_limit)")

        # Register all tools with middleware integration
        registered_tools = register_all_tools(self.app, self.docker_client, config.safety)
        total_tools = sum(len(tools) for tools in registered_tools.values())

        # Register resources with optional filtering
        allowed_resources = (
            config.safety.allowed_resources
            if isinstance(config.safety.allowed_resources, list)
            else None
        )
        registered_resources = register_all_resources(
            self.app, self.docker_client, allowed_resources
        )
        total_resources = sum(len(resources) for resources in registered_resources.values())

        # Register prompts with optional filtering
        allowed_prompts = (
            config.safety.allowed_prompts
            if isinstance(config.safety.allowed_prompts, list)
            else None
        )
        registered_prompts = register_all_prompts(self.app, self.docker_client, allowed_prompts)
        total_prompts = sum(len(prompts) for prompts in registered_prompts.values())

        logger.info(
            f"Registered {total_tools} tools, {total_resources} resources, "
            f"{total_prompts} prompts across FastMCP"
        )
        logger.info(
            f"Security: rate_limit={config.security.rate_limit_enabled}, "
            f"audit={config.security.audit_log_enabled}"
        )

        # Warn if destructive operations are enabled
        if config.safety.allow_destructive_operations:
            logger.warning(
                "⚠️  Destructive operations ENABLED! "
                "Clients can permanently delete containers, images, volumes, and networks. "
                "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false to disable."
            )

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
        await self.auth_middleware.close()

    def get_app(self) -> FastMCP:
        """Get the underlying FastMCP application.

        Returns:
            FastMCP application instance
        """
        return self.app
