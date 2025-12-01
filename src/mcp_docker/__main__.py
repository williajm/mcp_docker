"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server with FastMCP 2.0.
"""

import asyncio
import os
from enum import Enum
from pathlib import Path
from typing import Any

import typer

from mcp_docker.config import Config
from mcp_docker.server import FastMCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger
from mcp_docker.version import __version__


class Transport(str, Enum):
    """Supported transport types."""

    stdio = "stdio"
    http = "http"


# Logging Constants
SHUTDOWN_COMPLETE_MSG = "MCP server shutdown complete"


def run_stdio(
    logger: Any,
    fastmcp_docker_server: FastMCPDockerServer,
    fastmcp_app: Any,
) -> None:
    """Run the MCP server with stdio transport."""
    logger.info("Starting FastMCP server with stdio transport")

    # FastMCP's run() is synchronous and handles async internally
    # We need to run initialization in an async context first
    async def _startup() -> None:
        await fastmcp_docker_server.start()

    async def _shutdown() -> None:
        await fastmcp_docker_server.stop()
        logger.info(SHUTDOWN_COMPLETE_MSG)

    # Run startup
    asyncio.run(_startup())

    try:
        # Run FastMCP with stdio transport (synchronous call)
        fastmcp_app.run(transport="stdio")
    finally:
        # Run shutdown
        asyncio.run(_shutdown())


def run_http(  # noqa: PLR0913
    host: str,
    port: int,
    config: Config,
    logger: Any,
    fastmcp_docker_server: FastMCPDockerServer,
    fastmcp_app: Any,
) -> None:
    """Run the MCP server with HTTP transport.

    Note: FastMCP's HTTP transport runs plain HTTP. For HTTPS in production,
    use a reverse proxy (NGINX, Caddy, etc.) for TLS termination.

    Args:
        host: Host to bind the server to
        port: Port to bind the server to
        config: Server configuration
        logger: Logger instance
        fastmcp_docker_server: FastMCP Docker server instance
        fastmcp_app: FastMCP application instance
    """
    logger.info(f"Starting FastMCP server with HTTP transport on http://{host}:{port}")

    # Log security warnings for non-localhost deployments
    is_localhost = host in ["127.0.0.1", "localhost", "::1"]
    if not is_localhost:
        logger.warning(
            "═════════════════════════════════════════════════════════════\n"
            "⚠️  SECURITY WARNING ⚠️\n"
            "Running HTTP server on a non-localhost address!\n"
            "Traffic will be transmitted in PLAINTEXT over the network.\n"
            "\n"
            "For production deployments:\n"
            "  1. Use a reverse proxy (NGINX, Caddy) for HTTPS/TLS\n"
            "  2. Configure authentication (OAuth or IP allowlist)\n"
            "  3. Enable rate limiting and audit logging\n"
            "\n"
            "Example NGINX config:\n"
            "  server {\n"
            "    listen 443 ssl;\n"
            "    ssl_certificate /path/to/cert.pem;\n"
            "    ssl_certificate_key /path/to/key.pem;\n"
            "    location / {\n"
            "      proxy_pass http://127.0.0.1:8000;\n"
            "    }\n"
            "  }\n"
            "═════════════════════════════════════════════════════════════"
        )

    if not config.security.allowed_client_ips and not is_localhost:
        logger.warning(
            "⚠️  IP allowlist is NOT configured!\n"
            "Anyone who can reach this server can execute Docker commands.\n"
            'Set SECURITY_ALLOWED_CLIENT_IPS=["127.0.0.1", "192.168.1.100"]\n'
            "Or bind to localhost only: --host 127.0.0.1"
        )

    # FastMCP's run() is synchronous and handles async internally
    # We need to run initialization in an async context first
    async def _startup() -> None:
        await fastmcp_docker_server.start()

    async def _shutdown() -> None:
        await fastmcp_docker_server.stop()
        logger.info(SHUTDOWN_COMPLETE_MSG)

    # Run startup
    asyncio.run(_startup())

    try:
        # Run FastMCP with HTTP transport (synchronous call)
        # FastMCP 2.0 native HTTP support (plain HTTP, use reverse proxy for HTTPS)
        fastmcp_app.run(
            transport="http",
            host=host,
            port=port,
        )
    finally:
        # Run shutdown
        asyncio.run(_shutdown())


app = typer.Typer(
    name="mcp-docker",
    help="MCP Docker Server (FastMCP 2.0)",
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"mcp-docker {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(  # noqa: B008
    transport: Transport = typer.Option(
        Transport.stdio,
        "--transport",
        help="Transport type",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host to bind server",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port to bind server",
    ),
    version: bool = typer.Option(  # noqa: ARG001
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Run the MCP Docker server with the specified transport."""
    # Load configuration
    config = Config()

    # Setup logging to file
    # Use env var if set, otherwise default to current working directory
    log_path = os.getenv("MCP_DOCKER_LOG_PATH")
    log_file = Path(log_path) if log_path else Path("mcp_docker.log")
    setup_logger(config.server, log_file)

    logger = get_logger(__name__)
    logger.info("=" * 60)
    logger.info(f"MCP Docker Server v{__version__} (FastMCP 2.0)")
    logger.info("=" * 60)
    logger.info(f"Configuration: {config}")

    # Initialize FastMCP server
    logger.info("Initializing FastMCP 2.0 server")
    fastmcp_docker_server = FastMCPDockerServer(config)
    fastmcp_app = fastmcp_docker_server.get_app()
    logger.info("FastMCP Docker server initialized")

    try:
        if transport == Transport.stdio:
            run_stdio(logger, fastmcp_docker_server, fastmcp_app)
        elif transport == Transport.http:
            run_http(host, port, config, logger, fastmcp_docker_server, fastmcp_app)
        else:
            logger.error(f"Unsupported transport: {transport}")
            raise typer.Exit(code=1)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        raise


if __name__ == "__main__":
    app()
