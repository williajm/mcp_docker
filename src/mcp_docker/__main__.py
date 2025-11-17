"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server with FastMCP 2.0.
"""

import sys

from mcp_docker.version import __version__

# Early exit for --version/-v and --help/-h (only when running as script, not during imports)
if __name__ == "__main__":
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"mcp-docker {__version__}")
        sys.exit(0)

    if "--help" in sys.argv or "-h" in sys.argv:
        print("usage: mcp-docker [--transport {stdio,http}] [--host HOST] [--port PORT]")
        print()
        print("MCP Docker Server (FastMCP 2.0)")
        print()
        print("options:")
        print("  -h, --help            show this help message and exit")
        print("  -v, --version         show version and exit")
        print("  --transport {stdio,http}")
        print("                        Transport type (default: stdio)")
        print("  --host HOST          Host to bind server (default: 127.0.0.1)")
        print("  --port PORT          Port to bind server (default: 8000)")
        sys.exit(0)

import argparse
import asyncio
import os
from pathlib import Path

from mcp_docker.config import Config
from mcp_docker.fastmcp_server import FastMCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger

# Logging Constants
SHUTDOWN_COMPLETE_MSG = "MCP server shutdown complete"

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


def run_stdio() -> None:
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


def run_http(host: str, port: int) -> None:
    """Run the MCP server with HTTP transport.

    Note: FastMCP's HTTP transport runs plain HTTP. For HTTPS in production,
    use a reverse proxy (NGINX, Caddy, etc.) for TLS termination.

    Args:
        host: Host to bind the server to
        port: Port to bind the server to
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


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="MCP Docker Server (FastMCP 2.0)")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind server (default: 8000)",
    )

    args = parser.parse_args()

    try:
        if args.transport == "stdio":
            run_stdio()
        elif args.transport == "http":
            run_http(args.host, args.port)
        else:
            logger.error(f"Unsupported transport: {args.transport}")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
