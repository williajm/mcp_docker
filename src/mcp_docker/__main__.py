"""MCP Docker server entry point."""

import argparse
import asyncio
import os
from pathlib import Path
from typing import Any

from mcp_docker.config import Config
from mcp_docker.server import FastMCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger
from mcp_docker.version import __version__


def _run_stdio(
    logger: Any,
    fastmcp_docker_server: FastMCPDockerServer,
    fastmcp_app: Any,
) -> None:
    """Run the server with startup/shutdown lifecycle around stdio transport."""

    async def _startup() -> None:
        await fastmcp_docker_server.start()

    async def _shutdown() -> None:
        await fastmcp_docker_server.stop()
        logger.info("MCP server shutdown complete")

    asyncio.run(_startup())
    try:
        fastmcp_app.run(transport="stdio")
    finally:
        asyncio.run(_shutdown())


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Local MCP Docker Server")
    parser.add_argument("--version", "-v", action="store_true", help="Show version and exit")
    return parser.parse_args()


def main() -> None:
    """Run the local MCP Docker server over stdio."""
    args = _parse_args()
    if args.version:
        print(f"mcp-docker {__version__}")  # noqa: T201
        return

    config = Config()

    log_path = os.getenv("MCP_DOCKER_LOG_PATH")
    log_file = Path(log_path) if log_path else Path("mcp_docker.log")
    setup_logger(config.server, log_file)

    logger = get_logger(__name__)
    logger.info("=" * 60)
    logger.info(f"MCP Docker Server v{__version__}")
    logger.info("=" * 60)
    logger.info(
        f"Config: docker_url={config.docker.base_url}, "
        f"allow_moderate={config.safety.allow_moderate_operations}"
    )

    fastmcp_docker_server = FastMCPDockerServer(config)
    fastmcp_app = fastmcp_docker_server.get_app()

    try:
        logger.info("Starting FastMCP server with stdio transport")
        _run_stdio(logger, fastmcp_docker_server, fastmcp_app)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
