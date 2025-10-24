"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server.
"""

import asyncio
import sys
from pathlib import Path

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger


async def main() -> None:
    """Main entry point for MCP Docker server."""
    # Load configuration
    config = Config()

    # Setup logging
    # For now, always log to file
    log_file = Path("mcp_docker.log")
    setup_logger(config.server, log_file)

    logger = get_logger(__name__)
    logger.info("=" * 60)
    logger.info("MCP Docker Server Starting")
    logger.info("=" * 60)
    logger.info(f"Configuration: {config}")

    # Create and start server
    server = MCPDockerServer(config)

    try:
        await server.start()
        logger.info(f"Server initialized with {len(server.tools)} tools")
        logger.info("Server is ready to accept requests")

        # Keep server running
        # In a real MCP server, this would handle stdio or HTTP transport
        # For now, we just keep it alive
        logger.info("Press Ctrl+C to stop the server")

        # Simple demonstration: list available tools
        tools = server.list_tools()
        logger.info(f"Available tools: {', '.join(t['name'] for t in tools)}")

        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        sys.exit(1)
    finally:
        await server.stop()
        logger.info("Server shutdown complete")


def run() -> None:
    """Run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")


if __name__ == "__main__":
    run()
