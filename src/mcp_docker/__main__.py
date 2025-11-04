"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server.
"""

import argparse
import asyncio
import os
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.stdio import stdio_server
from mcp.types import Tool
from starlette.applications import Starlette
from starlette.routing import Mount

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger
from mcp_docker.version import __version__, get_full_version

# Load configuration
config = Config()

# Setup logging to file
# Use env var if set, otherwise default to current working directory
log_path = os.getenv("MCP_DOCKER_LOG_PATH")
log_file = Path(log_path) if log_path else Path("mcp_docker.log")
setup_logger(config.server, log_file)

logger = get_logger(__name__)
full_version = get_full_version()
logger.info("=" * 60)
logger.info(f"MCP Docker Server v{full_version} Initializing")
logger.info("=" * 60)
logger.info(f"Package version: {__version__}")
logger.info(f"Full version string: {full_version}")
logger.info(f"Configuration: {config}")

# Create Docker server wrapper
docker_server = MCPDockerServer(config)

# Create MCP server with version
mcp_server = Server("mcp-docker", version=full_version)

logger.info(f"Docker server initialized with {len(docker_server.tools)} tools")


# Register list_tools handler
@mcp_server.list_tools()  # type: ignore[misc, no-untyped-call]
async def handle_list_tools() -> list[Tool]:
    """List all available Docker tools."""
    logger.debug("list_tools handler called")
    tools = docker_server.list_tools()
    logger.debug(f"Returning {len(tools)} tools")
    # Convert to MCP Tool types
    return [
        Tool(name=tool["name"], description=tool["description"], inputSchema=tool["inputSchema"])
        for tool in tools
    ]


# Register call_tool handler
@mcp_server.call_tool()  # type: ignore[misc]
async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
    """Execute a Docker tool."""
    logger.debug(f"call_tool: {name}")
    logger.debug(f"Arguments: {arguments}")
    result = await docker_server.call_tool(name, arguments)

    # Return result in MCP format (list of content items)
    if result.get("success"):
        logger.debug(f"Tool {name} executed successfully")
        return [{"type": "text", "text": str(result.get("result", ""))}]

    error_msg = result.get("error", "Unknown error")
    logger.error(f"Tool {name} failed: {error_msg}")
    return [{"type": "text", "text": f"Error: {error_msg}"}]


# Register list_resources handler
@mcp_server.list_resources()  # type: ignore[misc, no-untyped-call]
async def handle_list_resources() -> list[dict[str, Any]]:
    """List all available Docker resources."""
    return docker_server.list_resources()


# Register read_resource handler
@mcp_server.read_resource()  # type: ignore[misc, no-untyped-call]
async def handle_read_resource(uri: str) -> str:
    """Read a Docker resource by URI."""
    result = await docker_server.read_resource(uri)

    # Return text content if available
    if "text" in result:
        return result["text"]  # type: ignore[no-any-return]
    return str(result)


# Register list_prompts handler
@mcp_server.list_prompts()  # type: ignore[misc, no-untyped-call]
async def handle_list_prompts() -> list[dict[str, Any]]:
    """List all available Docker prompts."""
    return docker_server.list_prompts()


# Register get_prompt handler
@mcp_server.get_prompt()  # type: ignore[misc, no-untyped-call]
async def handle_get_prompt(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Get a Docker prompt by name."""
    args = arguments or {}
    return await docker_server.get_prompt(name, args)


logger.info("MCP server handlers registered")


async def run_stdio() -> None:
    """Run the MCP server with stdio transport."""
    logger.info("Starting MCP server with stdio transport")

    # Initialize Docker server
    await docker_server.start()

    try:
        # Run server with stdio transport
        async with stdio_server() as (read_stream, write_stream):
            await mcp_server.run(
                read_stream, write_stream, mcp_server.create_initialization_options()
            )
    finally:
        await docker_server.stop()
        logger.info("MCP server shutdown complete")


async def run_sse(host: str, port: int) -> None:
    """Run the MCP server with SSE transport over HTTP."""
    logger.info(f"Starting MCP server with SSE transport on {host}:{port}")

    # Initialize Docker server
    await docker_server.start()

    try:
        # Create SSE transport
        sse = SseServerTransport("/messages")

        # Simplified approach: let connect_sse handle everything
        # It manages sessions internally via session_id
        async def sse_handler(
            scope: MutableMapping[str, Any],
            receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
            send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
        ) -> None:
            """Handle both /sse (GET) and /messages (POST) through the SSE transport."""
            path = scope.get("path", "")
            method = scope.get("method", "")
            logger.debug(f"Request: {method} {path}")

            # Logging wrappers for debugging
            async def log_receive() -> MutableMapping[str, Any]:
                msg = await receive()
                if msg.get("type") == "http.request" and msg.get("body"):
                    logger.debug(f"<<< HTTP body: {msg['body'][:300]}")
                return msg

            async def log_send(msg: MutableMapping[str, Any]) -> None:
                if msg.get("type") == "http.response.body" and msg.get("body"):
                    logger.debug(f">>> HTTP body: {msg['body'][:300]}")
                await send(msg)

            # For /sse GET requests, create a persistent SSE connection
            if path.startswith("/sse") and method == "GET":
                logger.debug("Creating persistent SSE connection")
                async with sse.connect_sse(scope, log_receive, log_send) as streams:
                    logger.debug("SSE connection established, running MCP server")
                    await mcp_server.run(
                        streams[0], streams[1], mcp_server.create_initialization_options()
                    )
                    logger.debug("MCP server completed")

            # For /messages POST requests, use the dedicated handler
            elif path.startswith("/messages") and method == "POST":
                logger.debug("Handling /messages POST")
                await sse.handle_post_message(scope, log_receive, log_send)
                logger.debug("/messages POST handled")

            else:
                logger.warning(f"Unhandled request: {method} {path}")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 404,
                        "headers": [[b"content-type", b"text/plain"]],
                    }
                )
                await send({"type": "http.response.body", "body": b"Not Found"})

        # Mount handler at root
        app = Starlette(
            debug=True,
            routes=[Mount("/", app=sse_handler)],
        )

        # Run server
        config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config_uvicorn)

        logger.info(f"MCP server listening on http://{host}:{port}/sse")
        await server.serve()

    finally:
        await docker_server.stop()
        logger.info("MCP server shutdown complete")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="MCP Docker Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind SSE server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind SSE server (default: 8000)",
    )

    args = parser.parse_args()

    try:
        if args.transport == "stdio":
            asyncio.run(run_stdio())
        else:  # sse
            asyncio.run(run_sse(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
