"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server.
"""

import argparse
import asyncio
import contextvars
import json
import os
import signal
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.stdio import stdio_server
from mcp.types import Tool
from secure import (
    CacheControl,
    ContentSecurityPolicy,
    PermissionsPolicy,
    ReferrerPolicy,
    Secure,
    StrictTransportSecurity,
    XFrameOptions,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger
from mcp_docker.version import __version__, get_full_version

# HTTP Message Type Constants
HTTP_RESPONSE_START = "http.response.start"
HTTP_RESPONSE_BODY = "http.response.body"

# Logging Constants
LOG_BODY_PREVIEW_LENGTH = 300  # Characters to show in debug logs for HTTP bodies

# Context variable for client IP address in SSE transport
client_ip_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "client_ip", default=None
)

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
    """Execute a Docker tool.

    Authentication can be provided via the special '_auth' argument:
    {
        "_auth": {
            "ssh": {  # SSH key authentication
                "client_id": "client-id",
                "timestamp": "2025-11-04T12:00:00Z",
                "nonce": "random-nonce",
                "signature": "base64-signature"
            }
        },
        "actual_arg1": "value1",  # Tool's actual arguments
        "actual_arg2": "value2"
    }
    """
    logger.debug(f"call_tool: {name}")

    # Extract authentication data (if present) - must be done before logging
    auth_data = arguments.pop("_auth", {})

    # Validate auth_data is a dict to prevent AttributeError on malformed requests
    if not isinstance(auth_data, dict):
        logger.warning(f"Invalid _auth type: {type(auth_data).__name__}, expected dict")
        auth_data = {}

    # Safe to log arguments now that _auth has been removed (no credential leakage)
    # SECURITY: Loguru handles large payloads safely with automatic serialization
    logger.debug(f"Arguments (auth redacted): {arguments}")

    ssh_auth_data = auth_data.get("ssh")

    # Get client IP from context variable (set by SSE transport)
    ip_address = client_ip_context.get()

    # Call tool with authentication
    result = await docker_server.call_tool(
        name,
        arguments,
        ip_address=ip_address,
        ssh_auth_data=ssh_auth_data,
    )

    # Return result in MCP format (list of content items)
    if result.get("success"):
        logger.debug(f"Tool {name} executed successfully")
        result_data = result.get("result", {})
        return [{"type": "text", "text": json.dumps(result_data)}]

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


def _create_logging_wrappers(
    receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
) -> tuple[
    Callable[[], Awaitable[MutableMapping[str, Any]]],
    Callable[[MutableMapping[str, Any]], Awaitable[None]],
]:
    """Create logging wrapper functions for SSE receive/send."""

    async def log_receive() -> MutableMapping[str, Any]:
        msg = await receive()
        if msg.get("type") == "http.request" and msg.get("body"):
            logger.debug(f"<<< HTTP body: {msg['body'][:LOG_BODY_PREVIEW_LENGTH]}")
        return msg

    async def log_send(msg: MutableMapping[str, Any]) -> None:
        if msg.get("type") == HTTP_RESPONSE_BODY and msg.get("body"):
            logger.debug(f">>> HTTP body: {msg['body'][:LOG_BODY_PREVIEW_LENGTH]}")
        await send(msg)

    return log_receive, log_send


async def _handle_sse_connection(
    sse: SseServerTransport,
    scope: MutableMapping[str, Any],
    log_receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    log_send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
) -> None:
    """Handle SSE GET requests with persistent connection."""
    logger.debug("Creating persistent SSE connection")
    try:
        async with sse.connect_sse(scope, log_receive, log_send) as streams:
            logger.debug("SSE connection established, running MCP server")
            await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())
            logger.debug("MCP server completed")
    except asyncio.CancelledError:
        logger.debug("SSE connection cancelled during shutdown")
        raise  # Re-raise to properly propagate cancellation


async def _handle_post_message(
    sse: SseServerTransport,
    scope: MutableMapping[str, Any],
    log_receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    log_send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
) -> None:
    """Handle POST requests to /messages endpoint."""
    logger.debug("Handling /messages POST")
    try:
        await sse.handle_post_message(scope, log_receive, log_send)
        logger.debug("/messages POST handled")
    except asyncio.CancelledError:
        logger.debug("POST message handling cancelled during shutdown")
        raise  # Re-raise to properly propagate cancellation


async def _handle_404(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]], method: str, path: str
) -> None:
    """Handle unrecognized requests with 404."""
    logger.warning(f"Unhandled request: {method} {path}")
    await send(
        {
            "type": HTTP_RESPONSE_START,
            "status": 404,
            "headers": [[b"content-type", b"text/plain"]],
        }
    )
    await send({"type": HTTP_RESPONSE_BODY, "body": b"Not Found"})


async def _monitor_shutdown(
    server_task: asyncio.Task[None],
    shutdown_task: asyncio.Task[Any],
    server: uvicorn.Server,
) -> None:
    """Monitor for shutdown signal and handle graceful shutdown."""
    # Wait for either server completion or shutdown signal
    done, pending = await asyncio.wait(
        {server_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
    )

    # If shutdown was signaled, force server shutdown
    if shutdown_task in done:
        logger.info("Shutdown signal received, stopping server...")
        server.should_exit = True

        # Wait for graceful shutdown with timeout
        try:
            await asyncio.wait_for(server_task, timeout=5.0)
        except TimeoutError:
            logger.warning("Graceful shutdown timeout, forcing exit...")
            # Cancel any remaining tasks
            for task in pending:
                task.cancel()


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


def _validate_sse_security(host: str) -> None:
    """Validate security configuration for SSE transport.

    Args:
        host: The host address to bind to

    Raises:
        RuntimeError: If security requirements are not met
        ValueError: If TLS configuration is incomplete
    """
    is_localhost = host in ["127.0.0.1", "localhost", "::1"]

    # Check TLS configuration for non-localhost
    if not config.server.tls_enabled and not is_localhost:
        logger.error(
            "═════════════════════════════════════════════════════════════\n"
            "⚠️  CRITICAL SECURITY WARNING ⚠️\n"
            "Running SSE transport over HTTP without TLS on a non-localhost address!\n"
            "API keys and data will be transmitted in PLAINTEXT over the network.\n"
            "This is UNSAFE for production use.\n"
            "\n"
            "Enable TLS by setting:\n"
            "  MCP_TLS_ENABLED=true\n"
            "  MCP_TLS_CERT_FILE=/path/to/cert.pem\n"
            "  MCP_TLS_KEY_FILE=/path/to/key.pem\n"
            "═════════════════════════════════════════════════════════════"
        )

    # Check authentication for non-localhost
    if not config.security.auth_enabled and not is_localhost:
        logger.error(
            "═════════════════════════════════════════════════════════════\n"
            "⚠️  CRITICAL SECURITY WARNING ⚠️\n"
            "Authentication is DISABLED while binding to a non-localhost address!\n"
            "Anyone who can reach this server can execute Docker commands\n"
            "without credentials.\n"
            "\n"
            "Enable authentication by setting:\n"
            "  SECURITY_AUTH_ENABLED=true\n"
            "Or bind to localhost only: --host 127.0.0.1\n"
            "═════════════════════════════════════════════════════════════"
        )
        raise RuntimeError(
            "Authentication MUST be enabled when binding to non-localhost addresses. "
            "Set SECURITY_AUTH_ENABLED=true or bind to 127.0.0.1 only."
        )

    # Validate TLS configuration if enabled
    if config.server.tls_enabled and (
        not config.server.tls_cert_file or not config.server.tls_key_file
    ):
        raise ValueError(
            "TLS is enabled but certificate or key file not specified. "
            "Set MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE."
        )


def _extract_client_ip(scope: MutableMapping[str, Any]) -> str | None:
    """Extract client IP address from ASGI scope.

    SECURITY: ProxyHeadersMiddleware has already processed X-Forwarded-For
    headers from trusted proxies and updated scope['client'] with the real
    client IP. This prevents IP spoofing attacks.

    Args:
        scope: ASGI connection scope (processed by ProxyHeadersMiddleware)

    Returns:
        Client IP address or None if not available
    """
    # ProxyHeadersMiddleware updates scope['client'] with real IP
    if "client" in scope and scope["client"]:
        client_tuple = scope["client"]
        if isinstance(client_tuple, (list, tuple)) and len(client_tuple) > 0:
            return str(client_tuple[0])  # (host, port) tuple, take host
    return None


async def run_sse(host: str, port: int) -> None:
    """Run the MCP server with SSE transport over HTTP/HTTPS."""
    protocol = "https" if config.server.tls_enabled else "http"
    logger.info(f"Starting MCP server with SSE transport on {protocol}://{host}:{port}")

    # Validate security configuration
    _validate_sse_security(host)

    # Initialize Docker server
    await docker_server.start()

    # Shutdown event for graceful termination
    shutdown_event = asyncio.Event()

    def signal_handler(sig: int, frame: Any) -> None:  # noqa: ARG001
        """Handle shutdown signals."""
        logger.info(f"Received signal {sig}, initiating shutdown...")
        shutdown_event.set()

    # Install signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Create SSE transport
        sse = SseServerTransport("/messages")

        async def sse_handler(
            scope: MutableMapping[str, Any],
            receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
            send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
        ) -> None:
            """Handle both /sse (GET) and /messages (POST) through the SSE transport."""
            path = scope.get("path", "")
            method = scope.get("method", "")

            # Extract and store client IP for authentication/logging
            # SECURITY: ProxyHeadersMiddleware has already validated trusted proxies
            client_ip = _extract_client_ip(scope)
            client_ip_context.set(client_ip)

            logger.debug(f"Request: {method} {path} from {client_ip or 'unknown'}")

            # Create logging wrappers
            log_receive, log_send = _create_logging_wrappers(receive, send)

            # Route based on path and method
            if path.startswith("/sse") and method == "GET":
                await _handle_sse_connection(sse, scope, log_receive, log_send)
            elif path.startswith("/sse") and method == "HEAD":
                # Handle HEAD request for health checks
                await send(
                    {
                        "type": HTTP_RESPONSE_START,
                        "status": 200,
                        "headers": [
                            [b"content-type", b"text/event-stream"],
                            [b"cache-control", b"no-cache"],
                            [b"connection", b"keep-alive"],
                        ],
                    }
                )
                await send({"type": HTTP_RESPONSE_BODY, "body": b""})
            elif path.startswith("/messages") and method == "POST":
                await _handle_post_message(sse, scope, log_receive, log_send)
            else:
                await _handle_404(send, method, path)

        # Mount handler at root
        if config.server.debug_mode:
            logger.warning(
                "⚠️  Debug mode enabled - detailed errors will be exposed to clients. "
                "DO NOT use in production!"
            )

        # SECURITY: Initialize secure headers middleware with OWASP recommended defaults
        # This replaces custom security header code with a battle-tested library
        csp = (
            ContentSecurityPolicy()
            .default_src("'self'")
            .script_src("'self'")
            .style_src("'self'")
            .img_src("'self'")
            .font_src("'self'")
            .connect_src("'self'")
            .frame_ancestors("'none'")
            .base_uri("'self'")
            .form_action("'self'")
        )

        hsts = (
            StrictTransportSecurity()
            .include_subdomains()
            .preload()
            .max_age(31536000)
            if config.server.tls_enabled
            else None
        )

        cache = CacheControl().no_store().no_cache().must_revalidate()

        xfo = XFrameOptions().deny()

        referrer = ReferrerPolicy().strict_origin_when_cross_origin()

        permissions = (
            PermissionsPolicy()
            .geolocation("'none'")
            .microphone("'none'")
            .camera("'none'")
            .payment("'none'")
            .usb("'none'")
        )

        secure_headers = Secure(
            csp=csp,
            hsts=hsts,
            cache=cache,
            xfo=xfo,
            referrer=referrer,
            permissions=permissions,
        )

        # Wrap handler with ProxyHeadersMiddleware for secure X-Forwarded-For handling
        # SECURITY: Only trusts X-Forwarded-For from configured trusted_proxies
        trusted_proxies = (
            config.security.trusted_proxies
            if config.security.trusted_proxies
            else ["127.0.0.1"]
        )
        # Type ignore needed due to ASGI type variance between MutableMapping and specific types
        wrapped_handler = ProxyHeadersMiddleware(
            sse_handler,  # type: ignore[arg-type]
            trusted_hosts=trusted_proxies,
        )

        # Wrap with secure headers middleware
        async def security_headers_middleware(
            scope: MutableMapping[str, Any],
            receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
            send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
        ) -> None:
            """Apply security headers using the secure library."""

            async def send_wrapper(message: MutableMapping[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    # Create a simple response object that the secure library can work with
                    class SimpleResponse:
                        def __init__(
                            self, headers: list[tuple[bytes, bytes]]
                        ) -> None:
                            self.headers: MutableMapping[str, str] = {
                                k.decode(): v.decode() for k, v in headers
                            }

                    response = SimpleResponse(message.get("headers", []))
                    await secure_headers.set_headers_async(response)

                    # Convert headers back to ASGI format
                    message["headers"] = [
                        (k.encode(), v.encode()) for k, v in response.headers.items()
                    ]

                await send(message)

            await wrapped_handler(scope, receive, send_wrapper)  # type: ignore[arg-type]

        # Build middleware stack (from innermost to outermost)
        # SECURITY: Configure TrustedHostMiddleware based on environment
        # For localhost: allow localhost variants
        # For production: restrict to specific hostnames/domains
        is_localhost = host in ["127.0.0.1", "localhost", "::1"]
        allowed_hosts = ["127.0.0.1", "localhost", "::1"] if is_localhost else [host]

        middleware_stack = [
            # Trusted host middleware (validate Host header to prevent Host header injection)
            Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
        ]

        # Add HTTPS redirect if TLS is enabled
        if config.server.tls_enabled:
            middleware_stack.insert(0, Middleware(HTTPSRedirectMiddleware))

        app = Starlette(
            debug=config.server.debug_mode,
            routes=[Mount("/", app=security_headers_middleware)],
            middleware=middleware_stack,
        )

        # Run server with timeout configuration and TLS support
        uvicorn_config_params = {
            "app": app,
            "host": host,
            "port": port,
            "log_level": "info",
            "timeout_graceful_shutdown": 5,
            "limit_max_requests": 1000,  # Restart after 1000 requests to prevent memory leaks
            "limit_concurrency": 100,  # Max 100 concurrent connections
            "timeout_keep_alive": 30,  # Close idle connections after 30 seconds
        }

        # Add TLS configuration if enabled
        if config.server.tls_enabled:
            uvicorn_config_params["ssl_keyfile"] = str(config.server.tls_key_file)
            uvicorn_config_params["ssl_certfile"] = str(config.server.tls_cert_file)

        config_uvicorn = uvicorn.Config(**uvicorn_config_params)  # type: ignore[arg-type]
        server = uvicorn.Server(config_uvicorn)

        logger.info(f"MCP server listening on {protocol}://{host}:{port}/sse")

        # Run server with shutdown monitoring
        server_task = asyncio.create_task(server.serve())
        shutdown_task = asyncio.create_task(shutdown_event.wait())

        # Monitor shutdown and handle gracefully
        await _monitor_shutdown(server_task, shutdown_task, server)

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
