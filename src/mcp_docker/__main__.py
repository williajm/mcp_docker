"""MCP Docker server entry point.

This module provides the main entry point for running the MCP Docker server.
"""

import sys

from mcp_docker.version import __version__

# Early exit for --version/-v and --help/-h (only when running as script, not during imports)
if __name__ == "__main__":
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"mcp-docker {__version__}")
        sys.exit(0)

    if "--help" in sys.argv or "-h" in sys.argv:
        print("usage: mcp-docker [--transport {stdio,sse,httpstream}] [--host HOST] [--port PORT]")
        print()
        print("MCP Docker Server")
        print()
        print("options:")
        print("  -h, --help            show this help message and exit")
        print("  -v, --version         show version and exit")
        print("  --transport {stdio,sse,httpstream}")
        print("                        Transport type (default: stdio)")
        print("  --host HOST          Host to bind server (default: 127.0.0.1)")
        print("  --port PORT          Port to bind server (default: 8000)")
        sys.exit(0)

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
from mcp.server.streamable_http import (  # type: ignore[attr-defined]
    TransportSecuritySettings,
)
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
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
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from mcp_docker.config import Config
from mcp_docker.event_store import InMemoryEventStore
from mcp_docker.server import MCPDockerServer
from mcp_docker.utils.logger import get_logger, setup_logger

# HTTP Message Type Constants
HTTP_RESPONSE_START = "http.response.start"
HTTP_RESPONSE_BODY = "http.response.body"
CONTENT_TYPE_JSON = b"application/json"

# Logging Constants
LOG_BODY_PREVIEW_LENGTH = 300  # Characters to show in debug logs for HTTP bodies
SHUTDOWN_COMPLETE_MSG = "MCP server shutdown complete"

# CSP (Content Security Policy) directive constants
# Used to reduce duplication and improve maintainability
CSP_SELF = "'self'"
CSP_NONE = "'none'"

# SSE Endpoint Path Constants
SSE_PATH = "/sse"
MESSAGES_PATH = "/messages"

# Network binding constants
# Used for host validation and security middleware configuration
LOCALHOST_VARIANTS = frozenset(["127.0.0.1", "localhost", "::1"])
WILDCARD_BINDS = frozenset(["0.0.0.0", "::"])

# Context variables for SSE transport
client_ip_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "client_ip", default=None
)
bearer_token_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bearer_token", default=None
)

# Load configuration
config = Config()

# Setup logging to file
# Use env var if set, otherwise default to current working directory
log_path = os.getenv("MCP_DOCKER_LOG_PATH")
log_file = Path(log_path) if log_path else Path("mcp_docker.log")
setup_logger(config.server, log_file)

logger = get_logger(__name__)
logger.info("=" * 60)
logger.info(f"MCP Docker Server v{__version__} Initializing")
logger.info("=" * 60)
logger.info(f"Configuration: {config}")

# Create Docker server wrapper
docker_server = MCPDockerServer(config)

# Create MCP server with version
mcp_server = Server("mcp-docker", version=__version__)

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

    Args:
        name: Name of the tool to execute
        arguments: Tool-specific arguments
    """
    logger.debug(f"call_tool: {name}")
    logger.debug(f"Arguments: {arguments}")

    # Get client IP and bearer token from context variables (set by SSE transport)
    ip_address = client_ip_context.get()
    bearer_token = bearer_token_context.get()

    # Call tool
    result = await docker_server.call_tool(
        name,
        arguments,
        ip_address=ip_address,
        bearer_token=bearer_token,
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
            # Note: In Python 3.11+, asyncio.TimeoutError is an alias for built-in TimeoutError
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
        logger.info(SHUTDOWN_COMPLETE_MSG)


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

    # Check IP allowlist for non-localhost
    if not config.security.allowed_client_ips and not is_localhost:
        logger.warning(
            "═════════════════════════════════════════════════════════════\n"
            "⚠️  SECURITY WARNING ⚠️\n"
            "IP allowlist is NOT configured while binding to a non-localhost address!\n"
            "Anyone who can reach this server can execute Docker commands\n"
            "without restriction.\n"
            "\n"
            "To restrict access, set:\n"
            '  SECURITY_ALLOWED_CLIENT_IPS=["127.0.0.1", "192.168.1.100"]\n'
            "Or bind to localhost only: --host 127.0.0.1\n"
            "═════════════════════════════════════════════════════════════"
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


def _extract_bearer_token(scope: MutableMapping[str, Any]) -> str | None:
    """Extract bearer token from Authorization header.

    Args:
        scope: ASGI connection scope with headers

    Returns:
        Bearer token string or None if not present
    """
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"authorization":
            auth_value: str = value.decode("utf-8", errors="ignore")
            # Check if it's a Bearer token (case-insensitive per RFC 7235)
            if auth_value.lower().startswith("bearer "):
                token: str = auth_value[7:].strip()  # Remove "Bearer " prefix
                return token
    return None


def _create_security_headers(config: Config) -> Secure:
    """Create security headers middleware configuration.

    Args:
        config: MCP configuration with TLS settings

    Returns:
        Configured Secure middleware instance with OWASP recommended headers
    """
    csp = (
        ContentSecurityPolicy()
        .default_src(CSP_SELF)
        .script_src(CSP_SELF)
        .style_src(CSP_SELF)
        .img_src(CSP_SELF)
        .font_src(CSP_SELF)
        .connect_src(CSP_SELF)
        .frame_ancestors(CSP_NONE)
        .base_uri(CSP_SELF)
        .form_action(CSP_SELF)
    )

    hsts = (
        StrictTransportSecurity().include_subdomains().preload().max_age(31536000)
        if config.server.tls_enabled
        else None
    )

    cache = CacheControl().no_store().no_cache().must_revalidate()
    xfo = XFrameOptions().deny()
    referrer = ReferrerPolicy().strict_origin_when_cross_origin()

    permissions = (
        PermissionsPolicy()
        .geolocation(CSP_NONE)
        .microphone(CSP_NONE)
        .camera(CSP_NONE)
        .payment(CSP_NONE)
        .usb(CSP_NONE)
    )

    return Secure(
        csp=csp,
        hsts=hsts,
        cache=cache,
        xfo=xfo,
        referrer=referrer,
        permissions=permissions,
    )


def _build_allowed_hosts_list(host: str, config: Config) -> list[str]:
    """Build allowed hosts list based on bind address.

    This function constructs a list of hostnames/IPs that should be allowed
    in the Host header for security middleware (TrustedHostMiddleware and
    TransportSecuritySettings).

    Security: Simple fail-secure policy - localhost binds only accept localhost,
    all other binds require explicit HTTPSTREAM_ALLOWED_HOSTS configuration.
    This prevents DNS rebinding attacks and Host header injection.

    Args:
        host: Server bind address (e.g., '127.0.0.1', '0.0.0.0', 'api.example.com')
        config: MCP configuration with user-configured allowed hosts

    Returns:
        List of allowed hostnames/IPs:
        - Localhost binds: All localhost variants (127.0.0.1, localhost, ::1)
        - Non-localhost binds: Bind host + HTTPSTREAM_ALLOWED_HOSTS (if configured)

    Raises:
        ValueError: If binding to non-localhost without HTTPSTREAM_ALLOWED_HOSTS
    """
    allowed_hosts: list[str] = []

    # Add localhost variants if binding to localhost
    if host in LOCALHOST_VARIANTS:
        allowed_hosts.extend(LOCALHOST_VARIANTS)
    # Add the bind host itself (unless it's a wildcard bind)
    elif host not in WILDCARD_BINDS:
        allowed_hosts.append(host)

    # Always add user-configured hosts (if provided)
    if config.httpstream.allowed_hosts:
        allowed_hosts.extend(config.httpstream.allowed_hosts)

    # Fail-secure: Reject non-localhost binds without explicit configuration
    if not allowed_hosts:
        raise ValueError(
            f"Binding to {host} requires explicit HTTPSTREAM_ALLOWED_HOSTS configuration. "
            f'Set HTTPSTREAM_ALLOWED_HOSTS=\'["api.example.com", "192.0.2.1"]\' '
            f"or bind to localhost."
        )

    return allowed_hosts


def _create_uvicorn_config(app: Any, host: str, port: int, config: Config) -> uvicorn.Config:
    """Create Uvicorn server configuration with optional TLS.

    Args:
        app: ASGI application
        host: Server hostname
        port: Server port
        config: MCP configuration with TLS settings

    Returns:
        Configured Uvicorn Config instance
    """
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

    return uvicorn.Config(**uvicorn_config_params)


def _create_middleware_stack(host: str, config: Config) -> list[Middleware]:
    """Create middleware stack for Starlette application.

    Args:
        host: Server hostname
        config: MCP configuration with TLS settings

    Returns:
        List of configured middleware
    """
    # SECURITY: Configure TrustedHostMiddleware based on DNS rebinding protection setting
    # If DNS rebinding protection is disabled, allow all hosts (development mode)
    # If enabled (default), restrict to specific allowed hosts (production mode)
    if not config.httpstream.dns_rebinding_protection:
        # DNS rebinding protection disabled - allow any Host header
        # This is useful for development but UNSAFE for production
        allowed_hosts = ["*"]
        logger.warning(
            "⚠️  DNS rebinding protection DISABLED - accepting connections from any host. "
            "This is UNSAFE for production deployments."
        )
    else:
        # DNS rebinding protection enabled (default) - restrict to specific hosts
        allowed_hosts = _build_allowed_hosts_list(host, config)

        # Log configuration for debugging
        if config.httpstream.allowed_hosts:
            logger.info(
                f"TrustedHostMiddleware: Added {len(config.httpstream.allowed_hosts)} "
                f"configured hosts to allow-list"
            )
        logger.info(f"TrustedHostMiddleware: allowed_hosts={allowed_hosts}")

    middleware_stack = [
        # Trusted host middleware (validate Host header to prevent Host header injection)
        Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
    ]

    # Add CORS middleware if enabled
    if config.cors.enabled:
        middleware_stack.append(
            Middleware(
                CORSMiddleware,
                allow_origins=config.cors.allow_origins,
                allow_methods=config.cors.allow_methods,
                allow_headers=config.cors.allow_headers,
                expose_headers=config.cors.expose_headers,
                allow_credentials=config.cors.allow_credentials,
                max_age=config.cors.max_age,
            )
        )
        logger.info(
            f"CORS middleware enabled: origins={config.cors.allow_origins}, "
            f"credentials={config.cors.allow_credentials}"
        )

    # Add HTTPS redirect if TLS is enabled
    if config.server.tls_enabled:
        middleware_stack.insert(0, Middleware(HTTPSRedirectMiddleware))

    return middleware_stack


async def _authenticate_sse_request(
    method: str, path: str, client_ip: str | None, bearer_token: str | None
) -> tuple[bool, bytes | None]:
    """Authenticate SSE/messages requests.

    Args:
        method: HTTP method
        path: Request path
        client_ip: Client IP address
        bearer_token: Bearer token from Authorization header

    Returns:
        Tuple of (is_authenticated, error_body). error_body is None if authenticated.
    """
    # HEAD requests (health checks) bypass authentication
    if method == "HEAD":
        return True, None

    # Only authenticate SSE and messages endpoints
    if not (path.startswith(SSE_PATH) or path.startswith(MESSAGES_PATH)):
        return True, None

    try:
        # Authenticate the request (OAuth or IP allowlist)
        await docker_server.auth_middleware.authenticate_request(
            ip_address=client_ip, bearer_token=bearer_token
        )
        return True, None
    except Exception as auth_error:
        # Authentication failed - prepare 401 response
        client_desc = client_ip or "unknown"
        error_msg = f"Auth failed for {method} {path} from {client_desc}"
        logger.warning(f"{error_msg}: {auth_error}")
        error_body = json.dumps({"error": "Unauthorized", "message": str(auth_error)}).encode()
        return False, error_body


async def _send_unauthorized_response(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]], error_body: bytes
) -> None:
    """Send a 401 Unauthorized response.

    Args:
        send: ASGI send callable
        error_body: Error message body
    """
    await send(
        {
            "type": HTTP_RESPONSE_START,
            "status": 401,
            "headers": [
                [b"content-type", CONTENT_TYPE_JSON],
                [b"www-authenticate", b"Bearer"],
            ],
        }
    )
    await send({"type": HTTP_RESPONSE_BODY, "body": error_body})


async def _route_sse_request(
    sse: SseServerTransport,
    scope: MutableMapping[str, Any],
    receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
) -> None:
    """Route SSE request to appropriate handler.

    Args:
        sse: SSE transport instance
        scope: ASGI connection scope
        receive: ASGI receive callable
        send: ASGI send callable
    """
    path = scope.get("path", "")
    method = scope.get("method", "")

    # Create logging wrappers
    log_receive, log_send = _create_logging_wrappers(receive, send)

    # Route based on path and method
    if path.startswith(SSE_PATH) and method == "GET":
        await _handle_sse_connection(sse, scope, log_receive, log_send)
    elif path.startswith(SSE_PATH) and method == "HEAD":
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
    elif path.startswith(MESSAGES_PATH) and method == "POST":
        await _handle_post_message(sse, scope, log_receive, log_send)
    else:
        await _handle_404(send, method, path)


def _create_sse_handler(
    sse: SseServerTransport,
) -> Callable[
    [
        MutableMapping[str, Any],
        Callable[[], Awaitable[MutableMapping[str, Any]]],
        Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]:
    """Create the SSE request handler.

    Args:
        sse: SSE transport instance

    Returns:
        ASGI application callable for handling SSE requests
    """

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

        # Extract and store bearer token for OAuth authentication
        bearer_token = _extract_bearer_token(scope)
        bearer_token_context.set(bearer_token)

        logger.debug(
            f"Request: {method} {path} from {client_ip or 'unknown'}"
            f"{' with bearer token' if bearer_token else ''}"
        )

        # AUTHENTICATION ENFORCEMENT: Validate OAuth tokens for SSE/messages endpoints
        is_authenticated, error_body = await _authenticate_sse_request(
            method, path, client_ip, bearer_token
        )
        if not is_authenticated and error_body:
            await _send_unauthorized_response(send, error_body)
            return

        # Route to appropriate handler
        await _route_sse_request(sse, scope, receive, send)

    return sse_handler


def _create_security_headers_middleware(
    wrapped_handler: Any, secure_headers: Secure
) -> Callable[
    [
        MutableMapping[str, Any],
        Callable[[], Awaitable[MutableMapping[str, Any]]],
        Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]:
    """Create security headers middleware wrapper.

    Args:
        wrapped_handler: Handler to wrap with security headers
        secure_headers: Secure headers configuration

    Returns:
        ASGI application callable that applies security headers
    """

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
                    def __init__(self, headers: list[tuple[bytes, bytes]]) -> None:
                        self.headers: MutableMapping[str, str] = {
                            k.decode(): v.decode() for k, v in headers
                        }

                response = SimpleResponse(message.get("headers", []))
                await secure_headers.set_headers_async(response)

                # Convert headers back to ASGI format
                message["headers"] = [(k.encode(), v.encode()) for k, v in response.headers.items()]

            await send(message)

        await wrapped_handler(scope, receive, send_wrapper)

    return security_headers_middleware


def _setup_signal_handlers(shutdown_event: asyncio.Event) -> None:
    """Setup signal handlers for graceful shutdown.

    Args:
        shutdown_event: Event to set when shutdown is signaled
    """

    def signal_handler(sig: int, frame: Any) -> None:  # noqa: ARG001
        """Handle shutdown signals."""
        logger.info(f"Received signal {sig}, initiating shutdown...")
        shutdown_event.set()

    # Install signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


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
    _setup_signal_handlers(shutdown_event)

    try:
        # Create SSE transport and handler
        sse = SseServerTransport(MESSAGES_PATH)
        sse_handler = _create_sse_handler(sse)

        # Log debug mode warning if enabled
        if config.server.debug_mode:
            logger.warning(
                "⚠️  Debug mode enabled - detailed errors will be exposed to clients. "
                "DO NOT use in production!"
            )

        # SECURITY: Initialize secure headers middleware with OWASP recommended defaults
        secure_headers = _create_security_headers(config)

        # Wrap handler with ProxyHeadersMiddleware for secure X-Forwarded-For handling
        # SECURITY: Only trusts X-Forwarded-For from configured trusted_proxies
        trusted_proxies = (
            config.security.trusted_proxies if config.security.trusted_proxies else ["127.0.0.1"]
        )
        wrapped_handler = ProxyHeadersMiddleware(
            sse_handler,  # type: ignore[arg-type]
            trusted_hosts=trusted_proxies,
        )

        # Wrap with secure headers middleware
        security_headers_middleware = _create_security_headers_middleware(
            wrapped_handler, secure_headers
        )

        # Build middleware stack and create Starlette app (SSE transport)
        middleware_stack = _create_middleware_stack(host, config)
        app = Starlette(
            debug=config.server.debug_mode,
            routes=[Mount("/", app=security_headers_middleware)],
            middleware=middleware_stack,
        )

        # Create and run server with TLS support
        config_uvicorn = _create_uvicorn_config(app, host, port, config)
        server = uvicorn.Server(config_uvicorn)

        logger.info(f"MCP server listening on {protocol}://{host}:{port}/sse")

        # Run server with shutdown monitoring
        server_task = asyncio.create_task(server.serve())
        shutdown_task = asyncio.create_task(shutdown_event.wait())
        await _monitor_shutdown(server_task, shutdown_task, server)

    finally:
        await docker_server.stop()
        logger.info(SHUTDOWN_COMPLETE_MSG)


def _create_event_store() -> InMemoryEventStore | None:
    """Create event store for resumability if enabled.

    Returns:
        InMemoryEventStore instance if resumability is enabled, None otherwise
    """
    if not config.httpstream.resumability_enabled:
        logger.info("Resumability disabled - EventStore not created")
        return None

    event_store = InMemoryEventStore(
        max_events=config.httpstream.event_store_max_events,
        ttl_seconds=config.httpstream.event_store_ttl_seconds,
    )
    logger.info(
        f"EventStore enabled: max_events={config.httpstream.event_store_max_events}, "
        f"ttl={config.httpstream.event_store_ttl_seconds}s"
    )
    return event_store


def _create_transport_security_settings(host: str) -> TransportSecuritySettings | None:
    """Create TransportSecuritySettings for DNS rebinding protection.

    Args:
        host: The host the server is binding to

    Returns:
        TransportSecuritySettings instance if protection is enabled, None otherwise
    """
    if not config.httpstream.dns_rebinding_protection:
        logger.warning("DNS rebinding protection DISABLED - not recommended for production")
        return None

    # Build allowed hosts list (consistent with TrustedHostMiddleware)
    allowed_hosts = _build_allowed_hosts_list(host, config)

    # Log configured hosts if any were added
    if config.httpstream.allowed_hosts:
        count = len(config.httpstream.allowed_hosts)
        logger.info(f"Added {count} configured hosts to allow-list")

    # Configure allowed origins for browser clients
    allowed_origins = config.cors.allow_origins if config.cors.enabled else []

    security_settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )
    logger.info(
        f"DNS rebinding protection enabled: allowed_hosts={allowed_hosts}, "
        f"allowed_origins={allowed_origins}"
    )
    return security_settings


async def _handle_httpstream_request(
    scope: MutableMapping[str, Any],
    receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    session_manager: StreamableHTTPSessionManager,
) -> None:
    """Handle HTTP Stream requests with security checks.

    Args:
        scope: ASGI scope dictionary
        receive: ASGI receive callable
        send: ASGI send callable
        session_manager: StreamableHTTPSessionManager instance
    """
    path = scope.get("path", "")
    method = scope.get("method", "")

    # Extract and store client IP for authentication/logging
    client_ip = _extract_client_ip(scope)
    client_ip_context.set(client_ip)

    # Extract and store bearer token for OAuth authentication
    bearer_token = _extract_bearer_token(scope)
    bearer_token_context.set(bearer_token)

    logger.debug(
        f"Request: {method} {path} from {client_ip or 'unknown'}"
        f"{' with bearer token' if bearer_token else ''}"
    )

    # HEALTH CHECK BYPASS: Allow HEAD requests without authentication
    if method == "HEAD":
        logger.debug("HEAD request - bypassing authentication for health check")
        await send(
            {
                "type": HTTP_RESPONSE_START,
                "status": 200,
                "headers": [
                    [b"content-type", CONTENT_TYPE_JSON],
                    [b"cache-control", b"no-cache"],
                ],
            }
        )
        await send({"type": HTTP_RESPONSE_BODY, "body": b""})
        return

    # CORS PREFLIGHT BYPASS: Allow OPTIONS requests without authentication
    # Browsers never send Authorization headers on CORS preflight requests,
    # so we must handle OPTIONS before authentication to enable CORS + OAuth
    if method == "OPTIONS":
        logger.debug("OPTIONS request - bypassing authentication for CORS preflight")
        # Let session manager handle OPTIONS (CORS middleware will add appropriate headers)
        await session_manager.handle_request(scope, receive, send)
        return

    # AUTHENTICATION: OAuth or IP allowlist
    try:
        await docker_server.auth_middleware.authenticate_request(
            ip_address=client_ip,
            bearer_token=bearer_token,
        )
    except Exception as auth_error:
        # Authentication failed - return 401
        client_desc = client_ip or "unknown"
        error_msg = f"Auth failed for {method} {path} from {client_desc}"
        logger.warning(f"{error_msg}: {auth_error}")
        error_body = json.dumps({"error": "Unauthorized", "message": str(auth_error)}).encode()

        await send(
            {
                "type": HTTP_RESPONSE_START,
                "status": 401,
                "headers": [
                    [b"content-type", CONTENT_TYPE_JSON],
                    [b"www-authenticate", b"Bearer"],
                ],
            }
        )
        await send({"type": HTTP_RESPONSE_BODY, "body": error_body})
        return

    # DELEGATE TO MCP SDK: Let session manager handle the request
    await session_manager.handle_request(scope, receive, send)


async def run_httpstream(host: str, port: int) -> None:
    """Run the MCP server with HTTP Stream Transport over HTTP/HTTPS."""
    protocol = "https" if config.server.tls_enabled else "http"
    logger.info(f"Starting MCP server with HTTP Stream Transport on {protocol}://{host}:{port}")

    # Validate security configuration (reuse SSE validation)
    _validate_sse_security(host)

    # Initialize Docker server
    await docker_server.start()

    # Shutdown event for graceful termination
    shutdown_event = asyncio.Event()
    _setup_signal_handlers(shutdown_event)

    try:
        # Create event store for resumability if enabled
        event_store = _create_event_store()

        # Create TransportSecuritySettings for DNS rebinding protection
        security_settings = _create_transport_security_settings(host)

        # Create session manager with MCP SDK
        session_manager = StreamableHTTPSessionManager(
            app=mcp_server,
            event_store=event_store,
            json_response=config.httpstream.json_response_default,
            stateless=config.httpstream.stateless_mode,
            security_settings=security_settings,
        )

        logger.info(
            f"HTTP Stream Transport configured: "
            f"json_response={config.httpstream.json_response_default}, "
            f"stateless={config.httpstream.stateless_mode}, "
            f"resumability={config.httpstream.resumability_enabled}"
        )

        # Start session manager (required before handling requests)
        async with session_manager.run():
            # Create HTTP Stream handler wrapper
            async def httpstream_handler(
                scope: MutableMapping[str, Any],
                receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
                send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
            ) -> None:
                await _handle_httpstream_request(scope, receive, send, session_manager)

            # Log debug mode warning if enabled
            if config.server.debug_mode:
                logger.warning(
                    "⚠️  Debug mode enabled - detailed errors will be exposed to clients. "
                    "DO NOT use in production!"
                )

            # SECURITY: Initialize secure headers middleware with OWASP recommended defaults
            secure_headers = _create_security_headers(config)

            # Wrap handler with ProxyHeadersMiddleware for secure X-Forwarded-For handling
            trusted_proxies = (
                config.security.trusted_proxies
                if config.security.trusted_proxies
                else ["127.0.0.1"]
            )
            wrapped_handler = ProxyHeadersMiddleware(
                httpstream_handler,  # type: ignore[arg-type]
                trusted_hosts=trusted_proxies,
            )

            # Wrap with secure headers middleware
            security_headers_middleware = _create_security_headers_middleware(
                wrapped_handler, secure_headers
            )

            # Build middleware stack and create Starlette app (HTTP Stream transport)
            middleware_stack = _create_middleware_stack(host, config)
            app = Starlette(
                debug=config.server.debug_mode,
                routes=[Mount("/", app=security_headers_middleware)],
                middleware=middleware_stack,
            )

            # Create and run server with TLS support
            config_uvicorn = _create_uvicorn_config(app, host, port, config)
            server = uvicorn.Server(config_uvicorn)

            logger.info(f"MCP server listening on {protocol}://{host}:{port}")
            logger.info("HTTP Stream Transport endpoint: POST /")

            # Run server with shutdown monitoring
            server_task = asyncio.create_task(server.serve())
            shutdown_task = asyncio.create_task(shutdown_event.wait())
            await _monitor_shutdown(server_task, shutdown_task, server)

    finally:
        await docker_server.stop()
        logger.info(SHUTDOWN_COMPLETE_MSG)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="MCP Docker Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "httpstream"],
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
            asyncio.run(run_stdio())
        elif args.transport == "sse":
            asyncio.run(run_sse(args.host, args.port))
        elif args.transport == "httpstream":
            asyncio.run(run_httpstream(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.exception(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
