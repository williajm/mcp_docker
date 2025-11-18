#!/bin/bash
# Start MCP Docker server in HTTP mode using local code
#
# This script starts the MCP Docker server with HTTP transport using
# the latest code in the current directory.
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server.sh
#
# Environment variables:
#   MCP_HOST       - Host to bind to (default: 127.0.0.1)
#   MCP_PORT       - Port to bind to (default: 8000)
#   MCP_LOG_LEVEL  - Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: DEBUG)
#   MCP_DEBUG_MODE - Enable debug mode with detailed errors (default: true)
#
# Examples:
#   # Start on default host and port with debug logging
#   ./start_http_server.sh
#
#   # Start on custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=9000 ./start_http_server.sh
#
#   # Start with INFO level logging
#   MCP_LOG_LEVEL=INFO ./start_http_server.sh
#

set -e  # Exit on error

# Default configuration
HOST="${MCP_HOST:-127.0.0.1}"
PORT="${MCP_PORT:-8000}"
LOG_LEVEL="${MCP_LOG_LEVEL:-DEBUG}"
DEBUG_MODE="${MCP_DEBUG_MODE:-true}"

# Export environment variables for the server
export MCP_LOG_LEVEL="$LOG_LEVEL"
export MCP_DEBUG_MODE="$DEBUG_MODE"

echo "=========================================="
echo "MCP Docker Server - HTTP Mode"
echo "=========================================="
echo "Host: $HOST"
echo "Port: $PORT"
echo "Log Level: $LOG_LEVEL"
echo "Debug Mode: $DEBUG_MODE"
echo ""
echo "⚠️  WARNING: Using plain HTTP without TLS"
echo "   For production, use a reverse proxy with HTTPS"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=========================================="
echo ""

# Start the server using local code with all tools and safety levels enabled
exec env \
  -u SAFETY_ALLOWED_TOOLS \
  SAFETY_ALLOW_MODERATE_OPERATIONS=true \
  SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true \
  uv run python -m mcp_docker --transport http --host "$HOST" --port "$PORT"
