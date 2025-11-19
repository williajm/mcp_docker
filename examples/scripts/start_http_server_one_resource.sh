#!/bin/bash
# Start MCP Docker server in HTTP mode with ONLY one resource enabled
#
# This script starts the MCP Docker server with a single resource enabled:
# container_logs. This is useful for minimal monitoring configurations where
# you only need to access container logs.
#
# Only this resource is enabled:
# - container_logs: Access container logs via URI (container://logs/{container_id})
#
# All other resources are DISABLED:
# - container_stats
#
# All tools and prompts are also DISABLED by default.
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_one_resource.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_one_resource.sh
#
#   # With environment file
#   source ../env/.env.one_resource && ./start_http_server_one_resource.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Only allow the container_logs resource, disable everything else
ALLOWED_RESOURCES="container_logs"

# Print header and configuration
print_header "One Resource Only (container_logs)"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
echo "Safety Configuration:"
echo "  Allow Moderate Operations: false"
echo "  Allow Destructive Operations: false"
echo "  Allowed Tools: None (empty)"
echo "  Allowed Prompts: None (empty)"
echo "  Allowed Resources: $ALLOWED_RESOURCES"
echo ""
print_tls_warning
print_instructions

# Explicitly disable tools and prompts, enable only one resource
export SAFETY_ALLOWED_TOOLS=""
export SAFETY_ALLOWED_PROMPTS=""
export SAFETY_ALLOWED_RESOURCES="$ALLOWED_RESOURCES"
export SAFETY_ALLOW_MODERATE_OPERATIONS="false"
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="false"
export MCP_LOG_LEVEL="$LOG_LEVEL"
export MCP_DEBUG_MODE="$DEBUG_MODE"

# Start the server
exec uv run python -m mcp_docker --transport http --host "$HOST" --port "$PORT"
