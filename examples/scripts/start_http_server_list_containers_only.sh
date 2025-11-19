#!/bin/bash
# Start MCP Docker server in HTTP mode with ONLY container listing enabled
#
# This script starts the MCP Docker server with a single tool enabled: docker_list_containers.
# This is the most restrictive configuration, suitable for minimal monitoring use cases.
#
# Only this tool is enabled:
# - docker_list_containers: List all containers with optional filtering
#
# All other operations are DISABLED, including:
# - Inspecting container details
# - Reading logs
# - Starting/stopping containers
# - Image operations
# - Network operations
# - Volume operations
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_list_containers_only.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_list_containers_only.sh
#
#   # With environment file
#   source ../env/.env.list_containers_only && ./start_http_server_list_containers_only.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Only allow the list containers tool, disable everything else
ALLOWED_TOOLS="docker_list_containers"

# Print header and configuration
print_header "List Containers Only (Minimal)"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
echo "Safety Configuration:"
echo "  Allow Moderate Operations: false"
echo "  Allow Destructive Operations: false"
echo "  Allowed Tools: $ALLOWED_TOOLS"
echo "  Allowed Prompts: None (empty)"
echo "  Allowed Resources: None (empty)"
echo ""
print_tls_warning
print_instructions

# Explicitly disable prompts and resources
export SAFETY_ALLOWED_TOOLS="$ALLOWED_TOOLS"
export SAFETY_ALLOWED_PROMPTS=""
export SAFETY_ALLOWED_RESOURCES=""
export SAFETY_ALLOW_MODERATE_OPERATIONS="false"
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="false"
export MCP_LOG_LEVEL="$LOG_LEVEL"
export MCP_DEBUG_MODE="$DEBUG_MODE"

# Start the server
exec uv run python -m mcp_docker --transport http --host "$HOST" --port "$PORT"
