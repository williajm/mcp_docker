#!/bin/bash
# Start MCP Docker server in HTTP mode with SAFE operations only
#
# This script starts the MCP Docker server with only SAFE (read-only) operations enabled.
# Perfect for read-only monitoring and inspection use cases.
#
# SAFE operations include:
# - Listing containers, images, networks, volumes
# - Inspecting container/image details
# - Reading container logs
# - Getting container stats
# - Viewing system info
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_safe.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_safe.sh
#
#   # With environment file
#   source ../env/.env.safe && ./start_http_server_safe.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Print header and configuration
print_header "SAFE Operations Only (Read-Only)"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
print_safety_config "false" "false" "All SAFE tools"
print_tls_warning
print_instructions

# Start server with SAFE operations only
start_server "false" "false" ""
