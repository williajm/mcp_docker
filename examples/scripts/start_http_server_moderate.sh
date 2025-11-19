#!/bin/bash
# Start MCP Docker server in HTTP mode with MODERATE operations
#
# This script starts the MCP Docker server with SAFE and MODERATE operations enabled.
# Suitable for most development and management use cases.
#
# SAFE operations: All read-only operations (list, inspect, logs, stats, etc.)
#
# MODERATE operations include:
# - Starting/stopping/restarting containers
# - Creating/removing containers
# - Pulling images
# - Creating/removing networks
# - Creating/removing volumes
# - Pausing/unpausing containers
# - Executing commands in containers
#
# DESTRUCTIVE operations are DISABLED:
# - Force removing containers/images (with dependencies)
# - Pruning (system-wide cleanup)
# - Pushing images to registries
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_moderate.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_moderate.sh
#
#   # With environment file
#   source ../env/.env.moderate && ./start_http_server_moderate.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Print header and configuration
print_header "SAFE + MODERATE Operations"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
print_safety_config "true" "false" "All SAFE and MODERATE tools"
print_tls_warning
print_instructions

# Start server with SAFE and MODERATE operations
start_server "true" "false" ""
