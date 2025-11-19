#!/bin/bash
# Start MCP Docker server in HTTP mode with ALL operations (including DESTRUCTIVE)
#
# This script starts the MCP Docker server with ALL operations enabled, including
# DESTRUCTIVE operations that can permanently delete data.
#
# ⚠️  WARNING: This configuration allows DESTRUCTIVE operations! ⚠️
# Use with caution and only in controlled environments.
#
# SAFE operations: All read-only operations
# MODERATE operations: Reversible management operations
#
# DESTRUCTIVE operations include:
# - Force removing containers (with dependencies)
# - Force removing images (with dependencies)
# - Pruning containers, images, networks, volumes, system
# - Pushing images to registries
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_destructive.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_destructive.sh
#
#   # With environment file
#   source ../env/.env.destructive && ./start_http_server_destructive.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Print header and configuration
print_header "⚠️  ALL Operations (Including DESTRUCTIVE) ⚠️"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
print_safety_config "true" "true" "All SAFE, MODERATE, and DESTRUCTIVE tools"
print_tls_warning
echo "⚠️  DESTRUCTIVE OPERATIONS ENABLED ⚠️"
echo "   This configuration can permanently delete data!"
echo "   Use with caution in controlled environments."
echo ""
print_instructions

# Start server with ALL operations enabled
start_server "true" "true" ""
