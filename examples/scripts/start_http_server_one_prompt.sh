#!/bin/bash
# Start MCP Docker server in HTTP mode with ONLY one prompt enabled
#
# This script starts the MCP Docker server with a single prompt enabled:
# troubleshoot_container. This is useful for minimal AI assistant configurations
# where you only want container troubleshooting capabilities.
#
# Only this prompt is enabled:
# - troubleshoot_container: Diagnose and troubleshoot container issues
#
# All other prompts are DISABLED:
# - optimize_container
# - generate_compose
# - debug_networking
# - security_audit
#
# All tools and resources are also DISABLED by default.
#
# For production deployments, use a reverse proxy (NGINX, Caddy) for:
# - HTTPS/TLS termination
# - Authentication
# - Rate limiting
#
# Usage:
#   ./start_http_server_one_prompt.sh
#
#   # With custom host/port
#   MCP_HOST=0.0.0.0 MCP_PORT=8000 ./start_http_server_one_prompt.sh
#
#   # With environment file
#   source ../env/.env.one_prompt && ./start_http_server_one_prompt.sh
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common.sh"

# Get default configuration
get_default_config

# Only allow the troubleshoot_container prompt, disable everything else
ALLOWED_PROMPTS="troubleshoot_container"

# Print header and configuration
print_header "One Prompt Only (troubleshoot_container)"
print_config "$HOST" "$PORT" "$LOG_LEVEL" "$DEBUG_MODE"
echo "Safety Configuration:"
echo "  Allow Moderate Operations: false"
echo "  Allow Destructive Operations: false"
echo "  Allowed Tools: None (empty)"
echo "  Allowed Prompts: $ALLOWED_PROMPTS"
echo "  Allowed Resources: None (empty)"
echo ""
print_tls_warning
print_instructions

# Explicitly disable tools and resources, enable only one prompt
export SAFETY_ALLOWED_TOOLS=""
export SAFETY_ALLOWED_PROMPTS="$ALLOWED_PROMPTS"
export SAFETY_ALLOWED_RESOURCES=""
export SAFETY_ALLOW_MODERATE_OPERATIONS="false"
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="false"
export MCP_LOG_LEVEL="$LOG_LEVEL"
export MCP_DEBUG_MODE="$DEBUG_MODE"

# Start the server
exec uv run python -m mcp_docker --transport http --host "$HOST" --port "$PORT"
