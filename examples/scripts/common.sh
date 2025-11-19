#!/bin/bash
# Common functions for MCP Docker HTTP server startup scripts
#
# This file provides shared functionality for all HTTP server startup scripts.
# Source this file in your startup scripts to use these functions.

set -e  # Exit on error

# Print a formatted header
print_header() {
    local title="$1"
    echo "=========================================="
    echo "MCP Docker Server - HTTP Mode"
    echo "$title"
    echo "=========================================="
}

# Print server configuration
print_config() {
    local host="$1"
    local port="$2"
    local log_level="$3"
    local debug_mode="$4"

    echo "Host: $host"
    echo "Port: $port"
    echo "Log Level: $log_level"
    echo "Debug Mode: $debug_mode"
    echo ""
}

# Print safety configuration
print_safety_config() {
    local allow_moderate="$1"
    local allow_destructive="$2"
    local allowed_tools="$3"

    echo "Safety Configuration:"
    echo "  Allow Moderate Operations: $allow_moderate"
    echo "  Allow Destructive Operations: $allow_destructive"
    if [ -n "$allowed_tools" ]; then
        echo "  Allowed Tools: $allowed_tools"
    else
        echo "  Allowed Tools: All tools for configured safety level"
    fi
    echo ""
}

# Print TLS warning
print_tls_warning() {
    echo "⚠️  WARNING: Using plain HTTP without TLS"
    echo "   For production, use a reverse proxy with HTTPS"
    echo ""
}

# Print instructions
print_instructions() {
    echo "Press Ctrl+C to stop the server"
    echo "=========================================="
    echo ""
}

# Default configuration
get_default_config() {
    export HOST="${MCP_HOST:-127.0.0.1}"
    export PORT="${MCP_PORT:-8000}"
    # Always use DEBUG level for example scripts to show what's called and returned
    export LOG_LEVEL="${MCP_LOG_LEVEL:-DEBUG}"
    export DEBUG_MODE="${MCP_DEBUG_MODE:-true}"
}

# Start the server with given safety configuration
start_server() {
    local allow_moderate="$1"
    local allow_destructive="$2"
    local allowed_tools="$3"

    # Export environment variables for the server
    export MCP_LOG_LEVEL="$LOG_LEVEL"
    export MCP_DEBUG_MODE="$DEBUG_MODE"
    export SAFETY_ALLOW_MODERATE_OPERATIONS="$allow_moderate"
    export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS="$allow_destructive"

    if [ -n "$allowed_tools" ]; then
        export SAFETY_ALLOWED_TOOLS="$allowed_tools"
    else
        # Unset to allow all tools for the configured safety level
        unset SAFETY_ALLOWED_TOOLS
    fi

    # Start the server using local code
    exec uv run python -m mcp_docker --transport http --host "$HOST" --port "$PORT"
}
