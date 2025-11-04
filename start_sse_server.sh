#!/bin/bash

# MCP Docker SSE Server Startup Script
# This script starts the MCP Docker server with SSE transport over HTTP

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_HOST="127.0.0.1"
DEFAULT_PORT="8000"
DEFAULT_TRANSPORT="sse"

# Override with environment variables if set
SSE_HOST="${SSE_HOST:-$DEFAULT_HOST}"
SSE_PORT="${SSE_PORT:-$DEFAULT_PORT}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            SSE_HOST="$2"
            shift 2
            ;;
        -p|--port)
            SSE_PORT="$2"
            shift 2
            ;;
        --help)
            echo -e "${BLUE}MCP Docker SSE Server Startup Script${NC}"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -h, --host HOST    Set the host to bind to (default: 127.0.0.1)"
            echo "  -p, --port PORT    Set the port to bind to (default: 8000)"
            echo "  --help             Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  SSE_HOST                              Override default host"
            echo "  SSE_PORT                              Override default port"
            echo "  DOCKER_BASE_URL                       Docker socket URL (default: unix:///var/run/docker.sock)"
            echo "  SAFETY_ALLOW_MODERATE_OPERATIONS      Allow state-changing operations (default: true)"
            echo "  SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS   Allow destructive operations (default: false)"
            echo "  SAFETY_ALLOW_PRIVILEGED_CONTAINERS    Allow privileged containers (default: false)"
            echo "  MCP_LOG_LEVEL                         Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)"
            echo "  MCP_DOCKER_LOG_PATH                   Custom log file path (optional)"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Start with defaults (127.0.0.1:8000)"
            echo "  $0 --host 0.0.0.0 --port 8080        # Bind to all interfaces on port 8080"
            echo "  SSE_PORT=9000 $0                      # Use environment variable for port"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Print banner
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MCP Docker SSE Server Startup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if Docker is available
echo -e "${YELLOW}[1/4]${NC} Checking Docker availability..."
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        echo -e "${GREEN}✓${NC} Docker is available and running"
    else
        echo -e "${RED}✗${NC} Docker daemon is not running"
        echo -e "${YELLOW}Please start Docker and try again${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗${NC} Docker is not installed"
    echo -e "${YELLOW}Please install Docker and try again${NC}"
    exit 1
fi

# Check if uv is available (preferred method)
echo -e "${YELLOW}[2/4]${NC} Checking for uv package manager..."
if command -v uv &> /dev/null; then
    UV_VERSION=$(uv --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} uv $UV_VERSION detected (will manage Python version automatically)"
    USE_UV=true
else
    echo -e "${YELLOW}⚠${NC} uv not found, checking for manual installation..."
    USE_UV=false

    # Fallback: Check if Python 3.11+ is available
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 11 ]; then
            echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION detected"
        else
            echo -e "${RED}✗${NC} Python 3.11+ is required (found: $PYTHON_VERSION)"
            echo -e "${YELLOW}Install uv for automatic Python version management: https://github.com/astral-sh/uv${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗${NC} Python 3 is not installed"
        echo -e "${YELLOW}Install uv for automatic Python version management: https://github.com/astral-sh/uv${NC}"
        exit 1
    fi
fi

# Check if mcp-docker is available
echo -e "${YELLOW}[3/4]${NC} Checking MCP Docker installation..."
if [ "$USE_UV" = true ]; then
    # Check if we're in the project directory or if mcp-docker is installed
    if [ -f "$(dirname "$0")/pyproject.toml" ]; then
        echo -e "${GREEN}✓${NC} Using uv to run from local project (will sync dependencies if needed)"
        USE_METHOD="uv-local"
    else
        echo -e "${GREEN}✓${NC} Using uvx to run mcp-docker"
        USE_METHOD="uvx"
    fi
elif command -v mcp-docker &> /dev/null; then
    echo -e "${GREEN}✓${NC} mcp-docker command found"
    USE_METHOD="direct"
elif [ -f "$(dirname "$0")/src/mcp_docker/__main__.py" ]; then
    echo -e "${GREEN}✓${NC} Using local source code with python3"
    USE_METHOD="source"
else
    echo -e "${RED}✗${NC} mcp-docker is not installed"
    echo -e "${YELLOW}Please install with: uvx mcp-docker${NC}"
    echo -e "${YELLOW}Or install uv and run from project directory${NC}"
    exit 1
fi

# Display configuration
echo -e "${YELLOW}[4/4]${NC} Starting SSE server with configuration:"
echo -e "  Transport:  ${GREEN}SSE (Server-Sent Events)${NC}"
echo -e "  Host:       ${GREEN}$SSE_HOST${NC}"
echo -e "  Port:       ${GREEN}$SSE_PORT${NC}"
echo -e "  URL:        ${GREEN}http://$SSE_HOST:$SSE_PORT/sse${NC}"
echo ""

# Display safety configuration if set
if [ -n "$SAFETY_ALLOW_MODERATE_OPERATIONS" ] || [ -n "$SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS" ]; then
    echo -e "${YELLOW}Safety Configuration:${NC}"
    [ -n "$SAFETY_ALLOW_MODERATE_OPERATIONS" ] && echo -e "  Moderate Operations:    ${GREEN}$SAFETY_ALLOW_MODERATE_OPERATIONS${NC}"
    [ -n "$SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS" ] && echo -e "  Destructive Operations: ${GREEN}$SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS${NC}"
    [ -n "$SAFETY_ALLOW_PRIVILEGED_CONTAINERS" ] && echo -e "  Privileged Containers:  ${GREEN}$SAFETY_ALLOW_PRIVILEGED_CONTAINERS${NC}"
    echo ""
fi

# Enable all operations (set to false to restrict destructive operations)
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true

# Setup signal handlers for graceful shutdown
trap 'echo -e "\n${YELLOW}Shutting down SSE server...${NC}"; exit 0' SIGINT SIGTERM

# Start the server
echo -e "${GREEN}Server starting...${NC}"
echo -e "${BLUE}----------------------------------------${NC}"
echo ""

case "$USE_METHOD" in
    uv-local)
        # Use uv to run from local project (syncs dependencies and uses correct Python version)
        cd "$(dirname "$0")"
        exec uv run mcp-docker --transport "$DEFAULT_TRANSPORT" --host "$SSE_HOST" --port "$SSE_PORT"
        ;;
    uvx)
        # Use uvx to run mcp-docker (automatically manages Python version)
        exec uvx mcp-docker --transport "$DEFAULT_TRANSPORT" --host "$SSE_HOST" --port "$SSE_PORT"
        ;;
    direct)
        # Use installed mcp-docker command
        exec mcp-docker --transport "$DEFAULT_TRANSPORT" --host "$SSE_HOST" --port "$SSE_PORT"
        ;;
    source)
        # Use local source code with python3 (fallback)
        cd "$(dirname "$0")"
        exec python3 -m mcp_docker --transport "$DEFAULT_TRANSPORT" --host "$SSE_HOST" --port "$SSE_PORT"
        ;;
    *)
        echo -e "${RED}✗${NC} Unknown execution method: $USE_METHOD"
        exit 1
        ;;
esac
