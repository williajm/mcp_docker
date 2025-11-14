#!/bin/bash
# MCP Docker Server - HTTP Stream Transport with TLS
# Startup script for running the server with HTTPS (authentication disabled by default)

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== MCP Docker Server - HTTP Stream Transport ===${NC}"

# Configuration paths
CERT_DIR="$HOME/.mcp-docker/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

# Server configuration
HOST="${MCP_HOST:-localhost}"
PORT="${MCP_PORT:-8443}"

# Validate certificates exist
if [ ! -f "$CERT_FILE" ]; then
    echo -e "${RED}ERROR: Certificate not found at $CERT_FILE${NC}"
    echo -e "${YELLOW}Generate self-signed certificates with:${NC}"
    echo -e "  mkdir -p $CERT_DIR"
    echo -e "  openssl req -x509 -newkey rsa:4096 -keyout $KEY_FILE -out $CERT_FILE -days 365 -nodes -subj '/CN=localhost'"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo -e "${RED}ERROR: Private key not found at $KEY_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ TLS certificates found${NC}"
echo -e "  Cert: $CERT_FILE"
echo -e "  Key:  $KEY_FILE"

# Export environment variables
export MCP_TLS_ENABLED=true
export MCP_TLS_CERT_FILE="$CERT_FILE"
export MCP_TLS_KEY_FILE="$KEY_FILE"

# SECURITY: Debug mode is DISABLED by default for production
# Debug mode exposes detailed error messages, tracebacks, and internal state to clients
# Only enable for local development/testing by setting: export MCP_DEBUG_MODE=true
# export MCP_DEBUG_MODE=true

# HTTP Stream Transport configuration
export HTTPSTREAM_JSON_RESPONSE_DEFAULT=false  # Streaming mode (SSE)
export HTTPSTREAM_STATELESS_MODE=false
export HTTPSTREAM_RESUMABILITY_ENABLED=true
export HTTPSTREAM_EVENT_STORE_MAX_EVENTS=1000
export HTTPSTREAM_EVENT_STORE_TTL_SECONDS=300
export HTTPSTREAM_DNS_REBINDING_PROTECTION=true

# CORS (disabled by default, enable for browser clients)
export CORS_ENABLED=false
# export CORS_ALLOW_ORIGINS='["https://app.example.com"]'
# export CORS_ALLOW_CREDENTIALS=true

# Security configuration
# OAuth/OIDC Authentication (disabled by default)
export SECURITY_OAUTH_ENABLED=false
# export SECURITY_OAUTH_ISSUER="https://accounts.google.com"
# export SECURITY_OAUTH_AUDIENCE='["mcp-docker-api"]'
# export SECURITY_OAUTH_JWKS_URL="https://accounts.google.com/.well-known/jwks.json"
# export SECURITY_OAUTH_REQUIRED_SCOPES='["docker:read", "docker:write"]'

export SECURITY_RATE_LIMIT_ENABLED=true
export SECURITY_RATE_LIMIT_RPM=60
export SECURITY_AUDIT_LOG_ENABLED=true
export SECURITY_AUDIT_LOG_FILE="$HOME/.mcp-docker/mcp_audit.log"

# Safety configuration
export SAFETY_ALLOW_MODERATE_OPERATIONS=true
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Docker configuration
export DOCKER_BASE_URL=unix:///var/run/docker.sock

echo ""
echo -e "${GREEN}=== Security Configuration ===${NC}"
echo -e "  TLS/HTTPS:              ${GREEN}ENABLED${NC}"
echo -e "  Authentication:         ${RED}DISABLED${NC}"
echo -e "  Rate Limiting:          ${GREEN}ENABLED${NC} (60 req/min)"
echo -e "  Audit Logging:          ${GREEN}ENABLED${NC}"
echo -e "  Destructive Operations: ${RED}DISABLED${NC}"
echo ""
echo -e "${GREEN}=== HTTP Stream Transport Configuration ===${NC}"
echo -e "  Response Mode:          ${GREEN}Streaming (SSE)${NC}"
echo -e "  Resumability:           ${GREEN}ENABLED${NC}"
echo -e "  Event Store Max Events: 1000"
echo -e "  Event Store TTL:        300s (5 minutes)"
echo -e "  DNS Rebinding Protect:  ${GREEN}ENABLED${NC}"
echo -e "  CORS:                   ${RED}DISABLED${NC}"
echo ""
echo -e "${GREEN}=== Server Configuration ===${NC}"
echo -e "  Host:                   $HOST"
echo -e "  Port:                   $PORT"
echo -e "  Endpoint:               https://$HOST:$PORT/"
echo -e "  Protocol:               HTTP Stream Transport (POST /)"
echo ""

# Check if Docker is accessible
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}WARNING: Cannot connect to Docker daemon${NC}"
    echo -e "Make sure Docker is running and you have permission to access it."
    echo ""
fi

echo -e "${GREEN}Starting MCP Docker server...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Run the server
exec uv run mcp-docker --transport httpstream --host "$HOST" --port "$PORT"
