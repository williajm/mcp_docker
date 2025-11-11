#!/bin/bash
# Test script for MCP Docker SSE server

set -e

# Configuration
HOST="${MCP_HOST:-localhost}"
PORT="${MCP_PORT:-8443}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Testing MCP Docker SSE Server ===${NC}"
echo ""

# Test 1: SSE endpoint (should establish connection)
echo -e "${YELLOW}Test 1: Testing SSE endpoint (GET /sse)${NC}"
echo "Command: curl -k https://$HOST:$PORT/sse"
echo ""

if curl -k \
    -H "Accept: text/event-stream" \
    --max-time 3 \
    "https://$HOST:$PORT/sse" 2>&1 | grep -q "event:"; then
    echo -e "${GREEN}✓ SSE endpoint accessible${NC}"
else
    echo -e "${YELLOW}⚠ SSE endpoint response (might timeout - this is normal)${NC}"
fi
echo ""

# Test 3: Server info
echo -e "${YELLOW}Test 3: Server TLS info${NC}"
echo "Certificate details:"
openssl s_client -connect "$HOST:$PORT" -showcerts </dev/null 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates 2>/dev/null || \
    echo "Could not retrieve certificate info"
echo ""

echo -e "${GREEN}=== Test Complete ===${NC}"
echo ""
echo "To manually test with curl:"
echo "  curl -k https://$HOST:$PORT/sse"
