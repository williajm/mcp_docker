# HTTP Stream Transport Configuration Examples

This document provides comprehensive configuration examples for the HTTP Stream Transport in mcp-docker.

## Table of Contents

- [Basic Development Setup](#basic-development-setup)
- [Production Setup with TLS](#production-setup-with-tls)
- [OAuth/OIDC Authentication](#oauthoidc-authentication)
- [Browser Client with CORS](#browser-client-with-cors)
- [Resumability Configuration](#resumability-configuration)
- [Batch Response Mode](#batch-response-mode)
- [Stateless Mode](#stateless-mode)
- [Complete Production Configuration](#complete-production-configuration)

## Basic Development Setup

Simple localhost development with streaming responses:

```bash
# Start server on localhost
mcp-docker --transport httpstream --host 127.0.0.1 --port 8000
```

**Default Configuration:**
- Streaming responses (SSE)
- Resumability enabled
- No TLS (HTTP only)
- No authentication
- No CORS

**Use Case:** Local development and testing.

## Production Setup with TLS

Enable TLS/HTTPS for network deployments:

### Generate Self-Signed Certificate

```bash
# Create certificate directory
mkdir -p ~/.mcp-docker/certs

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 \
  -keyout ~/.mcp-docker/certs/key.pem \
  -out ~/.mcp-docker/certs/cert.pem \
  -days 365 -nodes \
  -subj '/CN=localhost'
```

### Environment Variables

```bash
# TLS Configuration
export MCP_TLS_ENABLED=true
export MCP_TLS_CERT_FILE=~/.mcp-docker/certs/cert.pem
export MCP_TLS_KEY_FILE=~/.mcp-docker/certs/key.pem

# HTTP Stream Transport
export HTTPSTREAM_DNS_REBINDING_PROTECTION=true
export HTTPSTREAM_ALLOWED_HOSTS='["api.example.com", "192.0.2.1"]'

# Security
export SECURITY_RATE_LIMIT_ENABLED=true
export SECURITY_RATE_LIMIT_RPM=60
export SECURITY_AUDIT_LOG_ENABLED=true

# Safety
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Start server
mcp-docker --transport httpstream --host 0.0.0.0 --port 8443
```

**Use Case:** Production deployments with encrypted transport.

## OAuth/OIDC Authentication

Integrate with OAuth 2.0 or OpenID Connect providers:

```bash
# OAuth Configuration
export SECURITY_OAUTH_ENABLED=true
export SECURITY_OAUTH_ISSUER=https://auth.example.com
export SECURITY_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json
export SECURITY_OAUTH_AUDIENCE=mcp-docker-api
export SECURITY_OAUTH_REQUIRED_SCOPES=docker.read,docker.write

# Optional: Token introspection (for opaque tokens)
export SECURITY_OAUTH_INTROSPECTION_URL=https://auth.example.com/oauth/introspect
export SECURITY_OAUTH_INTROSPECTION_CLIENT_ID=mcp-docker-client
export SECURITY_OAUTH_INTROSPECTION_CLIENT_SECRET=your-client-secret

# TLS (required for production)
export MCP_TLS_ENABLED=true
export MCP_TLS_CERT_FILE=~/.mcp-docker/certs/cert.pem
export MCP_TLS_KEY_FILE=~/.mcp-docker/certs/key.pem

# Start server
mcp-docker --transport httpstream --host 0.0.0.0 --port 8443
```

**Client Request Example:**

```bash
# Include Bearer token in Authorization header
curl -X POST https://api.example.com/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

**Use Case:** Enterprise deployments with centralized authentication.

## Browser Client with CORS

Enable CORS for web-based MCP clients:

```bash
# CORS Configuration
export CORS_ENABLED=true
export CORS_ALLOW_ORIGINS='["https://app.example.com", "https://admin.example.com"]'
export CORS_ALLOW_CREDENTIALS=true
export CORS_ALLOW_METHODS='["GET", "POST", "OPTIONS"]'
export CORS_ALLOW_HEADERS='["Content-Type", "Authorization", "mcp-session-id", "last-event-id"]'
export CORS_EXPOSE_HEADERS='["mcp-session-id"]'
export CORS_MAX_AGE=3600

# TLS (required for credentials)
export MCP_TLS_ENABLED=true
export MCP_TLS_CERT_FILE=~/.mcp-docker/certs/cert.pem
export MCP_TLS_KEY_FILE=~/.mcp-docker/certs/key.pem

# Start server
mcp-docker --transport httpstream --host 0.0.0.0 --port 8443
```

**JavaScript Client Example:**

```javascript
// Browser client with credentials
fetch('https://api.example.com/', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer YOUR_TOKEN'
  },
  credentials: 'include',  // Send cookies and auth headers
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'tools/list',
    id: 1
  })
});
```

**Security Notes:**
- Never use wildcard origin (`*`) with credentials
- Always use HTTPS in production
- Specify explicit allowed origins

**Use Case:** Web applications that need to call the MCP server from the browser.

## Resumability Configuration

Configure message history and reconnection support:

```bash
# Resumability Settings
export HTTPSTREAM_RESUMABILITY_ENABLED=true
export HTTPSTREAM_EVENT_STORE_MAX_EVENTS=2000  # Increase for more history
export HTTPSTREAM_EVENT_STORE_TTL_SECONDS=600  # 10 minutes

# Start server
mcp-docker --transport httpstream --host 127.0.0.1 --port 8000
```

**Client Reconnection Example:**

```bash
# Initial request - server returns mcp-session-id and event IDs
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'

# Response headers include:
#   mcp-session-id: abc123...
#   (events include event-id in SSE format)

# Reconnect after disconnect - replay missed events
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: abc123..." \
  -H "last-event-id: def456..." \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 2}'
```

**Configuration Tips:**
- `max_events`: Balance memory usage vs. history depth
- `ttl_seconds`: Match your expected reconnection window
- Larger values use more memory but support longer disconnections

**Use Case:** Unreliable networks, mobile clients, long-running operations.

## Batch Response Mode

Switch from streaming (SSE) to batch (JSON) responses:

```bash
# Enable batch mode (all responses as complete JSON arrays)
export HTTPSTREAM_JSON_RESPONSE_DEFAULT=true

# Start server
mcp-docker --transport httpstream --host 127.0.0.1 --port 8000
```

**Response Format:**

```json
// Streaming mode (default): SSE format
data: {"jsonrpc": "2.0", "result": {...}, "id": 1}

// Batch mode: Complete JSON array
[
  {"jsonrpc": "2.0", "result": {...}, "id": 1}
]
```

**Configuration:**
- `HTTPSTREAM_JSON_RESPONSE_DEFAULT=false`: Streaming mode (SSE) - default
- `HTTPSTREAM_JSON_RESPONSE_DEFAULT=true`: Batch mode (JSON arrays)

**Use Case:** Clients that prefer complete responses over streaming, simpler parsing.

## Stateless Mode

Disable session management for horizontal scaling:

```bash
# Stateless Configuration
export HTTPSTREAM_STATELESS_MODE=true
export HTTPSTREAM_RESUMABILITY_ENABLED=false  # No message history in stateless

# Start server
mcp-docker --transport httpstream --host 127.0.0.1 --port 8000
```

**Behavior:**
- No `mcp-session-id` headers
- No message history or event store
- Each request is independent
- Easier to load balance across multiple servers

**Trade-offs:**
- ✅ Simpler horizontal scaling
- ✅ Lower memory usage
- ❌ No resumability
- ❌ No reconnection support

**Use Case:** High-scale deployments with load balancers, stateless microservices.

## Complete Production Configuration

Full-featured production setup with all security and reliability features:

```bash
#!/bin/bash
# Production HTTP Stream Transport Configuration

# TLS/HTTPS (required)
export MCP_TLS_ENABLED=true
export MCP_TLS_CERT_FILE=/etc/mcp-docker/certs/cert.pem
export MCP_TLS_KEY_FILE=/etc/mcp-docker/certs/key.pem

# HTTP Stream Transport
export HTTPSTREAM_JSON_RESPONSE_DEFAULT=false  # Streaming (SSE)
export HTTPSTREAM_STATELESS_MODE=false
export HTTPSTREAM_RESUMABILITY_ENABLED=true
export HTTPSTREAM_EVENT_STORE_MAX_EVENTS=2000
export HTTPSTREAM_EVENT_STORE_TTL_SECONDS=600
export HTTPSTREAM_DNS_REBINDING_PROTECTION=true
export HTTPSTREAM_ALLOWED_HOSTS='["api.example.com", "api-backup.example.com"]'

# CORS (for browser clients)
export CORS_ENABLED=true
export CORS_ALLOW_ORIGINS='["https://app.example.com"]'
export CORS_ALLOW_CREDENTIALS=true
export CORS_ALLOW_METHODS='["GET", "POST", "OPTIONS"]'
export CORS_ALLOW_HEADERS='["Content-Type", "Authorization", "mcp-session-id", "last-event-id"]'
export CORS_EXPOSE_HEADERS='["mcp-session-id"]'
export CORS_MAX_AGE=3600

# OAuth/OIDC Authentication
export SECURITY_OAUTH_ENABLED=true
export SECURITY_OAUTH_ISSUER=https://auth.example.com
export SECURITY_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json
export SECURITY_OAUTH_AUDIENCE=mcp-docker-api
export SECURITY_OAUTH_REQUIRED_SCOPES=docker.read,docker.write

# Optional: Token introspection
# export SECURITY_OAUTH_INTROSPECTION_URL=https://auth.example.com/oauth/introspect
# export SECURITY_OAUTH_INTROSPECTION_CLIENT_ID=mcp-docker-client
# export SECURITY_OAUTH_INTROSPECTION_CLIENT_SECRET=your-secret

# IP Filtering (optional - restricts by client IP)
# export SECURITY_ALLOWED_CLIENT_IPS='["10.0.0.0/8", "192.168.1.100"]'

# Rate Limiting
export SECURITY_RATE_LIMIT_ENABLED=true
export SECURITY_RATE_LIMIT_RPM=60

# Audit Logging
export SECURITY_AUDIT_LOG_ENABLED=true
export SECURITY_AUDIT_LOG_FILE=/var/log/mcp-docker/audit.log

# Safety Controls
export SAFETY_ALLOW_MODERATE_OPERATIONS=true
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
# export SAFETY_DENIED_TOOLS=docker_system_prune,docker_remove_volume

# Docker Configuration
export DOCKER_BASE_URL=unix:///var/run/docker.sock

# Start server
exec mcp-docker --transport httpstream --host 0.0.0.0 --port 8443
```

**Production Checklist:**

- ✅ TLS/HTTPS enabled with valid certificates
- ✅ OAuth/OIDC authentication configured
- ✅ Rate limiting enabled
- ✅ Audit logging enabled
- ✅ Destructive operations disabled
- ✅ DNS rebinding protection with allowed hosts
- ✅ CORS configured for web clients (if needed)
- ✅ Resumability enabled for reliability
- ✅ Regular certificate rotation
- ✅ Audit log monitoring
- ✅ Docker socket permissions restricted

**Use Case:** Enterprise production deployments with maximum security and reliability.

## Quick Reference

| Feature | Environment Variable | Default | Production Recommendation |
|---------|---------------------|---------|---------------------------|
| TLS/HTTPS | `MCP_TLS_ENABLED` | `false` | `true` (required) |
| Response Mode | `HTTPSTREAM_JSON_RESPONSE_DEFAULT` | `false` (streaming) | `false` (streaming) |
| Resumability | `HTTPSTREAM_RESUMABILITY_ENABLED` | `true` | `true` |
| Event History | `HTTPSTREAM_EVENT_STORE_MAX_EVENTS` | `1000` | `1000-5000` |
| Event TTL | `HTTPSTREAM_EVENT_STORE_TTL_SECONDS` | `300` (5 min) | `300-600` |
| DNS Protection | `HTTPSTREAM_DNS_REBINDING_PROTECTION` | `true` | `true` |
| CORS | `CORS_ENABLED` | `false` | `true` (if browser clients) |
| OAuth | `SECURITY_OAUTH_ENABLED` | `false` | `true` (required) |
| Rate Limiting | `SECURITY_RATE_LIMIT_ENABLED` | `false` | `true` |
| Audit Logging | `SECURITY_AUDIT_LOG_ENABLED` | `false` | `true` |

## Troubleshooting

### DNS Rebinding Errors

**Error:** `Invalid Host header - potential DNS rebinding attack`

**Solution:** Add your domain to allowed hosts:
```bash
export HTTPSTREAM_ALLOWED_HOSTS='["api.example.com", "192.0.2.1"]'
```

### CORS Errors

**Error:** `CORS policy: No 'Access-Control-Allow-Origin' header`

**Solution:** Enable CORS and add your origin:
```bash
export CORS_ENABLED=true
export CORS_ALLOW_ORIGINS='["https://app.example.com"]'
```

### Session Not Found

**Error:** Session expired or event history lost

**Solution:** Increase TTL or max events:
```bash
export HTTPSTREAM_EVENT_STORE_TTL_SECONDS=600  # 10 minutes
export HTTPSTREAM_EVENT_STORE_MAX_EVENTS=2000
```

### OAuth Token Rejected

**Error:** `Invalid token` or `Token validation failed`

**Solution:** Verify OAuth configuration:
```bash
# Check JWKS URL is accessible
curl https://auth.example.com/.well-known/jwks.json

# Verify audience matches your token
export SECURITY_OAUTH_AUDIENCE=mcp-docker-api
```

## See Also

- [README.md](../../README.md) - Main documentation
- [SECURITY.md](../../SECURITY.md) - Security best practices
- [MCP HTTP Stream Transport Specification](https://mcp-framework.com/docs/Transports/http-stream-transport)
