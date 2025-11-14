# Configuration Reference

Complete reference for all MCP Docker server configuration options.

## Quick Start

All configuration is via environment variables. For local development, create a `.env` file:

```bash
# Example .env file
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
SECURITY_RATE_LIMIT_RPM=60
```

For production deployments, see [SECURITY.md](SECURITY.md) for security best practices.

---

## Docker Configuration

Controls connection to Docker daemon.

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_BASE_URL` | Auto-detected | Docker daemon socket URL<br>• **Linux/macOS/WSL**: `unix:///var/run/docker.sock`<br>• **Windows**: `npipe:////./pipe/docker_engine` |
| `DOCKER_TIMEOUT` | `60` | Default timeout for Docker operations (seconds) |
| `DOCKER_TLS_VERIFY` | `false` | Enable TLS verification for Docker daemon |
| `DOCKER_TLS_CA_CERT` | `null` | Path to CA certificate for Docker TLS |
| `DOCKER_TLS_CLIENT_CERT` | `null` | Path to client certificate for Docker TLS |
| `DOCKER_TLS_CLIENT_KEY` | `null` | Path to client key for Docker TLS |

---

## Safety Configuration

Controls which operations are allowed and safety limits.

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFETY_ALLOW_MODERATE_OPERATIONS` | `true` | Allow reversible operations (start/stop containers) |
| `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS` | `false` | Allow permanent operations (delete containers/images) |
| `SAFETY_ALLOW_PRIVILEGED_CONTAINERS` | `false` | Allow creating privileged containers |
| `SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE` | `true` | Require explicit confirmation for destructive ops |
| `SAFETY_MAX_CONCURRENT_OPERATIONS` | `10` | Maximum concurrent Docker operations |
| `SAFETY_MAX_LOG_LINES` | `10000` | Maximum log lines to return |
| `SAFETY_MAX_EXEC_OUTPUT_BYTES` | `1048576` | Maximum exec command output (1 MB) |
| `SAFETY_MAX_LIST_RESULTS` | `1000` | Maximum items in list results |
| `SAFETY_TRUNCATE_INSPECT_OUTPUT` | `false` | Truncate large inspect responses |
| `SAFETY_MAX_INSPECT_FIELD_BYTES` | `65536` | Maximum size of inspect fields (64 KB) |
| `SAFETY_ALLOWED_TOOLS` | `[]` | Comma-separated list of allowed tools (empty = all)<br>Example: `docker_list_containers,docker_inspect_container` |
| `SAFETY_DENIED_TOOLS` | `[]` | Comma-separated list of denied tools<br>Example: `docker_system_prune,docker_remove_container` |

**Note**: `SAFETY_ALLOWED_TOOLS` and `SAFETY_DENIED_TOOLS` are mutually exclusive. Use one or the other.

---

## Security Configuration

Controls authentication, authorization, and audit logging.

### General Security

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_AUDIT_LOG_ENABLED` | `true` | Enable audit logging of all operations |
| `SECURITY_AUDIT_LOG_FILE` | `mcp_audit.log` | Path to audit log file |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_RATE_LIMIT_ENABLED` | `true` | Enable per-client rate limiting |
| `SECURITY_RATE_LIMIT_RPM` | `60` | Maximum requests per minute per client |
| `SECURITY_RATE_LIMIT_CONCURRENT` | `3` | Maximum concurrent requests per client |

### IP Filtering

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_ALLOWED_CLIENT_IPS` | `[]` | JSON array of allowed client IPs (empty = all)<br>Example: `["127.0.0.1", "192.168.1.100"]` |
| `SECURITY_TRUSTED_PROXIES` | `[]` | JSON array of trusted proxy IPs for X-Forwarded-For |

### OAuth Authentication

OAuth is only enforced for network transports (SSE/HTTP Stream). stdio transport always bypasses authentication.

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_OAUTH_ENABLED` | `false` | Enable OAuth2/OIDC authentication |
| `SECURITY_OAUTH_ISSUER` | `null` | OAuth issuer URL (e.g., `https://auth.example.com/`) |
| `SECURITY_OAUTH_AUDIENCE` | `[]` | JSON array of valid audiences (e.g., `["mcp-docker-api"]`) |
| `SECURITY_OAUTH_JWKS_URL` | `null` | JWKS endpoint URL for token verification |
| `SECURITY_OAUTH_REQUIRED_SCOPES` | `[]` | Required OAuth scopes (comma-separated) |
| `SECURITY_OAUTH_INTROSPECTION_URL` | `null` | Token introspection endpoint (optional) |
| `SECURITY_OAUTH_CLIENT_ID` | `null` | OAuth client ID for introspection |
| `SECURITY_OAUTH_CLIENT_SECRET` | `null` | OAuth client secret for introspection |
| `SECURITY_OAUTH_CLOCK_SKEW_SECONDS` | `60` | Allowed clock skew for token validation |

---

## Server Configuration

Controls server behavior and TLS settings.

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVER_NAME` | `mcp-docker` | Server name in MCP protocol |
| `MCP_SERVER_VERSION` | (from package) | Server version |
| `MCP_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `MCP_JSON_LOGGING` | `false` | Enable JSON-formatted logs |
| `MCP_DEBUG_MODE` | `false` | Enable debug mode (verbose logging) |
| `MCP_TLS_ENABLED` | `false` | Enable TLS/HTTPS for network transports |
| `MCP_TLS_CERT_FILE` | `null` | Path to TLS certificate (required if TLS enabled) |
| `MCP_TLS_KEY_FILE` | `null` | Path to TLS private key (required if TLS enabled) |

---

## HTTP Stream Transport Configuration

HTTP Stream Transport is the modern network transport (recommended over SSE).

### Response Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPSTREAM_JSON_RESPONSE_DEFAULT` | `false` | Default response mode<br>• `false`: Streaming SSE (default, recommended)<br>• `true`: Batch JSON (for simple clients) |
| `HTTPSTREAM_STATELESS_MODE` | `false` | Disable session tracking<br>• `false`: Session-based (default)<br>• `true`: Stateless (no session management) |

### Session Resumability

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPSTREAM_RESUMABILITY_ENABLED` | `true` | Enable stream resumability with EventStore |
| `HTTPSTREAM_EVENT_STORE_MAX_EVENTS` | `1000` | Maximum events in history (100-10000) |
| `HTTPSTREAM_EVENT_STORE_TTL_SECONDS` | `300` | Event expiration time (60-3600 seconds) |

### DNS Rebinding Protection

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPSTREAM_DNS_REBINDING_PROTECTION` | `true` | Enable DNS rebinding attack protection<br>• `true`: Restrict Host header to allowed hosts (production)<br>• `false`: Allow any Host header (**UNSAFE**, dev only) |
| `HTTPSTREAM_ALLOWED_HOSTS` | `[]` | JSON array of allowed hostnames/IPs<br>Example: `["api.example.com", "192.168.1.100"]`<br>**Required for wildcard bindings** (0.0.0.0/::) in production |

---

## CORS Configuration

Cross-Origin Resource Sharing for browser clients.

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ENABLED` | `false` | Enable CORS middleware |
| `CORS_ALLOW_ORIGINS` | `[]` | JSON array of allowed origins<br>Example: `["https://app.example.com"]`<br>⚠️ Cannot use `["*"]` with credentials |
| `CORS_ALLOW_METHODS` | `["GET", "POST", "OPTIONS"]` | Allowed HTTP methods |
| `CORS_ALLOW_HEADERS` | `["Content-Type", "Authorization", "mcp-session-id", "last-event-id"]` | Allowed request headers |
| `CORS_EXPOSE_HEADERS` | `["mcp-session-id"]` | Headers exposed to browser |
| `CORS_ALLOW_CREDENTIALS` | `true` | Allow credentials (cookies, auth headers) |
| `CORS_MAX_AGE` | `3600` | Preflight cache duration (seconds) |

**CORS Security Notes:**
- Cannot combine wildcard origins (`["*"]`) with `CORS_ALLOW_CREDENTIALS=true`
- Always specify explicit origins in production
- See [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

## Transport Selection

Choose transport via command-line flags:

```bash
# stdio - Local process communication (default, most secure)
uv run mcp-docker --transport stdio

# HTTP Stream Transport - Modern network transport (recommended)
uv run mcp-docker --transport httpstream --host 127.0.0.1 --port 8000

# SSE - Legacy network transport (deprecated, use HTTP Stream instead)
uv run mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Transport Security:**
- **stdio**: Always secure (local only), no auth required
- **HTTP Stream/SSE**: Require TLS + authentication for production
- See [SECURITY.md](SECURITY.md) for production deployment guidelines

---

## Common Configuration Scenarios

### Local Development (stdio)

Simplest setup for local testing:

```bash
# No configuration needed - defaults are safe
uv run mcp-docker
```

### Development Server (HTTP Stream, no TLS)

For local network testing (development only):

```bash
# .env file
SECURITY_AUTH_ENABLED=false
MCP_TLS_ENABLED=false
HTTPSTREAM_DNS_REBINDING_PROTECTION=false  # Allow access from any host

# Start server
uv run mcp-docker --transport httpstream --host 0.0.0.0 --port 8000
```

⚠️ **WARNING**: This is UNSAFE for production! Only use on trusted networks.

### Production Server (HTTP Stream + TLS + OAuth)

Secure production deployment:

```bash
# .env file
MCP_TLS_ENABLED=true
MCP_TLS_CERT_FILE=/path/to/cert.pem
MCP_TLS_KEY_FILE=/path/to/key.pem

SECURITY_OAUTH_ENABLED=true
SECURITY_OAUTH_ISSUER=https://auth.example.com/
SECURITY_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json
SECURITY_OAUTH_AUDIENCE=["mcp-docker-api"]
SECURITY_OAUTH_REQUIRED_SCOPES=docker.read,docker.write

SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_RPM=60

SECURITY_AUDIT_LOG_ENABLED=true

HTTPSTREAM_DNS_REBINDING_PROTECTION=true
HTTPSTREAM_ALLOWED_HOSTS=["api.example.com", "10.0.1.50"]

CORS_ENABLED=true
CORS_ALLOW_ORIGINS=["https://app.example.com"]
CORS_ALLOW_CREDENTIALS=true

SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Start server
uv run mcp-docker --transport httpstream --host 0.0.0.0 --port 8443
```

### Browser Client (CORS)

For web applications accessing the MCP server:

```bash
# .env file
CORS_ENABLED=true
CORS_ALLOW_ORIGINS=["https://app.example.com", "https://staging.example.com"]
CORS_ALLOW_CREDENTIALS=true
CORS_ALLOW_HEADERS=["Content-Type", "Authorization", "mcp-session-id"]

HTTPSTREAM_DNS_REBINDING_PROTECTION=true
HTTPSTREAM_ALLOWED_HOSTS=["api.example.com"]

# Also enable TLS and authentication for production
MCP_TLS_ENABLED=true
SECURITY_OAUTH_ENABLED=true
```

---

## Configuration Validation

The server validates configuration on startup and will:

- **Error**: Invalid or conflicting settings (server won't start)
- **Warn**: Insecure settings (e.g., no TLS on non-localhost)
- **Info**: Applied configuration for debugging

Check logs on startup for validation messages.

---

## Environment Variable Formats

### JSON Arrays

Some variables accept JSON arrays:

```bash
# Correct formats
SECURITY_ALLOWED_CLIENT_IPS='["127.0.0.1", "192.168.1.100"]'
CORS_ALLOW_ORIGINS='["https://app1.com", "https://app2.com"]'
HTTPSTREAM_ALLOWED_HOSTS='["api.example.com", "10.0.1.50"]'
```

### Comma-Separated Lists

Alternative format for simple lists:

```bash
# Also supported
SAFETY_ALLOWED_TOOLS=docker_list_containers,docker_inspect_container
SAFETY_DENIED_TOOLS=docker_system_prune,docker_remove_container
SECURITY_OAUTH_REQUIRED_SCOPES=docker.read,docker.write
```

### Boolean Values

Use standard boolean strings:

```bash
# All equivalent to true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=True
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=1

# All equivalent to false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=False
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=0
```

---

## See Also

- [SECURITY.md](SECURITY.md) - Production security guidelines
- [README.md](README.md) - Getting started and features
- [src/mcp_docker/config.py](src/mcp_docker/config.py) - Configuration implementation
