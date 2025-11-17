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

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURITY_OAUTH_ENABLED` | `false` | Enable OAuth2/OIDC authentication (network transports only) |
| `SECURITY_OAUTH_ISSUER` | `null` | OAuth issuer URL |
| `SECURITY_OAUTH_AUDIENCE` | `[]` | Valid token audiences (JSON array) |
| `SECURITY_OAUTH_JWKS_URL` | `null` | JWKS endpoint for token verification |
| `SECURITY_OAUTH_REQUIRED_SCOPES` | `[]` | Required scopes (comma-separated) |
| `SECURITY_OAUTH_INTROSPECTION_URL` | `null` | Token introspection endpoint (optional) |
| `SECURITY_OAUTH_CLIENT_ID` | `null` | Client ID for introspection |
| `SECURITY_OAUTH_CLIENT_SECRET` | `null` | Client secret for introspection |
| `SECURITY_OAUTH_CLOCK_SKEW_SECONDS` | `60` | Clock skew tolerance for validation |

For OAuth setup with popular identity providers (Auth0, Keycloak, Azure AD, AWS Cognito), see [SECURITY.md](SECURITY.md#oauth-authentication).

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

## Transport Selection

See [README.md](README.md#usage) for transport options and startup commands.

---

## Common Configuration Scenarios

**Local Development (stdio):** No configuration needed - `uv run mcp-docker`

**Development Server (HTTP, no reverse proxy):**

```bash
# Security (development only - use reverse proxy in production)
SECURITY_OAUTH_ENABLED=false
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_ALLOWED_CLIENT_IPS=["127.0.0.1"]

# Start: uv run mcp-docker --transport http --host 127.0.0.1 --port 8000
```

⚠️ **Warning:** Never expose HTTP transport directly to the internet without a reverse proxy providing HTTPS, authentication, and rate limiting.

**Production Server (HTTP behind reverse proxy):**

For production, deploy behind NGINX/Caddy reverse proxy that provides:

- HTTPS/TLS termination
- OAuth/authentication
- Rate limiting
- IP filtering

```bash
# Server config
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_AUDIT_LOG_ENABLED=true

# Safety
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Start: uv run mcp-docker --transport http --host 127.0.0.1 --port 8000
# (Reverse proxy handles external HTTPS and forwards to localhost:8000)
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
