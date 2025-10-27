# Security Guide

This document describes the security features of the MCP Docker server and how to configure them.

## Overview

The MCP Docker server implements multiple layers of security:

1. **Authentication** - API key validation
2. **Rate Limiting** - Prevent abuse and resource exhaustion
3. **Audit Logging** - Track all operations
4. **IP Filtering** - Network-level access control (optional)
5. **Safety Controls** - Three-tier operation classification

## Quick Start

### 1. Enable Authentication

**IMPORTANT**: Authentication is **disabled by default** for ease of development. You **MUST** enable it for production use.

```bash
# In .env file
SECURITY_AUTH_ENABLED=true
```

### 2. Generate API Keys

Use Python to generate secure API keys:

```python
import secrets

# Generate a secure 32-byte API key
api_key = secrets.token_urlsafe(32)
print(f"API Key: {api_key}")
```

Or use the command line:

```bash
# Python one-liner
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Configure API Keys

Create `.mcp_keys.json` from the example:

```bash
cp .mcp_keys.json.example .mcp_keys.json
```

Edit `.mcp_keys.json` and replace the placeholder keys with your generated keys:

```json
{
  "clients": [
    {
      "api_key": "your_generated_key_here",
      "client_id": "claude-desktop",
      "description": "Claude Desktop application",
      "enabled": true
    }
  ]
}
```

**IMPORTANT**:
- Keep `.mcp_keys.json` secure and never commit it to version control
- Use `.gitignore` to exclude it (already configured)
- Use keys of at least 32 bytes for security

### 4. Configure Clients

For **stdio transport** (Claude Desktop), API keys cannot be passed via HTTP headers. You have two options:

**Option A: Keep auth disabled for local use**
```bash
# In .env
SECURITY_AUTH_ENABLED=false
```

**Option B: Use SSE transport for remote access**
```bash
# Start server with SSE
mcp-docker --transport sse --host 127.0.0.1 --port 8000

# Clients pass API key via HTTP header
curl -H "X-MCP-API-Key: your_key_here" http://localhost:8000/sse
```

## Authentication

### API Key Authentication

The server validates API keys on every request:

1. Client sends API key in request (method varies by transport)
2. Server validates key against `.mcp_keys.json`
3. Server logs the client ID for audit purposes
4. Request proceeds if valid, rejected if invalid

### Key Management

**Adding a new client:**

1. Generate a new API key
2. Add entry to `.mcp_keys.json`:
```json
{
  "api_key": "new_generated_key",
  "client_id": "new-client",
  "description": "Description of client",
  "enabled": true
}
```
3. Restart server or call reload API (if implemented)

**Revoking access:**

Set `"enabled": false` in `.mcp_keys.json` and restart server.

**Rotating keys:**

1. Generate new key
2. Update client configuration with new key
3. Update `.mcp_keys.json` with new key
4. Restart server
5. Old key is now invalid

## Rate Limiting

Rate limiting prevents abuse and resource exhaustion:

### Requests Per Minute (RPM)

Limits total requests per client in a sliding 60-second window:

```bash
# In .env
SECURITY_RATE_LIMIT_RPM=60  # Max 60 requests per minute
```

### Concurrent Requests

Limits simultaneous requests per client:

```bash
# In .env
SECURITY_RATE_LIMIT_CONCURRENT=3  # Max 3 concurrent requests
```

### Disabling Rate Limiting

```bash
# In .env
SECURITY_RATE_LIMIT_ENABLED=false
```

**WARNING**: Disabling rate limiting may expose your server to abuse.

## Audit Logging

All operations are logged to `mcp_audit.log` (configurable):

```bash
# In .env
SECURITY_AUDIT_LOG_ENABLED=true
SECURITY_AUDIT_LOG_FILE=mcp_audit.log
```

### Audit Log Format

Each log entry is a JSON object with:

```json
{
  "timestamp": "2025-10-27T10:30:45.123456Z",
  "event_type": "tool_call",
  "client_id": "claude-desktop",
  "client_ip": "127.0.0.1",
  "api_key_hash": "abc123...",
  "tool_name": "docker_list_containers",
  "arguments": {"all": true},
  "result": {"success": true, "...": "..."},
  "error": null
}
```

### Event Types

- `tool_call` - Tool execution (success or failure)
- `auth_failure` - Authentication failure
- `rate_limit_exceeded` - Rate limit violation

### Sensitive Data

The audit logger automatically redacts sensitive fields:
- `password`, `api_key`, `token`, `secret`, `credential`, `auth`

Keys are hashed (SHA-256, truncated to 16 chars) for audit purposes.

## IP Filtering

Restrict access by IP address (optional):

```bash
# In .env (Python list format)
SECURITY_ALLOWED_CLIENT_IPS=["127.0.0.1", "192.168.1.100"]
```

Empty list (default) = allow all IPs.

**Note**: IP filtering is only effective for SSE transport. The stdio transport doesn't expose client IPs.

## Safety Controls

The existing safety system classifies operations into three tiers:

### SAFE Operations
- Read-only: list, inspect, logs, stats
- Always allowed
- No special configuration needed

### MODERATE Operations
- State-changing but reversible: start, stop, restart, create
- Generally allowed
- Can be audited

### DESTRUCTIVE Operations
- Permanent changes: remove, prune, delete
- **Requires explicit permission**:

```bash
# In .env
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
```

### Privileged Containers
- Running privileged containers requires explicit permission:

```bash
# In .env
SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true
```

## Production Deployment Checklist

Before deploying to production:

- [ ] Enable authentication (`SECURITY_AUTH_ENABLED=true`)
- [ ] Generate strong API keys (minimum 32 bytes)
- [ ] Secure `.mcp_keys.json` file (permissions, no version control)
- [ ] Enable audit logging
- [ ] Configure rate limiting appropriately
- [ ] Review and restrict `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS`
- [ ] Review and restrict `SAFETY_ALLOW_PRIVILEGED_CONTAINERS`
- [ ] Set up log rotation for audit logs
- [ ] Configure IP allowlist if applicable
- [ ] Use HTTPS for SSE transport
- [ ] Restrict Docker socket/pipe permissions at OS level
- [ ] Set up monitoring/alerting for:
  - Failed authentication attempts
  - Rate limit violations
  - Destructive operations
- [ ] Document incident response procedures
- [ ] Test authentication failures return proper errors

## Security Best Practices

### API Keys

1. **Length**: Use at least 32 bytes (43 characters in URL-safe base64)
2. **Randomness**: Use `secrets.token_urlsafe()` for cryptographic randomness
3. **Storage**: Never commit keys to version control
4. **Rotation**: Rotate keys periodically (e.g., every 90 days)
5. **Scope**: Use different keys for different clients/purposes

### Docker Socket Security

The Docker socket/pipe provides root-level access to the host system. Protect it:

1. **File Permissions**: Restrict socket permissions
   ```bash
   # Linux
   sudo chmod 660 /var/run/docker.sock
   sudo chown root:docker /var/run/docker.sock
   ```

2. **User Groups**: Only add trusted users to the `docker` group

3. **Network Exposure**: Never expose Docker socket over network without authentication

### Network Security

For SSE transport:

1. **HTTPS**: Always use HTTPS in production
2. **Firewall**: Restrict access to known IPs
3. **Reverse Proxy**: Use nginx/Apache with additional security headers
4. **Certificate**: Use valid TLS certificates

### Audit Logs

1. **Retention**: Keep logs for compliance requirements
2. **Rotation**: Use logrotate or similar tools
3. **Monitoring**: Set up alerts for suspicious activity
4. **Access Control**: Restrict who can read audit logs

## Threat Model

### Threats Mitigated

✅ **Unauthorized Access**: API key authentication blocks unauthenticated requests

✅ **Resource Exhaustion**: Rate limiting prevents DoS attacks

✅ **Audit Trail Gaps**: Comprehensive logging for forensics

✅ **Privileged Escalation**: Explicit controls for privileged containers

✅ **Network Attacks**: IP filtering limits network exposure

### Remaining Risks

⚠️ **Compromised API Key**: If a key is stolen, the attacker has full access
- Mitigation: Short-lived keys, rotation, monitoring

⚠️ **Docker Socket Access**: The server has full Docker access
- Mitigation: Principle of least privilege, socket permissions

⚠️ **Side-Channel Attacks**: Timing attacks may reveal information
- Mitigation: Use constant-time comparisons (Python's `secrets.compare_digest`)

⚠️ **Log Injection**: Malicious input in logs
- Mitigation: Input sanitization, structured logging (JSON)

## Incident Response

### Suspected Key Compromise

1. Immediately disable the key in `.mcp_keys.json` (`"enabled": false`)
2. Restart the server
3. Generate and distribute new key
4. Review audit logs for suspicious activity
5. Investigate how key was compromised

### Rate Limit Violations

1. Check audit logs for pattern
2. Identify if legitimate (adjust limits) or malicious (investigate client)
3. Temporarily disable client if malicious
4. Review IP allowlist configuration

### Unauthorized Access Attempts

1. Review audit logs for failed auth attempts
2. Identify source IPs
3. Add IP filtering if not already configured
4. Check if keys were leaked
5. Rotate all keys if compromise suspected

## Support

For security issues, please follow responsible disclosure:

1. **Do not** open public GitHub issues for security vulnerabilities
2. Email security concerns to the maintainers
3. Include details but avoid public disclosure until patched

For configuration help, see the main README.md or open a GitHub issue.
