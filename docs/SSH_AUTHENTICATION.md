# SSH Authentication for MCP Docker

This document describes the SSH key-based authentication implementation for MCP Docker.

## Overview

MCP Docker now supports SSH key-based authentication as an alternative to API keys. This provides:

- **Public key cryptography** for secure authentication
- **Multiple keys per client** for key rotation and multi-device setups
- **Replay attack protection** using timestamps and nonce deduplication
- **OpenSSH compatibility** using standard authorized_keys format

## Quick Start

### 1. Generate SSH Key Pair

```bash
# Use the provided setup script
./scripts/setup_ssh_auth.sh my-client

# Or generate manually
ssh-keygen -t ed25519 -f ~/.ssh/mcp_client_key -C "my-client:description"
```

### 2. Add Public Key to Authorized Keys

```bash
# Create authorized_keys file
cat ~/.ssh/mcp_client_key.pub >> ~/.ssh/mcp_authorized_keys
```

### 3. Configure MCP Server

Add to your `.env` file:

```bash
SECURITY_AUTH_ENABLED=true
SECURITY_SSH_AUTH_ENABLED=true
SECURITY_SSH_AUTHORIZED_KEYS_FILE=~/.ssh/mcp_authorized_keys
SECURITY_SSH_SIGNATURE_MAX_AGE=300  # 5 minutes
```

### 4. Authenticate with SSH Key

See `examples/ssh_auth_client.py` for a complete Python example.

## Authentication Protocol

### Challenge-Response Flow

1. **Client generates challenge**:

   ```text
   message = "{client_id}|{timestamp}|{nonce}"
   ```

2. **Client signs challenge**:

   ```python
   signature = private_key.sign_ssh_data(message.encode())
   ```

3. **Client sends authentication request**:

   ```json
   {
     "client_id": "my-client",
     "timestamp": "2025-11-04T12:00:00Z",
     "nonce": "random-base64-string",
     "signature": "base64-encoded-signature"
   }
   ```

4. **Server validates**:
   - Timestamp is recent (within 5 minutes by default)
   - Nonce hasn't been used before (replay protection)
   - Signature is valid for the client's public key

### Security Features

#### Timestamp Validation

- Prevents long-term replay attacks
- Configurable window (default: 5 minutes)
- Allows for reasonable clock skew

#### Nonce Deduplication

- Prevents replay attacks within timestamp window
- Thread-safe nonce store
- Automatic cleanup of expired nonces

#### Multiple Keys Per Client

Supports key rotation and multi-device scenarios:

```text
# authorized_keys format
ssh-ed25519 AAAAC3Nza... client1:laptop
ssh-ed25519 AAAAC3Nza... client1:desktop
ssh-ed25519 AAAAC3Nza... client1:ci-server
```

## Authorized Keys File Format

Standard OpenSSH `authorized_keys` format:

```text
# Comments start with #

# Format: key-type public-key client-id:description
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... client1:laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... client2:server

# Disabled keys (comment out)
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... old-client:deprecated
```

**Fields**:

- `key-type`: SSH key algorithm (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256)
- `public-key`: Base64-encoded public key
- `client-id`: Unique client identifier (before colon)
- `description`: Optional description (after colon)

## Supported Key Types

| Algorithm | Recommended | Supported | Notes |
|-----------|-------------|-----------|-------|
| Ed25519 | ✅ Yes | ✅ Yes | Fast, secure, modern |
| RSA (2048+) | ⚠️  Legacy | ✅ Yes | Widely supported |
| ECDSA (P-256/384/521) | ⚠️  Legacy | ✅ Yes | Good balance |
| DSA | ❌ No | ❌ No | Deprecated, insecure |

**Recommendation**: Use Ed25519 for new deployments.

## Configuration Reference

### Environment Variables

```bash
# SSH Authentication
SECURITY_SSH_AUTH_ENABLED=true|false          # Enable SSH auth (default: false)
SECURITY_SSH_AUTHORIZED_KEYS_FILE=/path/to/file  # Authorized keys file
SECURITY_SSH_SIGNATURE_MAX_AGE=300            # Max signature age in seconds

# General Security (also applies to SSH auth)
SECURITY_AUTH_ENABLED=true                    # Enable authentication
SECURITY_RATE_LIMIT_ENABLED=true              # Enable rate limiting
SECURITY_RATE_LIMIT_RPM=60                    # Requests per minute
SECURITY_AUDIT_LOG_ENABLED=true               # Enable audit logging
```

### Python Configuration

```python
from mcp_docker.config import SecurityConfig

config = SecurityConfig(
    auth_enabled=True,
    ssh_auth_enabled=True,
    ssh_authorized_keys_file=Path("~/.ssh/mcp_authorized_keys"),
    ssh_signature_max_age=300,  # 5 minutes
)
```

## Client Implementation

### MCP Tool Call with SSH Auth

When calling MCP Docker tools, include SSH authentication in the `_auth` argument:

```python
import base64
import secrets
from datetime import UTC, datetime
from mcp import ClientSession
from mcp.client.stdio import stdio_client

def create_ssh_auth_data(client_id: str, private_key_path: str):
    """Create SSH authentication data for tool calls."""
    # Load private key

    # Generate challenge
    timestamp = datetime.now(UTC).isoformat()
    nonce = secrets.token_urlsafe(32)  # 256 bits
    message = f"{client_id}|{timestamp}|{nonce}".encode('utf-8')

    # Sign challenge
    signature = key.sign_ssh_data(message)
    signature_b64 = base64.b64encode(signature.asbytes()).decode('utf-8')

    return {
        "client_id": client_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature_b64
    }

# Using with MCP client
async with stdio_client(...) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # Create auth data (generate fresh for each call!)
        ssh_auth = create_ssh_auth_data("my-client", "~/.ssh/mcp_client_key")

        # Call tool with SSH auth
        result = await session.call_tool(
            "list_containers",
            arguments={
                "_auth": {  # Special auth argument
                    "ssh": ssh_auth
                },
                "all": True  # Actual tool arguments
            }
        )
```

See `examples/ssh_auth_mcp_client.py` for complete example.

### API Key Auth (Alternative)

You can also use API key authentication:

```python
result = await session.call_tool(
    "list_containers",
    arguments={
        "_auth": {
            "api_key": "your-api-key"  # API key auth
        },
        "all": True
    }
)
```

### Important Notes

**Generate Fresh Auth Data for Each Tool Call**:

```python
# ❌ WRONG - Don't reuse auth data
ssh_auth = create_ssh_auth_data(...)
await session.call_tool("list_containers", {"_auth": {"ssh": ssh_auth}, ...})
await session.call_tool("inspect_container", {"_auth": {"ssh": ssh_auth}, ...})  # Replay attack!

# ✅ CORRECT - Generate fresh auth for each call
ssh_auth1 = create_ssh_auth_data(...)
await session.call_tool("list_containers", {"_auth": {"ssh": ssh_auth1}, ...})

ssh_auth2 = create_ssh_auth_data(...)  # Fresh timestamp & nonce
await session.call_tool("inspect_container", {"_auth": {"ssh": ssh_auth2}, ...})
```

**Why?**

- Each auth data has a unique nonce
- Nonces are tracked to prevent replay attacks
- Reusing the same nonce will be rejected

## Key Management

### Key Rotation

To rotate keys without downtime:

1. **Add new key** while keeping old key:

   ```bash
   # Old key still in authorized_keys
   ssh-ed25519 AAAAC3Nza...old client1:old-key

   # Add new key
   ssh-ed25519 AAAAC3Nza...new client1:new-key
   ```

2. **Update client** to use new key

3. **Remove old key** after transition:

   ```bash
   # Remove old key line from authorized_keys
   ```

### Hot Reload

Reload keys without restarting the server:

```python
# Server has a reload endpoint or signal handler
# Implementation depends on your server setup
```

### Multi-Device Setup

```text
# authorized_keys
ssh-ed25519 AAAAC3Nza...laptop client1:laptop
ssh-ed25519 AAAAC3Nza...desktop client1:desktop
ssh-ed25519 AAAAC3Nza...ci-server client1:ci-server
```

All devices can authenticate as the same client using different keys.

## Troubleshooting

### "SSH authentication failed: expired timestamp"

**Cause**: Timestamp too old or clock skew

**Solution**:

```bash
# Check system time
timedatectl status

# Sync time with NTP
sudo ntpdate pool.ntp.org

# Or increase max age (not recommended)
SECURITY_SSH_SIGNATURE_MAX_AGE=600  # 10 minutes
```

### "SSH authentication failed: nonce has already been used"

**Cause**: Replay attack detected or duplicate request

**Solution**:

- Don't reuse authentication requests
- Generate new nonce for each request
- Check for network issues causing request duplication

### "SSH authentication failed: unknown client_id"

**Cause**: Public key not in authorized_keys

**Solution**:

```bash
# Add public key
cat ~/.ssh/mcp_client_key.pub >> ~/.ssh/mcp_authorized_keys

# Verify format
cat ~/.ssh/mcp_authorized_keys
```

### "SSH authentication failed: invalid signature"

**Cause**: Wrong key, wrong message format, or corrupted signature

**Solution**:

1. Verify message format: `{client_id}|{timestamp}|{nonce}`
2. Ensure using correct private key
3. Check signature is base64-encoded
4. Verify timestamp format is ISO 8601

## Security Best Practices

1. **Use Ed25519 keys** - Modern, fast, secure
2. **Protect private keys** - `chmod 600 ~/.ssh/mcp_client_key`
3. **Use passphrases** - Encrypt private keys with passphrase
4. **Rotate keys regularly** - Use multi-key support for rotation
5. **Monitor audit logs** - Track authentication attempts
6. **Use rate limiting** - Prevent brute force attacks
7. **Keep timestamp window short** - Default 5 minutes is recommended
8. **Use strong nonces** - 256 bits of entropy (default)

## API Reference

### AuthMiddleware.authenticate_request()

```python
def authenticate_request(
    self,
    ip_address: str | None = None,
    ssh_auth_data: dict[str, Any] | None = None,
) -> ClientInfo:
    """Authenticate request using SSH key.

    Args:
        ip_address: Client IP address
        ssh_auth_data: SSH authentication data (optional):
            {
                "client_id": str,
                "signature": base64-encoded bytes,
                "timestamp": str (ISO 8601),
                "nonce": str
            }

    Returns:
        ClientInfo with client_id, api_key_hash, description, ip_address

    Raises:
        AuthenticationError: If authentication fails
    """
```

### SSHKeyAuthenticator.authenticate()

```python
def authenticate(
    self,
    client_id: str,
    signature: bytes,
    timestamp: str,
    nonce: str
) -> ClientInfo:
    """Authenticate client using SSH signature.

    Validates:
    1. Timestamp is recent (within ssh_signature_max_age)
    2. Nonce hasn't been used (replay protection)
    3. Signature is valid for client's public key

    Returns:
        ClientInfo if successful

    Raises:
        SSHTimestampExpiredError: Timestamp too old
        SSHNonceReuseError: Nonce already used (replay attack)
        SSHKeyNotFoundError: Client key not authorized
        SSHSignatureInvalidError: Signature verification failed
    """
```

## Implementation Details

### Files

- `src/mcp_docker/auth/ssh_auth.py` - SSH authentication implementation
- `src/mcp_docker/auth/ssh_keys.py` - SSH key management
- `src/mcp_docker/auth/middleware.py` - Authentication middleware
- `src/mcp_docker/config.py` - Configuration models
- `src/mcp_docker/utils/errors.py` - SSH error types

### Dependencies

- `
- `cryptography>=46.0.0` - Cryptographic primitives for SSH operations

### Testing

Run tests:

```bash
# Unit tests
uv run pytest tests/unit/auth/test_ssh_keys.py -v
uv run pytest tests/unit/auth/test_ssh_auth.py -v

# All auth tests
uv run pytest tests/unit/auth/ -v
```

## Comparison: SSH Auth vs API Keys

| Feature | SSH Keys | API Keys |
|---------|----------|----------|
| Security | Public key cryptography | Shared secret |
| Key Rotation | Multiple keys, no downtime | Manual update required |
| Replay Protection | Timestamp + nonce | N/A |
| Key Management | Standard SSH tools | Custom management |
| Multi-Device | Native support | Share same key |
| Complexity | Higher | Lower |
| Industry Standard | Yes (SSH) | Yes (API keys) |

**When to use SSH keys**:

- Multi-device setups
- Frequent key rotation required
- Integration with SSH infrastructure
- Higher security requirements

**When to use API keys**:

- Simpler setup needed
- Single-device scenarios
- Quick prototyping
- Legacy system integration

## Future Enhancements

Potential future improvements:

1. **SSH Certificate Support** - Use SSH certificates instead of raw keys
2. **Hardware Token Support** - YubiKey, TPM integration
3. **Key Revocation Lists** - Centralized key revocation
4. **Audit Dashboard** - Web UI for auth monitoring
5. **OIDC Integration** - OpenID Connect for federated auth

## References

- [OpenSSH Authentication](https://www.openssh.com/manual.html)
- [RFC 4251: SSH Protocol Architecture](https://tools.ietf.org/html/rfc4251)
- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
