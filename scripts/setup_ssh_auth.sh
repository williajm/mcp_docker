#!/bin/bash
# Setup SSH authentication for MCP Docker
#
# This script:
# 1. Generates an SSH Ed25519 key pair
# 2. Creates authorized_keys file
# 3. Configures environment variables

set -e

CLIENT_ID="${1:-my-client}"
KEY_DIR="${2:-$HOME/.ssh}"
KEY_NAME="mcp_client_key"

echo "=== MCP Docker SSH Authentication Setup ==="
echo

# Create .ssh directory if it doesn't exist
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

# Generate SSH key pair
KEY_PATH="$KEY_DIR/$KEY_NAME"
if [ -f "$KEY_PATH" ]; then
    echo "Key already exists: $KEY_PATH"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing key"
    else
        ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$CLIENT_ID:setup-script"
        echo "✓ Generated new SSH key pair"
    fi
else
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$CLIENT_ID:setup-script"
    echo "✓ Generated SSH key pair"
fi

# Create authorized_keys file
AUTHORIZED_KEYS="$KEY_DIR/mcp_authorized_keys"
if [ ! -f "$AUTHORIZED_KEYS" ]; then
    touch "$AUTHORIZED_KEYS"
    chmod 644 "$AUTHORIZED_KEYS"
    echo "✓ Created authorized_keys file"
fi

# Add public key to authorized_keys if not already present
PUBLIC_KEY=$(cat "$KEY_PATH.pub")
if grep -q "$PUBLIC_KEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
    echo "✓ Public key already in authorized_keys"
else
    echo "$PUBLIC_KEY" >> "$AUTHORIZED_KEYS"
    echo "✓ Added public key to authorized_keys"
fi

# Display configuration
echo
echo "=== Configuration Complete ==="
echo
echo "Client ID:          $CLIENT_ID"
echo "Private Key:        $KEY_PATH"
echo "Public Key:         $KEY_PATH.pub"
echo "Authorized Keys:    $AUTHORIZED_KEYS"
echo
echo "=== Environment Variables ==="
echo "Add these to your .env file:"
echo
echo "SECURITY_AUTH_ENABLED=true"
echo "SECURITY_SSH_AUTH_ENABLED=true"
echo "SECURITY_SSH_AUTHORIZED_KEYS_FILE=$AUTHORIZED_KEYS"
echo "SECURITY_SSH_SIGNATURE_MAX_AGE=300"
echo
echo "=== Test Authentication ==="
echo "Run the example client:"
echo "  python examples/ssh_auth_client.py"
echo
echo "Or use the Python SDK:"
echo "  from mcp_docker.auth.ssh_auth import SSHAuthProtocol"
echo "  # See examples/ssh_auth_client.py for complete example"
echo
