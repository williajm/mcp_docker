"""SSH public key management for MCP Docker authentication."""

import threading
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from mcp_docker.utils.errors import SSHKeyError

# SSH authorized_keys format constants
MIN_SSH_KEY_PARTS = 2  # Minimum: key-type public-key
MIN_PARTS_WITH_COMMENT = 3  # With comment: key-type public-key comment


class SSHPublicKey(BaseModel):
    """Represents an SSH public key for authentication.

    Supports multiple keys per client for:
    - Key rotation (old + new key active simultaneously)
    - Multiple devices (laptop, server, CI/CD)
    """

    client_id: str = Field(description="Unique client identifier")
    key_type: str = Field(
        description="SSH key algorithm (ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256, etc.)"
    )
    public_key: str = Field(description="Base64-encoded public key")
    description: str | None = Field(default=None, description="Key description/comment")
    enabled: bool = Field(default=True, description="Whether key is active")

    @classmethod
    def from_authorized_keys_line(cls, line: str, line_num: int) -> "SSHPublicKey":
        """Parse OpenSSH authorized_keys format.

        Supports standard format with options:
        - Simple: ssh-ed25519 AAAAC3Nza... client1:laptop
        - With options: command="..." ssh-ed25519 AAAAC3Nza... client1:laptop
        - Multiple options: no-port-forwarding,command="..." ssh-ed25519 AAAAC3Nza...

        Args:
            line: Line from authorized_keys file
            line_num: Line number (for error reporting)

        Returns:
            SSHPublicKey instance

        Raises:
            SSHKeyError: If line format is invalid
        """
        line = line.strip()
        parts = line.split()

        if len(parts) < MIN_SSH_KEY_PARTS:
            raise SSHKeyError(
                f"Invalid authorized_keys line {line_num}: "
                f"expected 'key-type public-key [comment]', got '{line}'"
            )

        # Check if first token is a key type or an option
        # Key types start with known prefixes
        known_key_types = ["ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-"]

        # Find where the key type starts
        key_start_idx = 0
        for idx, part in enumerate(parts):
            if any(part.startswith(kt) for kt in known_key_types):
                key_start_idx = idx
                break

        # Everything before key_start_idx is options (we ignore them)
        if key_start_idx > 0:
            logger.debug(f"Ignoring authorized_keys options on line {line_num}")

        # Now parse from the key type onwards
        remaining_parts = parts[key_start_idx:]

        if len(remaining_parts) < MIN_SSH_KEY_PARTS:
            raise SSHKeyError(
                f"Invalid authorized_keys line {line_num}: "
                f"expected 'key-type public-key [comment]', got '{line}'"
            )

        key_type = remaining_parts[0]
        public_key = remaining_parts[1]

        # Parse comment field (optional)
        if len(remaining_parts) >= MIN_PARTS_WITH_COMMENT:
            comment = " ".join(remaining_parts[2:])  # Join remaining parts
            # Extract client_id from comment (format: client-id:description)
            if ":" in comment:
                client_id, description = comment.split(":", 1)
            else:
                client_id = comment
                description = None
        else:
            # No comment, generate client_id from line number
            client_id = f"client-{line_num}"
            description = None

        return cls(
            client_id=client_id,
            key_type=key_type,
            public_key=public_key,
            description=description,
        )


class SSHKeyManager:
    """Manage authorized SSH public keys.

    Supports:
    - Multiple keys per client (for key rotation and multi-device)
    - Hot reload without server restart
    - Thread-safe operations
    """

    def __init__(self, authorized_keys_file: Path):
        """Initialize SSH key manager.

        Args:
            authorized_keys_file: Path to authorized_keys file
        """
        self.authorized_keys_file = authorized_keys_file
        self._public_keys: dict[str, list[SSHPublicKey]] = {}
        self._lock = threading.Lock()
        self._load_keys()

    def _load_keys(self) -> None:
        """Load authorized public keys from file.

        Format: OpenSSH authorized_keys
        - One key per line
        - Comments start with #
        - Format: key-type public-key [client-id:description]
        """
        keys: dict[str, list[SSHPublicKey]] = {}

        if not self.authorized_keys_file.exists():
            logger.warning(
                f"Authorized keys file not found: {self.authorized_keys_file}. "
                "No SSH keys will be authorized."
            )
            with self._lock:
                self._public_keys = keys
            return

        try:
            with self.authorized_keys_file.open() as f:
                for line_num, raw_line in enumerate(f, 1):
                    line = raw_line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    try:
                        key = SSHPublicKey.from_authorized_keys_line(line, line_num)

                        # Add to keys dict (support multiple keys per client_id)
                        if key.client_id not in keys:
                            keys[key.client_id] = []
                        keys[key.client_id].append(key)

                        logger.debug(
                            f"Loaded SSH key for client '{key.client_id}' "
                            f"(type: {key.key_type}, description: {key.description})"
                        )

                    except SSHKeyError as e:
                        logger.error(f"Failed to parse line {line_num}: {e}")
                        continue

            logger.info(
                f"Loaded {sum(len(k) for k in keys.values())} SSH key(s) "
                f"for {len(keys)} client(s) from {self.authorized_keys_file}"
            )

            with self._lock:
                self._public_keys = keys

        except Exception as e:
            logger.error(f"Failed to load authorized keys: {e}")
            raise SSHKeyError(f"Failed to load authorized keys: {e}") from e

    def reload_keys(self) -> None:
        """Reload authorized keys from file (hot reload).

        Thread-safe operation that reloads keys without restart.
        """
        logger.info("Reloading SSH authorized keys")
        self._load_keys()

    def get_keys(self, client_id: str) -> list[SSHPublicKey]:
        """Get all public keys for a client.

        Supports multiple keys per client for:
        - Key rotation (old + new key active)
        - Multiple devices

        Args:
            client_id: Client identifier

        Returns:
            List of authorized public keys for the client (empty if none found)
        """
        with self._lock:
            return self._public_keys.get(client_id, [])

    def get_all_keys(self) -> dict[str, list[SSHPublicKey]]:
        """Get all authorized keys.

        Returns:
            Dictionary mapping client_id to list of public keys
        """
        with self._lock:
            return dict(self._public_keys)  # Return copy

    def get_stats(self) -> dict[str, int]:
        """Get statistics about loaded keys.

        Returns:
            Dict with 'total_keys' and 'total_clients'
        """
        with self._lock:
            return {
                "total_clients": len(self._public_keys),
                "total_keys": sum(len(keys) for keys in self._public_keys.values()),
            }
