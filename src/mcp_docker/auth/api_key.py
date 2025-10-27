"""API Key authentication implementation."""

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class ClientInfo(BaseModel):
    """Information about an authenticated client."""

    client_id: str = Field(description="Unique client identifier")
    api_key_hash: str = Field(description="SHA-256 hash of the API key")
    description: str | None = Field(default=None, description="Human-readable description")
    ip_address: str | None = Field(default=None, description="Client IP address")
    authenticated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of authentication",
    )


class APIKeyConfig(BaseModel):
    """Configuration for a single API key."""

    api_key: str = Field(description="The API key (keep secret)")
    client_id: str = Field(description="Unique identifier for this client")
    description: str | None = Field(default=None, description="Description of this client")
    enabled: bool = Field(default=True, description="Whether this key is active")


class APIKeysFile(BaseModel):
    """Structure of the API keys configuration file."""

    clients: list[APIKeyConfig] = Field(default_factory=list, description="List of API key configs")


class APIKeyAuthenticator:
    """Handles API key authentication for MCP Docker server.

    This authenticator loads API keys from a JSON file and validates
    incoming requests against the configured keys.
    """

    def __init__(self, keys_file: Path) -> None:
        """Initialize the API key authenticator.

        Args:
            keys_file: Path to the JSON file containing API keys
        """
        self.keys_file = keys_file
        self._key_to_client: dict[str, APIKeyConfig] = {}
        self._load_keys()

    def _load_keys(self) -> None:
        """Load API keys from the configuration file.

        Raises:
            FileNotFoundError: If keys file doesn't exist
            ValueError: If keys file is invalid
        """
        if not self.keys_file.exists():
            logger.warning(f"API keys file not found: {self.keys_file}")
            logger.info("Authentication will fail until keys file is created")
            return

        try:
            with self.keys_file.open(encoding="utf-8") as f:
                data = json.load(f)

            keys_config = APIKeysFile(**data)

            # Build lookup dictionary
            self._key_to_client = {}
            for config in keys_config.clients:
                if config.enabled:
                    self._key_to_client[config.api_key] = config

            logger.info(f"Loaded {len(self._key_to_client)} API key(s) from {self.keys_file}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in keys file {self.keys_file}: {e}")
            raise ValueError(f"Invalid JSON in keys file: {e}") from e
        except Exception as e:
            logger.error(f"Failed to load keys file {self.keys_file}: {e}")
            raise

    def reload_keys(self) -> None:
        """Reload API keys from the configuration file.

        This allows updating keys without restarting the server.
        """
        logger.info("Reloading API keys")
        self._load_keys()

    def authenticate(self, api_key: str, ip_address: str | None = None) -> ClientInfo | None:
        """Authenticate a client using an API key.

        Args:
            api_key: The API key to validate
            ip_address: Optional IP address of the client

        Returns:
            ClientInfo if authentication succeeds, None otherwise
        """
        if not api_key:
            logger.debug("Authentication failed: empty API key")
            return None

        # Look up the key
        config = self._key_to_client.get(api_key)
        if not config:
            logger.warning("Authentication failed: invalid API key")
            return None

        # Hash the key for audit logging (never log the actual key)
        # Note: SHA256 is appropriate here as this is for audit logging, not password storage.
        # The actual authentication is done via direct key comparison above (line 118).
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]  # nosec B324

        logger.info(f"Authentication successful for client: {config.client_id}")

        return ClientInfo(
            client_id=config.client_id,
            api_key_hash=key_hash,
            description=config.description,
            ip_address=ip_address,
        )

    def validate_key_format(self, api_key: str) -> bool:
        """Validate that an API key has the correct format.

        Args:
            api_key: The API key to validate

        Returns:
            True if format is valid
        """
        # API keys should be at least 32 characters for security
        return len(api_key) >= 32

    @staticmethod
    def generate_api_key() -> str:
        """Generate a cryptographically secure API key.

        Returns:
            A new API key (32 bytes = 43 chars in base64)
        """
        return secrets.token_urlsafe(32)

    def list_clients(self) -> list[dict[str, Any]]:
        """List all configured clients (without exposing keys).

        Returns:
            List of client information (without API keys)
        """
        return [
            {
                "client_id": config.client_id,
                "description": config.description,
                "enabled": config.enabled,
            }
            for config in self._key_to_client.values()
        ]
