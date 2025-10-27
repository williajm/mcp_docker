"""Unit tests for API key authentication."""

import json
from pathlib import Path

import pytest

from mcp_docker.auth.api_key import APIKeyAuthenticator, APIKeyConfig, APIKeysFile, ClientInfo


class TestClientInfo:
    """Tests for ClientInfo model."""

    def test_client_info_creation(self) -> None:
        """Test creating a ClientInfo instance."""
        client_info = ClientInfo(
            client_id="test-client",
            api_key_hash="abc123",
            description="Test client",
            ip_address="127.0.0.1",
        )

        assert client_info.client_id == "test-client"
        assert client_info.api_key_hash == "abc123"
        assert client_info.description == "Test client"
        assert client_info.ip_address == "127.0.0.1"
        assert client_info.authenticated_at is not None

    def test_client_info_optional_fields(self) -> None:
        """Test ClientInfo with optional fields."""
        client_info = ClientInfo(
            client_id="test-client",
            api_key_hash="abc123",
        )

        assert client_info.description is None
        assert client_info.ip_address is None


class TestAPIKeyConfig:
    """Tests for APIKeyConfig model."""

    def test_api_key_config_creation(self) -> None:
        """Test creating an APIKeyConfig instance."""
        config = APIKeyConfig(
            api_key="test-key-123",
            client_id="test-client",
            description="Test config",
            enabled=True,
        )

        assert config.api_key == "test-key-123"
        assert config.client_id == "test-client"
        assert config.description == "Test config"
        assert config.enabled is True

    def test_api_key_config_defaults(self) -> None:
        """Test APIKeyConfig default values."""
        config = APIKeyConfig(
            api_key="test-key-123",
            client_id="test-client",
        )

        assert config.description is None
        assert config.enabled is True


class TestAPIKeysFile:
    """Tests for APIKeysFile model."""

    def test_api_keys_file_creation(self) -> None:
        """Test creating an APIKeysFile instance."""
        keys_file = APIKeysFile(
            clients=[
                APIKeyConfig(api_key="key1", client_id="client1"),
                APIKeyConfig(api_key="key2", client_id="client2"),
            ]
        )

        assert len(keys_file.clients) == 2
        assert keys_file.clients[0].client_id == "client1"
        assert keys_file.clients[1].client_id == "client2"

    def test_api_keys_file_empty(self) -> None:
        """Test creating an empty APIKeysFile."""
        keys_file = APIKeysFile()
        assert len(keys_file.clients) == 0


class TestAPIKeyAuthenticator:
    """Tests for APIKeyAuthenticator."""

    @pytest.fixture
    def temp_keys_file(self, tmp_path: Path) -> Path:
        """Create a temporary API keys file."""
        keys_file = tmp_path / ".mcp_keys.json"
        keys_data = {
            "clients": [
                {
                    "api_key": "valid-key-123",
                    "client_id": "test-client",
                    "description": "Test client",
                    "enabled": True,
                },
                {
                    "api_key": "disabled-key-456",
                    "client_id": "disabled-client",
                    "description": "Disabled client",
                    "enabled": False,
                },
            ]
        }
        keys_file.write_text(json.dumps(keys_data))
        return keys_file

    def test_load_keys_success(self, temp_keys_file: Path) -> None:
        """Test successfully loading API keys from file."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        # Should load only enabled keys
        assert len(authenticator._key_to_client) == 1
        assert "valid-key-123" in authenticator._key_to_client
        assert "disabled-key-456" not in authenticator._key_to_client

    def test_load_keys_missing_file(self, tmp_path: Path) -> None:
        """Test handling of missing keys file."""
        missing_file = tmp_path / "nonexistent.json"
        authenticator = APIKeyAuthenticator(missing_file)

        # Should not raise error, but should have empty keys
        assert len(authenticator._key_to_client) == 0

    def test_load_keys_invalid_json(self, tmp_path: Path) -> None:
        """Test handling of invalid JSON in keys file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        with pytest.raises(ValueError, match="Invalid JSON in keys file"):
            APIKeyAuthenticator(invalid_file)

    def test_authenticate_valid_key(self, temp_keys_file: Path) -> None:
        """Test authenticating with a valid API key."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        client_info = authenticator.authenticate("valid-key-123", "127.0.0.1")

        assert client_info is not None
        assert client_info.client_id == "test-client"
        assert client_info.description == "Test client"
        assert client_info.ip_address == "127.0.0.1"
        assert len(client_info.api_key_hash) == 16  # Truncated SHA-256

    def test_authenticate_invalid_key(self, temp_keys_file: Path) -> None:
        """Test authenticating with an invalid API key."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        client_info = authenticator.authenticate("invalid-key", "127.0.0.1")

        assert client_info is None

    def test_authenticate_disabled_key(self, temp_keys_file: Path) -> None:
        """Test authenticating with a disabled API key."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        client_info = authenticator.authenticate("disabled-key-456", "127.0.0.1")

        assert client_info is None

    def test_authenticate_empty_key(self, temp_keys_file: Path) -> None:
        """Test authenticating with an empty API key."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        client_info = authenticator.authenticate("", "127.0.0.1")

        assert client_info is None

    def test_reload_keys(self, temp_keys_file: Path) -> None:
        """Test reloading API keys from file."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        # Initially has 1 key
        assert len(authenticator._key_to_client) == 1

        # Update the file with new keys
        keys_data = {
            "clients": [
                {
                    "api_key": "new-key-789",
                    "client_id": "new-client",
                    "description": "New client",
                    "enabled": True,
                }
            ]
        }
        temp_keys_file.write_text(json.dumps(keys_data))

        # Reload keys
        authenticator.reload_keys()

        # Should have new key, old key should be gone
        assert len(authenticator._key_to_client) == 1
        assert "new-key-789" in authenticator._key_to_client
        assert "valid-key-123" not in authenticator._key_to_client

    def test_validate_key_format_valid(self) -> None:
        """Test validating a valid API key format."""
        authenticator = APIKeyAuthenticator(Path("dummy"))

        # 32 characters (minimum)
        assert authenticator.validate_key_format("a" * 32) is True

        # More than 32 characters
        assert authenticator.validate_key_format("a" * 50) is True

    def test_validate_key_format_invalid(self) -> None:
        """Test validating an invalid API key format."""
        authenticator = APIKeyAuthenticator(Path("dummy"))

        # Less than 32 characters
        assert authenticator.validate_key_format("a" * 31) is False
        assert authenticator.validate_key_format("short") is False
        assert authenticator.validate_key_format("") is False

    def test_generate_api_key(self) -> None:
        """Test generating a secure API key."""
        key1 = APIKeyAuthenticator.generate_api_key()
        key2 = APIKeyAuthenticator.generate_api_key()

        # Keys should be at least 32 characters
        assert len(key1) >= 32
        assert len(key2) >= 32

        # Keys should be different (extremely unlikely to be same)
        assert key1 != key2

        # Keys should be URL-safe (no special characters that need encoding)
        assert all(c.isalnum() or c in "-_" for c in key1)

    def test_list_clients(self, temp_keys_file: Path) -> None:
        """Test listing all configured clients."""
        authenticator = APIKeyAuthenticator(temp_keys_file)

        clients = authenticator.list_clients()

        assert len(clients) == 1
        assert clients[0]["client_id"] == "test-client"
        assert clients[0]["description"] == "Test client"
        assert clients[0]["enabled"] is True
        # API key should not be exposed
        assert "api_key" not in clients[0]
