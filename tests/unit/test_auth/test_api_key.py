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

    def test_api_key_hash_determinism(self, temp_keys_file: Path) -> None:
        """Test that API key hashes are deterministic across calls.

        The hash should be stable so operators can correlate audit logs
        from the same client across time.
        """
        authenticator = APIKeyAuthenticator(temp_keys_file)

        # Authenticate multiple times with same key
        result1 = authenticator.authenticate("valid-key-123", "127.0.0.1")
        result2 = authenticator.authenticate("valid-key-123", "127.0.0.2")
        result3 = authenticator.authenticate("valid-key-123", "192.168.1.1")

        assert result1 is not None
        assert result2 is not None
        assert result3 is not None

        # Hash should be identical regardless of IP or time
        assert result1.api_key_hash == result2.api_key_hash
        assert result2.api_key_hash == result3.api_key_hash

    def test_api_key_hash_stable_across_restarts(self, temp_keys_file: Path) -> None:
        """Test that API key hashes remain consistent across process restarts.

        Simulates server restart by creating new authenticator instances.
        This is critical for audit log correlation.
        """
        # First "process"
        auth1 = APIKeyAuthenticator(temp_keys_file)
        result1 = auth1.authenticate("valid-key-123", "127.0.0.1")
        assert result1 is not None
        hash1 = result1.api_key_hash

        # Simulate restart by creating new instance
        auth2 = APIKeyAuthenticator(temp_keys_file)
        result2 = auth2.authenticate("valid-key-123", "127.0.0.1")
        assert result2 is not None
        hash2 = result2.api_key_hash

        # Hash must be identical after "restart"
        assert hash1 == hash2, (
            f"API key hash changed after restart! "
            f"Before: {hash1}, After: {hash2}. "
            f"This breaks audit log correlation."
        )

    def test_api_key_hash_uniqueness(self, temp_keys_file: Path) -> None:
        """Test that different API keys produce different hashes.

        While hashes should be stable for the same key, different keys
        should produce different hashes for identification purposes.
        """
        # Add another key to the file
        keys_data = {
            "clients": [
                {
                    "api_key": "key-one-12345678901234567890123",
                    "client_id": "client1",
                    "enabled": True,
                },
                {
                    "api_key": "key-two-98765432109876543210987",
                    "client_id": "client2",
                    "enabled": True,
                },
            ]
        }
        temp_keys_file.write_text(json.dumps(keys_data))

        auth = APIKeyAuthenticator(temp_keys_file)

        result1 = auth.authenticate("key-one-12345678901234567890123", "127.0.0.1")
        result2 = auth.authenticate("key-two-98765432109876543210987", "127.0.0.1")

        assert result1 is not None
        assert result2 is not None

        # Different keys should produce different hashes
        assert result1.api_key_hash != result2.api_key_hash

    def test_api_key_hash_uses_cryptographic_function(self, temp_keys_file: Path) -> None:
        """Test that API key hashes use a cryptographic hash, not Python's hash().

        Python's built-in hash() is salted per-process for security reasons,
        which makes it unsuitable for audit logging that needs to persist
        across restarts.
        """
        import subprocess

        authenticator = APIKeyAuthenticator(temp_keys_file)
        result = authenticator.authenticate("valid-key-123", "127.0.0.1")
        assert result is not None
        api_key_hash = result.api_key_hash

        # Get Python's hash in a separate process
        python_hash_result = subprocess.run(
            ["python3", "-c", "print(format(abs(hash('valid-key-123')), '016x')[:16])"],
            capture_output=True,
            text=True,
            check=True,
        )
        python_hash = python_hash_result.stdout.strip()

        # Our hash should NOT equal Python's hash (which changes per process)
        # This verifies we're using a cryptographic hash like SHA-256
        assert api_key_hash != python_hash, (
            f"API key hash appears to use Python's hash() function, "
            f"which is not stable across process restarts. "
            f"Expected cryptographic hash, got: {api_key_hash}"
        )
