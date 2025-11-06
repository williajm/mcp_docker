"""Unit tests for SSH public key management."""

from textwrap import dedent

import pytest

from mcp_docker.auth.ssh_keys import SSHKeyManager, SSHPublicKey
from mcp_docker.utils.errors import SSHKeyError


class TestSSHPublicKey:
    """Unit tests for SSHPublicKey model."""

    def test_from_authorized_keys_line_basic(self):
        """Test parsing basic authorized_keys line."""
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFoo client1:laptop"
        key = SSHPublicKey.from_authorized_keys_line(line, 1)

        assert key.client_id == "client1"
        assert key.key_type == "ssh-ed25519"
        assert key.public_key == "AAAAC3NzaC1lZDI1NTE5AAAAIFoo"
        assert key.description == "laptop"
        assert key.enabled is True

    def test_from_authorized_keys_line_no_description(self):
        """Test parsing line without description."""
        line = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDer client2"
        key = SSHPublicKey.from_authorized_keys_line(line, 2)

        assert key.client_id == "client2"
        assert key.key_type == "ssh-rsa"
        assert key.description is None

    def test_from_authorized_keys_line_no_comment(self):
        """Test parsing line without any comment."""
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBar"
        key = SSHPublicKey.from_authorized_keys_line(line, 5)

        assert key.client_id == "client-5"  # Auto-generated from line number
        assert key.description is None

    def test_from_authorized_keys_line_invalid(self):
        """Test parsing invalid line raises error."""
        with pytest.raises(SSHKeyError, match="Invalid authorized_keys line"):
            SSHPublicKey.from_authorized_keys_line("invalid", 1)

    def test_multiple_keys_same_client(self):
        """Test that multiple keys can exist for same client."""
        line1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:laptop"
        line2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2 client1:desktop"

        key1 = SSHPublicKey.from_authorized_keys_line(line1, 1)
        key2 = SSHPublicKey.from_authorized_keys_line(line2, 2)

        assert key1.client_id == key2.client_id == "client1"
        assert key1.description == "laptop"
        assert key2.description == "desktop"
        assert key1.public_key != key2.public_key


class TestSSHKeyManager:
    """Unit tests for SSHKeyManager."""

    def test_load_keys_file_not_exists(self, tmp_path):
        """Test loading keys when file doesn't exist."""
        keys_file = tmp_path / "nonexistent"
        manager = SSHKeyManager(keys_file)

        assert manager.get_all_keys() == {}
        assert manager.get_keys("client1") == []

    def test_load_single_key(self, tmp_path):
        """Test loading single key from file."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFoo client1:test-key\n"
        )

        manager = SSHKeyManager(keys_file)
        keys = manager.get_keys("client1")

        assert len(keys) == 1
        assert keys[0].client_id == "client1"
        assert keys[0].key_type == "ssh-ed25519"

    def test_load_multiple_keys_per_client(self, tmp_path):
        """Test loading multiple keys for same client (key rotation)."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text(dedent("""
            # Client1 with laptop and desktop keys
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:laptop
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2 client1:desktop

            # Client2 with single key
            ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDer client2:server
        """))

        manager = SSHKeyManager(keys_file)

        # Check client1 has 2 keys
        client1_keys = manager.get_keys("client1")
        assert len(client1_keys) == 2
        assert client1_keys[0].description == "laptop"
        assert client1_keys[1].description == "desktop"

        # Check client2 has 1 key
        client2_keys = manager.get_keys("client2")
        assert len(client2_keys) == 1
        assert client2_keys[0].description == "server"

        # Check stats
        stats = manager.get_stats()
        assert stats["total_clients"] == 2
        assert stats["total_keys"] == 3

    def test_load_keys_skip_comments_and_empty_lines(self, tmp_path):
        """Test that comments and empty lines are ignored."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text(dedent("""
            # This is a comment

            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:key1

            # Another comment
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2 client2:key2
        """))

        manager = SSHKeyManager(keys_file)
        all_keys = manager.get_all_keys()

        assert len(all_keys) == 2
        assert "client1" in all_keys
        assert "client2" in all_keys

    def test_reload_keys(self, tmp_path):
        """Test hot-reloading keys from file."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:key1\n")

        manager = SSHKeyManager(keys_file)
        assert len(manager.get_keys("client1")) == 1

        # Add another key
        keys_file.write_text(dedent("""
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:key1
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2 client1:key2
        """))

        # Reload
        manager.reload_keys()
        assert len(manager.get_keys("client1")) == 2

    def test_get_keys_unknown_client(self, tmp_path):
        """Test getting keys for unknown client returns empty list."""
        keys_file = tmp_path / "authorized_keys"
        keys_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 client1:key1\n")

        manager = SSHKeyManager(keys_file)
        assert manager.get_keys("unknown-client") == []
