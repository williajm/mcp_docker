"""Unit tests for SSH authentication protocol."""

import time
from datetime import UTC, datetime

from mcp_docker.auth.ssh_signing import get_public_key_string, load_private_key_from_file, sign_message
import pytest

from mcp_docker.auth.ssh_auth import SSHAuthProtocol, SSHAuthRequest, SSHSignatureValidator
from mcp_docker.auth.ssh_keys import SSHPublicKey


class TestSSHAuthProtocol:
    """Unit tests for SSH authentication protocol."""

    def test_create_message(self):
        """Test message creation."""
        message = SSHAuthProtocol.create_message("client1", "2025-11-04T12:00:00Z", "nonce123")
        assert message == b"client1|2025-11-04T12:00:00Z|nonce123"

    def test_validate_timestamp_valid(self):
        """Test validating recent timestamp."""
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        timestamp = datetime.now(UTC).isoformat()

        assert protocol.validate_timestamp(timestamp) is True

    def test_validate_timestamp_expired(self):
        """Test validating expired timestamp."""
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        # Timestamp from 10 minutes ago
        old_time = datetime.now(UTC).timestamp() - 600
        timestamp = datetime.fromtimestamp(old_time, UTC).isoformat()

        assert protocol.validate_timestamp(timestamp) is False

    def test_validate_timestamp_invalid_format(self):
        """Test validating invalid timestamp format."""
        protocol = SSHAuthProtocol()
        assert protocol.validate_timestamp("invalid") is False

    def test_validate_and_register_nonce_new(self):
        """Test registering new nonce."""
        protocol = SSHAuthProtocol()
        nonce = "unique-nonce-123"

        # First use should succeed
        assert protocol.validate_and_register_nonce(nonce) is True

        # Second use should fail (replay attack)
        assert protocol.validate_and_register_nonce(nonce) is False

    def test_validate_and_register_nonce_cleanup(self):
        """Test automatic nonce cleanup after expiry."""
        protocol = SSHAuthProtocol(max_timestamp_age=1)  # 1 second expiry
        nonce = "test-nonce"

        # Register nonce
        assert protocol.validate_and_register_nonce(nonce) is True
        stats = protocol.get_nonce_stats()
        assert stats["active_nonces"] == 1

        # Wait for expiry
        time.sleep(1.5)

        # Register new nonce (should trigger cleanup)
        assert protocol.validate_and_register_nonce("new-nonce") is True

        # Old nonce should be cleaned up
        stats = protocol.get_nonce_stats()
        assert stats["active_nonces"] == 1

    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce1 = SSHAuthProtocol.generate_nonce()
        nonce2 = SSHAuthProtocol.generate_nonce()

        # Nonces should be unique
        assert nonce1 != nonce2
        # Nonces should be long enough (32 bytes = ~43 chars base64)
        assert len(nonce1) >= 40
        assert len(nonce2) >= 40


class TestSSHSignatureValidator:
    """Unit tests for SSH signature validation."""

    @pytest.fixture
    def ed25519_keypair(self, tmp_path):
        """Generate Ed25519 key pair for testing."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Generate key using cryptography library
        crypto_private_key = ed25519.Ed25519PrivateKey.generate()

        # Save in OpenSSH format
        private_key_path = tmp_path / "test_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_path.write_bytes(private_pem)

        # Load with paramiko
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ssh-ed25519",
            public_key=get_public_key_string(private_key)[1],
            description="test-key",
        )

        return private_key, public_key

    def test_verify_valid_signature_ed25519(self, ed25519_keypair):
        """Test verifying valid Ed25519 signature."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_invalid_signature(self, ed25519_keypair):
        """Test verifying invalid signature."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        message = b"test-message"
        # Create invalid signature
        invalid_signature = b"invalid-signature-data"

        # Should return False (not raise exception)
        assert validator.verify_signature(public_key, message, invalid_signature) is False

    def test_verify_wrong_message(self, ed25519_keypair):
        """Test signature verification fails for wrong message."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        # Sign one message
        message1 = b"original-message"
        signature = sign_message(private_key, message1)

        # Try to verify different message
        message2 = b"different-message"
        assert validator.verify_signature(public_key, message2, signature) is False

    def test_verify_unsupported_key_type(self):
        """Test verification with unsupported key type."""
        validator = SSHSignatureValidator()

        # Create fake public key with unsupported type
        public_key = SSHPublicKey(
            client_id="test",
            key_type="unsupported-key-type",
            public_key="AAAAC3Nza...",
            description="test",
        )

        message = b"test"
        signature = b"fake-sig"

        # Should return False for unsupported key type
        assert validator.verify_signature(public_key, message, signature) is False


class TestSSHAuthIntegration:
    """Integration tests for complete SSH authentication flow."""

    @pytest.fixture
    def setup_auth_env(self, tmp_path):
        """Setup complete authentication environment."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from mcp_docker.auth.ssh_auth import SSHKeyAuthenticator
        from mcp_docker.config import SecurityConfig

        # Generate key pair using cryptography
        crypto_private_key = ed25519.Ed25519PrivateKey.generate()

        # Save private key
        private_key_path = tmp_path / "test_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_path.write_bytes(private_pem)

        # Load with paramiko
        _, private_key = load_private_key_from_file(private_key_path)

        # Create authorized_keys file
        auth_keys_file = tmp_path / "authorized_keys"
        public_key_line = f"ssh-ed25519 {get_public_key_string(private_key)[1]} test-client:test-key\n"
        auth_keys_file.write_text(public_key_line)

        # Create security config
        config = SecurityConfig(
            auth_enabled=True,
            ssh_auth_enabled=True,
            ssh_authorized_keys_file=auth_keys_file,
            ssh_signature_max_age=300,
        )

        # Create authenticator
        authenticator = SSHKeyAuthenticator(auth_keys_file, config)

        return private_key, authenticator

    def test_complete_authentication_flow(self, setup_auth_env):
        """Test complete SSH authentication flow."""
        private_key, authenticator = setup_auth_env

        # Create authentication challenge
        client_id = "test-client"
        timestamp = datetime.now(UTC).isoformat()
        nonce = SSHAuthProtocol.generate_nonce()

        # Sign challenge
        message = SSHAuthProtocol.create_message(client_id, timestamp, nonce)
        signature = sign_message(private_key, message)

        # Authenticate
        auth_request = SSHAuthRequest(
            client_id=client_id,
            signature=signature,
            timestamp=timestamp,
            nonce=nonce,
        )
        client_info = authenticator.authenticate(auth_request)

        # Verify authentication succeeded
        assert client_info is not None
        assert client_info.client_id == "test-client"
        assert client_info.description == "test-key"
