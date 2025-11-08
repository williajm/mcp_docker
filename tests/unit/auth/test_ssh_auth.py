"""Unit tests for SSH authentication protocol."""

import time
from datetime import UTC, datetime
from typing import Any

import pytest

from mcp_docker.auth.ssh_auth import SSHAuthProtocol, SSHAuthRequest, SSHSignatureValidator
from mcp_docker.auth.ssh_keys import SSHPublicKey
from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
)


class TestSSHAuthProtocol:
    """Unit tests for SSH authentication protocol."""

    def test_create_message(self) -> None:
        """Test message creation."""
        message = SSHAuthProtocol.create_message("client1", "2025-11-04T12:00:00Z", "nonce123")
        assert message == b"client1|2025-11-04T12:00:00Z|nonce123"

    def test_validate_timestamp_valid(self) -> None:
        """Test validating recent timestamp."""
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        timestamp = datetime.now(UTC).isoformat()

        assert protocol.validate_timestamp(timestamp) is True

    def test_validate_timestamp_expired(self) -> None:
        """Test validating expired timestamp."""
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        # Timestamp from 10 minutes ago
        old_time = datetime.now(UTC).timestamp() - 600
        timestamp = datetime.fromtimestamp(old_time, UTC).isoformat()

        assert protocol.validate_timestamp(timestamp) is False

    def test_validate_timestamp_invalid_format(self) -> None:
        """Test validating invalid timestamp format."""
        protocol = SSHAuthProtocol()
        assert protocol.validate_timestamp("invalid") is False

    def test_validate_and_register_nonce_new(self) -> None:
        """Test registering new nonce."""
        protocol = SSHAuthProtocol()
        nonce = "unique-nonce-123"

        # First use should succeed
        assert protocol.validate_and_register_nonce(nonce) is True

        # Second use should fail (replay attack)
        assert protocol.validate_and_register_nonce(nonce) is False

    def test_validate_and_register_nonce_cleanup(self) -> None:
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

    def test_generate_nonce(self) -> None:
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
    def ed25519_keypair(self, tmp_path: Any) -> tuple[Any, Any]:
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
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ssh-ed25519",
            public_key=get_public_key_string(private_key)[1],
            description="test-key",
        )

        return private_key, public_key

    def test_verify_valid_signature_ed25519(self, ed25519_keypair: Any) -> None:
        """Test verifying valid Ed25519 signature."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_invalid_signature(self, ed25519_keypair: Any) -> None:
        """Test verifying invalid signature."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        message = b"test-message"
        # Create invalid signature
        invalid_signature = b"invalid-signature-data"

        # Should return False (not raise exception)
        assert validator.verify_signature(public_key, message, invalid_signature) is False

    def test_verify_wrong_message(self, ed25519_keypair: Any) -> None:
        """Test signature verification fails for wrong message."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        # Sign one message
        message1 = b"original-message"
        signature = sign_message(private_key, message1)

        # Try to verify different message
        message2 = b"different-message"
        assert validator.verify_signature(public_key, message2, signature) is False

    def test_verify_unsupported_key_type(self) -> None:
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

    @pytest.fixture(scope="module")
    def rsa_keypair(self, tmp_path_factory: Any) -> tuple[Any, Any]:
        """Generate RSA key pair for testing (module-scoped for performance)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate key
        crypto_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Save in OpenSSH format
        tmp_path = tmp_path_factory.mktemp("ssh_keys")
        private_key_path = tmp_path / "test_rsa_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ssh-rsa",
            public_key=get_public_key_string(private_key)[1],
            description="test-rsa-key",
        )

        return private_key, public_key

    @pytest.fixture(scope="module")
    def ecdsa_p256_keypair(self, tmp_path_factory: Any) -> tuple[Any, Any]:
        """Generate ECDSA P-256 key pair for testing (module-scoped for performance)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate key
        crypto_private_key = ec.generate_private_key(ec.SECP256R1())

        # Save in OpenSSH format
        tmp_path = tmp_path_factory.mktemp("ssh_keys")
        private_key_path = tmp_path / "test_ecdsa_p256_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ecdsa-sha2-nistp256",
            public_key=get_public_key_string(private_key)[1],
            description="test-ecdsa-p256-key",
        )

        return private_key, public_key

    @pytest.fixture(scope="module")
    def ecdsa_p384_keypair(self, tmp_path_factory: Any) -> tuple[Any, Any]:
        """Generate ECDSA P-384 key pair for testing (module-scoped for performance)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate key
        crypto_private_key = ec.generate_private_key(ec.SECP384R1())

        # Save in OpenSSH format
        tmp_path = tmp_path_factory.mktemp("ssh_keys")
        private_key_path = tmp_path / "test_ecdsa_p384_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ecdsa-sha2-nistp384",
            public_key=get_public_key_string(private_key)[1],
            description="test-ecdsa-p384-key",
        )

        return private_key, public_key

    @pytest.fixture(scope="module")
    def ecdsa_p521_keypair(self, tmp_path_factory: Any) -> tuple[Any, Any]:
        """Generate ECDSA P-521 key pair for testing (module-scoped for performance)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate key
        crypto_private_key = ec.generate_private_key(ec.SECP521R1())

        # Save in OpenSSH format
        tmp_path = tmp_path_factory.mktemp("ssh_keys")
        private_key_path = tmp_path / "test_ecdsa_p521_key"
        private_pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create SSHPublicKey
        public_key = SSHPublicKey(
            client_id="test-client",
            key_type="ecdsa-sha2-nistp521",
            public_key=get_public_key_string(private_key)[1],
            description="test-ecdsa-p521-key",
        )

        return private_key, public_key

    def test_verify_valid_signature_rsa(self, rsa_keypair: Any) -> None:
        """Test verifying valid RSA signature."""
        private_key, public_key = rsa_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_valid_signature_ecdsa_p256(self, ecdsa_p256_keypair: Any) -> None:
        """Test verifying valid ECDSA P-256 signature."""
        private_key, public_key = ecdsa_p256_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_valid_signature_ecdsa_p384(self, ecdsa_p384_keypair: Any) -> None:
        """Test verifying valid ECDSA P-384 signature."""
        private_key, public_key = ecdsa_p384_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_valid_signature_ecdsa_p521(self, ecdsa_p521_keypair: Any) -> None:
        """Test verifying valid ECDSA P-521 signature."""
        private_key, public_key = ecdsa_p521_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Verify signature
        assert validator.verify_signature(public_key, message, signature) is True

    def test_verify_signature_type_mismatch(self, ed25519_keypair: Any, rsa_keypair: Any) -> None:
        """Test signature verification fails when signature type doesn't match key type."""
        ed_private_key, ed_public_key = ed25519_keypair
        _, rsa_public_key = rsa_keypair
        validator = SSHSignatureValidator()

        # Sign with Ed25519
        message = b"test-message"
        signature = sign_message(ed_private_key, message)

        # Try to verify with RSA public key (type mismatch)
        assert validator.verify_signature(rsa_public_key, message, signature) is False

    def test_verify_signature_with_trailing_data(self, ed25519_keypair: Any) -> None:
        """Test signature verification fails when signature has trailing data."""
        private_key, public_key = ed25519_keypair
        validator = SSHSignatureValidator()

        # Sign message
        message = b"test-message"
        signature = sign_message(private_key, message)

        # Add trailing data to signature
        malformed_signature = signature + b"extra-data"

        # Should reject signature with trailing data
        assert validator.verify_signature(public_key, message, malformed_signature) is False


class TestSSHAuthIntegration:
    """Integration tests for complete SSH authentication flow."""

    @pytest.fixture
    def setup_auth_env(self, tmp_path: Any) -> tuple[Any, Any]:
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
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.write_bytes(private_pem)

        # Load SSH private key
        _, private_key = load_private_key_from_file(private_key_path)

        # Create authorized_keys file
        auth_keys_file = tmp_path / "authorized_keys"
        public_key_line = (
            f"ssh-ed25519 {get_public_key_string(private_key)[1]} test-client:test-key\n"
        )
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

    def test_complete_authentication_flow(self, setup_auth_env: Any) -> None:
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
