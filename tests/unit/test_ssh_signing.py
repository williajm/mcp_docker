"""Unit tests for SSH signing utilities."""

import base64
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from mcp_docker.auth.ssh_signing import (
    get_public_key_string,
    load_private_key_from_file,
    sign_message,
    sign_message_ecdsa,
    sign_message_ed25519,
    sign_message_rsa,
)


@pytest.fixture(scope="module")
def ed25519_private_key() -> ed25519.Ed25519PrivateKey:
    """Generate Ed25519 private key for testing (module-scoped for performance)."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate RSA private key for testing (module-scoped for performance)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ecdsa_p256_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate ECDSA P-256 private key for testing (module-scoped for performance)."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ecdsa_p384_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate ECDSA P-384 private key for testing (module-scoped for performance)."""
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture(scope="module")
def ecdsa_p521_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate ECDSA P-521 private key for testing (module-scoped for performance)."""
    return ec.generate_private_key(ec.SECP521R1())


class TestLoadPrivateKeyFromFile:
    """Test load_private_key_from_file function."""

    def test_load_ed25519_openssh_format(
        self, ed25519_private_key: ed25519.Ed25519PrivateKey, tmp_path: Path
    ) -> None:
        """Test loading Ed25519 key in OpenSSH format."""
        key_path = tmp_path / "id_ed25519"
        key_bytes = ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ssh-ed25519"
        assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)

    def test_load_rsa_openssh_format(
        self, rsa_private_key: rsa.RSAPrivateKey, tmp_path: Path
    ) -> None:
        """Test loading RSA key in OpenSSH format."""
        key_path = tmp_path / "id_rsa"
        key_bytes = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ssh-rsa"
        assert isinstance(loaded_key, rsa.RSAPrivateKey)

    def test_load_ecdsa_p256_openssh_format(
        self, ecdsa_p256_private_key: ec.EllipticCurvePrivateKey, tmp_path: Path
    ) -> None:
        """Test loading ECDSA P-256 key in OpenSSH format."""
        key_path = tmp_path / "id_ecdsa_p256"
        key_bytes = ecdsa_p256_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ecdsa-sha2-nistp256"
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP256R1)

    def test_load_ecdsa_p384_openssh_format(
        self, ecdsa_p384_private_key: ec.EllipticCurvePrivateKey, tmp_path: Path
    ) -> None:
        """Test loading ECDSA P-384 key in OpenSSH format."""
        key_path = tmp_path / "id_ecdsa_p384"
        key_bytes = ecdsa_p384_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ecdsa-sha2-nistp384"
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP384R1)

    def test_load_ecdsa_p521_openssh_format(
        self, ecdsa_p521_private_key: ec.EllipticCurvePrivateKey, tmp_path: Path
    ) -> None:
        """Test loading ECDSA P-521 key in OpenSSH format."""
        key_path = tmp_path / "id_ecdsa_p521"
        key_bytes = ecdsa_p521_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ecdsa-sha2-nistp521"
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP521R1)

    def test_load_ed25519_pem_format(
        self, ed25519_private_key: ed25519.Ed25519PrivateKey, tmp_path: Path
    ) -> None:
        """Test loading Ed25519 key in PEM format."""
        key_path = tmp_path / "id_ed25519_pem"
        key_bytes = ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ssh-ed25519"
        assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)

    def test_load_rsa_pem_format(self, rsa_private_key: rsa.RSAPrivateKey, tmp_path: Path) -> None:
        """Test loading RSA key in PEM format."""
        key_path = tmp_path / "id_rsa_pem"
        key_bytes = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ssh-rsa"
        assert isinstance(loaded_key, rsa.RSAPrivateKey)

    def test_load_ecdsa_pem_format(
        self, ecdsa_p256_private_key: ec.EllipticCurvePrivateKey, tmp_path: Path
    ) -> None:
        """Test loading ECDSA key in PEM format."""
        key_path = tmp_path / "id_ecdsa_pem"
        key_bytes = ecdsa_p256_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        key_type, loaded_key = load_private_key_from_file(key_path)

        assert key_type == "ecdsa-sha2-nistp256"
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)

    def test_load_key_from_string_path(
        self, ed25519_private_key: ed25519.Ed25519PrivateKey, tmp_path: Path
    ) -> None:
        """Test loading key with string path instead of Path object."""
        key_path = tmp_path / "id_ed25519"
        key_bytes = ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        # Pass string path
        key_type, loaded_key = load_private_key_from_file(str(key_path))

        assert key_type == "ssh-ed25519"
        assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)

    def test_load_unsupported_key_type(self, tmp_path: Path) -> None:
        """Test loading unsupported key type raises ValueError."""
        # Create a DSA key (unsupported)
        from cryptography.hazmat.primitives.asymmetric import dsa

        dsa_key = dsa.generate_private_key(key_size=2048)
        key_path = tmp_path / "id_dsa"
        key_bytes = dsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_bytes)

        with pytest.raises(ValueError, match="Unsupported key type"):
            load_private_key_from_file(key_path)


class TestSignMessageEd25519:
    """Test sign_message_ed25519 function."""

    def test_sign_message_ed25519(self, ed25519_private_key: ed25519.Ed25519PrivateKey) -> None:
        """Test Ed25519 message signing."""
        message = b"test message"
        signature = sign_message_ed25519(ed25519_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Signature should be in SSH wire format
        # Should start with length prefix for "ssh-ed25519"
        assert signature[:4] == b"\x00\x00\x00\x0b"  # Length of "ssh-ed25519" = 11


class TestSignMessageRSA:
    """Test sign_message_rsa function."""

    def test_sign_message_rsa(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        """Test RSA message signing with default algorithm (rsa-sha2-512)."""
        message = b"test message"
        signature = sign_message_rsa(rsa_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Signature should be in SSH wire format
        # Default is rsa-sha2-512
        assert signature[:4] == b"\x00\x00\x00\x0c"  # Length of "rsa-sha2-512" = 12

    def test_sign_message_rsa_sha2_256(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        """Test RSA message signing with rsa-sha2-256."""
        message = b"test message"
        signature = sign_message_rsa(rsa_private_key, message, algorithm="rsa-sha2-256")

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Should use rsa-sha2-256
        assert signature[:4] == b"\x00\x00\x00\x0c"  # Length of "rsa-sha2-256" = 12

    def test_sign_message_rsa_legacy_sha1(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        """Test RSA message signing with legacy ssh-rsa (SHA-1)."""
        message = b"test message"
        signature = sign_message_rsa(rsa_private_key, message, algorithm="ssh-rsa")

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Should use legacy ssh-rsa
        assert signature[:4] == b"\x00\x00\x00\x07"  # Length of "ssh-rsa" = 7

    def test_sign_message_rsa_unsupported_algorithm(
        self, rsa_private_key: rsa.RSAPrivateKey
    ) -> None:
        """Test RSA message signing with unsupported algorithm."""
        message = b"test message"
        with pytest.raises(ValueError, match="Unsupported RSA signature algorithm"):
            sign_message_rsa(rsa_private_key, message, algorithm="invalid")


class TestSignMessageECDSA:
    """Test sign_message_ecdsa function."""

    def test_sign_message_ecdsa_p256(
        self, ecdsa_p256_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test ECDSA P-256 message signing."""
        message = b"test message"
        signature = sign_message_ecdsa(ecdsa_p256_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Signature should contain "ecdsa-sha2-nistp256"
        # Length of "ecdsa-sha2-nistp256" = 19
        assert signature[:4] == b"\x00\x00\x00\x13"

    def test_sign_message_ecdsa_p384(
        self, ecdsa_p384_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test ECDSA P-384 message signing."""
        message = b"test message"
        signature = sign_message_ecdsa(ecdsa_p384_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Signature should contain "ecdsa-sha2-nistp384"
        # Length of "ecdsa-sha2-nistp384" = 19
        assert signature[:4] == b"\x00\x00\x00\x13"

    def test_sign_message_ecdsa_p521(
        self, ecdsa_p521_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test ECDSA P-521 message signing."""
        message = b"test message"
        signature = sign_message_ecdsa(ecdsa_p521_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Signature should contain "ecdsa-sha2-nistp521"
        # Length of "ecdsa-sha2-nistp521" = 19
        assert signature[:4] == b"\x00\x00\x00\x13"

    def test_sign_message_ecdsa_unsupported_curve(self) -> None:
        """Test ECDSA with unsupported curve raises ValueError."""
        # Create a key with an unsupported curve (e.g., SECP192R1)
        unsupported_key = ec.generate_private_key(ec.SECP192R1())
        message = b"test message"

        with pytest.raises(ValueError, match="Unsupported ECDSA curve"):
            sign_message_ecdsa(unsupported_key, message)


class TestSignMessage:
    """Test sign_message function (auto-detect key type)."""

    def test_sign_message_ed25519(self, ed25519_private_key: ed25519.Ed25519PrivateKey) -> None:
        """Test auto-detect signing with Ed25519."""
        message = b"test message"
        signature = sign_message(ed25519_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_message_rsa(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        """Test auto-detect signing with RSA."""
        message = b"test message"
        signature = sign_message(rsa_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_message_ecdsa(self, ecdsa_p256_private_key: ec.EllipticCurvePrivateKey) -> None:
        """Test auto-detect signing with ECDSA."""
        message = b"test message"
        signature = sign_message(ecdsa_p256_private_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_sign_message_unsupported_type(self) -> None:
        """Test signing with unsupported key type raises ValueError."""
        # Create a mock unsupported key type
        unsupported_key = Mock()

        with pytest.raises(ValueError, match="Unsupported key type"):
            sign_message(unsupported_key, b"test")


class TestGetPublicKeyString:
    """Test get_public_key_string function."""

    def test_get_public_key_string_ed25519(
        self, ed25519_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        """Test getting public key string for Ed25519."""
        key_type, public_key_b64 = get_public_key_string(ed25519_private_key)

        assert key_type == "ssh-ed25519"
        assert isinstance(public_key_b64, str)

        # Should be valid base64
        decoded = base64.b64decode(public_key_b64)
        assert len(decoded) > 0

    def test_get_public_key_string_rsa(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        """Test getting public key string for RSA."""
        key_type, public_key_b64 = get_public_key_string(rsa_private_key)

        assert key_type == "ssh-rsa"
        assert isinstance(public_key_b64, str)

        # Should be valid base64
        decoded = base64.b64decode(public_key_b64)
        assert len(decoded) > 0

    def test_get_public_key_string_ecdsa_p256(
        self, ecdsa_p256_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test getting public key string for ECDSA P-256."""
        key_type, public_key_b64 = get_public_key_string(ecdsa_p256_private_key)

        assert key_type == "ecdsa-sha2-nistp256"
        assert isinstance(public_key_b64, str)

        # Should be valid base64
        decoded = base64.b64decode(public_key_b64)
        assert len(decoded) > 0

    def test_get_public_key_string_ecdsa_p384(
        self, ecdsa_p384_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test getting public key string for ECDSA P-384."""
        key_type, public_key_b64 = get_public_key_string(ecdsa_p384_private_key)

        assert key_type == "ecdsa-sha2-nistp384"
        assert isinstance(public_key_b64, str)

        # Should be valid base64
        decoded = base64.b64decode(public_key_b64)
        assert len(decoded) > 0

    def test_get_public_key_string_ecdsa_p521(
        self, ecdsa_p521_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Test getting public key string for ECDSA P-521."""
        key_type, public_key_b64 = get_public_key_string(ecdsa_p521_private_key)

        assert key_type == "ecdsa-sha2-nistp521"
        assert isinstance(public_key_b64, str)

        # Should be valid base64
        decoded = base64.b64decode(public_key_b64)
        assert len(decoded) > 0

    def test_get_public_key_string_ecdsa_unsupported_curve(self) -> None:
        """Test getting public key string with unsupported ECDSA curve."""
        # Create a key with an unsupported curve
        unsupported_key = ec.generate_private_key(ec.SECP192R1())

        with pytest.raises(ValueError, match="Unsupported ECDSA curve"):
            get_public_key_string(unsupported_key)

    def test_get_public_key_string_unsupported_type(self) -> None:
        """Test getting public key string with unsupported key type."""
        # Create a mock unsupported key type
        unsupported_key = Mock()

        with pytest.raises(ValueError, match="Unsupported key type"):
            get_public_key_string(unsupported_key)
