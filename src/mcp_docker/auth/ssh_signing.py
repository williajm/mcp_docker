"""SSH key loading and signing utilities.

This module provides utilities for loading SSH private keys and creating signatures
using the cryptography library. Supports Ed25519, RSA, and ECDSA keys.
"""

import base64
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from mcp_docker.auth.ssh_wire import create_ssh_signature

# Type alias for supported SSH private key types
SSHPrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def load_private_key_from_file(
    key_path: str | Path,
) -> tuple[str, SSHPrivateKey]:
    """Load SSH private key from file.

    Supports Ed25519, RSA, and ECDSA keys in OpenSSH or PEM format.

    Args:
        key_path: Path to private key file

    Returns:
        Tuple of (key_type, private_key)
        key_type is "ssh-ed25519", "ssh-rsa", or "ecdsa-sha2-nistp256" etc.

    Raises:
        ValueError: If key format is unsupported
    """
    key_path = Path(key_path)

    with key_path.open("rb") as f:
        key_data = f.read()

    # Try to load as OpenSSH format first, then PEM
    loaded_key: PrivateKeyTypes
    try:
        loaded_key = serialization.load_ssh_private_key(key_data, password=None)
    except Exception:
        # Try PEM format
        loaded_key = serialization.load_pem_private_key(key_data, password=None)

    # Determine key type and narrow to SSHPrivateKey
    private_key: SSHPrivateKey
    if isinstance(loaded_key, ed25519.Ed25519PrivateKey):
        key_type = "ssh-ed25519"
        private_key = loaded_key
    elif isinstance(loaded_key, rsa.RSAPrivateKey):
        key_type = "ssh-rsa"
        private_key = loaded_key
    elif isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        # Determine ECDSA curve
        curve = loaded_key.curve
        if isinstance(curve, ec.SECP256R1):
            key_type = "ecdsa-sha2-nistp256"
        elif isinstance(curve, ec.SECP384R1):
            key_type = "ecdsa-sha2-nistp384"
        elif isinstance(curve, ec.SECP521R1):
            key_type = "ecdsa-sha2-nistp521"
        else:
            raise ValueError(f"Unsupported ECDSA curve: {type(curve)}")
        private_key = loaded_key
    else:
        raise ValueError(f"Unsupported key type: {type(loaded_key)}")

    return key_type, private_key


def sign_message_ed25519(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign message with Ed25519 private key.

    Args:
        private_key: Ed25519 private key
        message: Message to sign

    Returns:
        SSH wire format signature
    """
    # Sign the message
    signature_data = private_key.sign(message)

    # Create SSH wire format signature
    return create_ssh_signature("ssh-ed25519", signature_data)


def sign_message_rsa(
    private_key: rsa.RSAPrivateKey,
    message: bytes,
    algorithm: str = "rsa-sha2-512",
) -> bytes:
    """Sign message with RSA private key using specified hash algorithm.

    Args:
        private_key: RSA private key
        message: Message to sign
        algorithm: Signature algorithm to use. One of:
            - "rsa-sha2-512" (default, recommended - uses SHA-512)
            - "rsa-sha2-256" (recommended - uses SHA-256)
            - "ssh-rsa" (legacy - uses SHA-1, deprecated)

    Returns:
        SSH wire format signature

    Raises:
        ValueError: If algorithm is not supported

    Note:
        Defaults to rsa-sha2-512 for maximum security. The legacy ssh-rsa algorithm
        using SHA-1 is deprecated and should only be used for compatibility with
        old systems that don't support the modern algorithms.
    """
    # Select hash algorithm based on requested signature type
    hash_algo: hashes.SHA512 | hashes.SHA256 | hashes.SHA1
    if algorithm == "rsa-sha2-512":
        hash_algo = hashes.SHA512()
    elif algorithm == "rsa-sha2-256":
        hash_algo = hashes.SHA256()
    elif algorithm == "ssh-rsa":
        # SHA-1 is deprecated but included for legacy compatibility
        hash_algo = hashes.SHA1()
    else:
        raise ValueError(
            f"Unsupported RSA signature algorithm: {algorithm}. "
            "Use 'rsa-sha2-512', 'rsa-sha2-256', or 'ssh-rsa'"
        )

    # Sign with PKCS1v15 padding and selected hash algorithm
    signature_data = private_key.sign(message, asym_padding.PKCS1v15(), hash_algo)

    # Create SSH wire format signature with the specified algorithm
    return create_ssh_signature(algorithm, signature_data)


def sign_message_ecdsa(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign message with ECDSA private key.

    Args:
        private_key: ECDSA private key
        message: Message to sign

    Returns:
        SSH wire format signature
    """
    # Determine curve and hash algorithm
    curve = private_key.curve
    hash_algo: hashes.SHA256 | hashes.SHA384 | hashes.SHA512
    if isinstance(curve, ec.SECP256R1):
        key_type = "ecdsa-sha2-nistp256"
        hash_algo = hashes.SHA256()
    elif isinstance(curve, ec.SECP384R1):
        key_type = "ecdsa-sha2-nistp384"
        hash_algo = hashes.SHA384()
    elif isinstance(curve, ec.SECP521R1):
        key_type = "ecdsa-sha2-nistp521"
        hash_algo = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported ECDSA curve: {type(curve)}")

    # Sign the message
    signature_data = private_key.sign(message, ec.ECDSA(hash_algo))

    # Create SSH wire format signature
    return create_ssh_signature(key_type, signature_data)


def sign_message(
    private_key: SSHPrivateKey,
    message: bytes,
    rsa_algorithm: str = "rsa-sha2-512",
) -> bytes:
    """Sign message with private key (auto-detect key type).

    Args:
        private_key: SSH private key
        message: Message to sign
        rsa_algorithm: RSA signature algorithm (only used for RSA keys).
            One of "rsa-sha2-512" (default), "rsa-sha2-256", or "ssh-rsa" (legacy)

    Returns:
        SSH wire format signature

    Raises:
        ValueError: If key type is unsupported

    Note:
        For RSA keys, defaults to rsa-sha2-512 for maximum security.
        Ed25519 and ECDSA keys use their built-in hash algorithms.
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return sign_message_ed25519(private_key, message)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return sign_message_rsa(private_key, message, algorithm=rsa_algorithm)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return sign_message_ecdsa(private_key, message)
    raise ValueError(f"Unsupported key type: {type(private_key)}")


def get_public_key_string(
    private_key: SSHPrivateKey,
) -> tuple[str, str]:
    """Get public key in SSH format from private key.

    Args:
        private_key: SSH private key

    Returns:
        Tuple of (key_type, public_key_base64)

    Raises:
        ValueError: If key type is unsupported
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        key_type = "ssh-ed25519"
        ed_public_key = private_key.public_key()
        pub_bytes = ed_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        # Create SSH wire format
        key_type_encoded = key_type.encode("utf-8")
        wire_data = (
            struct.pack(">I", len(key_type_encoded))
            + key_type_encoded
            + struct.pack(">I", len(pub_bytes))
            + pub_bytes
        )
        return key_type, base64.b64encode(wire_data).decode("ascii")

    if isinstance(private_key, rsa.RSAPrivateKey):
        key_type = "ssh-rsa"
        rsa_public_key = private_key.public_key()
        public_numbers = rsa_public_key.public_numbers()
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")

        # Create SSH wire format
        key_type_encoded = key_type.encode("utf-8")
        wire_data = (
            struct.pack(">I", len(key_type_encoded))
            + key_type_encoded
            + struct.pack(">I", len(e_bytes))
            + e_bytes
            + struct.pack(">I", len(n_bytes))
            + n_bytes
        )
        return key_type, base64.b64encode(wire_data).decode("ascii")

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # Determine curve
        curve = private_key.curve
        if isinstance(curve, ec.SECP256R1):
            key_type = "ecdsa-sha2-nistp256"
            curve_name = "nistp256"
        elif isinstance(curve, ec.SECP384R1):
            key_type = "ecdsa-sha2-nistp384"
            curve_name = "nistp384"
        elif isinstance(curve, ec.SECP521R1):
            key_type = "ecdsa-sha2-nistp521"
            curve_name = "nistp521"
        else:
            raise ValueError(f"Unsupported ECDSA curve: {type(curve)}")

        # Get point bytes (uncompressed format)
        ec_public_key = private_key.public_key()
        point_bytes = ec_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Create SSH wire format
        key_type_encoded = key_type.encode("utf-8")
        curve_name_encoded = curve_name.encode("utf-8")
        wire_data = (
            struct.pack(">I", len(key_type_encoded))
            + key_type_encoded
            + struct.pack(">I", len(curve_name_encoded))
            + curve_name_encoded
            + struct.pack(">I", len(point_bytes))
            + point_bytes
        )
        return key_type, base64.b64encode(wire_data).decode("ascii")

    raise ValueError(f"Unsupported key type: {type(private_key)}")
