"""SSH-based authentication for MCP Docker clients."""

import base64
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from loguru import logger

from mcp_docker.auth.ssh_keys import SSHKeyManager, SSHPublicKey
from mcp_docker.auth.ssh_wire import SSHWireMessage
from mcp_docker.config import DEFAULT_SSH_SIGNATURE_MAX_AGE_SECONDS, SecurityConfig
from mcp_docker.utils.errors import (
    SSHKeyNotFoundError,
    SSHNonceReuseError,
    SSHSignatureInvalidError,
    SSHTimestampExpiredError,
)


@dataclass
class SSHAuthRequest:
    """SSH authentication request data.

    Groups the parameters needed for SSH authentication to reduce
    function parameter count and improve cohesion. Using a plain
    dataclass instead of Pydantic to avoid validation complexity
    with bytes fields.
    """

    client_id: str
    """Client identifier from authorized_keys"""

    signature: bytes
    """SSH signature in wire format"""

    timestamp: str
    """ISO 8601 timestamp of the request"""

    nonce: str
    """Random nonce for replay protection"""


class SSHSignatureValidator:
    """Verify SSH signatures using public keys.

    Supports:
    - Ed25519 (recommended)
    - RSA (2048+ bits)
    - ECDSA (P-256, P-384, P-521)
    """

    def _verify_ed25519_signature(self, key_data: bytes, message: bytes, sig_data: bytes) -> bool:
        """Verify Ed25519 signature.

        Args:
            key_data: SSH wire format public key data
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # Ed25519: key_data contains raw 32-byte public key
        key_msg = SSHWireMessage(key_data)
        _ = key_msg.get_text()  # Skip key type
        raw_public_key = key_msg.get_binary()

        # Create cryptography public key and verify
        crypto_public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_public_key)
        crypto_public_key.verify(sig_data, message)
        logger.debug("Ed25519 signature verification succeeded")
        return True

    def _verify_rsa_signature(self, key_data: bytes, message: bytes, sig_data: bytes) -> bool:
        """Verify RSA signature.

        Args:
            key_data: SSH wire format public key data
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # RSA: Parse the key data
        key_msg = SSHWireMessage(key_data)
        _ = key_msg.get_text()  # Skip key type
        e = key_msg.get_mpint()  # Public exponent
        n = key_msg.get_mpint()  # Modulus

        # Create cryptography RSA public key
        public_numbers = rsa.RSAPublicNumbers(e, n)
        crypto_public_key = public_numbers.public_key()

        # Verify with PKCS1v15 padding and SHA-1 (SSH-RSA default)
        # Note: ssh-rsa uses SHA-1, rsa-sha2-256 uses SHA-256, rsa-sha2-512 uses SHA-512
        crypto_public_key.verify(sig_data, message, asym_padding.PKCS1v15(), hashes.SHA1())
        logger.debug("RSA signature verification succeeded")
        return True

    def _verify_ecdsa_signature(
        self, key_type: str, key_data: bytes, message: bytes, sig_data: bytes
    ) -> bool:
        """Verify ECDSA signature.

        Args:
            key_type: SSH key type (e.g., "ecdsa-sha2-nistp256")
            key_data: SSH wire format public key data
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # ECDSA: Parse the key data
        key_msg = SSHWireMessage(key_data)
        _ = key_msg.get_text()  # Skip key type
        curve_name = key_msg.get_text()
        point = key_msg.get_binary()

        # Determine curve and hash algorithm
        if "nistp256" in curve_name or "P-256" in key_type:
            curve = ec.SECP256R1()
            hash_algo = hashes.SHA256()
        elif "nistp384" in curve_name or "P-384" in key_type:
            curve = ec.SECP384R1()
            hash_algo = hashes.SHA384()
        elif "nistp521" in curve_name or "P-521" in key_type:
            curve = ec.SECP521R1()
            hash_algo = hashes.SHA512()
        else:
            logger.warning(f"Unsupported ECDSA curve: {curve_name}")
            return False

        # Parse the point (first byte is 0x04 for uncompressed point)
        if point[0] != 0x04:
            logger.debug("Invalid ECDSA point format")
            return False

        # Create cryptography ECDSA public key
        crypto_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, point)

        # Verify signature
        crypto_public_key.verify(sig_data, message, ec.ECDSA(hash_algo))
        logger.debug("ECDSA signature verification succeeded")
        return True

    def verify_signature(self, public_key: SSHPublicKey, message: bytes, signature: bytes) -> bool:
        """Verify SSH signature using public key.

        Delegates to key-type-specific verification methods for better maintainability
        and testability. Each key type (Ed25519, RSA, ECDSA) has its own verification method.

        Args:
            public_key: SSH public key to verify with
            message: Original message that was signed
            signature: SSH signature in SSH wire format

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Parse SSH signature format (key_type_len + key_type + sig_len + sig_data)
            sig_msg = SSHWireMessage(signature)
            sig_type = sig_msg.get_text()
            sig_data = sig_msg.get_binary()

            # Verify signature type matches key type and no trailing data
            if sig_type != public_key.key_type:
                logger.debug(f"Signature type mismatch: {sig_type} != {public_key.key_type}")
                return False
            if sig_msg.get_remainder():
                logger.debug("Signature has unexpected trailing data")
                return False

            # Decode public key data
            key_data = base64.b64decode(public_key.public_key)

            # Delegate to key-type-specific verification method
            verifier_map = {
                "ssh-ed25519": self._verify_ed25519_signature,
                "ssh-rsa": self._verify_rsa_signature,
            }

            # Check exact match first
            if public_key.key_type in verifier_map:
                return verifier_map[public_key.key_type](key_data, message, sig_data)

            # Check ECDSA prefix match
            if public_key.key_type.startswith("ecdsa-sha2-"):
                return self._verify_ecdsa_signature(
                    public_key.key_type, key_data, message, sig_data
                )

            logger.warning(f"Unsupported key type: {public_key.key_type}")
            return False

        except (InvalidSignature, Exception) as e:
            error_msg = "invalid signature" if isinstance(e, InvalidSignature) else str(e)
            logger.debug(f"Signature verification failed: {error_msg}")
            return False


class SSHAuthProtocol:
    """SSH authentication protocol logic with replay protection.

    Implements:
    - Timestamp validation (prevents long-term replay)
    - Nonce deduplication (prevents replay within timestamp window)
    - Automatic nonce cleanup (prevents memory growth)
    """

    def __init__(self, max_timestamp_age: int = DEFAULT_SSH_SIGNATURE_MAX_AGE_SECONDS):
        """Initialize protocol with configurable timestamp window.

        Args:
            max_timestamp_age: Maximum age of timestamp in seconds (from config)
        """
        self.max_timestamp_age = max_timestamp_age
        self._nonce_store: dict[str, float] = {}  # nonce -> expiry_time
        self._nonce_lock = threading.Lock()

    @staticmethod
    def create_message(client_id: str, timestamp: str, nonce: str) -> bytes:
        """Create message for signing.

        Format: "{client_id}|{timestamp}|{nonce}"

        Args:
            client_id: Client identifier
            timestamp: ISO 8601 timestamp
            nonce: Random nonce

        Returns:
            Message bytes to be signed
        """
        message = f"{client_id}|{timestamp}|{nonce}"
        return message.encode("utf-8")

    def validate_timestamp(self, timestamp: str) -> bool:
        """Validate timestamp is recent.

        Args:
            timestamp: ISO 8601 timestamp string

        Returns:
            True if timestamp is within acceptable window, False otherwise
        """
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(UTC)
            age = abs((now - ts).total_seconds())
            return age <= self.max_timestamp_age
        except Exception as e:
            logger.debug(f"Timestamp validation failed: {e}")
            return False

    def validate_and_register_nonce(self, nonce: str) -> bool:
        """Validate nonce is unique and register it.

        This prevents replay attacks within the timestamp window.
        Nonces are automatically cleaned up after expiry.

        Args:
            nonce: Random nonce string

        Returns:
            True if nonce is new (valid), False if already used (replay attack)
        """
        with self._nonce_lock:
            # Clean expired nonces (prevent memory growth)
            now = time.time()
            self._nonce_store = {n: exp for n, exp in self._nonce_store.items() if exp > now}

            # Check if nonce already used
            if nonce in self._nonce_store:
                logger.warning(f"Replay attack detected: nonce '{nonce}' already used")
                return False

            # Register nonce with expiry
            self._nonce_store[nonce] = now + self.max_timestamp_age
            return True

    @staticmethod
    def generate_nonce() -> str:
        """Generate cryptographically secure random nonce.

        Returns:
            Base64-encoded nonce with 256 bits of entropy
        """
        return secrets.token_urlsafe(32)  # 32 bytes = 256 bits

    def get_nonce_stats(self) -> dict[str, int]:
        """Get statistics about nonce store (for monitoring).

        Returns:
            Dict with 'active_nonces' count
        """
        with self._nonce_lock:
            return {"active_nonces": len(self._nonce_store)}


# ClientInfo is imported from api_key module
from mcp_docker.auth.api_key import ClientInfo  # noqa: E402


class SSHKeyAuthenticator:
    """Authenticate MCP clients using SSH public keys.

    Features:
    - Multiple keys per client (key rotation, multi-device)
    - Replay attack prevention (timestamp + nonce)
    - Thread-safe operations
    - Configurable timestamp window
    """

    def __init__(self, authorized_keys_file, security_config: SecurityConfig):
        """Initialize SSH key authenticator.

        Args:
            authorized_keys_file: Path to authorized_keys file
            security_config: Security configuration (for ssh_signature_max_age)
        """
        self.key_manager = SSHKeyManager(authorized_keys_file)
        self.signature_validator = SSHSignatureValidator()
        # Initialize protocol with configurable timestamp age
        self.protocol = SSHAuthProtocol(max_timestamp_age=security_config.ssh_signature_max_age)

    def authenticate(self, request: SSHAuthRequest) -> ClientInfo | None:
        """Authenticate client using SSH signature.

        Args:
            request: SSH authentication request containing client_id, signature,
                timestamp, and nonce

        Returns:
            ClientInfo if authentication succeeds, None otherwise
        """
        # 1. Validate timestamp
        if not self.protocol.validate_timestamp(request.timestamp):
            logger.warning(f"SSH auth failed: expired timestamp for client '{request.client_id}'")
            raise SSHTimestampExpiredError(
                f"Timestamp expired or invalid (max age: {self.protocol.max_timestamp_age}s)"
            )

        # 2. Validate and register nonce (prevents replay attacks)
        if not self.protocol.validate_and_register_nonce(request.nonce):
            logger.warning(
                f"SSH auth failed: replay attack detected for client '{request.client_id}'"
            )
            raise SSHNonceReuseError("Nonce has already been used (replay attack detected)")

        # 3. Look up client's public keys (supports multiple keys)
        public_keys = self.key_manager.get_keys(request.client_id)
        if not public_keys:
            logger.warning(f"SSH auth failed: unknown client_id '{request.client_id}'")
            raise SSHKeyNotFoundError(f"No authorized keys found for client '{request.client_id}'")

        # 4. Reconstruct challenge message
        message = SSHAuthProtocol.create_message(
            request.client_id, request.timestamp, request.nonce
        )

        # 5. Try to verify signature with any of the client's keys
        verified_key = None
        for public_key in public_keys:
            if not public_key.enabled:
                continue

            if self.signature_validator.verify_signature(public_key, message, request.signature):
                verified_key = public_key
                break

        if verified_key is None:
            logger.warning(f"SSH auth failed: invalid signature for client '{request.client_id}'")
            raise SSHSignatureInvalidError("Signature verification failed")

        # 6. Authentication successful
        logger.info(
            f"SSH authentication successful: client='{request.client_id}', "
            f"key_type={verified_key.key_type}, description={verified_key.description}"
        )

        # Create truncated hash for audit logging
        key_hash = hashlib.sha256(verified_key.public_key.encode()).hexdigest()[:16]

        return ClientInfo(
            client_id=request.client_id,
            api_key_hash=key_hash,
            description=verified_key.description,
        )
