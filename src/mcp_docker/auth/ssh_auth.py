"""SSH-based authentication for MCP Docker clients.

SECURITY: Uses cryptography library for SSH key parsing (battle-tested).
Replaces custom SSHWireMessage key parsing with load_ssh_public_key().
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cachetools import TTLCache
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from loguru import logger

from mcp_docker.auth.models import ClientInfo
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

    def _verify_ed25519_signature(
        self, crypto_public_key: ed25519.Ed25519PublicKey, message: bytes, sig_data: bytes
    ) -> bool:
        """Verify Ed25519 signature.

        Args:
            crypto_public_key: Cryptography Ed25519 public key object
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # SECURITY: Uses cryptography library (battle-tested) for signature verification
        crypto_public_key.verify(sig_data, message)
        logger.debug("Ed25519 signature verification succeeded")
        return True

    def _verify_rsa_signature(
        self, sig_type: str, crypto_public_key: rsa.RSAPublicKey, message: bytes, sig_data: bytes
    ) -> bool:
        """Verify RSA signature with secure hash algorithm.

        Only supports modern RSA signature algorithms using SHA-256 or SHA-512.
        Legacy ssh-rsa with SHA-1 is not supported due to security concerns.

        Args:
            sig_type: Signature algorithm type (rsa-sha2-256 or rsa-sha2-512)
            crypto_public_key: Cryptography RSA public key object
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # Select hash algorithm based on signature type (only secure algorithms)
        hash_algo: hashes.SHA512 | hashes.SHA256
        if sig_type == "rsa-sha2-512":
            hash_algo = hashes.SHA512()
            logger.debug("Using SHA-512 for RSA signature verification")
        elif sig_type == "rsa-sha2-256":
            hash_algo = hashes.SHA256()
            logger.debug("Using SHA-256 for RSA signature verification")
        else:
            logger.warning(
                f"Unsupported RSA signature type: {sig_type}. "
                "Only rsa-sha2-256 and rsa-sha2-512 are supported. "
                "Legacy ssh-rsa (SHA-1) is rejected for security reasons."
            )
            return False

        # SECURITY: Uses cryptography library (battle-tested) for signature verification
        crypto_public_key.verify(sig_data, message, asym_padding.PKCS1v15(), hash_algo)
        logger.debug(f"RSA signature verification succeeded with {sig_type}")
        return True

    def _verify_ecdsa_signature(
        self, crypto_public_key: ec.EllipticCurvePublicKey, message: bytes, sig_data: bytes
    ) -> bool:
        """Verify ECDSA signature.

        Args:
            crypto_public_key: Cryptography ECDSA public key object
            message: Original message that was signed
            sig_data: Signature data (without SSH wire format wrapper)

        Returns:
            True if signature is valid

        Raises:
            InvalidSignature: If signature verification fails
        """
        # Determine hash algorithm from the curve (introspect cryptography key object)
        curve = crypto_public_key.curve
        hash_algo: hashes.SHA256 | hashes.SHA384 | hashes.SHA512
        if isinstance(curve, ec.SECP256R1):
            hash_algo = hashes.SHA256()
        elif isinstance(curve, ec.SECP384R1):
            hash_algo = hashes.SHA384()
        elif isinstance(curve, ec.SECP521R1):
            hash_algo = hashes.SHA512()
        else:
            logger.warning(f"Unsupported ECDSA curve: {curve.name}")
            return False

        # SECURITY: Uses cryptography library (battle-tested) for signature verification
        crypto_public_key.verify(sig_data, message, ec.ECDSA(hash_algo))
        logger.debug("ECDSA signature verification succeeded")
        return True

    def _validate_signature_type(self, key_type: str, sig_type: str) -> bool:
        """Validate that signature type is compatible with key type.

        Args:
            key_type: SSH public key type
            sig_type: Signature algorithm type from signature data

        Returns:
            True if signature type is valid for the given key type
        """
        # For RSA keys, only allow modern algorithms (SHA-256 and SHA-512)
        # Legacy ssh-rsa (SHA-1) is rejected for security reasons
        if key_type == "ssh-rsa":
            return sig_type in ("rsa-sha2-256", "rsa-sha2-512")
        # For other key types, signature type must match exactly
        return sig_type == key_type

    def _verify_by_key_type(
        self,
        crypto_public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        sig_type: str,
        message: bytes,
        sig_data: bytes,
    ) -> bool:
        """Delegate signature verification to key-type-specific method.

        Args:
            crypto_public_key: Cryptography public key object
            sig_type: Signature algorithm type
            message: Original message that was signed
            sig_data: Signature data

        Returns:
            True if signature is valid, False otherwise
        """
        # Dispatch based on cryptography key type (no SSH wire format parsing needed)
        if isinstance(crypto_public_key, ed25519.Ed25519PublicKey):
            return self._verify_ed25519_signature(crypto_public_key, message, sig_data)
        if isinstance(crypto_public_key, rsa.RSAPublicKey):
            return self._verify_rsa_signature(sig_type, crypto_public_key, message, sig_data)
        if isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
            return self._verify_ecdsa_signature(crypto_public_key, message, sig_data)

        logger.warning(f"Unsupported key type: {type(crypto_public_key)}")
        return False

    def verify_signature(self, public_key: SSHPublicKey, message: bytes, signature: bytes) -> bool:
        """Verify SSH signature using public key.

        SECURITY: Uses cryptography library's load_ssh_public_key (battle-tested)
        to parse SSH public keys instead of custom SSHWireMessage parsing.

        Delegates to key-type-specific verification methods for better maintainability
        and testability. Each key type (Ed25519, RSA, ECDSA) has its own verification method.

        Supported RSA signature algorithms (secure only):
        - rsa-sha2-512 (recommended, uses SHA-512)
        - rsa-sha2-256 (uses SHA-256)

        Note: Legacy ssh-rsa (SHA-1) is NOT supported due to security concerns.

        Args:
            public_key: SSH public key to verify with
            message: Original message that was signed
            signature: SSH signature in SSH wire format

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Parse SSH signature format (key_type_len + key_type + sig_len + sig_data)
            # NOTE: Still uses SSHWireMessage for signature parsing (not key parsing)
            sig_msg = SSHWireMessage(signature)
            sig_type = sig_msg.get_text()
            sig_data = sig_msg.get_binary()

            # Verify signature type is compatible with key type
            is_valid_sig_type = self._validate_signature_type(public_key.key_type, sig_type)
            if not is_valid_sig_type or sig_msg.get_remainder():
                if not is_valid_sig_type:
                    logger.debug(
                        f"Invalid signature type: {sig_type} for key: {public_key.key_type}"
                    )
                else:
                    logger.debug("Signature has unexpected trailing data")
                return False

            # SECURITY: Use cryptography library to parse SSH public key (battle-tested)
            # Construct SSH public key line (format: "ssh-ed25519 AAAAC3Nza...")
            ssh_key_line = f"{public_key.key_type} {public_key.public_key}".encode()
            try:
                crypto_public_key = load_ssh_public_key(ssh_key_line)
            except Exception as parse_error:
                logger.debug(
                    f"Failed to parse SSH public key: {parse_error}, key_type={public_key.key_type}"
                )
                return False

            # SECURITY: Reject DSA keys (deprecated and insecure)
            if isinstance(crypto_public_key, dsa.DSAPublicKey):
                logger.warning(f"Rejected DSA key (deprecated): client_id={public_key.client_id}")
                return False

            # Delegate to key-type-specific verification method
            return self._verify_by_key_type(crypto_public_key, sig_type, message, sig_data)

        except InvalidSignature:
            logger.debug("Signature verification failed: invalid signature")
            return False
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
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
        # TTLCache: automatically expires entries after TTL (thread-safe, bounded)
        # SECURITY: Prevents memory exhaustion from replay attacks
        self._nonce_store: TTLCache[str, float] = TTLCache(
            maxsize=10000,  # Max 10k concurrent auth attempts
            ttl=max_timestamp_age,  # Auto-expire after signature max age
        )

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
        TTLCache automatically expires nonces and enforces size limits.

        Args:
            nonce: Random nonce string

        Returns:
            True if nonce is new (valid), False if already used (replay attack)
        """
        # TTLCache is thread-safe, handles expiration and capacity automatically
        if nonce in self._nonce_store:
            logger.warning(f"Replay attack detected: nonce '{nonce}' already used")
            return False

        # Register nonce (TTL handled by cache, expires after max_timestamp_age)
        self._nonce_store[nonce] = True
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
            Dict with 'active_nonces' count and 'max_capacity'
        """
        return {
            "active_nonces": len(self._nonce_store),
            "max_capacity": int(self._nonce_store.maxsize),
        }


class SSHKeyAuthenticator:
    """Authenticate MCP clients using SSH public keys.

    Features:
    - Multiple keys per client (key rotation, multi-device)
    - Replay attack prevention (timestamp + nonce)
    - Thread-safe operations
    - Configurable timestamp window
    """

    def __init__(self, authorized_keys_file: Path, security_config: SecurityConfig) -> None:
        """Initialize SSH key authenticator.

        Args:
            authorized_keys_file: Path to authorized_keys file
            security_config: Security configuration (for ssh_signature_max_age)
        """
        self.key_manager = SSHKeyManager(authorized_keys_file)
        self.signature_validator = SSHSignatureValidator()
        # Initialize protocol with configurable timestamp age
        self.protocol = SSHAuthProtocol(max_timestamp_age=security_config.ssh_signature_max_age)

    def authenticate(self, request: SSHAuthRequest) -> ClientInfo:
        """Authenticate client using SSH signature.

        Args:
            request: SSH authentication request containing client_id, signature,
                timestamp, and nonce

        Returns:
            ClientInfo if authentication succeeds

        Raises:
            SSHTimestampExpiredError: If timestamp is too old
            SSHNonceReuseError: If nonce has been used before (replay attack)
            SSHKeyNotFoundError: If client_id not found in authorized keys
            SSHSignatureInvalidError: If signature verification fails
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
        # SECURITY: Use constant-time verification to prevent timing attacks
        verified_key = None
        valid_keys = []

        for public_key in public_keys:
            if not public_key.enabled:
                continue

            # Check ALL keys (constant time) - do not break early
            if self.signature_validator.verify_signature(public_key, message, request.signature):
                valid_keys.append(public_key)

        # Use first valid key (if any) after checking all
        if valid_keys:
            verified_key = valid_keys[0]
        else:
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
