"""SSH wire format parser - replacement for paramiko.Message.

This module provides utilities for parsing and creating SSH wire format data
without requiring the paramiko library. The SSH wire format is defined in
RFC 4251 Section 5 (Data Type Representations).

Wire format types:
- string: 4-byte length (big-endian) + data
- mpint: 4-byte length + data (multiple precision integer, MSB first)
- binary: same as string (4-byte length + data)
"""

import struct


class SSHWireMessage:
    """Parser for SSH wire format messages.

    Provides methods to read various SSH wire format data types from a byte buffer.
    This is a lightweight replacement for paramiko.Message specifically for our
    SSH signature verification needs.
    """

    def __init__(self, data: bytes):
        """Initialize with wire format data.

        Args:
            data: SSH wire format byte data
        """
        self.data = data
        self.offset = 0

    def get_text(self) -> str:
        """Read a length-prefixed string.

        SSH wire format: 4-byte length + UTF-8 string data

        Returns:
            Decoded string

        Raises:
            ValueError: If data is truncated or invalid
        """
        length = self._get_uint32()
        if self.offset + length > len(self.data):
            raise ValueError(f"Truncated string: need {length} bytes, have {len(self.data) - self.offset}")

        text_data = self.data[self.offset : self.offset + length]
        self.offset += length
        return text_data.decode("utf-8")

    def get_binary(self) -> bytes:
        """Read length-prefixed binary data.

        SSH wire format: 4-byte length + binary data

        Returns:
            Binary data bytes

        Raises:
            ValueError: If data is truncated
        """
        length = self._get_uint32()
        if self.offset + length > len(self.data):
            raise ValueError(f"Truncated binary: need {length} bytes, have {len(self.data) - self.offset}")

        binary_data = self.data[self.offset : self.offset + length]
        self.offset += length
        return binary_data

    def get_mpint(self) -> int:
        """Read a multiple precision integer.

        SSH wire format: 4-byte length + big-endian integer data
        MSB first, two's complement representation.

        Returns:
            Integer value

        Raises:
            ValueError: If data is truncated or invalid
        """
        length = self._get_uint32()
        if self.offset + length > len(self.data):
            raise ValueError(f"Truncated mpint: need {length} bytes, have {len(self.data) - self.offset}")

        if length == 0:
            return 0

        mpint_data = self.data[self.offset : self.offset + length]
        self.offset += length

        # Convert big-endian bytes to integer
        return int.from_bytes(mpint_data, byteorder="big", signed=False)

    def get_remainder(self) -> bytes:
        """Get remaining unread data.

        Useful for detecting trailing data that should not be present.

        Returns:
            Remaining bytes in buffer
        """
        return self.data[self.offset:]

    def _get_uint32(self) -> int:
        """Read a 4-byte unsigned integer (big-endian).

        Returns:
            Integer value

        Raises:
            ValueError: If less than 4 bytes remain
        """
        if self.offset + 4 > len(self.data):
            raise ValueError(f"Truncated uint32: need 4 bytes, have {len(self.data) - self.offset}")

        value = struct.unpack(">I", self.data[self.offset : self.offset + 4])[0]
        self.offset += 4
        return value


def create_ssh_signature(key_type: str, signature_data: bytes) -> bytes:
    """Create SSH wire format signature.

    SSH signature format: string(key_type) + string(signature_data)
    Used for creating test signatures.

    Args:
        key_type: SSH key type (e.g., "ssh-ed25519", "ssh-rsa")
        signature_data: Raw signature bytes

    Returns:
        SSH wire format signature
    """
    # Encode key_type as string
    key_type_bytes = key_type.encode("utf-8")
    key_type_wire = struct.pack(">I", len(key_type_bytes)) + key_type_bytes

    # Encode signature_data as string
    sig_wire = struct.pack(">I", len(signature_data)) + signature_data

    return key_type_wire + sig_wire
