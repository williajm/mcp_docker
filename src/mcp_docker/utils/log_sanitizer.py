"""Log sanitization utilities to prevent resource exhaustion and information leakage.

This module provides utilities to sanitize data before logging to prevent:
- Resource exhaustion from large payloads
- Disk space exhaustion from unbounded logs
- Information leakage of sensitive data
- Performance degradation from excessive I/O
"""

import json
import re
from typing import Any

# Default limits (can be overridden via environment variables)
DEFAULT_MAX_STRING_LENGTH = 1024  # 1 KB per string
DEFAULT_MAX_TOTAL_SIZE = 10240  # 10 KB total per log entry
DEFAULT_MAX_DEPTH = 10  # Maximum nesting depth for objects
DEFAULT_MAX_LIST_ITEMS = 100  # Maximum items in a list before truncation

# Byte display limits
MAX_HEX_BYTES_DISPLAY = 64  # Show up to 64 bytes in hex format
BYTES_PER_KB = 1024  # Bytes in a kilobyte


class LogSanitizer:
    """Sanitizes data for safe logging."""

    def __init__(
        self,
        max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        """Initialize log sanitizer.

        Args:
            max_string_length: Maximum length for individual strings (bytes)
            max_total_size: Maximum total size for serialized output (bytes)
            max_depth: Maximum nesting depth for objects/lists
        """
        self.max_string_length = max_string_length
        self.max_total_size = max_total_size
        self.max_depth = max_depth

        # Sensitive field patterns (case-insensitive)
        # Enhanced to catch common variations and database connection strings
        self.sensitive_patterns = {
            "password",
            "passwd",
            "pwd",
            "api_key",
            "apikey",
            "token",
            "secret",
            "credential",
            "auth",
            "authorization",
            "private_key",
            "privatekey",
            # Add common variations
            "access_token",
            "refresh_token",
            "bearer",
            "ssh_key",
            "sshkey",
            "db_password",
            "database_password",
            "connection_string",
            "api_secret",
            "client_secret",
            "shared_secret",
            "auth_token",
            "session_token",
            "jwt",
        }

        # Regex patterns for value-based detection (URLs with credentials, private keys)
        self.credential_patterns = [
            re.compile(r"[a-zA-Z]+://[^:]+:[^@]+@"),  # URLs with user:pass@host
            re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),  # Private keys
            re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"),  # Long base64 (likely key/token)
        ]

    def sanitize(self, data: Any, current_depth: int = 0) -> Any:  # noqa: PLR0911
        """Sanitize data for logging.

        Args:
            data: Data to sanitize
            current_depth: Current nesting depth (used internally)

        Returns:
            Sanitized data safe for logging
        """
        # Check depth limit (allow up to max_depth inclusive, block beyond)
        if current_depth > self.max_depth:
            return f"<max depth {self.max_depth} exceeded>"

        # Handle None
        if data is None:
            return None

        # Handle strings
        if isinstance(data, str):
            return self._truncate_string(data)

        # Handle bytes
        if isinstance(data, bytes):
            return self._truncate_bytes(data)

        # Handle numbers and booleans (pass through)
        if isinstance(data, (int, float, bool)):
            return data

        # Handle dictionaries
        if isinstance(data, dict):
            return self._sanitize_dict(data, current_depth)

        # Handle lists and tuples
        if isinstance(data, (list, tuple)):
            return self._sanitize_list(data, current_depth)

        # Handle other objects - convert to string and truncate
        try:
            str_repr = str(data)
            return self._truncate_string(str_repr, prefix="<object: ")
        except Exception:
            return "<unprintable object>"

    def _truncate_string(self, text: str, prefix: str = "") -> str:
        """Truncate a string to max length.

        Args:
            text: String to truncate
            prefix: Optional prefix for truncated string

        Returns:
            Truncated string with size indicator if truncated
        """
        if len(text) <= self.max_string_length:
            return text

        # Calculate sizes
        original_bytes = len(text.encode("utf-8", errors="replace"))
        truncated = text[: self.max_string_length]
        suffix = f"...truncated ({self._format_size(original_bytes)} total)>"

        return prefix + truncated + suffix if prefix else truncated + suffix

    def _truncate_bytes(self, data: bytes) -> str:
        """Convert bytes to truncated hex representation.

        Args:
            data: Bytes to truncate

        Returns:
            Truncated hex string with size indicator
        """
        if len(data) <= MAX_HEX_BYTES_DISPLAY:
            return f"<bytes: {data.hex()}>"

        truncated_hex = data[:MAX_HEX_BYTES_DISPLAY].hex()
        return f"<bytes: {truncated_hex}...truncated ({self._format_size(len(data))} total)>"

    def _contains_credentials(self, value: str) -> bool:
        """Check if a value contains embedded credentials using regex patterns.

        Args:
            value: String value to check

        Returns:
            True if value appears to contain credentials
        """
        if not isinstance(value, str):
            return False

        return any(pattern.search(value) for pattern in self.credential_patterns)

    def _sanitize_dict(self, data: dict[Any, Any], current_depth: int) -> dict[Any, Any]:
        """Sanitize dictionary recursively.

        Args:
            data: Dictionary to sanitize
            current_depth: Current nesting depth

        Returns:
            Sanitized dictionary
        """
        sanitized = {}
        for key, value in data.items():
            # Convert key to string for comparison
            key_str = str(key).lower()

            # Check if key is sensitive - only redact if value is a primitive
            # If value is a dict/list, recurse into it (keys inside might not be sensitive)
            if any(pattern in key_str for pattern in self.sensitive_patterns):
                # Only redact primitive values directly
                if isinstance(value, (dict, list, tuple)):
                    # Recurse into nested structures
                    sanitized[key] = self.sanitize(value, current_depth + 1)
                else:
                    sanitized[key] = "***REDACTED***"
            # Also check if value contains credentials (e.g., connection strings)
            elif isinstance(value, str) and self._contains_credentials(value):
                sanitized[key] = "***REDACTED*** (contains credentials)"
            else:
                # Recursively sanitize value
                sanitized[key] = self.sanitize(value, current_depth + 1)

        return sanitized

    def _sanitize_list(self, data: list[Any] | tuple[Any, ...], current_depth: int) -> list[Any]:
        """Sanitize list/tuple recursively.

        Args:
            data: List or tuple to sanitize
            current_depth: Current nesting depth

        Returns:
            Sanitized list
        """
        # Limit list length to prevent huge arrays
        if len(data) > DEFAULT_MAX_LIST_ITEMS:
            sanitized = [
                self.sanitize(item, current_depth + 1) for item in data[:DEFAULT_MAX_LIST_ITEMS]
            ]
            sanitized.append(f"...truncated ({len(data)} total items)")
            return sanitized

        return [self.sanitize(item, current_depth + 1) for item in data]

    def sanitize_for_json(self, data: Any) -> str:
        """Sanitize data and serialize to JSON string with size limit.

        Args:
            data: Data to sanitize and serialize

        Returns:
            JSON string, truncated if necessary
        """
        # First sanitize the data
        sanitized = self.sanitize(data)

        # Serialize to JSON
        try:
            json_str = json.dumps(sanitized, ensure_ascii=False, default=str)
        except Exception as e:
            return f"<failed to serialize: {str(e)[:100]}>"

        # Check total size
        json_bytes = len(json_str.encode("utf-8", errors="replace"))
        if json_bytes <= self.max_total_size:
            return json_str

        # Truncate if too large
        # Try to keep it valid JSON by truncating and adding indicator
        truncated = json_str[: self.max_total_size]
        return f'{truncated}..."...TRUNCATED ({self._format_size(json_bytes)} total)"'

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte size as human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted string (e.g., "1.5 KB", "2.3 MB")
        """
        if size_bytes < BYTES_PER_KB:
            return f"{size_bytes} B"
        if size_bytes < BYTES_PER_KB * BYTES_PER_KB:
            return f"{size_bytes / BYTES_PER_KB:.1f} KB"
        return f"{size_bytes / (BYTES_PER_KB * BYTES_PER_KB):.1f} MB"


# Global instance with default settings
_default_sanitizer = LogSanitizer()


def sanitize_for_logging(data: Any) -> Any:
    """Sanitize data for logging using default settings.

    This is a convenience function that uses the global sanitizer instance.

    Args:
        data: Data to sanitize

    Returns:
        Sanitized data safe for logging

    Example:
        >>> logger.debug(f"Arguments: {sanitize_for_logging(arguments)}")
    """
    return _default_sanitizer.sanitize(data)


def sanitize_for_json_logging(data: Any) -> str:
    """Sanitize data and convert to JSON string for logging.

    This is a convenience function that uses the global sanitizer instance.

    Args:
        data: Data to sanitize

    Returns:
        JSON string, truncated if necessary

    Example:
        >>> logger.debug(f"Result: {sanitize_for_json_logging(result)}")
    """
    return _default_sanitizer.sanitize_for_json(data)
