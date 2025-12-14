"""Audit logging for MCP Docker operations using structured logging.

SECURITY: Uses loguru's structured logging (battle-tested) instead of custom
JSON file writing. Loguru handles file rotation, size limits, and serialization.

Benefits of using loguru instead of custom code:
- Automatic file rotation (10 MB per file)
- Automatic retention (7 days of logs)
- Automatic compression (zip)
- Thread-safe async writing (enqueue=True)
- JSON serialization (serialize=True)
- No custom file I/O code to maintain
- Automatic redaction of sensitive fields (password, token, secret, etc.)
"""

import re
from pathlib import Path
from typing import Any

from loguru import logger as loguru_logger

from mcp_docker.auth.models import ClientInfo

# Patterns for sensitive field names (case-insensitive matching)
SENSITIVE_FIELD_PATTERNS = [
    r".*password.*",
    r".*passwd.*",
    r".*token.*",
    r".*secret.*",
    r".*credential.*",
    r".*api_key.*",
    r".*apikey.*",
    r".*auth.*",
    r".*private.*",
    r".*jwt.*",
    r".*bearer.*",
]

# Compiled regex for efficiency
_SENSITIVE_PATTERN = re.compile("|".join(SENSITIVE_FIELD_PATTERNS), re.IGNORECASE)

# Redaction placeholder
REDACTED = "<REDACTED>"


def _is_sensitive_key(key: str) -> bool:
    """Check if a key name matches sensitive field patterns.

    Args:
        key: Field/key name to check

    Returns:
        True if the key matches a sensitive pattern
    """
    return bool(_SENSITIVE_PATTERN.match(key))


def _redact_sensitive_values(data: Any, max_depth: int = 10) -> Any:
    """Recursively redact sensitive values from data structures.

    SECURITY: Redacts values where the key matches sensitive patterns.
    This prevents credentials from being logged.

    Args:
        data: Data to redact (dict, list, or primitive)
        max_depth: Maximum recursion depth to prevent infinite loops

    Returns:
        Data with sensitive values replaced by REDACTED
    """
    if max_depth <= 0:
        return data

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                result[key] = REDACTED
            else:
                result[key] = _redact_sensitive_values(value, max_depth - 1)
        return result

    if isinstance(data, list):
        return [_redact_sensitive_values(item, max_depth - 1) for item in data]

    # Primitive types - return as-is
    return data


class AuditLogger:
    """Handles audit logging for MCP Docker operations using loguru.

    SECURITY: Uses loguru's structured logging (battle-tested) with:
    - Automatic file rotation (10 MB per file)
    - Automatic retention (7 days)
    - Compression (zip)
    - JSON serialization (serialize=True)
    - No custom file I/O or sanitization code

    Audit logs record all operations performed through the MCP server,
    including who performed them, when, and the results.
    """

    def __init__(self, audit_log_file: Path, enabled: bool = True) -> None:
        """Initialize audit logger using loguru.

        Args:
            audit_log_file: Path to the audit log file
            enabled: Whether audit logging is enabled
        """
        self.audit_log_file = audit_log_file
        self.enabled = enabled
        self.handler_id = None

        if self.enabled:
            # Ensure parent directory exists with restrictive permissions
            # SECURITY: 0o700 = owner-only access (no group/world read)
            self.audit_log_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Set permissions on existing directory (if it already existed)
            self.audit_log_file.parent.chmod(0o700)

            # Add dedicated audit log handler with loguru
            # SECURITY: Uses loguru's battle-tested file rotation and serialization
            self.handler_id = loguru_logger.add(
                self.audit_log_file,
                serialize=True,  # JSON output
                rotation="10 MB",  # Rotate at 10 MB
                retention="7 days",  # Keep 7 days of logs
                compression="zip",  # Compress rotated logs
                enqueue=True,  # Thread-safe async writing
                backtrace=False,  # Don't include tracebacks
                diagnose=False,  # Don't expose internals
            )

            # Set restrictive permissions on audit log file
            # SECURITY: 0o600 = owner-only read/write (no group/world access)
            if self.audit_log_file.exists():
                self.audit_log_file.chmod(0o600)

            loguru_logger.info(f"Audit logging enabled: {self.audit_log_file}")
        else:
            loguru_logger.warning("Audit logging DISABLED")

    def log_tool_call(
        self,
        client_info: ClientInfo,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Log a tool call operation using loguru structured logging.

        SECURITY: Automatically redacts sensitive fields (password, token,
        secret, credential, auth, etc.) from arguments and results.

        Args:
            client_info: Information about the client
            tool_name: Name of the tool called
            arguments: Tool arguments (sensitive values will be redacted)
            result: Result of the operation (sensitive values will be redacted)
            error: Error message (if operation failed)
        """
        if not self.enabled:
            return

        # SECURITY: Redact sensitive values before logging
        # Note: Use 'is not None' to preserve empty results ({}, []) in audit logs
        redacted_arguments = _redact_sensitive_values(arguments)
        redacted_result = _redact_sensitive_values(result) if result is not None else None

        # Use loguru's structured logging (bind adds fields to JSON output)
        loguru_logger.bind(
            event_type="tool_call",
            client_id=client_info.client_id,
            client_ip=client_info.ip_address,
            api_key_hash=client_info.api_key_hash,
            description=client_info.description,
            tool_name=tool_name,
            arguments=redacted_arguments,
            result=redacted_result,
            error=error,
        ).info(f"Tool call: {tool_name}")

    def log_auth_failure(
        self,
        reason: str,
        ip_address: str | None = None,
        api_key_hash: str | None = None,
    ) -> None:
        """Log an authentication failure using loguru structured logging.

        Args:
            reason: Reason for authentication failure
            ip_address: IP address of the client
            api_key_hash: Hash of the API key (if provided)
        """
        if not self.enabled:
            return

        # Use loguru's structured logging
        loguru_logger.bind(
            event_type="auth_failure",
            client_id="unknown",
            client_ip=ip_address,
            api_key_hash=api_key_hash or "none",
            error=reason,
        ).warning(f"Auth failure: {reason}")

    def log_rate_limit_exceeded(
        self,
        client_info: ClientInfo,
        limit_type: str,
    ) -> None:
        """Log a rate limit exceeded event using loguru structured logging.

        Args:
            client_info: Information about the client
            limit_type: Type of rate limit exceeded (e.g., "rpm", "concurrent")
        """
        if not self.enabled:
            return

        # Use loguru's structured logging
        loguru_logger.bind(
            event_type="rate_limit_exceeded",
            client_id=client_info.client_id,
            client_ip=client_info.ip_address,
            api_key_hash=client_info.api_key_hash,
            description=client_info.description,
            limit_type=limit_type,
        ).warning(f"Rate limit exceeded: {limit_type}")

    def close(self) -> None:
        """Close the audit logger and flush all pending logs.

        This is important for testing with enqueue=True (async writing).
        Removing the handler causes loguru to flush and close the file.
        """
        if self.handler_id is not None:
            loguru_logger.remove(self.handler_id)
            self.handler_id = None
