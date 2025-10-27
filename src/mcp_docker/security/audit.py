"""Audit logging for MCP Docker operations."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_docker.auth.api_key import ClientInfo
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class AuditEvent:
    """Represents a single audit event."""

    def __init__(
        self,
        event_type: str,
        client_info: ClientInfo,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Initialize audit event.

        Args:
            event_type: Type of event (e.g., "tool_call", "auth_failure")
            client_info: Information about the client
            tool_name: Name of the tool called (if applicable)
            arguments: Tool arguments (if applicable)
            result: Result of the operation (if applicable)
            error: Error message (if operation failed)
        """
        self.event_type = event_type
        self.timestamp = datetime.now(UTC)
        self.client_id = client_info.client_id
        self.client_ip = client_info.ip_address
        self.api_key_hash = client_info.api_key_hash
        self.tool_name = tool_name
        self.arguments = arguments
        self.result = result
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        """Convert audit event to dictionary.

        Returns:
            Dictionary representation of the event
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "client_id": self.client_id,
            "client_ip": self.client_ip,
            "api_key_hash": self.api_key_hash,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "result": self.result,
            "error": self.error,
        }

    def to_json(self) -> str:
        """Convert audit event to JSON string.

        Returns:
            JSON representation of the event
        """
        return json.dumps(self.to_dict())


class AuditLogger:
    """Handles audit logging for MCP Docker operations.

    Audit logs record all operations performed through the MCP server,
    including who performed them, when, and the results.
    """

    def __init__(self, audit_log_file: Path, enabled: bool = True) -> None:
        """Initialize audit logger.

        Args:
            audit_log_file: Path to the audit log file
            enabled: Whether audit logging is enabled
        """
        self.audit_log_file = audit_log_file
        self.enabled = enabled

        if self.enabled:
            # Ensure parent directory exists
            self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)

            # Create file if it doesn't exist
            if not self.audit_log_file.exists():
                self.audit_log_file.touch()

            logger.info(f"Audit logging enabled: {self.audit_log_file}")
        else:
            logger.warning("Audit logging DISABLED")

    def log_tool_call(
        self,
        client_info: ClientInfo,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Log a tool call operation.

        Args:
            client_info: Information about the client
            tool_name: Name of the tool called
            arguments: Tool arguments
            result: Result of the operation (if successful)
            error: Error message (if operation failed)
        """
        if not self.enabled:
            return

        event = AuditEvent(
            event_type="tool_call",
            client_info=client_info,
            tool_name=tool_name,
            arguments=self._sanitize_arguments(arguments),
            result=result,
            error=error,
        )

        self._write_event(event)

    def log_auth_failure(
        self,
        reason: str,
        ip_address: str | None = None,
        api_key_hash: str | None = None,
    ) -> None:
        """Log an authentication failure.

        Args:
            reason: Reason for authentication failure
            ip_address: IP address of the client
            api_key_hash: Hash of the API key (if provided)
        """
        if not self.enabled:
            return

        # Create a minimal client info for failed auth
        client_info = ClientInfo(
            client_id="unknown",
            api_key_hash=api_key_hash or "none",
            ip_address=ip_address,
        )

        event = AuditEvent(
            event_type="auth_failure",
            client_info=client_info,
            error=reason,
        )

        self._write_event(event)

    def log_rate_limit_exceeded(
        self,
        client_info: ClientInfo,
        limit_type: str,
    ) -> None:
        """Log a rate limit exceeded event.

        Args:
            client_info: Information about the client
            limit_type: Type of rate limit exceeded (e.g., "rpm", "concurrent")
        """
        if not self.enabled:
            return

        event = AuditEvent(
            event_type="rate_limit_exceeded",
            client_info=client_info,
            error=f"Rate limit exceeded: {limit_type}",
        )

        self._write_event(event)

    def _write_event(self, event: AuditEvent) -> None:
        """Write an audit event to the log file.

        Args:
            event: The audit event to write
        """
        try:
            with self.audit_log_file.open("a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def _sanitize_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Sanitize arguments to remove sensitive data before logging.

        Args:
            arguments: Original arguments

        Returns:
            Sanitized arguments
        """
        # Create a copy to avoid modifying the original
        sanitized = arguments.copy()

        # Remove or mask sensitive fields
        sensitive_keys = {
            "password",
            "api_key",
            "token",
            "secret",
            "credential",
            "auth",
        }

        for key in list(sanitized.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"

        return sanitized
