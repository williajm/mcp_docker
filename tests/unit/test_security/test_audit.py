"""Unit tests for audit logging."""

import json
from pathlib import Path

import pytest

from mcp_docker.auth.api_key import ClientInfo
from mcp_docker.security.audit import AuditEvent, AuditLogger


class TestAuditEvent:
    """Tests for AuditEvent."""

    @pytest.fixture
    def client_info(self) -> ClientInfo:
        """Create a test client info."""
        return ClientInfo(
            client_id="test-client",
            api_key_hash="abc123",
            description="Test client",
            ip_address="127.0.0.1",
        )

    def test_audit_event_creation(self, client_info: ClientInfo) -> None:
        """Test creating an audit event."""
        event = AuditEvent(
            event_type="tool_call",
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
            result={"success": True},
        )

        assert event.event_type == "tool_call"
        assert event.client_id == "test-client"
        assert event.client_ip == "127.0.0.1"
        assert event.api_key_hash == "abc123"
        assert event.tool_name == "docker_list_containers"
        assert event.arguments == {"all": True}
        assert event.result == {"success": True}
        assert event.error is None
        assert event.timestamp is not None

    def test_audit_event_to_dict(self, client_info: ClientInfo) -> None:
        """Test converting audit event to dictionary."""
        event = AuditEvent(
            event_type="tool_call",
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "tool_call"
        assert event_dict["client_id"] == "test-client"
        assert event_dict["client_ip"] == "127.0.0.1"
        assert event_dict["api_key_hash"] == "abc123"
        assert event_dict["tool_name"] == "docker_list_containers"
        assert event_dict["arguments"] == {"all": True}
        assert "timestamp" in event_dict

    def test_audit_event_to_json(self, client_info: ClientInfo) -> None:
        """Test converting audit event to JSON."""
        event = AuditEvent(
            event_type="tool_call",
            client_info=client_info,
            tool_name="docker_list_containers",
        )

        event_json = event.to_json()

        # Should be valid JSON
        parsed = json.loads(event_json)
        assert parsed["event_type"] == "tool_call"
        assert parsed["client_id"] == "test-client"


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.fixture
    def audit_log_file(self, tmp_path: Path) -> Path:
        """Create a temporary audit log file path."""
        return tmp_path / "audit.log"

    @pytest.fixture
    def client_info(self) -> ClientInfo:
        """Create a test client info."""
        return ClientInfo(
            client_id="test-client",
            api_key_hash="abc123",
            description="Test client",
            ip_address="127.0.0.1",
        )

    def test_init_enabled(self, audit_log_file: Path) -> None:
        """Test initializing audit logger when enabled."""
        logger = AuditLogger(audit_log_file, enabled=True)

        assert logger.enabled is True
        assert logger.audit_log_file == audit_log_file
        assert audit_log_file.exists()

    def test_init_disabled(self, audit_log_file: Path) -> None:
        """Test initializing audit logger when disabled."""
        logger = AuditLogger(audit_log_file, enabled=False)

        assert logger.enabled is False
        # File should not be created when disabled
        assert not audit_log_file.exists()

    def test_log_tool_call_success(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging a successful tool call."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_tool_call(
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
            result={"success": True, "containers": []},
        )

        # Check log file contents
        log_content = audit_log_file.read_text()
        log_entry = json.loads(log_content.strip())

        assert log_entry["event_type"] == "tool_call"
        assert log_entry["client_id"] == "test-client"
        assert log_entry["tool_name"] == "docker_list_containers"
        assert log_entry["arguments"] == {"all": True}
        assert log_entry["result"] == {"success": True, "containers": []}
        assert log_entry["error"] is None

    def test_log_tool_call_failure(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging a failed tool call."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_tool_call(
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
            error="Connection failed",
        )

        # Check log file contents
        log_content = audit_log_file.read_text()
        log_entry = json.loads(log_content.strip())

        assert log_entry["event_type"] == "tool_call"
        assert log_entry["error"] == "Connection failed"
        assert log_entry["result"] is None

    def test_log_tool_call_disabled(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging when audit logging is disabled."""
        logger = AuditLogger(audit_log_file, enabled=False)

        logger.log_tool_call(
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
        )

        # No file should be created
        assert not audit_log_file.exists()

    def test_log_auth_failure(self, audit_log_file: Path) -> None:
        """Test logging an authentication failure."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_auth_failure(
            reason="Invalid API key",
            ip_address="192.168.1.100",
            api_key_hash="xyz789",
        )

        # Check log file contents
        log_content = audit_log_file.read_text()
        log_entry = json.loads(log_content.strip())

        assert log_entry["event_type"] == "auth_failure"
        assert log_entry["client_id"] == "unknown"
        assert log_entry["client_ip"] == "192.168.1.100"
        assert log_entry["error"] == "Invalid API key"

    def test_log_rate_limit_exceeded(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging a rate limit exceeded event."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_rate_limit_exceeded(client_info, "rpm")

        # Check log file contents
        log_content = audit_log_file.read_text()
        log_entry = json.loads(log_content.strip())

        assert log_entry["event_type"] == "rate_limit_exceeded"
        assert log_entry["client_id"] == "test-client"
        assert "rpm" in log_entry["error"]

    def test_sanitize_arguments(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test that sensitive arguments are sanitized."""
        logger = AuditLogger(audit_log_file, enabled=True)

        # Arguments with sensitive data
        arguments = {
            "username": "user",
            "password": "secret123",
            "api_key": "key-123",
            "token": "token-456",
            "normal_field": "visible",
        }

        logger.log_tool_call(
            client_info=client_info,
            tool_name="test_tool",
            arguments=arguments,
        )

        # Check that sensitive fields are redacted
        log_content = audit_log_file.read_text()
        log_entry = json.loads(log_content.strip())

        assert log_entry["arguments"]["password"] == "***REDACTED***"
        assert log_entry["arguments"]["api_key"] == "***REDACTED***"
        assert log_entry["arguments"]["token"] == "***REDACTED***"
        assert log_entry["arguments"]["normal_field"] == "visible"
        assert log_entry["arguments"]["username"] == "user"

    def test_multiple_log_entries(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging multiple entries."""
        logger = AuditLogger(audit_log_file, enabled=True)

        # Log multiple events
        logger.log_tool_call(
            client_info=client_info,
            tool_name="tool1",
            arguments={},
        )
        logger.log_tool_call(
            client_info=client_info,
            tool_name="tool2",
            arguments={},
        )

        # Check that both entries are logged
        log_content = audit_log_file.read_text()
        log_lines = log_content.strip().split("\n")

        assert len(log_lines) == 2

        entry1 = json.loads(log_lines[0])
        entry2 = json.loads(log_lines[1])

        assert entry1["tool_name"] == "tool1"
        assert entry2["tool_name"] == "tool2"
