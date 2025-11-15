"""Unit tests for audit logging."""

import json
import stat
from pathlib import Path

import pytest

from mcp_docker.auth.models import ClientInfo
from mcp_docker.security.audit import AuditLogger

# NOTE: TestAuditEvent class removed after refactoring to use loguru
# (commit f22c6c1). AuditEvent class no longer exists - loguru's structured
# logging is used directly by AuditLogger instead.


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

        # Close logger to flush async writes (enqueue=True)
        logger.close()

        # Check log file contents (loguru format has fields nested under record.extra)
        # File contains multiple entries (init + tool call), get entries with event_type
        log_content = audit_log_file.read_text()
        log_lines = [line for line in log_content.strip().split("\n") if line]
        all_entries = [json.loads(line) for line in log_lines]
        audit_entries = [
            entry
            for entry in all_entries
            if "event_type" in entry.get("record", {}).get("extra", {})
        ]

        assert len(audit_entries) == 1
        extra = audit_entries[0]["record"]["extra"]

        assert extra["event_type"] == "tool_call"
        assert extra["client_id"] == "test-client"
        assert extra["tool_name"] == "docker_list_containers"
        assert extra["arguments"] == {"all": True}
        assert extra["result"] == {"success": True, "containers": []}
        assert extra["error"] is None

    def test_log_tool_call_failure(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging a failed tool call."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_tool_call(
            client_info=client_info,
            tool_name="docker_list_containers",
            arguments={"all": True},
            error="Connection failed",
        )

        # Close logger to flush async writes (enqueue=True)
        logger.close()

        # Check log file contents (loguru format has fields nested under record.extra)
        # File contains multiple entries (init + tool call), get entries with event_type
        log_content = audit_log_file.read_text()
        log_lines = [line for line in log_content.strip().split("\n") if line]
        all_entries = [json.loads(line) for line in log_lines]
        audit_entries = [
            entry
            for entry in all_entries
            if "event_type" in entry.get("record", {}).get("extra", {})
        ]

        assert len(audit_entries) == 1
        extra = audit_entries[0]["record"]["extra"]

        assert extra["event_type"] == "tool_call"
        assert extra["error"] == "Connection failed"
        assert extra["result"] is None

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

        # Close logger to flush async writes (enqueue=True)
        logger.close()

        # Check log file contents (loguru format has fields nested under record.extra)
        # File contains multiple entries (init + auth failure), get entries with event_type
        log_content = audit_log_file.read_text()
        log_lines = [line for line in log_content.strip().split("\n") if line]
        all_entries = [json.loads(line) for line in log_lines]
        audit_entries = [
            entry
            for entry in all_entries
            if "event_type" in entry.get("record", {}).get("extra", {})
        ]

        assert len(audit_entries) == 1
        extra = audit_entries[0]["record"]["extra"]

        assert extra["event_type"] == "auth_failure"
        assert extra["client_id"] == "unknown"
        assert extra["client_ip"] == "192.168.1.100"
        assert extra["error"] == "Invalid API key"

    def test_log_rate_limit_exceeded(self, audit_log_file: Path, client_info: ClientInfo) -> None:
        """Test logging a rate limit exceeded event."""
        logger = AuditLogger(audit_log_file, enabled=True)

        logger.log_rate_limit_exceeded(client_info, "rpm")

        # Close logger to flush async writes (enqueue=True)
        logger.close()

        # Check log file contents (loguru format has fields nested under record.extra)
        # File contains multiple entries (init + rate limit), get entries with event_type
        log_content = audit_log_file.read_text()
        log_lines = [line for line in log_content.strip().split("\n") if line]
        all_entries = [json.loads(line) for line in log_lines]
        audit_entries = [
            entry
            for entry in all_entries
            if "event_type" in entry.get("record", {}).get("extra", {})
        ]

        assert len(audit_entries) == 1
        extra = audit_entries[0]["record"]["extra"]

        assert extra["event_type"] == "rate_limit_exceeded"
        assert extra["client_id"] == "test-client"
        # Check limit_type field instead of error
        assert extra["limit_type"] == "rpm"

    # NOTE: test_sanitize_arguments removed - argument sanitization was intentionally
    # removed when refactoring to use loguru (battle-tested library). The old
    # LogSanitizer was custom code that has been replaced with loguru's built-in
    # capabilities for handling large payloads.

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

        # Close logger to flush async writes (enqueue=True)
        logger.close()

        # Check that both entries are logged (loguru format has fields nested under record.extra)
        # File contains multiple entries (init + 2 tool calls), get entries with event_type
        log_content = audit_log_file.read_text()
        log_lines = [line for line in log_content.strip().split("\n") if line]
        all_entries = [json.loads(line) for line in log_lines]
        audit_entries = [
            entry
            for entry in all_entries
            if "event_type" in entry.get("record", {}).get("extra", {})
        ]

        assert len(audit_entries) == 2

        assert audit_entries[0]["record"]["extra"]["tool_name"] == "tool1"
        assert audit_entries[1]["record"]["extra"]["tool_name"] == "tool2"

    def test_audit_log_directory_permissions(self, audit_log_file: Path) -> None:
        """Test that audit log directory has restrictive permissions (0o700)."""
        logger = AuditLogger(audit_log_file, enabled=True)

        # Check directory permissions
        dir_stat = audit_log_file.parent.stat()
        dir_mode = stat.S_IMODE(dir_stat.st_mode)

        # Directory should be 0o700 (owner-only access)
        assert dir_mode == 0o700, f"Expected 0o700, got {oct(dir_mode)}"

        logger.close()

    def test_audit_log_file_permissions(self, audit_log_file: Path) -> None:
        """Test that audit log file has restrictive permissions (0o600)."""
        logger = AuditLogger(audit_log_file, enabled=True)

        # Check file permissions
        file_stat = audit_log_file.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)

        # File should be 0o600 (owner-only read/write)
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"

        logger.close()

    def test_audit_log_permissions_existing_directory(self, tmp_path: Path) -> None:
        """Test that permissions are set even when directory already exists."""
        # Create directory with world-readable permissions
        log_dir = tmp_path / "logs"
        log_dir.mkdir(mode=0o755)

        # Verify it starts with permissive permissions
        initial_mode = stat.S_IMODE(log_dir.stat().st_mode)
        assert initial_mode == 0o755

        # Create audit logger (should fix permissions)
        audit_log_file = log_dir / "audit.log"
        logger = AuditLogger(audit_log_file, enabled=True)

        # Check that permissions were fixed to 0o700
        fixed_mode = stat.S_IMODE(log_dir.stat().st_mode)
        assert fixed_mode == 0o700, f"Expected 0o700, got {oct(fixed_mode)}"

        logger.close()
