"""Unit tests for safety/core.py SafetyEnforcer."""

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.safety.core import SafetyEnforcer
from mcp_docker.utils.errors import UnsafeOperationError, ValidationError
from mcp_docker.utils.safety import OperationSafety


class TestSafetyEnforcer:
    """Test SafetyEnforcer class."""

    def test_init(self):
        """Test SafetyEnforcer initialization."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        assert enforcer.config == config

    def test_is_tool_allowed_deny_list(self):
        """Test tool denied by deny list."""
        config = SafetyConfig(denied_tools=["docker_remove_container"])
        enforcer = SafetyEnforcer(config)

        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")

        assert not allowed
        assert "denied by configuration" in reason

    def test_is_tool_allowed_not_in_allow_list(self):
        """Test tool not in allow list."""
        config = SafetyConfig(allowed_tools=["docker_list_containers"])
        enforcer = SafetyEnforcer(config)

        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")

        assert not allowed
        assert "not in allow list" in reason

    def test_is_tool_allowed_in_allow_list(self):
        """Test tool in allow list."""
        config = SafetyConfig(allowed_tools=["docker_list_containers"])
        enforcer = SafetyEnforcer(config)

        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")

        assert allowed
        assert "allowed" in reason.lower()

    def test_is_tool_allowed_default(self):
        """Test tool allowed by default (no lists)."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")

        assert allowed
        assert "allowed" in reason.lower()

    def test_check_operation_safety_moderate_not_allowed(self):
        """Test moderate operation denied in read-only mode."""
        config = SafetyConfig(allow_moderate_operations=False)
        enforcer = SafetyEnforcer(config)

        with pytest.raises(
            UnsafeOperationError, match="Moderate operation .* not allowed in read-only mode"
        ):
            enforcer.check_operation_safety("docker_start_container", OperationSafety.MODERATE)

    def test_check_operation_safety_moderate_allowed(self):
        """Test moderate operation allowed."""
        config = SafetyConfig(allow_moderate_operations=True)
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.check_operation_safety("docker_start_container", OperationSafety.MODERATE)

    def test_check_operation_safety_destructive_not_allowed(self):
        """Test destructive operation denied."""
        config = SafetyConfig(allow_destructive_operations=False)
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="Destructive operation .* not allowed"):
            enforcer.check_operation_safety("docker_remove_container", OperationSafety.DESTRUCTIVE)

    def test_check_operation_safety_destructive_allowed(self):
        """Test destructive operation allowed."""
        config = SafetyConfig(allow_destructive_operations=True)
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.check_operation_safety("docker_remove_container", OperationSafety.DESTRUCTIVE)

    def test_check_operation_safety_destructive_with_confirmation(self):
        """Test destructive operation with confirmation requirement."""
        config = SafetyConfig(
            allow_destructive_operations=True,
            require_confirmation_for_destructive=True,
        )
        enforcer = SafetyEnforcer(config)

        # Should not raise but log warning
        enforcer.check_operation_safety("docker_remove_container", OperationSafety.DESTRUCTIVE)

    def test_check_operation_safety_safe_always_allowed(self):
        """Test safe operation always allowed."""
        config = SafetyConfig(
            allow_moderate_operations=False,
            allow_destructive_operations=False,
        )
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.check_operation_safety("docker_list_containers", OperationSafety.SAFE)

    def test_check_tool_allowed_and_safe_denied_tool(self):
        """Test combined check with denied tool."""
        config = SafetyConfig(denied_tools=["docker_remove_container"])
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="denied by configuration"):
            enforcer.check_tool_allowed_and_safe(
                "docker_remove_container", OperationSafety.DESTRUCTIVE
            )

    def test_check_tool_allowed_and_safe_unsafe_operation(self):
        """Test combined check with unsafe operation level."""
        config = SafetyConfig(allow_destructive_operations=False)
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="not allowed"):
            enforcer.check_tool_allowed_and_safe(
                "docker_remove_container", OperationSafety.DESTRUCTIVE
            )

    def test_check_tool_allowed_and_safe_success(self):
        """Test combined check success."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.check_tool_allowed_and_safe("docker_list_containers", OperationSafety.SAFE)

    def test_validate_privileged_mode_not_allowed(self):
        """Test privileged mode validation when not allowed."""
        config = SafetyConfig(allow_privileged_containers=False)
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="Privileged mode is not allowed"):
            enforcer.validate_privileged_mode(True)

    def test_validate_privileged_mode_allowed(self):
        """Test privileged mode validation when allowed."""
        config = SafetyConfig(allow_privileged_containers=True)
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.validate_privileged_mode(True)

    def test_validate_privileged_mode_not_requested(self):
        """Test privileged mode validation when not requested."""
        config = SafetyConfig(allow_privileged_containers=False)
        enforcer = SafetyEnforcer(config)

        # Should not raise when privileged=False
        enforcer.validate_privileged_mode(False)

    def test_validate_mount_path_safe_blocked(self):
        """Test mount path validation with blocked path."""
        config = SafetyConfig(volume_mount_blocklist=["/etc", "/sys"])
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="Mount path .* is blocked"):
            enforcer.validate_mount_path_safe("/etc/passwd")

    def test_validate_mount_path_safe_allowed(self):
        """Test mount path validation with allowed path."""
        config = SafetyConfig(volume_mount_allowlist=["/data"])
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.validate_mount_path_safe("/data/test")

    def test_validate_command_safe_dangerous_command(self):
        """Test command validation with dangerous command."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        with pytest.raises((ValidationError, UnsafeOperationError)):
            enforcer.validate_command_safe("rm -rf /")

    def test_validate_command_safe_ok_command(self):
        """Test command validation with safe command."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.validate_command_safe("echo hello")

    def test_sanitize_and_validate_command_string(self):
        """Test command sanitization with string input."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        result = enforcer.sanitize_and_validate_command("echo hello world")

        assert isinstance(result, list)
        # String commands are returned as single-element list
        assert len(result) == 1
        assert "echo" in result[0]

    def test_sanitize_and_validate_command_list(self):
        """Test command sanitization with list input."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        result = enforcer.sanitize_and_validate_command(["echo", "hello"])

        assert isinstance(result, list)
        assert result == ["echo", "hello"]

    def test_get_operation_metadata(self):
        """Test getting operation metadata."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        metadata = enforcer.get_operation_metadata("docker_list_containers")

        assert "tool_name" in metadata
        assert "safety_level" in metadata
        assert "is_destructive" in metadata
        assert "is_moderate" in metadata
        assert "is_privileged" in metadata
        assert "allowed_by_config" in metadata
        assert metadata["tool_name"] == "docker_list_containers"

    def test_enforce_all_checks_success(self):
        """Test enforce_all_checks with allowed operation."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.enforce_all_checks("docker_list_containers", OperationSafety.SAFE)

    def test_enforce_all_checks_denied_tool(self):
        """Test enforce_all_checks with denied tool."""
        config = SafetyConfig(denied_tools=["docker_remove_container"])
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="denied"):
            enforcer.enforce_all_checks("docker_remove_container", OperationSafety.DESTRUCTIVE)

    def test_enforce_all_checks_with_privileged_argument(self):
        """Test enforce_all_checks with privileged argument."""
        config = SafetyConfig(allow_privileged_containers=False)
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="Privileged"):
            enforcer.enforce_all_checks(
                "docker_create_container",
                OperationSafety.MODERATE,
                arguments={"privileged": True},
            )

    def test_enforce_all_checks_with_command_argument(self):
        """Test enforce_all_checks with command argument."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        with pytest.raises((ValidationError, UnsafeOperationError)):
            enforcer.enforce_all_checks(
                "docker_exec_command",
                OperationSafety.MODERATE,
                arguments={"command": "rm -rf /"},
            )

    def test_enforce_all_checks_with_binds_argument(self):
        """Test enforce_all_checks with binds argument."""
        config = SafetyConfig(volume_mount_blocklist=["/etc"])
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="blocked"):
            enforcer.enforce_all_checks(
                "docker_create_container",
                OperationSafety.MODERATE,
                arguments={"binds": ["/etc:/etc:ro"]},
            )

    def test_enforce_all_checks_with_safe_binds(self):
        """Test enforce_all_checks with safe binds."""
        config = SafetyConfig(
            # Use yolo_mode to bypass mount path checks for this test
            yolo_mode=True,
        )
        enforcer = SafetyEnforcer(config)

        # Should not raise
        enforcer.enforce_all_checks(
            "docker_create_container",
            OperationSafety.MODERATE,
            arguments={"binds": ["/data:/app/data:rw"]},
        )

    def test_enforce_all_checks_with_multiple_arguments(self):
        """Test enforce_all_checks with multiple argument checks."""
        config = SafetyConfig(
            # Use yolo_mode to bypass mount path checks
            yolo_mode=True,
        )
        enforcer = SafetyEnforcer(config)

        # Should not raise with safe arguments
        enforcer.enforce_all_checks(
            "docker_create_container",
            OperationSafety.MODERATE,
            arguments={
                "privileged": False,
                "command": ["echo", "hello"],
                "binds": ["/data:/app:rw"],
            },
        )
