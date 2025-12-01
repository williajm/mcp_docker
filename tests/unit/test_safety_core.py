"""Unit tests for safety/core.py SafetyEnforcer."""

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety import OperationSafety
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.utils.errors import UnsafeOperationError, ValidationError


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

    def test_validate_privileged_mode_delegates_to_safety_module(self):
        """Test that validate_privileged_mode correctly delegates to safety module."""
        config = SafetyConfig(allow_privileged_containers=False)
        enforcer = SafetyEnforcer(config)

        # Should raise when privileged=True but not allowed
        with pytest.raises(UnsafeOperationError, match="Privileged mode is not allowed"):
            enforcer.validate_privileged_mode(True)

        # Should not raise when privileged=False
        enforcer.validate_privileged_mode(False)

    def test_validate_mount_path_safe_delegates_to_safety_module(self):
        """Test that validate_mount_path_safe correctly delegates to safety module."""
        config = SafetyConfig(volume_mount_blocklist=["/etc"])
        enforcer = SafetyEnforcer(config)

        with pytest.raises(UnsafeOperationError, match="Mount path .* is blocked"):
            enforcer.validate_mount_path_safe("/etc/passwd")

    def test_validate_command_safe_delegates_to_safety_module(self):
        """Test that validate_command_safe correctly delegates to safety module."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        with pytest.raises((ValidationError, UnsafeOperationError)):
            enforcer.validate_command_safe("rm -rf /")

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
