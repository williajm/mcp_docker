"""Unit tests for SafetyEnforcer."""

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety import OperationSafety
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.utils.errors import UnsafeOperationError


class TestSafetyEnforcer:
    """Test SafetyEnforcer class."""

    def test_init(self) -> None:
        """Test SafetyEnforcer initialization."""
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        assert enforcer.config == config

    def test_safe_operation_allowed(self) -> None:
        """Test safe operations are always allowed."""
        enforcer = SafetyEnforcer(SafetyConfig(allow_moderate_operations=False))

        enforcer.check_operation_safety("docker_list_containers", OperationSafety.SAFE)

    def test_moderate_operation_allowed_by_default(self) -> None:
        """Test moderate operations are allowed by default."""
        enforcer = SafetyEnforcer(SafetyConfig())

        enforcer.check_operation_safety("docker_start_container", OperationSafety.MODERATE)

    def test_moderate_operation_denied_in_read_only_mode(self) -> None:
        """Test moderate operation denied in read-only mode."""
        enforcer = SafetyEnforcer(SafetyConfig(allow_moderate_operations=False))

        with pytest.raises(
            UnsafeOperationError, match="Moderate operation .* is not allowed in read-only mode"
        ):
            enforcer.check_operation_safety("docker_start_container", OperationSafety.MODERATE)

    def test_destructive_operation_unavailable(self) -> None:
        """Test destructive operations are always unavailable."""
        enforcer = SafetyEnforcer(SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="not available in this slim package"):
            enforcer.check_operation_safety("unknown_destructive_tool", OperationSafety.DESTRUCTIVE)

    def test_enforce_all_checks_uses_operation_policy(self) -> None:
        """Test enforce_all_checks delegates to the operation policy."""
        enforcer = SafetyEnforcer(SafetyConfig(allow_moderate_operations=False))

        with pytest.raises(UnsafeOperationError):
            enforcer.enforce_all_checks("docker_restart_container", OperationSafety.MODERATE)
