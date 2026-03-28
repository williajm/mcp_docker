"""Tests for tool timeout resolution and ToolSpec timeout field."""

from unittest.mock import Mock

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import TIMEOUT_MEDIUM, TIMEOUT_SLOW, ToolSpec
from mcp_docker.tools.filters import _resolve_timeout, register_tools_with_filtering


class TestResolveTimeout:
    """Test _resolve_timeout helper."""

    def test_tool_override_used(self) -> None:
        """Tool-level timeout takes priority over config."""
        config = SafetyConfig(default_tool_timeout=30.0)
        assert _resolve_timeout(60.0, config) == 60.0

    def test_config_default_used(self) -> None:
        """Config default used when tool timeout is None."""
        config = SafetyConfig(default_tool_timeout=30.0)
        assert _resolve_timeout(None, config) == 30.0

    def test_zero_tool_means_no_timeout(self) -> None:
        """Tool timeout of 0 means no timeout (None for FastMCP)."""
        config = SafetyConfig(default_tool_timeout=30.0)
        assert _resolve_timeout(0, config) is None

    def test_zero_config_means_no_timeout(self) -> None:
        """Config default of 0 means no timeout (None for FastMCP)."""
        config = SafetyConfig(default_tool_timeout=0)
        assert _resolve_timeout(None, config) is None

    def test_no_config_returns_none(self) -> None:
        """No safety_config means no timeout."""
        assert _resolve_timeout(None, None) is None

    def test_tool_override_with_no_config(self) -> None:
        """Tool override works even without config."""
        assert _resolve_timeout(45.0, None) == 45.0


class TestToolSpecTimeout:
    """Test ToolSpec timeout field."""

    def test_default_is_none(self) -> None:
        """ToolSpec.timeout defaults to None (use config default)."""
        spec = ToolSpec(
            name="test",
            description="test",
            safety=OperationSafety.SAFE,
            func=lambda: None,
        )
        assert spec.timeout is None

    def test_explicit_timeout(self) -> None:
        """ToolSpec accepts explicit timeout."""
        spec = ToolSpec(
            name="test",
            description="test",
            safety=OperationSafety.SAFE,
            func=lambda: None,
            timeout=TIMEOUT_MEDIUM,
        )
        assert spec.timeout == 60.0

    def test_frozen_dataclass(self) -> None:
        """ToolSpec is frozen (immutable)."""
        spec = ToolSpec(
            name="test",
            description="test",
            safety=OperationSafety.SAFE,
            func=lambda: None,
            timeout=30.0,
        )
        with pytest.raises(AttributeError):
            spec.timeout = 60.0  # type: ignore[misc]


class TestTimeoutConstants:
    """Test timeout tier constants."""

    def test_medium_timeout(self) -> None:
        assert TIMEOUT_MEDIUM == 60.0

    def test_slow_timeout(self) -> None:
        assert TIMEOUT_SLOW == 300.0


class TestRegisterToolsPassesTimeout:
    """Test that register_tools_with_filtering passes timeout to app.tool()."""

    def test_timeout_passed_to_app_tool(self) -> None:
        """Verify timeout parameter is passed to app.tool()."""
        app = Mock()
        app.tool = Mock(return_value=lambda f: f)

        config = SafetyConfig(default_tool_timeout=30.0)

        tools = [
            ToolSpec(
                name="fast_tool",
                description="A fast tool",
                safety=OperationSafety.SAFE,
                func=lambda: None,
            ),
            ToolSpec(
                name="slow_tool",
                description="A slow tool",
                safety=OperationSafety.MODERATE,
                func=lambda: None,
                timeout=TIMEOUT_SLOW,
            ),
        ]

        register_tools_with_filtering(app, tools, config)

        # First call: fast_tool with config default 30.0
        call1_kwargs = app.tool.call_args_list[0][1]
        assert call1_kwargs["timeout"] == 30.0

        # Second call: slow_tool with explicit 300.0
        call2_kwargs = app.tool.call_args_list[1][1]
        assert call2_kwargs["timeout"] == 300.0

    def test_no_timeout_when_config_disabled(self) -> None:
        """Verify timeout is None when config default is 0."""
        app = Mock()
        app.tool = Mock(return_value=lambda f: f)

        config = SafetyConfig(default_tool_timeout=0)

        tools = [
            ToolSpec(
                name="test_tool",
                description="A test tool",
                safety=OperationSafety.SAFE,
                func=lambda: None,
            ),
        ]

        register_tools_with_filtering(app, tools, config)

        call_kwargs = app.tool.call_args_list[0][1]
        assert call_kwargs["timeout"] is None


class TestConfigValidation:
    """Test SafetyConfig timeout and response limit fields."""

    def test_default_tool_timeout(self) -> None:
        config = SafetyConfig()
        assert config.default_tool_timeout == 30.0

    def test_custom_tool_timeout(self) -> None:
        config = SafetyConfig(default_tool_timeout=120.0)
        assert config.default_tool_timeout == 120.0

    def test_tool_timeout_zero(self) -> None:
        config = SafetyConfig(default_tool_timeout=0)
        assert config.default_tool_timeout == 0

    def test_tool_timeout_max_bound(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SafetyConfig(default_tool_timeout=3601)

    def test_tool_timeout_negative_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SafetyConfig(default_tool_timeout=-1)

    def test_default_max_response_bytes(self) -> None:
        config = SafetyConfig()
        assert config.max_response_bytes == 1048576

    def test_custom_max_response_bytes(self) -> None:
        config = SafetyConfig(max_response_bytes=500000)
        assert config.max_response_bytes == 500000

    def test_max_response_bytes_zero(self) -> None:
        config = SafetyConfig(max_response_bytes=0)
        assert config.max_response_bytes == 0

    def test_max_response_bytes_max_bound(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SafetyConfig(max_response_bytes=10485761)
