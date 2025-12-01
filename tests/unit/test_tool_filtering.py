"""Unit tests for tool filtering behavior in SafetyEnforcer.

Tests that SAFETY_ALLOWED_TOOLS and SAFETY_DENIED_TOOLS correctly filter tools,
including the new behavior where None = allow all, [] = block all.
"""

from mcp_docker.config import SafetyConfig
from mcp_docker.services.safety_enforcer import SafetyEnforcer
from mcp_docker.tools.filters import should_register_tool


class TestToolFiltering:
    """Test tool filtering based on allowed_tools and denied_tools configuration."""

    def test_none_allowed_tools_allows_all(self):
        """Test that allowed_tools=None allows all tools (default behavior)."""
        config = SafetyConfig(allowed_tools=None)
        enforcer = SafetyEnforcer(config)

        # All tools should be allowed
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is True
        assert reason == "Tool allowed"

        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is True

    def test_empty_list_allowed_tools_blocks_all(self):
        """Test that allowed_tools=[] blocks all tools (explicit restriction)."""
        config = SafetyConfig(allowed_tools=[])
        enforcer = SafetyEnforcer(config)

        # All tools should be blocked
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is False
        assert "not in allow list" in reason

        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is False

    def test_specific_tools_allowed(self):
        """Test that allowed_tools=['foo'] allows only foo."""
        config = SafetyConfig(allowed_tools=["docker_list_containers"])
        enforcer = SafetyEnforcer(config)

        # Only listed tool should be allowed
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is True

        # Other tools should be blocked
        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is False
        assert "not in allow list" in reason

    def test_multiple_tools_allowed(self):
        """Test that allowed_tools with multiple items allows only those."""
        config = SafetyConfig(allowed_tools=["docker_list_containers", "docker_inspect_container"])
        enforcer = SafetyEnforcer(config)

        # Both listed tools should be allowed
        assert enforcer.is_tool_allowed("docker_list_containers")[0] is True
        assert enforcer.is_tool_allowed("docker_inspect_container")[0] is True

        # Other tools should be blocked
        assert enforcer.is_tool_allowed("docker_remove_container")[0] is False

    def test_denied_tools_blocks_specific(self):
        """Test that denied_tools blocks specific tools."""
        config = SafetyConfig(denied_tools=["docker_remove_container"])
        enforcer = SafetyEnforcer(config)

        # Denied tool should be blocked
        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is False
        assert "denied by configuration" in reason

        # Other tools should be allowed
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is True

    def test_denied_tools_takes_precedence(self):
        """Test that denied_tools takes precedence over allowed_tools."""
        config = SafetyConfig(
            allowed_tools=["docker_list_containers", "docker_remove_container"],
            denied_tools=["docker_remove_container"],
        )
        enforcer = SafetyEnforcer(config)

        # Denied tool should be blocked even though it's in allowed list
        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is False
        assert "denied by configuration" in reason

        # Other allowed tool should work
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is True

    def test_empty_denied_tools_denies_all(self):
        """Test that denied_tools=[] denies all tools (explicit deny-all)."""
        config = SafetyConfig(denied_tools=[])
        enforcer = SafetyEnforcer(config)

        # Empty deny list should deny all tools
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is False
        assert "All tools denied" in reason or "empty deny list" in reason

        # All tools should be denied
        allowed, reason = enforcer.is_tool_allowed("docker_remove_container")
        assert allowed is False

    def test_none_denied_tools_is_default(self):
        """Test that denied_tools=None is the default (no denials)."""
        config = SafetyConfig(denied_tools=None)
        enforcer = SafetyEnforcer(config)

        # All tools should be allowed (no deny list)
        allowed, reason = enforcer.is_tool_allowed("docker_list_containers")
        assert allowed is True


class TestToolFilteringBackwardsCompatibility:
    """Test backwards compatibility of tool filtering changes."""

    def test_default_config_allows_all_tools(self):
        """Test that default config (no env vars) allows all tools.

        Critical for backwards compatibility - existing deployments that don't
        set SAFETY_ALLOWED_TOOLS should continue to work unchanged.
        """
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Should allow all tools with default config
        assert config.allowed_tools is None
        assert config.denied_tools is None

        # All tools should be allowed
        assert enforcer.is_tool_allowed("docker_list_containers")[0] is True
        assert enforcer.is_tool_allowed("docker_inspect_container")[0] is True
        assert enforcer.is_tool_allowed("docker_remove_container")[0] is True

    def test_explicit_empty_string_blocks_all(self, monkeypatch):
        """Test that SAFETY_ALLOWED_TOOLS="" blocks all tools."""
        monkeypatch.setenv("SAFETY_ALLOWED_TOOLS", "")
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Empty string should parse to [] which blocks all
        assert config.allowed_tools == []

        # All tools should be blocked
        assert enforcer.is_tool_allowed("docker_list_containers")[0] is False
        assert enforcer.is_tool_allowed("docker_inspect_container")[0] is False

    def test_unset_env_var_remains_none(self, monkeypatch):
        """Test that not setting SAFETY_ALLOWED_TOOLS keeps it as None."""
        monkeypatch.delenv("SAFETY_ALLOWED_TOOLS", raising=False)
        config = SafetyConfig()

        # Should be None (not [])
        assert config.allowed_tools is None

    def test_comma_separated_tools_parse_correctly(self, monkeypatch):
        """Test that comma-separated SAFETY_ALLOWED_TOOLS parses correctly."""
        monkeypatch.setenv(
            "SAFETY_ALLOWED_TOOLS", "docker_list_containers,docker_inspect_container"
        )
        config = SafetyConfig()

        assert config.allowed_tools == ["docker_list_containers", "docker_inspect_container"]

    def test_explicit_empty_denied_tools_blocks_all(self, monkeypatch):
        """Test that SAFETY_DENIED_TOOLS="" denies all tools."""
        monkeypatch.setenv("SAFETY_DENIED_TOOLS", "")
        config = SafetyConfig()
        enforcer = SafetyEnforcer(config)

        # Empty string should parse to [] which denies all
        assert config.denied_tools == []

        # All tools should be denied
        assert enforcer.is_tool_allowed("docker_list_containers")[0] is False
        assert enforcer.is_tool_allowed("docker_inspect_container")[0] is False
        assert enforcer.is_tool_allowed("docker_remove_container")[0] is False


class TestShouldRegisterTool:
    """Test the should_register_tool function that controls tool registration.

    This is a regression test for the bug where empty lists were treated the same as None,
    causing SAFETY_ALLOWED_TOOLS="" to not block tool registration.
    """

    def test_none_allowed_tools_registers_all_tools(self):
        """Test that allowed_tools=None allows all tools to be registered (default)."""
        config = SafetyConfig(allowed_tools=None)

        # All tools should be registered
        assert should_register_tool("docker_list_containers", config) is True
        assert should_register_tool("docker_remove_container", config) is True
        assert should_register_tool("any_tool", config) is True

    def test_empty_list_allowed_tools_blocks_all_registration(self):
        """Test that allowed_tools=[] blocks all tool registration (explicit empty).

        Regression test: Previously, empty list was treated the same as None due to
        truthy check, causing all tools to be registered even with SAFETY_ALLOWED_TOOLS="".
        """
        config = SafetyConfig(allowed_tools=[])

        # Empty list should block ALL tools from being registered
        assert should_register_tool("docker_list_containers", config) is False
        assert should_register_tool("docker_remove_container", config) is False
        assert should_register_tool("any_tool", config) is False

    def test_specific_tools_allowed_only_registers_those(self):
        """Test that allowed_tools=['foo'] only registers foo."""
        config = SafetyConfig(allowed_tools=["docker_list_containers"])

        # Only the allowed tool should be registered
        assert should_register_tool("docker_list_containers", config) is True

        # Other tools should not be registered
        assert should_register_tool("docker_remove_container", config) is False
        assert should_register_tool("docker_inspect_container", config) is False

    def test_none_denied_tools_denies_nothing(self):
        """Test that denied_tools=None denies no tools (default)."""
        config = SafetyConfig(denied_tools=None)

        # All tools should be registered (no denials)
        assert should_register_tool("docker_list_containers", config) is True
        assert should_register_tool("docker_remove_container", config) is True

    def test_empty_list_denied_tools_denies_all(self):
        """Test that denied_tools=[] denies all tools (explicit deny-all).

        Both allowed_tools=[] and denied_tools=[] mean "block/deny all".
        This is consistent with the documentation that says
        "Set to empty string to deny all tools."
        """
        config = SafetyConfig(denied_tools=[])

        # Empty deny list should block all tools from registration
        assert should_register_tool("docker_list_containers", config) is False
        assert should_register_tool("docker_remove_container", config) is False
        assert should_register_tool("any_tool", config) is False

    def test_specific_tools_denied_blocks_those(self):
        """Test that denied_tools=['foo'] blocks registration of foo."""
        config = SafetyConfig(denied_tools=["docker_remove_container"])

        # Denied tool should not be registered
        assert should_register_tool("docker_remove_container", config) is False

        # Other tools should be registered
        assert should_register_tool("docker_list_containers", config) is True
        assert should_register_tool("docker_inspect_container", config) is True

    def test_denied_tools_takes_precedence_over_allowed(self):
        """Test that denied_tools takes precedence over allowed_tools."""
        config = SafetyConfig(
            allowed_tools=["docker_list_containers", "docker_remove_container"],
            denied_tools=["docker_remove_container"],
        )

        # Denied tool should not be registered even though it's in allowed list
        assert should_register_tool("docker_remove_container", config) is False

        # Other allowed tool should be registered
        assert should_register_tool("docker_list_containers", config) is True

        # Tools not in either list should not be registered
        assert should_register_tool("docker_inspect_container", config) is False

    def test_empty_allowed_and_empty_denied_blocks_all(self):
        """Test that allowed_tools=[] with denied_tools=[] blocks all registrations.

        Edge case: Empty allow list (block all) combined with empty deny list (deny all).
        The deny list is checked first and will block everything.
        """
        config = SafetyConfig(allowed_tools=[], denied_tools=[])

        # Empty deny list should block all tools (deny list takes precedence)
        assert should_register_tool("docker_list_containers", config) is False
        assert should_register_tool("docker_remove_container", config) is False
