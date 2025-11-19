"""Unit tests for SafetyConfig prompt and resource filtering defaults.

These tests ensure backwards compatibility - the default configuration
(when SAFETY_ALLOWED_PROMPTS and SAFETY_ALLOWED_RESOURCES are not set)
allows all prompts and resources, not blocking them.
"""

from mcp_docker.config import SafetyConfig


class TestSafetyConfigPromptResourceDefaults:
    """Test that prompt/resource filtering defaults don't break backwards compatibility."""

    def test_default_allowed_prompts_is_none(self):
        """Test that allowed_prompts defaults to None (not empty list)."""
        config = SafetyConfig()
        assert config.allowed_prompts is None

    def test_default_allowed_resources_is_none(self):
        """Test that allowed_resources defaults to None (not empty list)."""
        config = SafetyConfig()
        assert config.allowed_resources is None

    def test_empty_string_prompts_becomes_empty_list(self, monkeypatch):
        """Test that SAFETY_ALLOWED_PROMPTS="" becomes [] (block all)."""
        monkeypatch.setenv("SAFETY_ALLOWED_PROMPTS", "")
        config = SafetyConfig()
        assert config.allowed_prompts == []
        assert isinstance(config.allowed_prompts, list)

    def test_empty_string_resources_becomes_empty_list(self, monkeypatch):
        """Test that SAFETY_ALLOWED_RESOURCES="" becomes [] (block all)."""
        monkeypatch.setenv("SAFETY_ALLOWED_RESOURCES", "")
        config = SafetyConfig()
        assert config.allowed_resources == []
        assert isinstance(config.allowed_resources, list)

    def test_unset_prompts_remains_none(self, monkeypatch):
        """Test that not setting SAFETY_ALLOWED_PROMPTS keeps it as None."""
        # Ensure env var is not set
        monkeypatch.delenv("SAFETY_ALLOWED_PROMPTS", raising=False)
        config = SafetyConfig()
        assert config.allowed_prompts is None

    def test_unset_resources_remains_none(self, monkeypatch):
        """Test that not setting SAFETY_ALLOWED_RESOURCES keeps it as None."""
        # Ensure env var is not set
        monkeypatch.delenv("SAFETY_ALLOWED_RESOURCES", raising=False)
        config = SafetyConfig()
        assert config.allowed_resources is None

    def test_comma_separated_prompts(self, monkeypatch):
        """Test that comma-separated SAFETY_ALLOWED_PROMPTS parses correctly."""
        monkeypatch.setenv("SAFETY_ALLOWED_PROMPTS", "troubleshoot_container,optimize_container")
        config = SafetyConfig()
        assert config.allowed_prompts == ["troubleshoot_container", "optimize_container"]

    def test_comma_separated_resources(self, monkeypatch):
        """Test that comma-separated SAFETY_ALLOWED_RESOURCES parses correctly."""
        monkeypatch.setenv("SAFETY_ALLOWED_RESOURCES", "container_logs,container_stats")
        config = SafetyConfig()
        assert config.allowed_resources == ["container_logs", "container_stats"]

    def test_single_prompt(self, monkeypatch):
        """Test that single prompt name parses correctly."""
        monkeypatch.setenv("SAFETY_ALLOWED_PROMPTS", "troubleshoot_container")
        config = SafetyConfig()
        assert config.allowed_prompts == ["troubleshoot_container"]

    def test_whitespace_handling(self, monkeypatch):
        """Test that whitespace is properly stripped."""
        monkeypatch.setenv(
            "SAFETY_ALLOWED_PROMPTS", " troubleshoot_container , optimize_container "
        )
        config = SafetyConfig()
        assert config.allowed_prompts == ["troubleshoot_container", "optimize_container"]

    def test_backwards_compatibility_scenario(self, monkeypatch):
        """Test that default config (no env vars) allows all prompts/resources.

        This is critical for backwards compatibility - existing deployments
        that don't set these env vars should continue to work unchanged.
        """
        # Ensure env vars are not set
        monkeypatch.delenv("SAFETY_ALLOWED_PROMPTS", raising=False)
        monkeypatch.delenv("SAFETY_ALLOWED_RESOURCES", raising=False)

        config = SafetyConfig()

        # Default should be None (allow all), not [] (block all)
        assert config.allowed_prompts is None
        assert config.allowed_resources is None

        # This ensures backwards compatibility:
        # - Existing deployments without these env vars get None
        # - None means no filtering (allow all prompts/resources)
        # - Behavior unchanged from before this feature was added
