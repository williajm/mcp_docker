"""Unit tests for prompt filtering logic.

Tests that SAFETY_ALLOWED_PROMPTS correctly filters which prompts are registered.
"""

from unittest.mock import MagicMock

import pytest

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.server.prompts import register_all_prompts


class TestPromptFiltering:
    """Test prompt filtering based on allowed_prompts configuration."""

    @pytest.fixture
    def mock_app(self):
        """Create a mock FastMCP app."""
        app = MagicMock()
        # Mock the prompt decorator to return a function that does nothing
        app.prompt.return_value = lambda f: f
        return app

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        return MagicMock(spec=DockerClientWrapper)

    def test_none_allows_all_prompts(self, mock_app, mock_docker_client):
        """Test that allowed_prompts=None registers all prompts."""
        result = register_all_prompts(mock_app, mock_docker_client, allowed_prompts=None)

        # Should register all 5 prompts
        assert len(result["docker"]) == 5
        assert "troubleshoot_container" in result["docker"]
        assert "optimize_container" in result["docker"]
        assert "generate_compose" in result["docker"]
        assert "debug_networking" in result["docker"]
        assert "security_audit" in result["docker"]

    def test_empty_list_blocks_all_prompts(self, mock_app, mock_docker_client):
        """Test that allowed_prompts=[] blocks ALL prompts (SAFETY_ALLOWED_PROMPTS='').

        When SAFETY_ALLOWED_PROMPTS is explicitly set to empty string, it parses to []
        which means 'block all prompts'. This is different from None (not set) which
        means 'allow all'.
        """
        result = register_all_prompts(mock_app, mock_docker_client, allowed_prompts=[])

        # Should register 0 prompts (empty list explicitly blocks all)
        assert len(result["docker"]) == 0
        assert result["docker"] == []

    def test_single_prompt_filtering(self, mock_app, mock_docker_client):
        """Test that allowed_prompts=['troubleshoot_container'] registers only that prompt."""
        result = register_all_prompts(
            mock_app, mock_docker_client, allowed_prompts=["troubleshoot_container"]
        )

        # Should register only 1 prompt
        assert len(result["docker"]) == 1
        assert result["docker"] == ["troubleshoot_container"]

    def test_multiple_prompts_filtering(self, mock_app, mock_docker_client):
        """Test that allowed_prompts with multiple items registers only those prompts."""
        result = register_all_prompts(
            mock_app,
            mock_docker_client,
            allowed_prompts=["troubleshoot_container", "security_audit"],
        )

        # Should register only 2 prompts
        assert len(result["docker"]) == 2
        assert "troubleshoot_container" in result["docker"]
        assert "security_audit" in result["docker"]
        assert "optimize_container" not in result["docker"]

    def test_nonexistent_prompt_name_ignored(self, mock_app, mock_docker_client):
        """Test that nonexistent prompt names in allowed list don't cause errors."""
        result = register_all_prompts(
            mock_app,
            mock_docker_client,
            allowed_prompts=["troubleshoot_container", "nonexistent_prompt"],
        )

        # Should register only the valid prompt
        assert len(result["docker"]) == 1
        assert result["docker"] == ["troubleshoot_container"]

    def test_all_prompts_in_allowed_list(self, mock_app, mock_docker_client):
        """Test that explicitly listing all prompts registers all of them."""
        all_prompts = [
            "troubleshoot_container",
            "optimize_container",
            "generate_compose",
            "debug_networking",
            "security_audit",
        ]
        result = register_all_prompts(mock_app, mock_docker_client, allowed_prompts=all_prompts)

        # Should register all 5 prompts
        assert len(result["docker"]) == 5
        assert set(result["docker"]) == set(all_prompts)
