"""Unit tests for resource filtering logic.

Tests that SAFETY_ALLOWED_RESOURCES correctly filters which resources are registered.
"""

from unittest.mock import MagicMock

import pytest

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.server.resources import register_all_resources


class TestResourceFiltering:
    """Test resource filtering based on allowed_resources configuration."""

    @pytest.fixture
    def mock_app(self):
        """Create a mock FastMCP app."""
        app = MagicMock()
        # Mock the resource decorator to return a function that does nothing
        app.resource.return_value = lambda f: f
        return app

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        return MagicMock(spec=DockerClientWrapper)

    def test_none_allows_all_resources(self, mock_app, mock_docker_client):
        """Test that allowed_resources=None registers all resources."""
        result = register_all_resources(mock_app, mock_docker_client, allowed_resources=None)

        # Should register all 2 resources
        assert len(result["container"]) == 2
        # Check URIs are present (the actual values stored)
        uris = result["container"]
        assert any("logs" in uri for uri in uris)
        assert any("stats" in uri for uri in uris)

    def test_empty_list_blocks_all_resources(self, mock_app, mock_docker_client):
        """Test that allowed_resources=[] blocks ALL resources (SAFETY_ALLOWED_RESOURCES='').

        When SAFETY_ALLOWED_RESOURCES is explicitly set to empty string, it parses to []
        which means 'block all resources'. This is different from None (not set) which
        means 'allow all'.
        """
        result = register_all_resources(mock_app, mock_docker_client, allowed_resources=[])

        # Should register 0 resources (empty list explicitly blocks all)
        assert len(result["container"]) == 0
        assert result["container"] == []

    def test_single_resource_filtering(self, mock_app, mock_docker_client):
        """Test that allowed_resources=['container_logs'] registers only that resource."""
        result = register_all_resources(
            mock_app, mock_docker_client, allowed_resources=["container_logs"]
        )

        # Should register only 1 resource
        assert len(result["container"]) == 1
        # Check it's the logs URI
        assert any("logs" in uri for uri in result["container"])
        assert not any("stats" in uri for uri in result["container"])

    def test_multiple_resources_filtering(self, mock_app, mock_docker_client):
        """Test that allowed_resources with multiple items registers only those resources."""
        result = register_all_resources(
            mock_app,
            mock_docker_client,
            allowed_resources=["container_logs", "container_stats"],
        )

        # Should register both resources
        assert len(result["container"]) == 2
        uris = result["container"]
        assert any("logs" in uri for uri in uris)
        assert any("stats" in uri for uri in uris)

    def test_nonexistent_resource_name_ignored(self, mock_app, mock_docker_client):
        """Test that nonexistent resource names in allowed list don't cause errors."""
        result = register_all_resources(
            mock_app,
            mock_docker_client,
            allowed_resources=["container_logs", "nonexistent_resource"],
        )

        # Should register only the valid resource
        assert len(result["container"]) == 1
        assert any("logs" in uri for uri in result["container"])

    def test_stats_resource_only(self, mock_app, mock_docker_client):
        """Test that allowed_resources=['container_stats'] registers only stats resource."""
        result = register_all_resources(
            mock_app, mock_docker_client, allowed_resources=["container_stats"]
        )

        # Should register only 1 resource
        assert len(result["container"]) == 1
        # Check it's the stats URI
        assert any("stats" in uri for uri in result["container"])
        assert not any("logs" in uri for uri in result["container"])

    def test_all_resources_explicitly_listed(self, mock_app, mock_docker_client):
        """Test that explicitly listing all resources registers all of them."""
        all_resources = ["container_logs", "container_stats"]
        result = register_all_resources(
            mock_app, mock_docker_client, allowed_resources=all_resources
        )

        # Should register all 2 resources
        assert len(result["container"]) == 2
