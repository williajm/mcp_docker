"""Unit tests for MCP tool annotations."""

from typing import Any
from unittest.mock import Mock, patch

import pytest

from mcp_docker.config import Config, SafetyConfig, SecurityConfig
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def mock_config(tmp_path: Any) -> Any:
    """Create a mock configuration."""
    config = Mock(spec=Config)
    config.docker = Mock()
    config.safety = SafetyConfig(
        allow_moderate_operations=True,
        allow_destructive_operations=True,
    )
    config.security = SecurityConfig(
        audit_log_file=tmp_path / "audit.log",
    )
    return config


@pytest.fixture
def mock_docker_client() -> Any:
    """Create a mock Docker client wrapper."""
    with patch("mcp_docker.server.DockerClientWrapper") as mock_class:
        client = Mock()
        client.health_check.return_value = {
            "status": "healthy",
            "daemon_info": {},
            "containers": {},
            "images": 0,
        }
        mock_class.return_value = client
        yield client


class TestToolAnnotations:
    """Test MCP tool annotations in list_tools output."""

    def test_list_tools_includes_annotations_for_safe_tools(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that SAFE tools include readOnly annotation."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Find a SAFE tool (list containers)
        list_tool = next((t for t in tools if t["name"] == "docker_list_containers"), None)
        assert list_tool is not None

        # SAFE tools should have readOnly annotation
        assert "annotations" in list_tool
        assert list_tool["annotations"].get("readOnly") is True
        assert "destructive" not in list_tool["annotations"]

    def test_list_tools_includes_annotations_for_destructive_tools(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that DESTRUCTIVE tools include destructive annotation."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Find a DESTRUCTIVE tool (remove container)
        remove_tool = next((t for t in tools if t["name"] == "docker_remove_container"), None)
        assert remove_tool is not None

        # DESTRUCTIVE tools should have destructive annotation
        assert "annotations" in remove_tool
        assert remove_tool["annotations"].get("destructive") is True
        assert "readOnly" not in remove_tool["annotations"]

    def test_list_tools_includes_idempotent_annotation(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that idempotent tools include idempotent annotation."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # docker_start_container is marked as idempotent
        start_tool = next((t for t in tools if t["name"] == "docker_start_container"), None)
        assert start_tool is not None
        assert "annotations" in start_tool
        assert start_tool["annotations"].get("idempotent") is True

        # docker_pull_image is marked as idempotent
        pull_tool = next((t for t in tools if t["name"] == "docker_pull_image"), None)
        assert pull_tool is not None
        assert "annotations" in pull_tool
        assert pull_tool["annotations"].get("idempotent") is True

    def test_list_tools_includes_open_world_interaction_annotation(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that open-world tools include openWorldInteraction annotation."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # docker_pull_image talks to external registries
        pull_tool = next((t for t in tools if t["name"] == "docker_pull_image"), None)
        assert pull_tool is not None
        assert "annotations" in pull_tool
        assert pull_tool["annotations"].get("openWorldInteraction") is True

        # docker_push_image talks to external registries
        push_tool = next((t for t in tools if t["name"] == "docker_push_image"), None)
        assert push_tool is not None
        assert "annotations" in push_tool
        assert pull_tool["annotations"].get("openWorldInteraction") is True

        # docker_exec_command may access external networks
        exec_tool = next((t for t in tools if t["name"] == "docker_exec_command"), None)
        assert exec_tool is not None
        assert "annotations" in exec_tool
        assert exec_tool["annotations"].get("openWorldInteraction") is True

    def test_list_tools_annotations_only_include_true_values(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that annotations dict only includes True values per MCP spec."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # Check all tools - annotations should only have True values
        for tool in tools:
            if "annotations" in tool:
                for key, value in tool["annotations"].items():
                    assert value is True, (
                        f"Tool {tool['name']} has annotation {key}={value}, expected True"
                    )

    def test_list_tools_moderate_tools_have_no_read_only_or_destructive(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that MODERATE tools don't have readOnly or destructive annotations."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # docker_create_container is MODERATE (not read-only, not destructive)
        create_tool = next((t for t in tools if t["name"] == "docker_create_container"), None)
        assert create_tool is not None

        # MODERATE tools may have no annotations, or only idempotent/openWorldInteraction
        if "annotations" in create_tool:
            assert "readOnly" not in create_tool["annotations"]
            assert "destructive" not in create_tool["annotations"]

    def test_list_tools_all_tools_have_correct_schema_structure(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that all tools have the correct schema structure including annotations."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        assert len(tools) == 36  # All tools

        for tool in tools:
            # Required fields
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

            # Annotations are optional, but if present, must be a dict
            if "annotations" in tool:
                assert isinstance(tool["annotations"], dict)
                # Valid annotation keys per MCP spec
                valid_keys = {"readOnly", "destructive", "idempotent", "openWorldInteraction"}
                for key in tool["annotations"]:
                    assert key in valid_keys, f"Invalid annotation key: {key}"

    def test_annotation_combinations(self, mock_config: Any, mock_docker_client: Any) -> None:
        """Test that specific tools have the correct combination of annotations."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # docker_list_containers: SAFE, so only readOnly
        list_tool = next((t for t in tools if t["name"] == "docker_list_containers"), None)
        assert list_tool is not None
        assert list_tool["annotations"] == {"readOnly": True}

        # docker_remove_container: DESTRUCTIVE, so only destructive
        remove_tool = next((t for t in tools if t["name"] == "docker_remove_container"), None)
        assert remove_tool is not None
        assert remove_tool["annotations"] == {"destructive": True}

        # docker_pull_image: MODERATE + idempotent + open-world
        pull_tool = next((t for t in tools if t["name"] == "docker_pull_image"), None)
        assert pull_tool is not None
        assert pull_tool["annotations"] == {
            "idempotent": True,
            "openWorldInteraction": True,
        }

        # docker_start_container: MODERATE + idempotent
        start_tool = next((t for t in tools if t["name"] == "docker_start_container"), None)
        assert start_tool is not None
        assert start_tool["annotations"] == {"idempotent": True}

    def test_tools_without_annotations_have_no_annotations_field(
        self, mock_config: Any, mock_docker_client: Any
    ) -> None:
        """Test that tools with all False annotations don't include annotations field."""
        server = MCPDockerServer(mock_config)
        tools = server.list_tools()

        # docker_create_container is MODERATE with no special properties
        # Per MCP spec, we only include True values, so annotations field should not exist
        create_tool = next((t for t in tools if t["name"] == "docker_create_container"), None)
        assert create_tool is not None

        # Strict assertion: annotations field must NOT exist if all annotations are False
        assert "annotations" not in create_tool, (
            f"Tool {create_tool['name']} should not have annotations field when all annotations "
            "are False, per MCP spec (only include True values)"
        )
