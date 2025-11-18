"""Unit tests for FastMCP tool registration.

This module tests that all tools (SAFE, MODERATE, DESTRUCTIVE) can be registered
successfully with FastMCP. Updated for Phase 4 completion (33 total tools).
"""

from unittest.mock import MagicMock, Mock

import pytest
from fastmcp import FastMCP

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.registration import register_all_tools


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create a mock Docker client wrapper."""
    mock = Mock(spec=DockerClientWrapper)
    mock.client = MagicMock()
    return mock


@pytest.fixture
def safety_config() -> SafetyConfig:
    """Create a basic safety config."""
    return SafetyConfig()


@pytest.fixture
def fastmcp_app() -> FastMCP:
    """Create a FastMCP application instance."""
    return FastMCP(name="test-mcp-docker", version="1.0.0")


def test_register_all_tools_phase4(
    fastmcp_app: FastMCP,
    mock_docker_client: Mock,
    safety_config: SafetyConfig,
) -> None:
    """Test that all 33 tools (Phase 3 + Phase 4) are registered successfully."""
    # Register all tools
    registered = register_all_tools(fastmcp_app, mock_docker_client, safety_config)

    # Verify we have 6 categories (Phase 4 added container_lifecycle and system)
    assert len(registered) == 6, f"Expected 6 categories, got {len(registered)}"
    assert "container_inspection" in registered
    assert "container_lifecycle" in registered
    assert "image" in registered
    assert "network" in registered
    assert "volume" in registered
    assert "system" in registered

    # Verify tool counts per category
    # Phase 3 (SAFE tools) + Phase 4 additions
    assert len(registered["container_inspection"]) == 5, (
        "Expected 5 container inspection tools (4 SAFE + 1 MODERATE)"
    )
    assert len(registered["container_lifecycle"]) == 5, (
        "Expected 5 container lifecycle tools (MODERATE + DESTRUCTIVE)"
    )
    assert len(registered["image"]) == 9, "Expected 9 image tools (3 SAFE + 6 MODERATE/DESTRUCTIVE)"
    assert len(registered["network"]) == 6, (
        "Expected 6 network tools (2 SAFE + 4 MODERATE/DESTRUCTIVE)"
    )
    assert len(registered["volume"]) == 5, (
        "Expected 5 volume tools (2 SAFE + 3 MODERATE/DESTRUCTIVE)"
    )
    assert len(registered["system"]) == 3, "Expected 3 system tools (2 SAFE + 1 DESTRUCTIVE)"

    # Verify total tool count (Phase 3: 13 SAFE + Phase 4: 20 MODERATE/DESTRUCTIVE = 33 total)
    total_tools = sum(len(tools) for tools in registered.values())
    assert total_tools == 33, f"Expected 33 total tools, got {total_tools}"


def test_registered_tool_names_phase4(
    fastmcp_app: FastMCP,
    mock_docker_client: Mock,
    safety_config: SafetyConfig,
) -> None:
    """Test that all expected tool names (33 tools) are registered."""
    # Expected tool names by category (Phase 3 + Phase 4)
    expected_tools = {
        "container_inspection": [
            "docker_list_containers",
            "docker_inspect_container",
            "docker_container_logs",
            "docker_container_stats",
            "docker_exec_command",  # Phase 4: MODERATE
        ],
        "container_lifecycle": [  # Phase 4: New category
            "docker_create_container",
            "docker_start_container",
            "docker_stop_container",
            "docker_restart_container",
            "docker_remove_container",
        ],
        "image": [
            "docker_list_images",
            "docker_inspect_image",
            "docker_image_history",
            "docker_pull_image",  # Phase 4: MODERATE
            "docker_build_image",  # Phase 4: MODERATE
            "docker_push_image",  # Phase 4: MODERATE
            "docker_tag_image",  # Phase 4: MODERATE
            "docker_remove_image",  # Phase 4: DESTRUCTIVE
            "docker_prune_images",  # Phase 4: DESTRUCTIVE
        ],
        "network": [
            "docker_list_networks",
            "docker_inspect_network",
            "docker_create_network",  # Phase 4: MODERATE
            "docker_connect_container",  # Phase 4: MODERATE
            "docker_disconnect_container",  # Phase 4: MODERATE
            "docker_remove_network",  # Phase 4: DESTRUCTIVE
        ],
        "volume": [
            "docker_list_volumes",
            "docker_inspect_volume",
            "docker_create_volume",  # Phase 4: MODERATE
            "docker_remove_volume",  # Phase 4: DESTRUCTIVE
            "docker_prune_volumes",  # Phase 4: DESTRUCTIVE
        ],
        "system": [  # Phase 4: New category
            "docker_version",  # SAFE
            "docker_events",  # SAFE
            "docker_prune_system",  # DESTRUCTIVE
        ],
    }

    # Register all tools
    registered = register_all_tools(fastmcp_app, mock_docker_client, safety_config)

    # Verify each category has the expected tools
    for category, expected_names in expected_tools.items():
        assert category in registered, f"Category {category} not found in registered tools"
        actual_names = registered[category]
        assert set(actual_names) == set(expected_names), (
            f"Category {category}: expected {expected_names}, got {actual_names}"
        )


def test_registration_with_custom_safety_config(
    fastmcp_app: FastMCP,
    mock_docker_client: Mock,
) -> None:
    """Test registration with custom safety configuration."""
    # Create custom safety config with limits
    custom_config = SafetyConfig(
        max_list_results=50,
        max_log_lines=500,
        allow_moderate_operations=True,
        allow_destructive_operations=True,
    )

    # Register tools
    registered = register_all_tools(fastmcp_app, mock_docker_client, custom_config)

    # Verify registration succeeds with custom config (33 tools total)
    total_tools = sum(len(tools) for tools in registered.values())
    assert total_tools == 33, "Registration should succeed with custom config"
