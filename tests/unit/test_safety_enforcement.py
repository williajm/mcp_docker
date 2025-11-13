"""Integration tests for safety configuration enforcement.

This module tests that SafetyConfig settings are properly enforced
in the MCP server for destructive operations and privileged containers.
"""

from typing import Any

from mcp_docker.config import Config, SafetyConfig
from mcp_docker.server import MCPDockerServer


class TestSafetyEnforcement:
    """Test safety configuration enforcement."""

    def test_destructive_operation_blocked_by_default(self) -> None:
        """Test that destructive operations are blocked when safety config disallows them."""
        # Create config with destructive operations disabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=False,
            allow_privileged_containers=True,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # Try to call a destructive tool (docker_remove_container)
        import asyncio

        result = asyncio.run(
            server.call_tool(
                "docker_remove_container",
                {"container_id": "test-container", "force": False},
            )
        )

        # Check that operation was blocked
        assert result["success"] is False
        assert result["error_type"] == "PermissionDenied"
        assert "Destructive operation" in result["error"]
        assert "docker_remove_container" in result["error"]
        assert "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS" in result["error"]

    def test_destructive_operation_allowed_when_enabled(self) -> None:
        """Test that destructive operations are allowed when safety config allows them."""
        # Create config with destructive operations enabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=True,
            allow_privileged_containers=True,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # Call a destructive tool - it should get past safety check
        # (may fail later due to container not existing, but that's OK)
        import asyncio

        result = asyncio.run(
            server.call_tool(
                "docker_remove_container",
                {"container_id": "nonexistent-container", "force": False},
            )
        )

        # Should not be blocked by safety check
        # Will fail with container not found, not permission error
        assert result["success"] is False
        assert "not allowed" not in result.get("error", "").lower()

    def test_privileged_exec_blocked_by_default(self) -> None:
        """Test that privileged exec is blocked when safety config disallows it."""
        # Create config with privileged containers disabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=True,
            allow_privileged_containers=False,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # Try to exec with privileged=True
        import asyncio

        result = asyncio.run(
            server.call_tool(
                "docker_exec_command",
                {
                    "container_id": "test-container",
                    "command": ["echo", "test"],
                    "privileged": True,
                },
            )
        )

        # Check that operation was blocked
        assert result["success"] is False
        assert result["error_type"] == "PermissionDenied"
        assert "Privileged" in result["error"]
        assert "SAFETY_ALLOW_PRIVILEGED_CONTAINERS" in result["error"]

    def test_privileged_exec_allowed_when_enabled(self) -> None:
        """Test that privileged exec is allowed when safety config allows it."""
        # Create config with privileged containers enabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=True,
            allow_privileged_containers=True,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # Call exec with privileged=True - should get past safety check
        import asyncio

        result = asyncio.run(
            server.call_tool(
                "docker_exec_command",
                {
                    "container_id": "nonexistent-container",
                    "command": ["echo", "test"],
                    "privileged": True,
                },
            )
        )

        # Should not be blocked by safety check
        # Will fail with container not found, not permission error
        assert result["success"] is False
        assert (
            "privileged" not in result.get("error", "").lower()
            or "not allowed" not in result.get("error", "").lower()
        )

    def test_non_privileged_exec_always_allowed(self) -> None:
        """Test that non-privileged exec is allowed even when privileged is disabled."""
        # Create config with privileged containers disabled
        config = Config()
        config.safety = SafetyConfig(
            allow_moderate_operations=True,
            allow_destructive_operations=True,
            allow_privileged_containers=False,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # Call exec with privileged=False - should get past safety check
        import asyncio

        result = asyncio.run(
            server.call_tool(
                "docker_exec_command",
                {
                    "container_id": "nonexistent-container",
                    "command": ["echo", "test"],
                    "privileged": False,
                },
            )
        )

        # Should not be blocked by safety check
        assert result["success"] is False
        assert "not allowed" not in result.get("error", "").lower()

    def test_all_destructive_tools_are_protected(self) -> None:
        """Test that all DESTRUCTIVE tools are protected by safety config."""
        # Create config with destructive operations disabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=False,
            allow_privileged_containers=True,
            require_confirmation_for_destructive=False,
        )
        server = MCPDockerServer(config)

        # List of destructive tools to test
        destructive_tools: list[tuple[str, dict[str, Any]]] = [
            ("docker_remove_container", {"container_id": "test", "force": False}),
            ("docker_remove_image", {"image": "test:latest", "force": False}),
            ("docker_prune_images", {}),
            ("docker_remove_network", {"network_id": "test"}),
            ("docker_remove_volume", {"volume_name": "test", "force": False}),
            ("docker_prune_volumes", {}),
            ("docker_system_prune", {"all": False, "volumes": False}),
        ]

        import asyncio

        for tool_name, args in destructive_tools:
            result = asyncio.run(server.call_tool(tool_name, args))

            # Check that operation was blocked
            assert result["success"] is False, f"{tool_name} should be blocked"
            assert result["error_type"] == "PermissionDenied", (
                f"{tool_name} should raise PermissionDenied"
            )
            assert "Destructive operation" in result["error"], (
                f"{tool_name} error should mention 'Destructive operation'"
            )
            assert tool_name in result["error"], f"Error should mention {tool_name}"

    def test_safe_operations_always_allowed(self) -> None:
        """Test that SAFE operations are never blocked by safety config."""
        # Create config with everything disabled
        config = Config()
        config.safety = SafetyConfig(
            allow_destructive_operations=False,
            allow_privileged_containers=False,
            require_confirmation_for_destructive=True,
        )
        server = MCPDockerServer(config)

        # These operations should always work (though may fail due to Docker state)
        safe_operations = [
            ("docker_list_containers", {"all": True}),
            ("docker_list_images", {}),
            ("docker_list_networks", {}),
            ("docker_list_volumes", {}),
            ("docker_system_info", {}),
            ("docker_version", {}),
            ("docker_healthcheck", {}),
        ]

        import asyncio

        for tool_name, args in safe_operations:
            result = asyncio.run(server.call_tool(tool_name, args))

            # Should not be blocked by permission error
            if not result["success"]:
                assert "not allowed" not in result.get("error", "").lower(), (
                    f"{tool_name} should not be blocked by safety config"
                )
