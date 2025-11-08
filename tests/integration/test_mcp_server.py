"""End-to-end integration tests for MCP server.

These tests verify the complete MCP protocol integration with Docker operations.
"""

from collections.abc import AsyncGenerator

import pytest

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_moderate_operations = True
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_containers = True
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
async def mcp_server(integration_config: Config) -> AsyncGenerator[MCPDockerServer, None]:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    await server.start()
    yield server
    await server.stop()


@pytest.mark.integration
class TestMCPServerE2E:
    """End-to-end tests for MCP server."""

    @pytest.mark.asyncio
    async def test_server_lifecycle(self, integration_config: Config) -> None:
        """Test server start and stop lifecycle."""
        server = MCPDockerServer(integration_config)

        # Start server
        await server.start()
        assert server.docker_client is not None

        # Stop server
        await server.stop()

    def test_list_all_capabilities(self, mcp_server: MCPDockerServer) -> None:
        """Test listing all server capabilities."""
        # List tools
        tools = mcp_server.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 30  # Should have 37+ tools

        # List resources
        resources = mcp_server.list_resources()
        assert isinstance(resources, list)

        # List prompts
        prompts = mcp_server.list_prompts()
        assert isinstance(prompts, list)
        assert (
            len(prompts) == 5
        )  # troubleshoot_container, optimize_container, generate_compose, debug_networking, security_audit

    @pytest.mark.asyncio
    async def test_call_tool_list_containers(self, mcp_server: MCPDockerServer) -> None:
        """Test calling list_containers tool through MCP."""
        result = await mcp_server.call_tool("docker_list_containers", {"all": True})

        assert "success" in result
        if result["success"]:
            assert "result" in result
            assert "containers" in result["result"]
        # If unsuccessful, it should have an error message
        elif not result["success"]:
            assert "error" in result

    @pytest.mark.asyncio
    async def test_call_tool_system_info(self, mcp_server: MCPDockerServer) -> None:
        """Test calling system_info tool through MCP."""
        result = await mcp_server.call_tool("docker_system_info", {})

        assert result["success"] is True
        assert "result" in result
        assert "info" in result["result"]
        assert "ID" in result["result"]["info"] or "Name" in result["result"]["info"]

    @pytest.mark.asyncio
    async def test_call_tool_healthcheck(self, mcp_server: MCPDockerServer) -> None:
        """Test calling healthcheck tool through MCP."""
        result = await mcp_server.call_tool("docker_healthcheck", {})

        assert result["success"] is True
        assert "result" in result
        assert "healthy" in result["result"]
        assert result["result"]["healthy"] is True

    @pytest.mark.asyncio
    async def test_call_invalid_tool(self, mcp_server: MCPDockerServer) -> None:
        """Test calling non-existent tool."""
        result = await mcp_server.call_tool("nonexistent_tool", {})
        assert result["success"] is False
        assert "Tool not found" in result["error"]
        assert result["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_e2e_container_workflow(self, mcp_server: MCPDockerServer) -> None:
        """Test complete container workflow through MCP."""
        container_name = "mcp-e2e-test-container"

        try:
            # Create container
            create_result = await mcp_server.call_tool(
                "docker_create_container",
                {
                    "image": "alpine:latest",
                    "name": container_name,
                    "command": ["sleep", "300"],
                },
            )
            assert create_result["success"] is True
            container_id = create_result["result"]["container_id"]

            # Start container
            start_result = await mcp_server.call_tool(
                "docker_start_container", {"container_id": container_id}
            )
            assert start_result["success"] is True

            # Inspect container
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_container", {"container_id": container_id}
            )
            assert inspect_result["success"] is True
            assert inspect_result["result"]["details"]["State"]["Status"] == "running"

            # Stop container
            stop_result = await mcp_server.call_tool(
                "docker_stop_container", {"container_id": container_id, "timeout": 5}
            )
            assert stop_result["success"] is True

            # Remove container
            remove_result = await mcp_server.call_tool(
                "docker_remove_container", {"container_id": container_id, "force": True}
            )
            assert remove_result["success"] is True

        finally:
            # Ensure cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_container", {"container_id": container_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - container may already be removed

    @pytest.mark.asyncio
    async def test_e2e_image_workflow(self, mcp_server: MCPDockerServer) -> None:
        """Test image workflow through MCP."""
        # Pull image
        pull_result = await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})
        assert pull_result["success"] is True

        # List images
        list_result = await mcp_server.call_tool("docker_list_images", {})
        assert list_result["success"] is True
        assert len(list_result["result"]["images"]) > 0

        # Inspect image
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": "alpine:latest"}
        )
        assert inspect_result["success"] is True

    @pytest.mark.asyncio
    async def test_e2e_network_workflow(self, mcp_server: MCPDockerServer) -> None:
        """Test network workflow through MCP."""
        network_name = "mcp-e2e-test-network"

        try:
            # Create network
            create_result = await mcp_server.call_tool(
                "docker_create_network", {"name": network_name}
            )
            assert create_result["success"] is True
            network_id = create_result["result"]["network_id"]

            # List networks
            list_result = await mcp_server.call_tool("docker_list_networks", {})
            assert list_result["success"] is True

            # Inspect network
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_network", {"network_id": network_id}
            )
            assert inspect_result["success"] is True

            # Remove network
            remove_result = await mcp_server.call_tool(
                "docker_remove_network", {"network_id": network_id}
            )
            assert remove_result["success"] is True

        finally:
            # Ensure cleanup
            try:
                await mcp_server.call_tool("docker_remove_network", {"network_id": network_name})
            except Exception:
                pass  # Ignore cleanup errors - network may already be removed

    @pytest.mark.asyncio
    async def test_e2e_volume_workflow(self, mcp_server: MCPDockerServer) -> None:
        """Test volume workflow through MCP."""
        volume_name = "mcp-e2e-test-volume"

        try:
            # Create volume
            create_result = await mcp_server.call_tool(
                "docker_create_volume", {"name": volume_name}
            )
            assert create_result["success"] is True

            # List volumes
            list_result = await mcp_server.call_tool("docker_list_volumes", {})
            assert list_result["success"] is True

            # Inspect volume
            inspect_result = await mcp_server.call_tool(
                "docker_inspect_volume", {"volume_name": volume_name}
            )
            assert inspect_result["success"] is True

            # Remove volume
            remove_result = await mcp_server.call_tool(
                "docker_remove_volume", {"volume_name": volume_name, "force": True}
            )
            assert remove_result["success"] is True

        finally:
            # Ensure cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_volume", {"volume_name": volume_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - volume may already be removed

    @pytest.mark.asyncio
    async def test_resources_integration(self, mcp_server: MCPDockerServer) -> None:
        """Test resources through MCP server."""
        container_name = "mcp-resource-test-container"

        try:
            # Create and start container
            create_result = await mcp_server.call_tool(
                "docker_create_container",
                {
                    "image": "alpine:latest",
                    "name": container_name,
                    "command": ["sh", "-c", "echo 'test' && sleep 300"],
                },
            )
            container_id = create_result["result"]["container_id"]
            await mcp_server.call_tool("docker_start_container", {"container_id": container_id})

            # Wait for output
            import asyncio

            await asyncio.sleep(1)

            # List resources
            resources = mcp_server.list_resources()
            assert len(resources) > 0

            # Find logs resource
            logs_uri = f"container://logs/{container_id[:12]}"
            logs_resource = next((r for r in resources if r["uri"] == logs_uri), None)

            if logs_resource:
                # Read logs resource
                logs_content = await mcp_server.read_resource(logs_uri)
                assert "uri" in logs_content
                assert "text" in logs_content or "blob" in logs_content

            # Find stats resource (only for running containers)
            stats_uri = f"container://stats/{container_id[:12]}"
            stats_resource = next((r for r in resources if r["uri"] == stats_uri), None)

            if stats_resource:
                # Read stats resource
                stats_content = await mcp_server.read_resource(stats_uri)
                assert "uri" in stats_content

        finally:
            # Cleanup
            try:
                await mcp_server.call_tool(
                    "docker_remove_container", {"container_id": container_name, "force": True}
                )
            except Exception:
                pass  # Ignore cleanup errors - container may already be removed

    @pytest.mark.asyncio
    async def test_prompts_integration(self, mcp_server: MCPDockerServer) -> None:
        """Test prompts through MCP server."""
        # List prompts
        prompts = mcp_server.list_prompts()
        assert len(prompts) == 5

        # Test generate_compose prompt
        compose_prompt = await mcp_server.get_prompt(
            "generate_compose", {"service_description": "web app with database"}
        )
        assert "description" in compose_prompt
        assert "messages" in compose_prompt
        assert len(compose_prompt["messages"]) > 0

    @pytest.mark.asyncio
    async def test_error_responses(self, mcp_server: MCPDockerServer) -> None:
        """Test error responses from MCP server."""
        # Invalid tool arguments
        result = await mcp_server.call_tool("docker_inspect_container", {})
        assert result["success"] is False
        assert "error" in result

        # Non-existent resource
        with pytest.raises((ValueError, KeyError, RuntimeError)):  # Invalid URI scheme
            await mcp_server.read_resource("invalid://resource")

        # Invalid prompt
        with pytest.raises(ValueError):
            await mcp_server.get_prompt("invalid_prompt", {})

    def test_server_repr(self, mcp_server: MCPDockerServer) -> None:
        """Test server string representation."""
        repr_str = repr(mcp_server)
        assert "MCPDockerServer" in repr_str
        assert "tools=" in repr_str
        assert "resources=enabled" in repr_str
        assert "prompts=enabled" in repr_str
