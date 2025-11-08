"""Integration tests for image operations.

These tests require Docker to be running and internet connectivity for pulling images.
"""

from collections.abc import AsyncGenerator
from typing import Any

import pytest

from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_moderate_operations = True
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_containers = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
async def mcp_server(integration_config: Config) -> AsyncGenerator[MCPDockerServer, None]:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
def test_image_tag() -> str:
    """Test image tag."""
    return "mcp-docker-test:latest"


@pytest.fixture
async def cleanup_test_image(
    mcp_server: MCPDockerServer, test_image_tag: str
) -> AsyncGenerator[None, None]:
    """Cleanup fixture to remove test image after tests."""
    yield
    # Cleanup after test
    try:
        await mcp_server.call_tool("docker_remove_image", {"image": test_image_tag, "force": True})
    except Exception:
        pass  # Ignore cleanup errors - resource may not exist


@pytest.mark.integration
@pytest.mark.slow
class TestImageOperations:
    """Integration tests for image operations."""

    @pytest.mark.asyncio
    async def test_pull_image(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test pulling an image from registry."""
        # Pull a small test image
        pull_result = await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})
        assert pull_result["success"] is True
        assert pull_result["result"] is not None
        assert "alpine" in pull_result["result"]["image"].lower()

    @pytest.mark.asyncio
    async def test_list_images(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test listing images."""
        # Ensure we have at least one image
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # List images
        list_result = await mcp_server.call_tool("docker_list_images", {})
        assert list_result["success"] is True
        assert len(list_result["result"]["images"]) > 0

    @pytest.mark.asyncio
    async def test_inspect_image(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test inspecting an image."""
        # Ensure alpine image exists
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # Inspect image
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": "alpine:latest"}
        )
        assert inspect_result["success"] is True
        assert "details" in inspect_result["result"]
        details = inspect_result["result"]["details"]
        assert "Id" in details or "id" in details
        assert "Size" in details or "size" in details

    @pytest.mark.asyncio
    async def test_tag_image(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_image_tag: str,
        cleanup_test_image: Any,
    ) -> None:
        """Test tagging an image."""
        # Ensure alpine image exists
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # Tag the image
        tag_result = await mcp_server.call_tool(
            "docker_tag_image",
            {"image": "alpine:latest", "repository": test_image_tag.split(":")[0], "tag": "latest"},
        )
        assert tag_result["success"] is True

        # Verify tag exists
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": test_image_tag}
        )
        assert inspect_result["success"] is True

    @pytest.mark.asyncio
    async def test_image_history(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test getting image history."""
        # Ensure alpine image exists
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # Get history
        history_result = await mcp_server.call_tool(
            "docker_image_history", {"image": "alpine:latest"}
        )
        assert history_result["success"] is True
        assert "history" in history_result["result"]
        assert len(history_result["result"]["history"]) > 0

    @pytest.mark.asyncio
    async def test_remove_image(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
        test_image_tag: str,
    ) -> None:
        """Test removing an image."""
        # Pull and tag an image for removal
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        await mcp_server.call_tool(
            "docker_tag_image",
            {"image": "alpine:latest", "repository": test_image_tag.split(":")[0], "tag": "latest"},
        )

        # Remove the tagged image
        remove_result = await mcp_server.call_tool(
            "docker_remove_image", {"image": test_image_tag, "force": False}
        )
        assert remove_result["success"] is True

        # Verify image is removed
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": test_image_tag}
        )
        assert inspect_result["success"] is False

    @pytest.mark.asyncio
    async def test_prune_images(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test pruning unused images."""
        # Prune images (this might not remove anything, but should succeed)
        prune_result = await mcp_server.call_tool("docker_prune_images", {})
        assert prune_result["success"] is True
        assert "space_reclaimed" in prune_result["result"]
        assert "deleted" in prune_result["result"]

    @pytest.mark.asyncio
    async def test_image_error_handling(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid image operations."""
        # Try to inspect non-existent image
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": "nonexistent-image:notag"}
        )
        assert inspect_result["success"] is False
        assert "not found" in inspect_result["error"].lower()

        # Try to remove non-existent image
        remove_result = await mcp_server.call_tool(
            "docker_remove_image", {"image": "nonexistent-image:notag", "force": False}
        )
        assert remove_result["success"] is False

    @pytest.mark.asyncio
    async def test_pull_with_specific_tag(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test pulling image with specific tag."""
        # Pull specific version
        pull_result = await mcp_server.call_tool("docker_pull_image", {"image": "alpine:3.18"})
        assert pull_result["success"] is True

        # Verify the specific tag
        inspect_result = await mcp_server.call_tool(
            "docker_inspect_image", {"image_name": "alpine:3.18"}
        )
        assert inspect_result["success"] is True
        # Check that the image exists (successful inspection indicates the tag is present)
        assert "details" in inspect_result["result"]

    @pytest.mark.asyncio
    async def test_list_images_with_filters(
        self,
        mcp_server: MCPDockerServer,
        integration_config: Config,
    ) -> None:
        """Test listing images with filters."""
        # Ensure alpine image exists
        await mcp_server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # List all images
        list_result = await mcp_server.call_tool("docker_list_images", {"all": True})
        assert list_result["success"] is True
        total_images = len(list_result["result"]["images"])

        # List with dangling filter
        dangling_result = await mcp_server.call_tool(
            "docker_list_images", {"filters": {"dangling": ["true"]}}
        )
        assert dangling_result["success"] is True
        # Dangling images should be <= total images
        assert len(dangling_result["result"]["images"]) <= total_images
