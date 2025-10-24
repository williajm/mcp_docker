"""Integration tests for image operations.

These tests require Docker to be running and internet connectivity for pulling images.
"""

import pytest

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.image_tools import (
    ImageHistoryTool,
    InspectImageTool,
    ListImagesTool,
    PullImageTool,
    PruneImagesTool,
    RemoveImageTool,
    TagImageTool,
)


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_operations = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
def docker_wrapper(integration_config: Config) -> DockerClientWrapper:
    """Create Docker client wrapper."""
    wrapper = DockerClientWrapper(integration_config.docker)
    yield wrapper
    wrapper.close()


@pytest.fixture
def test_image_tag() -> str:
    """Test image tag."""
    return "mcp-docker-test:latest"


@pytest.fixture
def cleanup_test_image(docker_wrapper: DockerClientWrapper, test_image_tag: str):
    """Cleanup fixture to remove test image after tests."""
    yield
    # Cleanup after test
    try:
        docker_wrapper.client.images.remove(test_image_tag, force=True)
    except Exception:
        pass


@pytest.mark.integration
@pytest.mark.slow
class TestImageOperations:
    """Integration tests for image operations."""

    @pytest.mark.asyncio
    async def test_pull_image(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test pulling an image from registry."""
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)

        # Pull a small test image
        pull_result = await pull_tool.execute({"image": "alpine:latest"})
        assert pull_result.success is True
        assert pull_result.data is not None
        assert "alpine" in pull_result.data["image"].lower()

    @pytest.mark.asyncio
    async def test_list_images(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test listing images."""
        list_tool = ListImagesTool(docker_wrapper, integration_config.safety)

        # Ensure we have at least one image (alpine from previous test or existing)
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        # List images
        list_result = await list_tool.execute({})
        assert list_result.success is True
        assert len(list_result.data["images"]) > 0

    @pytest.mark.asyncio
    async def test_inspect_image(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test inspecting an image."""
        # Ensure alpine image exists
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        inspect_tool = InspectImageTool(docker_wrapper, integration_config.safety)

        # Inspect image
        inspect_result = await inspect_tool.execute({"image": "alpine:latest"})
        assert inspect_result.success is True
        assert "id" in inspect_result.data
        assert "tags" in inspect_result.data
        assert "size" in inspect_result.data

    @pytest.mark.asyncio
    async def test_tag_image(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_image_tag: str,
        cleanup_test_image,
    ) -> None:
        """Test tagging an image."""
        # Ensure alpine image exists
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        tag_tool = TagImageTool(docker_wrapper, integration_config.safety)

        # Tag the image
        tag_result = await tag_tool.execute(
            {"source_image": "alpine:latest", "target_image": test_image_tag}
        )
        assert tag_result.success is True

        # Verify tag exists
        inspect_tool = InspectImageTool(docker_wrapper, integration_config.safety)
        inspect_result = await inspect_tool.execute({"image": test_image_tag})
        assert inspect_result.success is True

    @pytest.mark.asyncio
    async def test_image_history(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test getting image history."""
        # Ensure alpine image exists
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        history_tool = ImageHistoryTool(docker_wrapper, integration_config.safety)

        # Get history
        history_result = await history_tool.execute({"image": "alpine:latest"})
        assert history_result.success is True
        assert "layers" in history_result.data
        assert len(history_result.data["layers"]) > 0

    @pytest.mark.asyncio
    async def test_remove_image(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_image_tag: str,
    ) -> None:
        """Test removing an image."""
        # Pull and tag an image for removal
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        tag_tool = TagImageTool(docker_wrapper, integration_config.safety)
        await tag_tool.execute(
            {"source_image": "alpine:latest", "target_image": test_image_tag}
        )

        # Remove the tagged image
        remove_tool = RemoveImageTool(docker_wrapper, integration_config.safety)
        remove_result = await remove_tool.execute({"image": test_image_tag, "force": False})
        assert remove_result.success is True

        # Verify image is removed
        inspect_tool = InspectImageTool(docker_wrapper, integration_config.safety)
        inspect_result = await inspect_tool.execute({"image": test_image_tag})
        assert inspect_result.success is False

    @pytest.mark.asyncio
    async def test_prune_images(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test pruning unused images."""
        prune_tool = PruneImagesTool(docker_wrapper, integration_config.safety)

        # Prune images (this might not remove anything, but should succeed)
        prune_result = await prune_tool.execute({})
        assert prune_result.success is True
        assert "space_reclaimed" in prune_result.data
        assert "images_deleted" in prune_result.data

    @pytest.mark.asyncio
    async def test_image_error_handling(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid image operations."""
        inspect_tool = InspectImageTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveImageTool(docker_wrapper, integration_config.safety)

        # Try to inspect non-existent image
        inspect_result = await inspect_tool.execute({"image": "nonexistent-image:notag"})
        assert inspect_result.success is False
        assert "not found" in inspect_result.error.lower()

        # Try to remove non-existent image
        remove_result = await remove_tool.execute(
            {"image": "nonexistent-image:notag", "force": False}
        )
        assert remove_result.success is False

    @pytest.mark.asyncio
    async def test_pull_with_specific_tag(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test pulling image with specific tag."""
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)

        # Pull specific version
        pull_result = await pull_tool.execute({"image": "alpine:3.18"})
        assert pull_result.success is True

        # Verify the specific tag
        inspect_tool = InspectImageTool(docker_wrapper, integration_config.safety)
        inspect_result = await inspect_tool.execute({"image": "alpine:3.18"})
        assert inspect_result.success is True
        assert any("alpine:3.18" in tag for tag in inspect_result.data.get("tags", []))

    @pytest.mark.asyncio
    async def test_list_images_with_filters(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test listing images with filters."""
        # Ensure alpine image exists
        pull_tool = PullImageTool(docker_wrapper, integration_config.safety)
        await pull_tool.execute({"image": "alpine:latest"})

        list_tool = ListImagesTool(docker_wrapper, integration_config.safety)

        # List all images
        list_result = await list_tool.execute({"all": True})
        assert list_result.success is True
        total_images = len(list_result.data["images"])

        # List with dangling filter
        dangling_result = await list_tool.execute({"filters": {"dangling": True}})
        assert dangling_result.success is True
        # Dangling images should be <= total images
        assert len(dangling_result.data["images"]) <= total_images
