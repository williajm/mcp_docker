"""Unit tests for image tools."""

from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError
from docker.errors import ImageNotFound as DockerImageNotFound

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.image_tools import (
    BuildImageInput,
    BuildImageTool,
    ImageHistoryInput,
    ImageHistoryTool,
    InspectImageInput,
    InspectImageTool,
    ListImagesInput,
    ListImagesTool,
    PruneImagesInput,
    PruneImagesTool,
    PullImageInput,
    PullImageTool,
    PushImageInput,
    PushImageTool,
    RemoveImageInput,
    RemoveImageTool,
    TagImageInput,
    TagImageTool,
)
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound


@pytest.fixture
def mock_docker_client() -> Any:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def mock_image() -> Any:
    """Create a mock image."""
    image = MagicMock()
    image.id = "sha256:abc123"
    image.short_id = "sha256:abc123"[:12]
    image.tags = ["ubuntu:latest", "ubuntu:22.04"]
    image.labels = {"maintainer": "test"}
    image.attrs = {"Id": "sha256:abc123", "Size": 72800000}
    return image


class TestListImagesTool:
    """Tests for ListImagesTool."""

    @pytest.mark.asyncio
    async def test_list_images_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image listing."""
        mock_docker_client.client.images.list.return_value = [mock_image]

        tool = ListImagesTool(mock_docker_client, safety_config)
        input_data = ListImagesInput(all=True)
        result = await tool.execute(input_data)

        assert result.count == 1
        assert len(result.images) == 1
        assert result.images[0]["id"] == "sha256:abc123"
        assert result.images[0]["tags"] == ["ubuntu:latest", "ubuntu:22.04"]
        mock_docker_client.client.images.list.assert_called_once_with(all=True, filters=None)

    @pytest.mark.asyncio
    async def test_list_images_with_filters(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test listing images with filters."""
        mock_docker_client.client.images.list.return_value = [mock_image]

        tool = ListImagesTool(mock_docker_client, safety_config)
        input_data = ListImagesInput(filters={"dangling": ["false"]})
        result = await tool.execute(input_data)

        assert result.count == 1
        mock_docker_client.client.images.list.assert_called_once_with(
            all=False, filters={"dangling": ["false"]}
        )

    @pytest.mark.asyncio
    async def test_list_images_api_error(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.images.list.side_effect = APIError("API error")

        tool = ListImagesTool(mock_docker_client, safety_config)
        input_data = ListImagesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestInspectImageTool:
    """Tests for InspectImageTool."""

    @pytest.mark.asyncio
    async def test_inspect_image_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image inspection."""
        mock_docker_client.client.images.get.return_value = mock_image

        tool = InspectImageTool(mock_docker_client, safety_config)
        input_data = InspectImageInput(image_name="ubuntu:latest")
        result = await tool.execute(input_data)

        assert result.details["Id"] == "sha256:abc123"
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:latest")

    @pytest.mark.asyncio
    async def test_inspect_image_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of image not found."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        tool = InspectImageTool(mock_docker_client, safety_config)
        input_data = InspectImageInput(image_name="nonexistent:latest")

        with pytest.raises(ImageNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_inspect_image_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.images.get.side_effect = APIError("API error")

        tool = InspectImageTool(mock_docker_client, safety_config)
        input_data = InspectImageInput(image_name="ubuntu:latest")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestPullImageTool:
    """Tests for PullImageTool."""

    @pytest.mark.asyncio
    async def test_pull_image_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image pull."""
        mock_docker_client.client.images.pull.return_value = mock_image

        tool = PullImageTool(mock_docker_client, safety_config)
        input_data = PullImageInput(image="ubuntu", tag="latest")
        result = await tool.execute(input_data)

        assert result.image == "ubuntu"
        assert result.id == "sha256:abc123"
        assert result.tags == ["ubuntu:latest", "ubuntu:22.04"]
        mock_docker_client.client.images.pull.assert_called_once()

    @pytest.mark.asyncio
    async def test_pull_image_with_platform(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test pulling image with platform specification."""
        mock_docker_client.client.images.pull.return_value = mock_image

        tool = PullImageTool(mock_docker_client, safety_config)
        input_data = PullImageInput(image="ubuntu", platform="linux/amd64")
        result = await tool.execute(input_data)

        assert result.image == "ubuntu"
        call_kwargs = mock_docker_client.client.images.pull.call_args[1]
        assert call_kwargs["platform"] == "linux/amd64"

    @pytest.mark.asyncio
    async def test_pull_image_api_error(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.images.pull.side_effect = APIError("API error")

        tool = PullImageTool(mock_docker_client, safety_config)
        input_data = PullImageInput(image="ubuntu")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestBuildImageTool:
    """Tests for BuildImageTool."""

    @pytest.mark.asyncio
    async def test_build_image_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image build."""
        build_logs = [
            {"stream": "Step 1/2 : FROM ubuntu\n"},
            {"stream": "Successfully built abc123\n"},
        ]
        mock_docker_client.client.images.build.return_value = (mock_image, build_logs)

        tool = BuildImageTool(mock_docker_client, safety_config)
        input_data = BuildImageInput(path="/path/to/context", tag="myimage:latest")
        result = await tool.execute(input_data)

        assert result.image_id == "sha256:abc123"
        assert len(result.logs) == 2
        assert "Step 1/2" in result.logs[0]
        mock_docker_client.client.images.build.assert_called_once()

    @pytest.mark.asyncio
    async def test_build_image_with_args(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test building image with build arguments."""
        mock_docker_client.client.images.build.return_value = (mock_image, [])

        tool = BuildImageTool(mock_docker_client, safety_config)
        input_data = BuildImageInput(
            path="/path/to/context",
            tag="myimage:latest",
            buildargs={"VERSION": "1.0"},
            nocache=True,
        )
        result = await tool.execute(input_data)

        assert result.image_id == "sha256:abc123"
        call_kwargs = mock_docker_client.client.images.build.call_args[1]
        assert call_kwargs["buildargs"] == {"VERSION": "1.0"}
        assert call_kwargs["nocache"] is True

    @pytest.mark.asyncio
    async def test_build_image_api_error(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.images.build.side_effect = APIError("API error")

        tool = BuildImageTool(mock_docker_client, safety_config)
        input_data = BuildImageInput(path="/path/to/context")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestPushImageTool:
    """Tests for PushImageTool."""

    @pytest.mark.asyncio
    async def test_push_image_success(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test successful image push."""
        mock_docker_client.client.images.push.return_value = "pushed"

        tool = PushImageTool(mock_docker_client, safety_config)
        input_data = PushImageInput(image="myregistry.com/myimage", tag="latest")
        result = await tool.execute(input_data)

        assert result.image == "myregistry.com/myimage"
        assert result.status == "pushed"
        mock_docker_client.client.images.push.assert_called_once()

    @pytest.mark.asyncio
    async def test_push_image_not_found(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test handling of image not found."""
        mock_docker_client.client.images.push.side_effect = DockerImageNotFound("Image not found")

        tool = PushImageTool(mock_docker_client, safety_config)
        input_data = PushImageInput(image="nonexistent:latest")

        with pytest.raises(ImageNotFound):
            await tool.execute(input_data)


class TestTagImageTool:
    """Tests for TagImageTool."""

    @pytest.mark.asyncio
    async def test_tag_image_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image tagging."""
        mock_docker_client.client.images.get.return_value = mock_image

        tool = TagImageTool(mock_docker_client, safety_config)
        input_data = TagImageInput(image="ubuntu:latest", repository="myrepo/ubuntu", tag="v1")
        result = await tool.execute(input_data)

        assert result.source == "ubuntu:latest"
        assert result.target == "myrepo/ubuntu:v1"
        mock_image.tag.assert_called_once_with(repository="myrepo/ubuntu", tag="v1")

    @pytest.mark.asyncio
    async def test_tag_image_not_found(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test handling of image not found."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        tool = TagImageTool(mock_docker_client, safety_config)
        input_data = TagImageInput(image="nonexistent:latest", repository="myrepo", tag="v1")

        with pytest.raises(ImageNotFound):
            await tool.execute(input_data)


class TestRemoveImageTool:
    """Tests for RemoveImageTool."""

    @pytest.mark.asyncio
    async def test_remove_image_success(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test successful image removal."""
        mock_docker_client.client.images.remove.return_value = None

        tool = RemoveImageTool(mock_docker_client, safety_config)
        input_data = RemoveImageInput(image="ubuntu:old", force=True)
        result = await tool.execute(input_data)

        assert result.deleted[0]["Deleted"] == "ubuntu:old"
        mock_docker_client.client.images.remove.assert_called_once_with(
            image="ubuntu:old", force=True, noprune=False
        )

    @pytest.mark.asyncio
    async def test_remove_image_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of image not found."""
        mock_docker_client.client.images.remove.side_effect = DockerImageNotFound("Image not found")

        tool = RemoveImageTool(mock_docker_client, safety_config)
        input_data = RemoveImageInput(image="nonexistent:latest")

        with pytest.raises(ImageNotFound):
            await tool.execute(input_data)


class TestPruneImagesTool:
    """Tests for PruneImagesTool."""

    @pytest.mark.asyncio
    async def test_prune_images_success(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test successful image pruning (dangling only by default)."""
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:abc123"}],
            "SpaceReclaimed": 72800000,
        }

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(filters={"dangling": ["true"]})
        result = await tool.execute(input_data)

        assert len(result.deleted) == 1
        assert result.space_reclaimed == 72800000
        mock_docker_client.client.images.prune.assert_called_once_with(
            filters={"dangling": ["true"]}
        )

    @pytest.mark.asyncio
    async def test_prune_images_with_all_flag(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning images with all=True removes all unused images."""
        # Create mock images
        mock_image1 = MagicMock()
        mock_image1.id = "sha256:abc123"
        mock_image1.attrs = {"Size": 1000000}

        mock_image2 = MagicMock()
        mock_image2.id = "sha256:def456"
        mock_image2.attrs = {"Size": 2000000}

        mock_docker_client.client.images.list.return_value = [mock_image1, mock_image2]

        # Mock container list with one image in use
        mock_container = MagicMock()
        mock_container.image = MagicMock()
        mock_container.image.id = "sha256:abc123"
        mock_docker_client.client.containers.list.return_value = [mock_container]

        # Mock image removal - only unused image should be removed
        mock_docker_client.client.images.remove.return_value = None

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(all=True)
        result = await tool.execute(input_data)

        # Should only remove the unused image (def456)
        assert len(result.deleted) == 1
        assert result.deleted[0]["Deleted"] == "sha256:def456"
        assert result.space_reclaimed == 2000000
        mock_docker_client.client.images.remove.assert_called_once_with(
            "sha256:def456", force=False
        )

    @pytest.mark.asyncio
    async def test_prune_images_force_all(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning images with force_all=True removes ALL images."""
        # Create mock images
        mock_image1 = MagicMock()
        mock_image1.id = "sha256:abc123"
        mock_image1.attrs = {"Size": 1000000}

        mock_image2 = MagicMock()
        mock_image2.id = "sha256:def456"
        mock_image2.attrs = {"Size": 2000000}

        mock_image3 = MagicMock()
        mock_image3.id = "sha256:ghi789"
        mock_image3.attrs = {"Size": 3000000}

        mock_docker_client.client.images.list.return_value = [
            mock_image1,
            mock_image2,
            mock_image3,
        ]
        mock_docker_client.client.images.remove.return_value = None

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(force_all=True)
        result = await tool.execute(input_data)

        # Should remove ALL images with force=True
        assert len(result.deleted) == 3
        assert result.space_reclaimed == 6000000
        assert mock_docker_client.client.images.remove.call_count == 3
        # Verify force=True was used
        for call in mock_docker_client.client.images.remove.call_args_list:
            assert call[1]["force"] is True

    @pytest.mark.asyncio
    async def test_prune_images_force_all_handles_errors(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning with force_all=True continues on errors."""
        # Create mock images
        mock_image1 = MagicMock()
        mock_image1.id = "sha256:abc123"
        mock_image1.attrs = {"Size": 1000000}

        mock_image2 = MagicMock()
        mock_image2.id = "sha256:def456"
        mock_image2.attrs = {"Size": 2000000}

        mock_docker_client.client.images.list.return_value = [mock_image1, mock_image2]

        # First removal fails, second succeeds
        mock_docker_client.client.images.remove.side_effect = [
            APIError("Failed to remove"),
            None,
        ]

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(force_all=True)
        result = await tool.execute(input_data)

        # Should continue despite error and remove the second image
        assert len(result.deleted) == 1
        assert result.deleted[0]["Deleted"] == "sha256:def456"
        assert result.space_reclaimed == 2000000

    @pytest.mark.asyncio
    async def test_prune_images_all_with_filters(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning images with all=True and filters."""
        # Create mock images matching filter
        mock_image1 = MagicMock()
        mock_image1.id = "sha256:abc123"
        mock_image1.attrs = {"Size": 1000000}

        mock_docker_client.client.images.list.return_value = [mock_image1]

        # No containers using images
        mock_docker_client.client.containers.list.return_value = []

        mock_docker_client.client.images.remove.return_value = None

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(all=True, filters={"label": ["env=test"]})
        result = await tool.execute(input_data)

        # Should remove filtered unused image
        assert len(result.deleted) == 1
        mock_docker_client.client.images.list.assert_called_once_with(
            all=True, filters={"label": ["env=test"]}
        )

    @pytest.mark.asyncio
    async def test_prune_images_skips_images_without_id(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test pruning skips images without an ID."""
        # Create mock images, one without ID
        mock_image1 = MagicMock()
        mock_image1.id = None  # No ID

        mock_image2 = MagicMock()
        mock_image2.id = "sha256:def456"
        mock_image2.attrs = {"Size": 2000000}

        mock_docker_client.client.images.list.return_value = [mock_image1, mock_image2]
        mock_docker_client.client.images.remove.return_value = None

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput(force_all=True)
        result = await tool.execute(input_data)

        # Should only remove image with ID
        assert len(result.deleted) == 1
        assert result.deleted[0]["Deleted"] == "sha256:def456"

    @pytest.mark.asyncio
    async def test_prune_images_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.images.prune.side_effect = APIError("API error")

        tool = PruneImagesTool(mock_docker_client, safety_config)
        input_data = PruneImagesInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestImageHistoryTool:
    """Tests for ImageHistoryTool."""

    @pytest.mark.asyncio
    async def test_image_history_success(
        self, mock_docker_client: Any, safety_config: Any, mock_image: Any
    ) -> None:
        """Test successful image history retrieval."""
        history = [
            {"Id": "sha256:abc123", "Created": 1234567890, "Size": 1000},
            {"Id": "sha256:def456", "Created": 1234567800, "Size": 2000},
        ]
        mock_image.history.return_value = history
        mock_docker_client.client.images.get.return_value = mock_image

        tool = ImageHistoryTool(mock_docker_client, safety_config)
        input_data = ImageHistoryInput(image="ubuntu:latest")
        result = await tool.execute(input_data)

        assert len(result.history) == 2
        assert result.history[0]["Id"] == "sha256:abc123"
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:latest")

    @pytest.mark.asyncio
    async def test_image_history_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of image not found."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        tool = ImageHistoryTool(mock_docker_client, safety_config)
        input_data = ImageHistoryInput(image="nonexistent:latest")

        with pytest.raises(ImageNotFound):
            await tool.execute(input_data)
