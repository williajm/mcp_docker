"""Unit tests for fastmcp_tools/image.py."""

from unittest.mock import AsyncMock, Mock

import pytest
from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound
from fastmcp.dependencies import Progress

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.image import (
    BuildImageInput,
    _validate_build_context_path,
    create_build_image_tool,
    create_image_history_tool,
    create_inspect_image_tool,
    create_list_images_tool,
    create_prune_images_tool,
    create_pull_image_tool,
    create_push_image_tool,
    create_remove_image_tool,
    create_tag_image_tool,
)
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound, ValidationError


@pytest.fixture
def mock_progress():
    """Create a mock Progress dependency."""
    progress = Mock(spec=Progress)
    progress.set_message = AsyncMock()
    return progress


# Module-level fixtures to avoid duplication across test classes
@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    client.client.images = Mock()
    client.client.containers = Mock()
    client.client.api = Mock()
    return client


@pytest.fixture
def safety_config():
    """Create safety config."""
    return SafetyConfig()


class TestBuildImageInputValidation:
    """Test BuildImageInput Pydantic model validation."""

    @pytest.mark.parametrize(
        "buildargs,expected",
        [
            ('{"NODE_VERSION": "18", "ENV": "prod"}', {"NODE_VERSION": "18", "ENV": "prod"}),
            ({"NODE_VERSION": "18", "ENV": "prod"}, {"NODE_VERSION": "18", "ENV": "prod"}),
            (None, None),
        ],
    )
    def test_buildargs_parsing(self, buildargs, expected):
        """Test that buildargs is parsed correctly from JSON string or passed through as dict."""
        input_data = BuildImageInput(path=".", buildargs=buildargs)
        assert input_data.buildargs == expected


class TestImageNotFoundErrors:
    """Test image not found error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs,error_type",
        [
            (create_inspect_image_tool, False, {"image_name": "nonexistent"}, DockerImageNotFound),
            (create_inspect_image_tool, False, {"image_name": "nonexistent"}, NotFound),
            (create_image_history_tool, True, {"image": "nonexistent"}, DockerImageNotFound),
            (
                create_tag_image_tool,
                False,
                {"image": "nonexistent", "repository": "myrepo"},
                DockerImageNotFound,
            ),
            (create_remove_image_tool, False, {"image": "nonexistent"}, DockerImageNotFound),
        ],
    )
    def test_image_not_found(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        call_kwargs,
        error_type,
    ):
        """Test that ImageNotFound is raised when image doesn't exist."""
        # Set up error on appropriate method based on tool
        if tool_creator in (create_remove_image_tool,):
            mock_docker_client.client.images.remove.side_effect = error_type("Image not found")
        else:
            mock_docker_client.client.images.get.side_effect = error_type("Image not found")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(ImageNotFound, match="Image not found"):
            func(**call_kwargs)

    @pytest.mark.asyncio
    async def test_push_image_not_found(self, mock_docker_client, mock_progress):
        """Test that ImageNotFound is raised when image doesn't exist during push."""
        mock_docker_client.client.api.push.side_effect = NotFound("Image not found")

        *_, func = create_push_image_tool(mock_docker_client)

        with pytest.raises(ImageNotFound, match="Image not found"):
            await func(image="nonexistent", progress=mock_progress)


class TestAPIErrors:
    """Test API error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs,error_match,setup_error_on",
        [
            (create_list_images_tool, True, {}, "Failed to list images", "images.list"),
            (
                create_inspect_image_tool,
                False,
                {"image_name": "test"},
                "Failed to inspect image",
                "images.get",
            ),
            (create_prune_images_tool, False, {}, "Failed to prune images", "images.prune"),
        ],
    )
    def test_api_error(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        call_kwargs,
        error_match,
        setup_error_on,
    ):
        """Test that DockerOperationError is raised on API errors."""
        # Set up the error on the right method
        method_mapping = {
            "images.list": mock_docker_client.client.images.list,
            "images.get": mock_docker_client.client.images.get,
            "images.prune": mock_docker_client.client.images.prune,
        }
        method_mapping[setup_error_on].side_effect = APIError("API failed")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(DockerOperationError, match=error_match):
            func(**call_kwargs)

    @pytest.mark.asyncio
    async def test_pull_api_error(self, mock_docker_client, mock_progress):
        """Test that DockerOperationError is raised on pull API errors."""
        mock_docker_client.client.api.pull.side_effect = APIError("API failed")

        *_, func = create_pull_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to pull image"):
            await func(image="ubuntu", progress=mock_progress)

    @pytest.mark.asyncio
    async def test_build_api_error(self, mock_docker_client, mock_progress, tmp_path):
        """Test that DockerOperationError is raised on build API errors."""
        mock_docker_client.client.images.build.side_effect = APIError("API failed")

        *_, func = create_build_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to build image"):
            await func(path=str(tmp_path), progress=mock_progress)

    @pytest.mark.asyncio
    async def test_push_api_error(self, mock_docker_client, mock_progress):
        """Test that DockerOperationError is raised on push API errors."""
        mock_docker_client.client.api.push.side_effect = APIError("API failed")

        *_, func = create_push_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to push image"):
            await func(image="myrepo/app", progress=mock_progress)

    def test_history_api_error(self, mock_docker_client, safety_config):
        """Test image history API error after getting image."""
        image = Mock()
        image.history.side_effect = APIError("History failed")
        mock_docker_client.client.images.get.return_value = image

        *_, history_func = create_image_history_tool(mock_docker_client, safety_config)

        with pytest.raises(DockerOperationError, match="Failed to get image history"):
            history_func(image="ubuntu:22.04")

    def test_tag_api_error(self, mock_docker_client):
        """Test image tagging API error after getting image."""
        image = Mock()
        image.tag.side_effect = APIError("Tag failed")
        mock_docker_client.client.images.get.return_value = image

        *_, tag_func = create_tag_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to tag image"):
            tag_func(image="ubuntu:22.04", repository="myrepo/ubuntu")

    def test_remove_api_error(self, mock_docker_client):
        """Test image removal API error."""
        mock_docker_client.client.images.remove.side_effect = APIError("Remove failed")

        *_, remove_func = create_remove_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Failed to remove image"):
            remove_func(image="ubuntu:22.04")


class TestListImagesTool:
    """Test docker_list_images tool."""

    def test_list_images_success(self, mock_docker_client, safety_config):
        """Test successful image listing."""
        img1 = Mock()
        img1.id = "sha256:abc123"
        img1.short_id = "abc123"
        img1.tags = ["ubuntu:22.04"]
        img1.labels = {"maintainer": "test"}
        img1.attrs = {"Size": 1000}

        img2 = Mock()
        img2.id = "sha256:def456"
        img2.short_id = "def456"
        img2.tags = ["alpine:latest"]
        img2.labels = {}
        img2.attrs = {"Size": 500}

        mock_docker_client.client.images.list.return_value = [img1, img2]

        *_, list_func = create_list_images_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 2
        assert len(result["images"]) == 2
        assert result["images"][0]["id"] == "sha256:abc123"
        assert result["images"][0]["tags"] == ["ubuntu:22.04"]
        assert result["images"][1]["id"] == "sha256:def456"

    @pytest.mark.parametrize(
        "kwargs,expected_call_kwargs",
        [
            ({"all": True}, {"all": True, "filters": None}),
            (
                {"filters": {"dangling": ["true"]}},
                {"all": False, "filters": {"dangling": ["true"]}},
            ),
        ],
    )
    def test_list_images_with_options(
        self, mock_docker_client, safety_config, kwargs, expected_call_kwargs
    ):
        """Test image listing with various options."""
        mock_docker_client.client.images.list.return_value = []

        *_, list_func = create_list_images_tool(mock_docker_client, safety_config)
        result = list_func(**kwargs)

        mock_docker_client.client.images.list.assert_called_once_with(**expected_call_kwargs)
        assert result["count"] == 0

    def test_list_images_with_truncation(self, mock_docker_client):
        """Test image listing with output truncation."""
        safety_config = SafetyConfig(max_list_results=1)

        img1 = Mock()
        img1.id = "sha256:abc123"
        img1.short_id = "abc123"
        img1.tags = ["ubuntu:22.04"]
        img1.labels = {}
        img1.attrs = {"Size": 1000}

        img2 = Mock()
        img2.id = "sha256:def456"
        img2.short_id = "def456"
        img2.tags = ["alpine:latest"]
        img2.labels = {}
        img2.attrs = {"Size": 500}

        mock_docker_client.client.images.list.return_value = [img1, img2]

        *_, list_func = create_list_images_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 2
        assert len(result["images"]) == 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]


class TestInspectImageTool:
    """Test docker_inspect_image tool."""

    def test_inspect_image_success(self, mock_docker_client):
        """Test successful image inspection."""
        image = Mock()
        image.attrs = {
            "Id": "sha256:abc123",
            "RepoTags": ["ubuntu:22.04"],
            "Created": "2024-01-01T00:00:00Z",
            "Size": 1000,
        }

        mock_docker_client.client.images.get.return_value = image

        *_, inspect_func = create_inspect_image_tool(mock_docker_client)
        result = inspect_func(image_name="ubuntu:22.04")

        assert result["details"]["Id"] == "sha256:abc123"
        assert result["details"]["RepoTags"] == ["ubuntu:22.04"]
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")


class TestImageHistoryTool:
    """Test docker_image_history tool."""

    def test_image_history_success(self, mock_docker_client, safety_config):
        """Test successful image history retrieval."""
        image = Mock()
        history_data = [
            {"Id": "layer1", "Created": 1234567890, "Size": 100},
            {"Id": "layer2", "Created": 1234567891, "Size": 200},
        ]
        image.history.return_value = history_data
        mock_docker_client.client.images.get.return_value = image

        *_, history_func = create_image_history_tool(mock_docker_client, safety_config)
        result = history_func(image="ubuntu:22.04")

        assert len(result["history"]) == 2
        assert result["history"][0]["Id"] == "layer1"
        assert result["history"][1]["Id"] == "layer2"
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")

    def test_image_history_with_truncation(self, mock_docker_client):
        """Test image history with output truncation."""
        safety_config = SafetyConfig(max_list_results=1)

        image = Mock()
        history_data = [
            {"Id": "layer1", "Created": 1234567890, "Size": 100},
            {"Id": "layer2", "Created": 1234567891, "Size": 200},
        ]
        image.history.return_value = history_data
        mock_docker_client.client.images.get.return_value = image

        *_, history_func = create_image_history_tool(mock_docker_client, safety_config)
        result = history_func(image="ubuntu:22.04")

        assert len(result["history"]) == 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]


class TestPullImageTool:
    """Test docker_pull_image tool."""

    @pytest.mark.asyncio
    async def test_pull_image_rejects_duplicate_tag(self, mock_docker_client, mock_progress):
        """Test that pull rejects image with tag when tag param also provided."""
        *_, pull_func = create_pull_image_tool(mock_docker_client)

        with pytest.raises(ValidationError, match="already contains a tag"):
            await pull_func(image="ubuntu:22.04", tag="latest", progress=mock_progress)

    @pytest.mark.asyncio
    async def test_pull_image_accepts_registry_with_port(self, mock_docker_client, mock_progress):
        """Test that pull accepts registry:port/image with separate tag param."""
        # Mock streaming response from api.pull
        mock_docker_client.client.api.pull.return_value = iter(
            [{"status": "Pulling from localhost:5000/myimg"}, {"status": "Pull complete"}]
        )
        # Mock the final image
        mock_image = Mock()
        mock_image.id = "sha256:registry123"
        mock_image.tags = ["localhost:5000/myimg:v1"]
        mock_docker_client.client.images.get.return_value = mock_image

        *_, pull_func = create_pull_image_tool(mock_docker_client)

        # This should NOT raise - registry port should not be confused with tag
        result = await pull_func(image="localhost:5000/myimg", tag="v1", progress=mock_progress)

        assert result["image"] == "localhost:5000/myimg"
        mock_docker_client.client.api.pull.assert_called_once_with(
            repository="localhost:5000/myimg",
            tag="v1",
            stream=True,
            decode=True,
            all_tags=False,
            platform=None,
        )

    @pytest.mark.asyncio
    async def test_pull_image_success(self, mock_docker_client, mock_progress):
        """Test successful image pull."""
        # Mock streaming response from api.pull
        mock_docker_client.client.api.pull.return_value = iter(
            [{"status": "Pulling from library/ubuntu"}, {"status": "Pull complete"}]
        )

        # Mock image retrieval after pull
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:22.04"]
        mock_docker_client.client.images.get.return_value = image

        *_, pull_func = create_pull_image_tool(mock_docker_client)
        result = await pull_func(image="ubuntu", progress=mock_progress)

        assert result["image"] == "ubuntu"
        assert result["id"] == "sha256:abc123"
        assert result["tags"] == ["ubuntu:22.04"]
        mock_docker_client.client.api.pull.assert_called_once()

    @pytest.mark.asyncio
    async def test_pull_image_with_tag(self, mock_docker_client, mock_progress):
        """Test image pull with tag."""
        mock_docker_client.client.api.pull.return_value = iter([{"status": "Pull complete"}])

        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:20.04"]
        mock_docker_client.client.images.get.return_value = image

        *_, pull_func = create_pull_image_tool(mock_docker_client)
        await pull_func(image="ubuntu", tag="20.04", progress=mock_progress)

        call_kwargs = mock_docker_client.client.api.pull.call_args.kwargs
        assert call_kwargs["repository"] == "ubuntu"
        assert call_kwargs["tag"] == "20.04"

    @pytest.mark.asyncio
    async def test_pull_image_with_progress(self, mock_docker_client, mock_progress):
        """Test image pull reports progress."""
        mock_docker_client.client.api.pull.return_value = iter(
            [
                {
                    "id": "abc123",
                    "status": "Pulling",
                    "progressDetail": {"current": 50, "total": 100},
                },
                {"id": "abc123", "status": "Complete"},
            ]
        )

        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:latest"]
        mock_docker_client.client.images.get.return_value = image

        *_, pull_func = create_pull_image_tool(mock_docker_client)
        await pull_func(image="ubuntu", progress=mock_progress)

        # Verify progress messages were set
        assert mock_progress.set_message.call_count >= 1


class TestBuildImageTool:
    """Test docker_build_image tool."""

    @pytest.mark.asyncio
    async def test_build_image_success(self, mock_docker_client, mock_progress, tmp_path):
        """Test successful image build."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["myapp:latest"]

        build_logs = [
            {"stream": "Step 1/2 : FROM ubuntu\n"},
            {"stream": "Step 2/2 : RUN echo hello\n"},
        ]
        mock_docker_client.client.images.build.return_value = (image, build_logs)

        *_, build_func = create_build_image_tool(mock_docker_client)
        result = await build_func(path=str(tmp_path), progress=mock_progress)

        assert result["image_id"] == "sha256:abc123"
        assert result["tags"] == ["myapp:latest"]
        assert len(result["logs"]) == 2
        mock_docker_client.client.images.build.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "extra_kwargs,expected_kwarg",
        [
            ({"tag": "myapp:v1.0"}, ("tag", "myapp:v1.0")),
            ({"buildargs": {"NODE_VERSION": "18"}}, ("buildargs", {"NODE_VERSION": "18"})),
            ({"dockerfile": "Dockerfile.dev"}, ("dockerfile", "Dockerfile.dev")),
            ({"nocache": True}, ("nocache", True)),
            ({"rm": False}, ("rm", False)),
            ({"pull": True}, ("pull", True)),
        ],
    )
    async def test_build_image_with_options(
        self, mock_docker_client, mock_progress, tmp_path, extra_kwargs, expected_kwarg
    ):
        """Test image build with various options."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = []
        mock_docker_client.client.images.build.return_value = (image, [])

        *_, build_func = create_build_image_tool(mock_docker_client)
        await build_func(path=str(tmp_path), progress=mock_progress, **extra_kwargs)

        call_kwargs = mock_docker_client.client.images.build.call_args.kwargs
        key, value = expected_kwarg
        assert call_kwargs[key] == value


class TestValidateBuildContextPath:
    """Test _validate_build_context_path helper function."""

    def test_rejects_root_directory(self):
        """Test that root directory is rejected."""
        with pytest.raises(ValidationError, match="Cannot build from root directory"):
            _validate_build_context_path("/")

    def test_rejects_nonexistent_path(self, tmp_path):
        """Test that non-existent path is rejected."""
        nonexistent = tmp_path / "does_not_exist"
        with pytest.raises(ValidationError, match="does not exist"):
            _validate_build_context_path(str(nonexistent))

    def test_rejects_file_path(self, tmp_path):
        """Test that file path (not directory) is rejected."""
        file_path = tmp_path / "somefile.txt"
        file_path.write_text("content")
        with pytest.raises(ValidationError, match="must be a directory"):
            _validate_build_context_path(str(file_path))

    def test_accepts_valid_directory(self, tmp_path):
        """Test that valid directory returns resolved path."""
        result = _validate_build_context_path(str(tmp_path))
        assert result == tmp_path.resolve()


class TestBuildImagePathValidation:
    """Test build_image path validation security checks."""

    @pytest.mark.asyncio
    async def test_build_image_rejects_root_directory(self, mock_docker_client, mock_progress):
        """Test that building from root directory '/' is rejected."""
        *_, build_func = create_build_image_tool(mock_docker_client)

        with pytest.raises(ValidationError, match="Cannot build from root directory"):
            await build_func(path="/", progress=mock_progress)

    @pytest.mark.asyncio
    async def test_build_image_rejects_nonexistent_path(
        self, mock_docker_client, mock_progress, tmp_path
    ):
        """Test that building from non-existent path is rejected."""
        nonexistent = tmp_path / "does_not_exist"
        *_, build_func = create_build_image_tool(mock_docker_client)

        with pytest.raises(ValidationError, match="does not exist"):
            await build_func(path=str(nonexistent), progress=mock_progress)

    @pytest.mark.asyncio
    async def test_build_image_rejects_file_path(self, mock_docker_client, mock_progress, tmp_path):
        """Test that building from a file (not directory) is rejected."""
        file_path = tmp_path / "Dockerfile"
        file_path.write_text("FROM ubuntu")
        *_, build_func = create_build_image_tool(mock_docker_client)

        with pytest.raises(ValidationError, match="must be a directory"):
            await build_func(path=str(file_path), progress=mock_progress)

    @pytest.mark.asyncio
    async def test_build_image_accepts_valid_directory(
        self, mock_docker_client, mock_progress, tmp_path
    ):
        """Test that valid directory path is accepted."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["test:latest"]
        mock_docker_client.client.images.build.return_value = (image, [])

        *_, build_func = create_build_image_tool(mock_docker_client)
        result = await build_func(path=str(tmp_path), progress=mock_progress)

        assert result["image_id"] == "sha256:abc123"
        # Verify resolved path was used
        call_kwargs = mock_docker_client.client.images.build.call_args.kwargs
        assert call_kwargs["path"] == str(tmp_path.resolve())


class TestPushImageTool:
    """Test docker_push_image tool."""

    @pytest.mark.asyncio
    async def test_push_image_success(self, mock_docker_client, mock_progress):
        """Test successful image push."""
        # Mock streaming response from api.push
        mock_docker_client.client.api.push.return_value = iter(
            [{"status": "Pushing"}, {"status": "Pushed"}]
        )

        *_, push_func = create_push_image_tool(mock_docker_client)
        result = await push_func(image="myrepo/myapp", progress=mock_progress)

        assert result["image"] == "myrepo/myapp"
        assert result["status"] == "Pushed"
        mock_docker_client.client.api.push.assert_called_once()

    @pytest.mark.asyncio
    async def test_push_image_with_tag(self, mock_docker_client, mock_progress):
        """Test pushing image with tag."""
        mock_docker_client.client.api.push.return_value = iter([{"status": "Pushed"}])

        *_, push_func = create_push_image_tool(mock_docker_client)
        await push_func(image="myrepo/myapp", tag="v1.0", progress=mock_progress)

        call_kwargs = mock_docker_client.client.api.push.call_args.kwargs
        assert call_kwargs["repository"] == "myrepo/myapp"
        assert call_kwargs["tag"] == "v1.0"

    @pytest.mark.asyncio
    async def test_push_image_with_error_in_stream(self, mock_docker_client, mock_progress):
        """Test pushing image with error in stream."""
        mock_docker_client.client.api.push.return_value = iter(
            [{"status": "Pushing"}, {"error": "Authentication required"}]
        )

        *_, push_func = create_push_image_tool(mock_docker_client)

        with pytest.raises(DockerOperationError, match="Authentication required"):
            await push_func(image="myrepo/myapp", progress=mock_progress)

    @pytest.mark.asyncio
    async def test_push_image_no_status(self, mock_docker_client, mock_progress):
        """Test pushing image with no status in stream."""
        mock_docker_client.client.api.push.return_value = iter([])

        *_, push_func = create_push_image_tool(mock_docker_client)
        result = await push_func(image="myrepo/myapp", progress=mock_progress)

        assert result["status"] == "pushed"


class TestTagImageTool:
    """Test docker_tag_image tool."""

    @pytest.mark.parametrize(
        "tag,expected_target",
        [
            (None, "myrepo/ubuntu:latest"),
            ("v1.0", "myrepo/ubuntu:v1.0"),
        ],
    )
    def test_tag_image(self, mock_docker_client, tag, expected_target):
        """Test image tagging with and without custom tag."""
        image = Mock()
        image.tag = Mock()
        mock_docker_client.client.images.get.return_value = image

        *_, tag_func = create_tag_image_tool(mock_docker_client)

        kwargs = {"image": "ubuntu:22.04", "repository": "myrepo/ubuntu"}
        if tag:
            kwargs["tag"] = tag

        result = tag_func(**kwargs)

        assert result["source"] == "ubuntu:22.04"
        assert result["target"] == expected_target
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")
        image.tag.assert_called_once_with(repository="myrepo/ubuntu", tag=tag or "latest")


class TestRemoveImageTool:
    """Test docker_remove_image tool."""

    @pytest.mark.parametrize(
        "kwargs,expected_call_kwargs",
        [
            ({}, {"image": "ubuntu:22.04", "force": False, "noprune": False}),
            ({"force": True}, {"image": "ubuntu:22.04", "force": True, "noprune": False}),
            ({"noprune": True}, {"image": "ubuntu:22.04", "force": False, "noprune": True}),
        ],
    )
    def test_remove_image(self, mock_docker_client, kwargs, expected_call_kwargs):
        """Test image removal with various options."""
        mock_docker_client.client.images.remove.return_value = None

        *_, remove_func = create_remove_image_tool(mock_docker_client)
        result = remove_func(image="ubuntu:22.04", **kwargs)

        assert result["deleted"][0]["Deleted"] == "ubuntu:22.04"
        mock_docker_client.client.images.remove.assert_called_once_with(**expected_call_kwargs)


class TestPruneImagesTool:
    """Test docker_prune_images tool."""

    def test_prune_images_standard(self, mock_docker_client):
        """Test standard image prune (dangling only)."""
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:abc123"}],
            "SpaceReclaimed": 5000,
        }

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func()

        assert len(result["deleted"]) == 1
        assert result["space_reclaimed"] == 5000
        mock_docker_client.client.images.prune.assert_called_once_with(filters=None)

    def test_prune_images_with_filters(self, mock_docker_client):
        """Test pruning images with filters."""
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [],
            "SpaceReclaimed": 0,
        }

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        filters = {"until": ["24h"]}
        prune_func(filters=filters)

        mock_docker_client.client.images.prune.assert_called_once_with(filters=filters)

    def test_prune_images_all(self, mock_docker_client):
        """Test pruning all unused images using manual iteration."""
        image1 = Mock()
        image1.id = "sha256:unused1"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:inuse1"
        image2.attrs = {"Size": 2000}

        container = Mock()
        container.image = Mock()
        container.image.id = "sha256:inuse1"

        mock_docker_client.client.images.list.return_value = [image1, image2]
        mock_docker_client.client.containers.list.return_value = [container]

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func(all=True)

        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:unused1"}
        assert result["space_reclaimed"] == 1000
        mock_docker_client.client.images.remove.assert_called_once_with(
            "sha256:unused1", force=False
        )

    def test_prune_images_all_with_filters(self, mock_docker_client):
        """Test pruning all unused images with custom filters."""
        image1 = Mock()
        image1.id = "sha256:unused1"
        image1.attrs = {"Size": 1500}

        mock_docker_client.client.images.list.return_value = [image1]
        mock_docker_client.client.containers.list.return_value = []

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        filters = {"label": ["env=test"]}
        result = prune_func(all=True, filters=filters)

        mock_docker_client.client.images.list.assert_called_once_with(all=True, filters=filters)
        assert len(result["deleted"]) == 1
        assert result["space_reclaimed"] == 1500

    def test_prune_images_all_removes_tagged_but_unused(self, mock_docker_client):
        """Regression test: Ensure all=True removes tagged-but-unused images."""
        tagged_unused = Mock()
        tagged_unused.id = "sha256:tagged123"
        tagged_unused.tags = ["myapp:old"]
        tagged_unused.attrs = {"Size": 5000}

        dangling = Mock()
        dangling.id = "sha256:dangling456"
        dangling.tags = []
        dangling.attrs = {"Size": 1000}

        in_use = Mock()
        in_use.id = "sha256:inuse789"
        in_use.tags = ["myapp:latest"]
        in_use.attrs = {"Size": 3000}

        container = Mock()
        container.image = Mock()
        container.image.id = "sha256:inuse789"

        mock_docker_client.client.images.list.return_value = [tagged_unused, dangling, in_use]
        mock_docker_client.client.containers.list.return_value = [container]

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func(all=True)

        assert len(result["deleted"]) == 2
        deleted_ids = [d["Deleted"] for d in result["deleted"]]
        assert "sha256:tagged123" in deleted_ids
        assert "sha256:dangling456" in deleted_ids
        assert "sha256:inuse789" not in deleted_ids
        assert result["space_reclaimed"] == 6000

    def test_prune_images_all_with_removal_error(self, mock_docker_client):
        """Test manual iteration handles removal errors gracefully."""
        image1 = Mock()
        image1.id = "sha256:error1"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:success1"
        image2.attrs = {"Size": 2000}

        mock_docker_client.client.images.list.return_value = [image1, image2]
        mock_docker_client.client.containers.list.return_value = []

        def remove_side_effect(image_id, force):
            if image_id == "sha256:error1":
                raise APIError("Removal failed")

        mock_docker_client.client.images.remove.side_effect = remove_side_effect

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func(all=True)

        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:success1"}
        assert result["space_reclaimed"] == 2000

    def test_prune_images_force_all(self, mock_docker_client):
        """Test force removing all images."""
        image1 = Mock()
        image1.id = "sha256:abc123"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:def456"
        image2.attrs = {"Size": 2000}

        image3 = Mock()
        image3.id = None  # Test skipping images without IDs

        mock_docker_client.client.images.list.return_value = [image1, image2, image3]

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func(force_all=True)

        assert len(result["deleted"]) == 2
        assert result["deleted"][0] == {"Deleted": "sha256:abc123"}
        assert result["deleted"][1] == {"Deleted": "sha256:def456"}
        assert result["space_reclaimed"] == 3000

        assert mock_docker_client.client.images.remove.call_count == 2
        mock_docker_client.client.images.remove.assert_any_call("sha256:abc123", force=True)
        mock_docker_client.client.images.remove.assert_any_call("sha256:def456", force=True)

    def test_prune_images_force_all_with_errors(self, mock_docker_client):
        """Test force removing all images with some failures."""
        image1 = Mock()
        image1.id = "sha256:abc123"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:def456"
        image2.attrs = {"Size": 2000}

        mock_docker_client.client.images.list.return_value = [image1, image2]

        def remove_side_effect(image_id, force):
            if image_id == "sha256:abc123":
                raise APIError("Image in use")

        mock_docker_client.client.images.remove.side_effect = remove_side_effect

        *_, prune_func = create_prune_images_tool(mock_docker_client)
        result = prune_func(force_all=True)

        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:def456"}
        assert result["space_reclaimed"] == 2000
