"""Unit tests for fastmcp_tools/image.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.image import (
    BuildImageInput,
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
from mcp_docker.utils.errors import DockerOperationError, ImageNotFound


class TestBuildImageInputValidation:
    """Test BuildImageInput Pydantic model validation."""

    def test_buildargs_json_string_parsing(self):
        """Test that buildargs JSON string is parsed correctly."""
        # JSON string should be parsed to dict
        input_data = BuildImageInput(
            path=".",
            buildargs='{"NODE_VERSION": "18", "ENV": "prod"}',
        )
        assert input_data.buildargs == {"NODE_VERSION": "18", "ENV": "prod"}

    def test_buildargs_dict_passthrough(self):
        """Test that buildargs dict is passed through."""
        # Dict should remain as dict
        input_data = BuildImageInput(
            path=".",
            buildargs={"NODE_VERSION": "18", "ENV": "prod"},
        )
        assert input_data.buildargs == {"NODE_VERSION": "18", "ENV": "prod"}

    def test_buildargs_none(self):
        """Test that buildargs can be None."""
        input_data = BuildImageInput(path=".")
        assert input_data.buildargs is None


class TestListImagesTool:
    """Test docker_list_images tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_list_images_success(self, mock_docker_client, safety_config):
        """Test successful image listing."""
        # Mock image objects
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

        # Get the list function
        _, _, _, _, _, list_func = create_list_images_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify
        assert result["count"] == 2
        assert len(result["images"]) == 2
        assert result["images"][0]["id"] == "sha256:abc123"
        assert result["images"][0]["tags"] == ["ubuntu:22.04"]
        assert result["images"][1]["id"] == "sha256:def456"

    def test_list_images_with_all_flag(self, mock_docker_client, safety_config):
        """Test image listing with all flag."""
        mock_docker_client.client.images.list.return_value = []

        # Get the list function
        _, _, _, _, _, list_func = create_list_images_tool(mock_docker_client, safety_config)

        # Execute with all flag
        result = list_func(all=True)

        # Verify all flag was passed
        mock_docker_client.client.images.list.assert_called_once_with(all=True, filters=None)
        assert result["count"] == 0

    def test_list_images_with_filters(self, mock_docker_client, safety_config):
        """Test image listing with filters."""
        mock_docker_client.client.images.list.return_value = []

        # Get the list function
        _, _, _, _, _, list_func = create_list_images_tool(mock_docker_client, safety_config)

        # Execute with filters
        filters = {"dangling": ["true"]}
        result = list_func(filters=filters)

        # Verify filters were passed
        mock_docker_client.client.images.list.assert_called_once_with(all=False, filters=filters)
        assert result["count"] == 0

    def test_list_images_with_truncation(self, mock_docker_client):
        """Test image listing with output truncation."""
        # Create safety config with limit
        safety_config = SafetyConfig(max_list_results=1)

        # Mock multiple images
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

        # Get the list function
        _, _, _, _, _, list_func = create_list_images_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify truncation
        assert result["count"] == 2  # Original count
        assert len(result["images"]) == 1  # Truncated to 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]

    def test_list_images_api_error(self, mock_docker_client, safety_config):
        """Test image listing with API error."""
        mock_docker_client.client.images.list.side_effect = APIError("List failed")

        # Get the list function
        _, _, _, _, _, list_func = create_list_images_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to list images"):
            list_func()


class TestInspectImageTool:
    """Test docker_inspect_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_inspect_image_success(self, mock_docker_client):
        """Test successful image inspection."""
        # Mock image object
        image = Mock()
        image.attrs = {
            "Id": "sha256:abc123",
            "RepoTags": ["ubuntu:22.04"],
            "Created": "2024-01-01T00:00:00Z",
            "Size": 1000,
        }

        mock_docker_client.client.images.get.return_value = image

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_image_tool(mock_docker_client)

        # Execute
        result = inspect_func(image_name="ubuntu:22.04")

        # Verify
        assert result["details"]["Id"] == "sha256:abc123"
        assert result["details"]["RepoTags"] == ["ubuntu:22.04"]
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")

    def test_inspect_image_not_found(self, mock_docker_client):
        """Test inspecting non-existent image."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            inspect_func(image_name="nonexistent")

    def test_inspect_image_not_found_generic(self, mock_docker_client):
        """Test inspecting image with generic NotFound error."""
        mock_docker_client.client.images.get.side_effect = NotFound("Image not found")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            inspect_func(image_name="nonexistent")

    def test_inspect_image_api_error(self, mock_docker_client):
        """Test image inspection with API error."""
        mock_docker_client.client.images.get.side_effect = APIError("Inspect failed")

        # Get the inspect function
        _, _, _, _, _, inspect_func = create_inspect_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to inspect image"):
            inspect_func(image_name="ubuntu:22.04")


class TestImageHistoryTool:
    """Test docker_image_history tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_image_history_success(self, mock_docker_client, safety_config):
        """Test successful image history retrieval."""
        # Mock image object
        image = Mock()
        history_data = [
            {"Id": "layer1", "Created": 1234567890, "Size": 100},
            {"Id": "layer2", "Created": 1234567891, "Size": 200},
        ]
        image.history.return_value = history_data

        mock_docker_client.client.images.get.return_value = image

        # Get the history function
        _, _, _, _, _, history_func = create_image_history_tool(mock_docker_client, safety_config)

        # Execute
        result = history_func(image="ubuntu:22.04")

        # Verify
        assert len(result["history"]) == 2
        assert result["history"][0]["Id"] == "layer1"
        assert result["history"][1]["Id"] == "layer2"
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")

    def test_image_history_with_truncation(self, mock_docker_client):
        """Test image history with output truncation."""
        # Create safety config with limit
        safety_config = SafetyConfig(max_list_results=1)

        # Mock image object
        image = Mock()
        history_data = [
            {"Id": "layer1", "Created": 1234567890, "Size": 100},
            {"Id": "layer2", "Created": 1234567891, "Size": 200},
        ]
        image.history.return_value = history_data

        mock_docker_client.client.images.get.return_value = image

        # Get the history function
        _, _, _, _, _, history_func = create_image_history_tool(mock_docker_client, safety_config)

        # Execute
        result = history_func(image="ubuntu:22.04")

        # Verify truncation
        assert len(result["history"]) == 1  # Truncated to 1
        assert result["truncation_info"]["truncated"] is True
        assert "message" in result["truncation_info"]

    def test_image_history_not_found(self, mock_docker_client, safety_config):
        """Test history of non-existent image."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        # Get the history function
        _, _, _, _, _, history_func = create_image_history_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            history_func(image="nonexistent")

    def test_image_history_api_error(self, mock_docker_client, safety_config):
        """Test image history with API error."""
        image = Mock()
        image.history.side_effect = APIError("History failed")
        mock_docker_client.client.images.get.return_value = image

        # Get the history function
        _, _, _, _, _, history_func = create_image_history_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to get image history"):
            history_func(image="ubuntu:22.04")


class TestPullImageTool:
    """Test docker_pull_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_pull_image_success(self, mock_docker_client):
        """Test successful image pull."""
        # Mock image object
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:22.04"]

        mock_docker_client.client.images.pull.return_value = image

        # Get the pull function
        _, _, _, _, _, pull_func = create_pull_image_tool(mock_docker_client)

        # Execute
        result = pull_func(image="ubuntu")

        # Verify
        assert result["image"] == "ubuntu"
        assert result["id"] == "sha256:abc123"
        assert result["tags"] == ["ubuntu:22.04"]
        mock_docker_client.client.images.pull.assert_called_once_with(repository="ubuntu")

    def test_pull_image_with_tag(self, mock_docker_client):
        """Test image pull with specific tag."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:20.04"]

        mock_docker_client.client.images.pull.return_value = image

        # Get the pull function
        _, _, _, _, _, pull_func = create_pull_image_tool(mock_docker_client)

        # Execute with tag
        result = pull_func(image="ubuntu", tag="20.04")

        # Verify tag was passed
        mock_docker_client.client.images.pull.assert_called_once_with(
            repository="ubuntu", tag="20.04"
        )
        assert result["tags"] == ["ubuntu:20.04"]

    def test_pull_image_all_tags(self, mock_docker_client):
        """Test pulling all tags."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:20.04", "ubuntu:22.04"]

        mock_docker_client.client.images.pull.return_value = image

        # Get the pull function
        _, _, _, _, _, pull_func = create_pull_image_tool(mock_docker_client)

        # Execute with all_tags
        pull_func(image="ubuntu", all_tags=True)

        # Verify all_tags was passed
        mock_docker_client.client.images.pull.assert_called_once_with(
            repository="ubuntu", all_tags=True
        )

    def test_pull_image_with_platform(self, mock_docker_client):
        """Test pulling image for specific platform."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["ubuntu:22.04"]

        mock_docker_client.client.images.pull.return_value = image

        # Get the pull function
        _, _, _, _, _, pull_func = create_pull_image_tool(mock_docker_client)

        # Execute with platform
        pull_func(image="ubuntu", platform="linux/amd64")

        # Verify platform was passed
        mock_docker_client.client.images.pull.assert_called_once_with(
            repository="ubuntu", platform="linux/amd64"
        )

    def test_pull_image_api_error(self, mock_docker_client):
        """Test image pull with API error."""
        mock_docker_client.client.images.pull.side_effect = APIError("Pull failed")

        # Get the pull function
        _, _, _, _, _, pull_func = create_pull_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to pull image"):
            pull_func(image="ubuntu")


class TestBuildImageTool:
    """Test docker_build_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_build_image_success(self, mock_docker_client):
        """Test successful image build."""
        # Mock image object and build logs
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["myapp:latest"]

        # Build logs as JSON strings (how Docker SDK actually returns them)
        build_logs = [
            '{"stream": "Step 1/2 : FROM ubuntu\\n"}\n',
            '{"stream": "Step 2/2 : RUN echo hello\\n"}\n',
        ]

        mock_docker_client.client.images.build.return_value = (image, build_logs)

        # Get the build function
        _, _, _, _, _, build_func = create_build_image_tool(mock_docker_client)

        # Execute
        result = build_func(path=".")

        # Verify
        assert result["image_id"] == "sha256:abc123"
        assert result["tags"] == ["myapp:latest"]
        assert len(result["logs"]) == 2
        mock_docker_client.client.images.build.assert_called_once()

    def test_build_image_with_tag(self, mock_docker_client):
        """Test image build with tag."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["myapp:v1.0"]

        mock_docker_client.client.images.build.return_value = (image, [])

        # Get the build function
        _, _, _, _, _, build_func = create_build_image_tool(mock_docker_client)

        # Execute with tag
        build_func(path=".", tag="myapp:v1.0")

        # Verify tag was passed
        call_kwargs = mock_docker_client.client.images.build.call_args.kwargs
        assert call_kwargs["tag"] == "myapp:v1.0"

    def test_build_image_with_buildargs(self, mock_docker_client):
        """Test image build with build arguments."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = []

        mock_docker_client.client.images.build.return_value = (image, [])

        # Get the build function
        _, _, _, _, _, build_func = create_build_image_tool(mock_docker_client)

        # Execute with buildargs
        buildargs = {"NODE_VERSION": "18", "ENV": "prod"}
        build_func(path=".", buildargs=buildargs)

        # Verify buildargs were passed
        call_kwargs = mock_docker_client.client.images.build.call_args.kwargs
        assert call_kwargs["buildargs"] == buildargs

    def test_build_image_with_all_options(self, mock_docker_client):
        """Test image build with all options."""
        image = Mock()
        image.id = "sha256:abc123"
        image.tags = ["myapp:dev"]

        mock_docker_client.client.images.build.return_value = (image, [])

        # Get the build function
        _, _, _, _, _, build_func = create_build_image_tool(mock_docker_client)

        # Execute with all options
        build_func(
            path="./app",
            tag="myapp:dev",
            dockerfile="Dockerfile.dev",
            buildargs={"VERSION": "1.0"},
            nocache=True,
            rm=False,
            pull=True,
        )

        # Verify all options were passed
        call_kwargs = mock_docker_client.client.images.build.call_args.kwargs
        assert call_kwargs["path"] == "./app"
        assert call_kwargs["tag"] == "myapp:dev"
        assert call_kwargs["dockerfile"] == "Dockerfile.dev"
        assert call_kwargs["buildargs"] == {"VERSION": "1.0"}
        assert call_kwargs["nocache"] is True
        assert call_kwargs["rm"] is False
        assert call_kwargs["pull"] is True

    def test_build_image_api_error(self, mock_docker_client):
        """Test image build with API error."""
        mock_docker_client.client.images.build.side_effect = APIError("Build failed")

        # Get the build function
        _, _, _, _, _, build_func = create_build_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to build image"):
            build_func(path=".")


class TestPushImageTool:
    """Test docker_push_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_push_image_success(self, mock_docker_client):
        """Test successful image push."""
        # Push stream as iterable of JSON strings (how Docker SDK actually returns them)
        push_stream = [
            '{"status": "Pushing"}\n',
            '{"status": "Pushed"}\n',
        ]
        mock_docker_client.client.images.push.return_value = push_stream

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute
        result = push_func(image="myrepo/myapp")

        # Verify
        assert result["image"] == "myrepo/myapp"
        assert result["status"] == "Pushed"
        mock_docker_client.client.images.push.assert_called_once_with(repository="myrepo/myapp")

    def test_push_image_with_tag(self, mock_docker_client):
        """Test pushing image with tag."""
        # Push stream as iterable of JSON strings
        push_stream = ['{"status": "Pushed"}\n']
        mock_docker_client.client.images.push.return_value = push_stream

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute with tag
        push_func(image="myrepo/myapp", tag="v1.0")

        # Verify tag was passed
        mock_docker_client.client.images.push.assert_called_once_with(
            repository="myrepo/myapp", tag="v1.0"
        )

    def test_push_image_with_error_in_stream(self, mock_docker_client):
        """Test pushing image with error in stream."""
        push_stream = '{"status": "Pushing"}\n{"error": "Authentication required"}\n'
        mock_docker_client.client.images.push.return_value = push_stream

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Authentication required"):
            push_func(image="myrepo/myapp")

    def test_push_image_no_status(self, mock_docker_client):
        """Test pushing image with no status in stream."""
        push_stream = ""
        mock_docker_client.client.images.push.return_value = push_stream

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute
        result = push_func(image="myrepo/myapp")

        # Verify default status
        assert result["status"] == "pushed"

    def test_push_image_not_found(self, mock_docker_client):
        """Test pushing non-existent image."""
        mock_docker_client.client.images.push.side_effect = DockerImageNotFound("Image not found")

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            push_func(image="nonexistent")

    def test_push_image_api_error(self, mock_docker_client):
        """Test image push with API error."""
        mock_docker_client.client.images.push.side_effect = APIError("Push failed")

        # Get the push function
        _, _, _, _, _, push_func = create_push_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to push image"):
            push_func(image="myrepo/myapp")


class TestTagImageTool:
    """Test docker_tag_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_tag_image_success(self, mock_docker_client):
        """Test successful image tagging."""
        # Mock image object
        image = Mock()
        image.tag = Mock()

        mock_docker_client.client.images.get.return_value = image

        # Get the tag function
        _, _, _, _, _, tag_func = create_tag_image_tool(mock_docker_client)

        # Execute
        result = tag_func(image="ubuntu:22.04", repository="myrepo/ubuntu")

        # Verify
        assert result["source"] == "ubuntu:22.04"
        assert result["target"] == "myrepo/ubuntu:latest"
        mock_docker_client.client.images.get.assert_called_once_with("ubuntu:22.04")
        image.tag.assert_called_once_with(repository="myrepo/ubuntu", tag="latest")

    def test_tag_image_with_custom_tag(self, mock_docker_client):
        """Test image tagging with custom tag."""
        image = Mock()
        image.tag = Mock()

        mock_docker_client.client.images.get.return_value = image

        # Get the tag function
        _, _, _, _, _, tag_func = create_tag_image_tool(mock_docker_client)

        # Execute with custom tag
        result = tag_func(image="ubuntu:22.04", repository="myrepo/ubuntu", tag="v1.0")

        # Verify custom tag
        assert result["target"] == "myrepo/ubuntu:v1.0"
        image.tag.assert_called_once_with(repository="myrepo/ubuntu", tag="v1.0")

    def test_tag_image_not_found(self, mock_docker_client):
        """Test tagging non-existent image."""
        mock_docker_client.client.images.get.side_effect = DockerImageNotFound("Image not found")

        # Get the tag function
        _, _, _, _, _, tag_func = create_tag_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            tag_func(image="nonexistent", repository="myrepo/ubuntu")

    def test_tag_image_api_error(self, mock_docker_client):
        """Test image tagging with API error."""
        image = Mock()
        image.tag.side_effect = APIError("Tag failed")

        mock_docker_client.client.images.get.return_value = image

        # Get the tag function
        _, _, _, _, _, tag_func = create_tag_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to tag image"):
            tag_func(image="ubuntu:22.04", repository="myrepo/ubuntu")


class TestRemoveImageTool:
    """Test docker_remove_image tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_remove_image_success(self, mock_docker_client):
        """Test successful image removal."""
        mock_docker_client.client.images.remove.return_value = None

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_image_tool(mock_docker_client)

        # Execute
        result = remove_func(image="ubuntu:22.04")

        # Verify
        assert result["deleted"][0]["Deleted"] == "ubuntu:22.04"
        mock_docker_client.client.images.remove.assert_called_once_with(
            image="ubuntu:22.04", force=False, noprune=False
        )

    def test_remove_image_with_force(self, mock_docker_client):
        """Test image removal with force flag."""
        mock_docker_client.client.images.remove.return_value = None

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_image_tool(mock_docker_client)

        # Execute with force
        remove_func(image="ubuntu:22.04", force=True)

        # Verify force was used
        mock_docker_client.client.images.remove.assert_called_once_with(
            image="ubuntu:22.04", force=True, noprune=False
        )

    def test_remove_image_with_noprune(self, mock_docker_client):
        """Test image removal with noprune flag."""
        mock_docker_client.client.images.remove.return_value = None

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_image_tool(mock_docker_client)

        # Execute with noprune
        remove_func(image="ubuntu:22.04", noprune=True)

        # Verify noprune was used
        mock_docker_client.client.images.remove.assert_called_once_with(
            image="ubuntu:22.04", force=False, noprune=True
        )

    def test_remove_image_not_found(self, mock_docker_client):
        """Test removing non-existent image."""
        mock_docker_client.client.images.remove.side_effect = DockerImageNotFound("Image not found")

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ImageNotFound, match="Image not found"):
            remove_func(image="nonexistent")

    def test_remove_image_api_error(self, mock_docker_client):
        """Test image removal with API error."""
        mock_docker_client.client.images.remove.side_effect = APIError("Remove failed")

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_image_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to remove image"):
            remove_func(image="ubuntu:22.04")


class TestPruneImagesTool:
    """Test docker_prune_images tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.images = Mock()
        return client

    def test_prune_images_standard(self, mock_docker_client):
        """Test standard image prune (dangling only)."""
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:abc123"}],
            "SpaceReclaimed": 5000,
        }

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute standard prune
        result = prune_func()

        # Verify
        assert len(result["deleted"]) == 1
        assert result["space_reclaimed"] == 5000
        mock_docker_client.client.images.prune.assert_called_once_with(filters=None)

    def test_prune_images_all(self, mock_docker_client):
        """Test pruning all unused images."""
        # Mock the SDK's prune call returning results
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:unused1"}],
            "SpaceReclaimed": 1500,
        }

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with all=True
        result = prune_func(all=True)

        # Verify SDK prune was used
        assert len(result["deleted"]) == 1
        assert result["space_reclaimed"] == 1500

    def test_prune_images_all_fallback_to_manual(self, mock_docker_client):
        """Test pruning all unused images with fallback to manual iteration."""
        # Mock SDK prune returning None (triggers fallback)
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": None,
            "SpaceReclaimed": 0,
        }

        # Create mock images
        image1 = Mock()
        image1.id = "sha256:unused1"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:inuse1"
        image2.attrs = {"Size": 2000}

        # Create mock container using image2
        container = Mock()
        container.image = Mock()
        container.image.id = "sha256:inuse1"

        mock_docker_client.client.images.list.return_value = [image1, image2]
        mock_docker_client.client.containers.list.return_value = [container]

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with all=True (no filters, triggers fallback)
        result = prune_func(all=True)

        # Verify only unused image was removed
        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:unused1"}
        assert result["space_reclaimed"] == 1000
        mock_docker_client.client.images.remove.assert_called_once_with(
            "sha256:unused1", force=False
        )

    def test_prune_images_all_fallback_with_removal_error(self, mock_docker_client):
        """Test manual fallback handles removal errors gracefully."""
        # Mock SDK prune returning None
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": None,
            "SpaceReclaimed": 0,
        }

        # Create mock images
        image1 = Mock()
        image1.id = "sha256:error1"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:success1"
        image2.attrs = {"Size": 2000}

        mock_docker_client.client.images.list.return_value = [image1, image2]
        mock_docker_client.client.containers.list.return_value = []

        # First removal fails, second succeeds
        def remove_side_effect(image_id, force):
            if image_id == "sha256:error1":
                raise APIError("Removal failed")

        mock_docker_client.client.images.remove.side_effect = remove_side_effect

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with all=True
        result = prune_func(all=True)

        # Should continue after first failure
        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:success1"}
        assert result["space_reclaimed"] == 2000

    def test_prune_images_with_filters(self, mock_docker_client):
        """Test pruning images with filters."""
        mock_docker_client.client.images.prune.return_value = {
            "ImagesDeleted": [],
            "SpaceReclaimed": 0,
        }

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with filters
        filters = {"until": ["24h"]}
        prune_func(filters=filters)

        # Verify filters were passed
        mock_docker_client.client.images.prune.assert_called_once_with(filters=filters)

    def test_prune_images_force_all(self, mock_docker_client):
        """Test force removing all images."""
        # Create mock images with IDs and sizes
        image1 = Mock()
        image1.id = "sha256:abc123"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:def456"
        image2.attrs = {"Size": 2000}

        image3 = Mock()
        image3.id = None  # Test skipping images without IDs

        mock_docker_client.client.images.list.return_value = [image1, image2, image3]

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with force_all=True
        result = prune_func(force_all=True)

        # Verify force removal was called for images with IDs
        assert len(result["deleted"]) == 2
        assert result["deleted"][0] == {"Deleted": "sha256:abc123"}
        assert result["deleted"][1] == {"Deleted": "sha256:def456"}
        assert result["space_reclaimed"] == 3000

        # Verify remove was called with force=True
        assert mock_docker_client.client.images.remove.call_count == 2
        mock_docker_client.client.images.remove.assert_any_call("sha256:abc123", force=True)
        mock_docker_client.client.images.remove.assert_any_call("sha256:def456", force=True)

    def test_prune_images_force_all_with_errors(self, mock_docker_client):
        """Test force removing all images with some failures."""
        # Create mock images
        image1 = Mock()
        image1.id = "sha256:abc123"
        image1.attrs = {"Size": 1000}

        image2 = Mock()
        image2.id = "sha256:def456"
        image2.attrs = {"Size": 2000}

        mock_docker_client.client.images.list.return_value = [image1, image2]

        # Make first image removal fail, second succeed
        def remove_side_effect(image_id, force):
            if image_id == "sha256:abc123":
                raise APIError("Image in use")
            # Second one succeeds (no exception)

        mock_docker_client.client.images.remove.side_effect = remove_side_effect

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute with force_all=True
        result = prune_func(force_all=True)

        # Should continue after first failure and remove second image
        assert len(result["deleted"]) == 1
        assert result["deleted"][0] == {"Deleted": "sha256:def456"}
        assert result["space_reclaimed"] == 2000

    def test_prune_images_api_error(self, mock_docker_client):
        """Test image prune with API error."""
        mock_docker_client.client.images.prune.side_effect = APIError("Prune failed")

        # Get the prune function
        _, _, _, _, _, prune_func = create_prune_images_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to prune images"):
            prune_func()
