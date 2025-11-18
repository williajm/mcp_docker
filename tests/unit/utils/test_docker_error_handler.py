"""Unit tests for utils/docker_error_handler.py."""

import pytest
from docker.errors import APIError
from docker.errors import ImageNotFound as DockerImageNotFound
from docker.errors import NotFound as DockerNotFound

from mcp_docker.utils.docker_error_handler import handle_docker_errors
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    ImageNotFound,
    NetworkNotFound,
    VolumeNotFound,
)


class TestHandleDockerErrors:
    """Test handle_docker_errors decorator."""

    @pytest.mark.asyncio
    async def test_async_container_not_found(self):
        """Test that NotFound exception is mapped to ContainerNotFound."""

        @handle_docker_errors(resource="container", operation="start")
        async def start_container(container_id: str) -> dict:
            raise DockerNotFound("Container not found")

        with pytest.raises(ContainerNotFound) as exc_info:
            await start_container("test-container")

        assert "test-container" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_image_not_found(self):
        """Test that docker ImageNotFound exception is mapped to our ImageNotFound."""

        @handle_docker_errors(resource="image", operation="inspect", resource_id_param="image_id")
        async def inspect_image(image_id: str) -> dict:
            raise DockerImageNotFound("Image not found")

        with pytest.raises(ImageNotFound) as exc_info:
            await inspect_image("test-image")

        assert "test-image" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_network_not_found(self):
        """Test that NotFound exception is mapped to NetworkNotFound."""

        @handle_docker_errors(
            resource="network", operation="remove", resource_id_param="network_id"
        )
        async def remove_network(network_id: str) -> dict:
            raise DockerNotFound("Network not found")

        with pytest.raises(NetworkNotFound) as exc_info:
            await remove_network("test-network")

        assert "test-network" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_volume_not_found(self):
        """Test that NotFound exception is mapped to VolumeNotFound."""

        @handle_docker_errors(
            resource="volume", operation="inspect", resource_id_param="volume_name"
        )
        async def inspect_volume(volume_name: str) -> dict:
            raise DockerNotFound("Volume not found")

        with pytest.raises(VolumeNotFound) as exc_info:
            await inspect_volume("test-volume")

        assert "test-volume" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_api_error(self):
        """Test that APIError is mapped to DockerOperationError."""

        @handle_docker_errors(resource="container", operation="stop")
        async def stop_container(container_id: str) -> dict:
            raise APIError("Docker daemon error")

        with pytest.raises(DockerOperationError) as exc_info:
            await stop_container("test-container")

        assert "Failed to stop container" in str(exc_info.value)
        assert "test-container" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_success(self):
        """Test that successful operations pass through unchanged."""

        @handle_docker_errors(resource="container", operation="start")
        async def start_container(container_id: str) -> dict:
            return {"status": "started", "container_id": container_id}

        result = await start_container("test-container")
        assert result == {"status": "started", "container_id": "test-container"}

    def test_sync_container_not_found(self):
        """Test synchronous function with NotFound exception."""

        @handle_docker_errors(resource="container", operation="inspect")
        def inspect_container(container_id: str) -> dict:
            raise DockerNotFound("Container not found")

        with pytest.raises(ContainerNotFound) as exc_info:
            inspect_container("test-container")

        assert "test-container" in str(exc_info.value)

    def test_sync_api_error(self):
        """Test synchronous function with APIError."""

        @handle_docker_errors(resource="image", operation="pull", resource_id_param="image_name")
        def pull_image(image_name: str) -> dict:
            raise APIError("Registry unreachable")

        with pytest.raises(DockerOperationError) as exc_info:
            pull_image("nginx:latest")

        assert "Failed to pull image" in str(exc_info.value)
        assert "nginx:latest" in str(exc_info.value)

    def test_sync_success(self):
        """Test that successful synchronous operations pass through."""

        @handle_docker_errors(
            resource="volume", operation="create", resource_id_param="volume_name"
        )
        def create_volume(volume_name: str) -> dict:
            return {"name": volume_name, "status": "created"}

        result = create_volume("test-volume")
        assert result == {"name": "test-volume", "status": "created"}

    def test_custom_resource_id_param(self):
        """Test custom resource_id_param extraction."""

        @handle_docker_errors(
            resource="image",
            operation="remove",
            resource_id_param="image_tag",
        )
        def remove_image(image_tag: str) -> dict:
            raise DockerNotFound("Image not found")

        with pytest.raises(ImageNotFound) as exc_info:
            remove_image(image_tag="my-image:v1")

        assert "my-image:v1" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resource_id_from_kwargs(self):
        """Test resource ID extraction from kwargs."""

        @handle_docker_errors(resource="container", operation="exec")
        async def exec_in_container(container_id: str, command: str) -> dict:
            raise DockerNotFound("Container not found")

        with pytest.raises(ContainerNotFound) as exc_info:
            await exec_in_container(container_id="test-container", command="ls")

        assert "test-container" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resource_id_from_positional_args(self):
        """Test resource ID extraction from positional arguments."""

        @handle_docker_errors(
            resource="network", operation="connect", resource_id_param="network_id"
        )
        async def connect_to_network(network_id: str, container_id: str) -> dict:
            raise DockerNotFound("Network not found")

        with pytest.raises(NetworkNotFound) as exc_info:
            await connect_to_network("my-network", "my-container")

        # Should extract first positional arg as network_id
        assert "my-network" in str(exc_info.value)

    def test_invalid_resource_type(self):
        """Test that invalid resource type raises ValueError."""

        with pytest.raises(ValueError) as exc_info:

            @handle_docker_errors(resource="invalid", operation="test")
            def test_func():
                pass

        assert "Unknown resource type: invalid" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_preserves_function_metadata(self):
        """Test that decorator preserves function name and docstring."""

        @handle_docker_errors(resource="container", operation="test")
        async def my_function(container_id: str) -> dict:
            """My docstring."""
            return {"result": "ok"}

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

        result = await my_function("test")
        assert result == {"result": "ok"}
