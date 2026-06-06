"""Unit tests exercising the execution paths of the slim tool surface.

These complement ``test_fastmcp_tools_slim.py`` (which only checks metadata) by
calling each tool's ``func`` with a mocked Docker client, covering both the
success path and the documented error-handling branches.
"""

from typing import Any
from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound
from docker.errors import ImageNotFound as DockerImageNotFound

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools import container_inspection
from mcp_docker.tools.container_inspection import (
    create_container_logs_tool,
    create_container_stats_tool,
    create_inspect_container_tool,
    create_list_containers_tool,
)
from mcp_docker.tools.container_lifecycle import (
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)
from mcp_docker.tools.image import create_inspect_image_tool, create_list_images_tool
from mcp_docker.tools.network import create_list_networks_tool
from mcp_docker.tools.system import create_version_tool
from mcp_docker.tools.volume import create_list_volumes_tool
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    ImageNotFound,
)


@pytest.fixture
def mock_docker_client() -> Mock:
    """Create a mock Docker client wrapper."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    return client


def _make_container(**attrs: Any) -> Mock:
    """Build a mock container with sensible defaults."""
    container = Mock()
    container.id = attrs.get("id", "abc123def456")
    container.short_id = attrs.get("short_id", "abc123")
    container.name = attrs.get("name", "test-container")
    container.status = attrs.get("status", "running")
    container.labels = attrs.get("labels", {})
    return container


# ---------------------------------------------------------------------------
# container_inspection: list_containers
# ---------------------------------------------------------------------------


def test_list_containers_success(mock_docker_client: Mock) -> None:
    """list_containers returns mapped container info (image with tag)."""
    container = _make_container()
    container.image = Mock()
    container.image.tags = ["nginx:latest"]
    mock_docker_client.client.containers.list.return_value = [container]

    spec = create_list_containers_tool(mock_docker_client)
    result = spec.func(all=True, filters={"status": "running"})

    assert result["count"] == 1
    assert result["containers"][0]["image"] == "nginx:latest"
    assert result["containers"][0]["name"] == "test-container"
    mock_docker_client.client.containers.list.assert_called_once_with(
        all=True, filters={"status": "running"}
    )


def test_list_containers_image_without_tags(mock_docker_client: Mock) -> None:
    """Falls back to image id when the image has no tags."""
    container = _make_container()
    container.image = Mock()
    container.image.tags = []
    container.image.id = "sha256:deadbeef"
    mock_docker_client.client.containers.list.return_value = [container]

    result = create_list_containers_tool(mock_docker_client).func()

    assert result["containers"][0]["image"] == "sha256:deadbeef"


def test_list_containers_no_image(mock_docker_client: Mock) -> None:
    """Reports 'unknown' when the container has no image."""
    container = _make_container()
    container.image = None
    mock_docker_client.client.containers.list.return_value = [container]

    result = create_list_containers_tool(mock_docker_client).func()

    assert result["containers"][0]["image"] == "unknown"


def test_list_containers_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.containers.list.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_list_containers_tool(mock_docker_client).func()


# ---------------------------------------------------------------------------
# container_inspection: inspect_container
# ---------------------------------------------------------------------------


def test_inspect_container_success(mock_docker_client: Mock) -> None:
    """inspect_container returns the container attrs."""
    container = _make_container()
    container.attrs = {"Id": "abc123def456", "State": {"Status": "running"}}
    mock_docker_client.client.containers.get.return_value = container

    result = create_inspect_container_tool(mock_docker_client).func("abc123")

    assert result["container_info"]["Id"] == "abc123def456"


def test_inspect_container_not_found(mock_docker_client: Mock) -> None:
    """NotFound is translated to ContainerNotFound."""
    mock_docker_client.client.containers.get.side_effect = NotFound("missing")

    with pytest.raises(ContainerNotFound):
        create_inspect_container_tool(mock_docker_client).func("nope")


def test_inspect_container_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.containers.get.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_inspect_container_tool(mock_docker_client).func("abc123")


# ---------------------------------------------------------------------------
# container_inspection: container_logs
# ---------------------------------------------------------------------------


def test_container_logs_static_bytes(mock_docker_client: Mock) -> None:
    """Static-mode logs (bytes) are decoded and kwargs are built correctly."""
    container = _make_container()
    container.logs.return_value = b"hello logs"
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_logs_tool(mock_docker_client).func(
        "abc123", tail=100, since="2024-01-01", until="2024-01-02", timestamps=True
    )

    assert result["logs"] == "hello logs"
    assert result["container_id"] == "abc123def456"
    kwargs = container.logs.call_args.kwargs
    assert kwargs["tail"] == 100
    assert kwargs["since"] == "2024-01-01"
    assert kwargs["until"] == "2024-01-02"
    assert kwargs["timestamps"] is True


def test_container_logs_follow_streaming(mock_docker_client: Mock) -> None:
    """Follow mode collects from the stream and closes the generator."""
    stream = Mock()
    stream.__iter__ = Mock(return_value=iter([b"line1\n", b"line2\n"]))
    container = _make_container()
    container.logs.return_value = stream
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_logs_tool(mock_docker_client).func("abc123", follow=True)

    assert result["logs"] == "line1\nline2\n"
    stream.close.assert_called_once()


def test_container_logs_follow_hits_line_limit(
    mock_docker_client: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Streaming collection stops at MAX_STREAMING_LOG_LINES."""
    monkeypatch.setattr(container_inspection, "MAX_STREAMING_LOG_LINES", 2)
    container = _make_container()
    container.logs.return_value = iter([b"a\n", b"b\n", b"c\n"])
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_logs_tool(mock_docker_client).func("abc123", follow=True)

    assert result["logs"] == "a\nb\n"


def test_container_logs_follow_collection_error(mock_docker_client: Mock) -> None:
    """An error mid-stream returns an error string rather than raising."""

    def _boom() -> Any:
        yield b"line1\n"
        raise RuntimeError("stream broke")

    container = _make_container()
    container.logs.return_value = _boom()
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_logs_tool(mock_docker_client).func("abc123", follow=True)

    assert result["logs"].startswith("Error collecting logs:")


def test_container_logs_not_found(mock_docker_client: Mock) -> None:
    """NotFound is translated to ContainerNotFound."""
    mock_docker_client.client.containers.get.side_effect = NotFound("missing")

    with pytest.raises(ContainerNotFound):
        create_container_logs_tool(mock_docker_client).func("nope")


def test_container_logs_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    container = _make_container()
    container.logs.side_effect = APIError("boom")
    mock_docker_client.client.containers.get.return_value = container

    with pytest.raises(DockerOperationError):
        create_container_logs_tool(mock_docker_client).func("abc123")


# ---------------------------------------------------------------------------
# container_inspection: container_stats
# ---------------------------------------------------------------------------


def test_container_stats_no_stream_dict(mock_docker_client: Mock) -> None:
    """stream=False returns the dict snapshot directly."""
    container = _make_container()
    container.stats.return_value = {"cpu_stats": {}}
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_stats_tool(mock_docker_client).func("abc123", stream=False)

    assert result["stats"] == {"cpu_stats": {}}
    assert result["container_id"] == "abc123def456"


def test_container_stats_no_stream_iterable(mock_docker_client: Mock) -> None:
    """stream=False that yields an iterable falls back to the first item."""
    container = _make_container()
    container.stats.return_value = iter([{"mem": 1}])
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_stats_tool(mock_docker_client).func("abc123", stream=False)

    assert result["stats"] == {"mem": 1}


def test_container_stats_stream(mock_docker_client: Mock) -> None:
    """stream=True reads the first snapshot then closes the generator."""
    gen = Mock()
    gen.__iter__ = Mock(return_value=iter([{"snapshot": 1}]))
    container = _make_container()
    container.stats.return_value = gen
    mock_docker_client.client.containers.get.return_value = container

    result = create_container_stats_tool(mock_docker_client).func("abc123", stream=True)

    assert result["stats"] == {"snapshot": 1}
    gen.close.assert_called_once()


def test_container_stats_not_found(mock_docker_client: Mock) -> None:
    """NotFound is translated to ContainerNotFound."""
    mock_docker_client.client.containers.get.side_effect = NotFound("missing")

    with pytest.raises(ContainerNotFound):
        create_container_stats_tool(mock_docker_client).func("nope")


def test_container_stats_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    container = _make_container()
    container.stats.side_effect = APIError("boom")
    mock_docker_client.client.containers.get.return_value = container

    with pytest.raises(DockerOperationError):
        create_container_stats_tool(mock_docker_client).func("abc123")


# ---------------------------------------------------------------------------
# container_lifecycle: start / stop / restart
# ---------------------------------------------------------------------------


def test_start_container_success(mock_docker_client: Mock) -> None:
    """A stopped container is started and the new status returned."""
    container = _make_container(status="exited")
    mock_docker_client.client.containers.get.return_value = container

    result = create_start_container_tool(mock_docker_client).func("abc123")

    container.start.assert_called_once()
    assert result["container_id"] == "abc123def456"


def test_start_container_already_running(mock_docker_client: Mock) -> None:
    """An already-running container short-circuits without calling start()."""
    container = _make_container(status="running")
    mock_docker_client.client.containers.get.return_value = container

    result = create_start_container_tool(mock_docker_client).func("abc123")

    container.start.assert_not_called()
    assert result["status"] == "running"


def test_start_container_not_found(mock_docker_client: Mock) -> None:
    """NotFound is translated to ContainerNotFound."""
    mock_docker_client.client.containers.get.side_effect = NotFound("missing")

    with pytest.raises(ContainerNotFound):
        create_start_container_tool(mock_docker_client).func("nope")


def test_start_container_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.containers.get.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_start_container_tool(mock_docker_client).func("abc123")


def test_stop_container_success(mock_docker_client: Mock) -> None:
    """A running container is stopped with the requested timeout."""
    container = _make_container(status="running")
    mock_docker_client.client.containers.get.return_value = container

    result = create_stop_container_tool(mock_docker_client).func("abc123", timeout=5)

    container.stop.assert_called_once_with(timeout=5)
    assert result["container_id"] == "abc123def456"


def test_stop_container_already_stopped(mock_docker_client: Mock) -> None:
    """An already-exited container short-circuits without calling stop()."""
    container = _make_container(status="exited")
    mock_docker_client.client.containers.get.return_value = container

    result = create_stop_container_tool(mock_docker_client).func("abc123")

    container.stop.assert_not_called()
    assert result["status"] == "exited"


def test_restart_container_success(mock_docker_client: Mock) -> None:
    """Restart always calls restart() with the timeout."""
    container = _make_container(status="running")
    mock_docker_client.client.containers.get.return_value = container

    result = create_restart_container_tool(mock_docker_client).func("abc123", timeout=3)

    container.restart.assert_called_once_with(timeout=3)
    assert result["container_id"] == "abc123def456"


def test_restart_container_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.containers.get.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_restart_container_tool(mock_docker_client).func("abc123")


# ---------------------------------------------------------------------------
# image: list_images / inspect_image
# ---------------------------------------------------------------------------


def test_list_images_success(mock_docker_client: Mock) -> None:
    """list_images maps image info including size from attrs."""
    image = Mock()
    image.id = "sha256:abc"
    image.short_id = "sha256:ab"
    image.tags = ["nginx:latest"]
    image.labels = {"maintainer": "nginx"}
    image.attrs = {"Size": 12345}
    mock_docker_client.client.images.list.return_value = [image]

    result = create_list_images_tool(mock_docker_client).func(all=True)

    assert result["count"] == 1
    assert result["images"][0]["tags"] == ["nginx:latest"]
    assert result["images"][0]["size"] == 12345


def test_list_images_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.images.list.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_list_images_tool(mock_docker_client).func()


def test_inspect_image_success(mock_docker_client: Mock) -> None:
    """inspect_image returns the image attrs."""
    image = Mock()
    image.attrs = {"Id": "sha256:abc", "Os": "linux"}
    mock_docker_client.client.images.get.return_value = image

    result = create_inspect_image_tool(mock_docker_client).func("nginx:latest")

    assert result["details"]["Id"] == "sha256:abc"


def test_inspect_image_not_found(mock_docker_client: Mock) -> None:
    """ImageNotFound from the SDK is translated to our ImageNotFound."""
    mock_docker_client.client.images.get.side_effect = DockerImageNotFound("missing")

    with pytest.raises(ImageNotFound):
        create_inspect_image_tool(mock_docker_client).func("nope")


def test_inspect_image_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.images.get.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_inspect_image_tool(mock_docker_client).func("nginx:latest")


# ---------------------------------------------------------------------------
# network: list_networks
# ---------------------------------------------------------------------------


def test_list_networks_success(mock_docker_client: Mock) -> None:
    """list_networks maps network info from attrs."""
    network = Mock()
    network.id = "net123"
    network.short_id = "net12"
    network.name = "bridge"
    network.attrs = {"Driver": "bridge", "Scope": "local", "Labels": {}}
    mock_docker_client.client.networks.list.return_value = [network]

    result = create_list_networks_tool(mock_docker_client).func()

    assert result["count"] == 1
    assert result["networks"][0]["name"] == "bridge"
    assert result["networks"][0]["driver"] == "bridge"


def test_list_networks_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.networks.list.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_list_networks_tool(mock_docker_client).func()


# ---------------------------------------------------------------------------
# volume: list_volumes
# ---------------------------------------------------------------------------


def test_list_volumes_success(mock_docker_client: Mock) -> None:
    """list_volumes maps volume info from attrs."""
    volume = Mock()
    volume.name = "data"
    volume.attrs = {
        "Driver": "local",
        "Mountpoint": "/var/lib/docker/volumes/data/_data",
        "Labels": {},
        "Scope": "local",
    }
    mock_docker_client.client.volumes.list.return_value = [volume]

    result = create_list_volumes_tool(mock_docker_client).func()

    assert result["count"] == 1
    assert result["volumes"][0]["name"] == "data"
    assert result["volumes"][0]["driver"] == "local"


def test_list_volumes_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.volumes.list.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_list_volumes_tool(mock_docker_client).func()


# ---------------------------------------------------------------------------
# system: version
# ---------------------------------------------------------------------------


def test_version_success(mock_docker_client: Mock) -> None:
    """version maps the Docker version payload into the output model."""
    mock_docker_client.client.version.return_value = {
        "Version": "24.0.7",
        "ApiVersion": "1.43",
        "Platform": {"Name": "Docker Engine"},
        "Os": "linux",
        "Arch": "amd64",
        "KernelVersion": "6.6.0",
        "Components": [{"Name": "Engine"}],
    }

    result = create_version_tool(mock_docker_client).func()

    assert result["version"] == "24.0.7"
    assert result["api_version"] == "1.43"
    assert result["platform"]["os"] == "linux"
    assert result["components"] == [{"Name": "Engine"}]


def test_version_defaults_when_missing(mock_docker_client: Mock) -> None:
    """Missing fields fall back to 'unknown'."""
    mock_docker_client.client.version.return_value = {}

    result = create_version_tool(mock_docker_client).func()

    assert result["version"] == "unknown"
    assert result["platform"]["name"] == "unknown"


def test_version_api_error(mock_docker_client: Mock) -> None:
    """API errors are wrapped in DockerOperationError."""
    mock_docker_client.client.version.side_effect = APIError("boom")

    with pytest.raises(DockerOperationError):
        create_version_tool(mock_docker_client).func()
