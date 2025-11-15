"""Unit tests for container tools."""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.container_inspection_tools import (
    ContainerLogsInput,
    ContainerLogsTool,
    ContainerStatsInput,
    ContainerStatsTool,
    ExecCommandInput,
    ExecCommandTool,
    InspectContainerInput,
    InspectContainerTool,
    ListContainersInput,
    ListContainersTool,
)
from mcp_docker.tools.container_lifecycle_tools import (
    CreateContainerInput,
    CreateContainerTool,
    RemoveContainerInput,
    RemoveContainerTool,
    RestartContainerInput,
    RestartContainerTool,
    StartContainerInput,
    StartContainerTool,
    StopContainerInput,
    StopContainerTool,
)
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError, ValidationError


@pytest.fixture
def mock_docker_client() -> Any:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def mock_container() -> Any:
    """Create a mock container."""
    container = MagicMock()
    container.id = "abc123def456"
    container.short_id = "abc123"
    container.name = "test_container"
    container.status = "running"
    container.labels = {"env": "test"}
    container.image = MagicMock()
    container.image.tags = ["ubuntu:latest"]
    container.attrs = {"Id": "abc123def456", "Name": "test_container"}
    return container


class TestListContainersTool:
    """Tests for ListContainersTool."""

    @pytest.mark.asyncio
    async def test_list_containers_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container listing."""
        mock_docker_client.client.containers.list.return_value = [mock_container]

        tool = ListContainersTool(mock_docker_client, safety_config)
        input_data = ListContainersInput(all=True)
        result = await tool.execute(input_data)

        assert result.count == 1
        assert len(result.containers) == 1
        assert result.containers[0]["id"] == "abc123def456"
        assert result.containers[0]["name"] == "test_container"
        mock_docker_client.client.containers.list.assert_called_once_with(all=True, filters=None)

    @pytest.mark.asyncio
    async def test_list_containers_with_filters(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test listing containers with filters."""
        mock_docker_client.client.containers.list.return_value = [mock_container]

        tool = ListContainersTool(mock_docker_client, safety_config)
        input_data = ListContainersInput(all=False, filters={"status": ["running"]})
        result = await tool.execute(input_data)

        assert result.count == 1
        mock_docker_client.client.containers.list.assert_called_once_with(
            all=False, filters={"status": ["running"]}
        )

    @pytest.mark.asyncio
    async def test_list_containers_empty(self, mock_docker_client: Any, safety_config: Any) -> None:
        """Test listing when no containers exist."""
        mock_docker_client.client.containers.list.return_value = []

        tool = ListContainersTool(mock_docker_client, safety_config)
        input_data = ListContainersInput()
        result = await tool.execute(input_data)

        assert result.count == 0
        assert len(result.containers) == 0

    @pytest.mark.asyncio
    async def test_list_containers_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.containers.list.side_effect = APIError("API error")

        tool = ListContainersTool(mock_docker_client, safety_config)
        input_data = ListContainersInput()

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_list_containers_with_truncation(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test that count field reflects total containers, not truncated count."""
        # Create 5 mock containers
        mock_containers = []
        for i in range(5):
            container = Mock()
            container.id = f"container{i}"
            container.short_id = f"cont{i}"
            container.name = f"test_container_{i}"
            container.status = "running"
            container.labels = {}
            container.image = Mock()
            container.image.tags = [f"image:tag{i}"]
            container.image.id = f"img{i}"
            mock_containers.append(container)

        mock_docker_client.client.containers.list.return_value = mock_containers

        # Set max_list_results to 3 to trigger truncation
        safety_config.max_list_results = 3

        tool = ListContainersTool(mock_docker_client, safety_config)
        input_data = ListContainersInput(all=True)
        result = await tool.execute(input_data)

        # count should reflect the total number of containers (5), not the truncated count (3)
        assert result.count == 5, "count should be the total number of containers"
        assert len(result.containers) == 3, "containers list should be truncated to 3"

        # Truncation info should be present
        assert result.truncation_info is not None
        assert result.truncation_info.get("truncated") is True
        assert result.truncation_info.get("original_count") == 5
        assert result.truncation_info.get("truncated_count") == 3
        assert "5" in result.truncation_info.get("message", "")


class TestInspectContainerTool:
    """Tests for InspectContainerTool."""

    @pytest.mark.asyncio
    async def test_inspect_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container inspection."""
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = InspectContainerTool(mock_docker_client, safety_config)
        input_data = InspectContainerInput(container_id="abc123")
        result = await tool.execute(input_data)

        assert result.details["Id"] == "abc123def456"
        assert result.details["Name"] == "test_container"
        mock_docker_client.client.containers.get.assert_called_once_with("abc123")

    @pytest.mark.asyncio
    async def test_inspect_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of container not found."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = InspectContainerTool(mock_docker_client, safety_config)
        input_data = InspectContainerInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_inspect_container_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.containers.get.side_effect = APIError("API error")

        tool = InspectContainerTool(mock_docker_client, safety_config)
        input_data = InspectContainerInput(container_id="abc123")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)


class TestCreateContainerTool:
    """Tests for CreateContainerTool."""

    @pytest.mark.asyncio
    async def test_create_container_minimal(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test creating container with minimal parameters."""
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, safety_config)
        input_data = CreateContainerInput(image="ubuntu:latest")
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.name == "test_container"
        mock_docker_client.client.containers.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_container_with_options(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test creating container with all options."""
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, safety_config)
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            name="my_container",
            command="echo hello",
            environment={"VAR": "value"},
            ports={"80/tcp": 8080},
            mem_limit="512m",
            cpu_shares=512,
        )
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        call_kwargs = mock_docker_client.client.containers.create.call_args[1]
        assert call_kwargs["image"] == "ubuntu:latest"
        assert call_kwargs["name"] == "my_container"
        assert call_kwargs["command"] == "echo hello"
        assert call_kwargs["environment"] == {"VAR": "value"}

    @pytest.mark.asyncio
    async def test_create_container_invalid_name(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test creating container with invalid name."""
        tool = CreateContainerTool(mock_docker_client, safety_config)
        input_data = CreateContainerInput(image="ubuntu:latest", name="Invalid Name!")

        # Should raise ValidationError due to invalid container name
        with pytest.raises(ValidationError):  # ValidationError from validate_container_name
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_create_container_api_error(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.containers.create.side_effect = APIError("API error")

        tool = CreateContainerTool(mock_docker_client, safety_config)
        input_data = CreateContainerInput(image="ubuntu:latest")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_create_container_blocks_dangerous_volume_mount(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test that dangerous volume mounts are blocked."""
        from mcp_docker.utils.errors import UnsafeOperationError

        tool = CreateContainerTool(mock_docker_client, safety_config)

        # Test Docker socket mount is blocked
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/var/run/docker.sock": {"bind": "/docker.sock", "mode": "rw"}},
        )
        with pytest.raises(UnsafeOperationError, match="blocked"):
            await tool.execute(input_data)

        # Test root filesystem mount is blocked
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/": {"bind": "/host_root", "mode": "rw"}},
        )
        with pytest.raises(UnsafeOperationError, match="blocked"):
            await tool.execute(input_data)

        # Test /etc mount is blocked
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/etc": {"bind": "/host_etc", "mode": "ro"}},
        )
        with pytest.raises(UnsafeOperationError, match="blocked"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_create_container_allows_safe_volume_mount(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test that safe volume mounts are allowed."""
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, safety_config)
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/home/user/data": {"bind": "/data", "mode": "ro"}},
        )
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        mock_docker_client.client.containers.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_container_allows_named_volumes(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test that Docker named volumes are allowed (standard functionality).

        Named volumes are managed by Docker and don't expose the host filesystem,
        so they're safe and should work without YOLO mode.
        """
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, safety_config)

        # Standard named volume usage
        input_data = CreateContainerInput(
            image="postgres:latest",
            volumes={"postgres-data": {"bind": "/var/lib/postgresql/data", "mode": "rw"}},
        )
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        mock_docker_client.client.containers.create.assert_called_once()

        # Verify named volume was passed to Docker API
        call_kwargs = mock_docker_client.client.containers.create.call_args[1]
        assert "postgres-data" in call_kwargs["volumes"]

    @pytest.mark.asyncio
    async def test_create_container_allows_multiple_named_volumes(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test that multiple named volumes can be used together."""
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, safety_config)

        # Multiple named volumes
        input_data = CreateContainerInput(
            image="wordpress:latest",
            volumes={
                "wp-content": {"bind": "/var/www/html/wp-content", "mode": "rw"},
                "wp-uploads": {"bind": "/var/www/html/wp-content/uploads", "mode": "rw"},
                "mysql-data": {"bind": "/var/lib/mysql", "mode": "rw"},
            },
        )
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        call_kwargs = mock_docker_client.client.containers.create.call_args[1]
        assert "wp-content" in call_kwargs["volumes"]
        assert "wp-uploads" in call_kwargs["volumes"]
        assert "mysql-data" in call_kwargs["volumes"]

    @pytest.mark.asyncio
    async def test_create_container_yolo_mode_allows_dangerous_mounts(
        self, mock_docker_client: Any, mock_container: Any
    ) -> None:
        """Test that YOLO mode allows dangerous volume mounts."""
        from mcp_docker.config import SafetyConfig

        # Create safety config with YOLO mode enabled
        yolo_config = SafetyConfig(yolo_mode=True)
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, yolo_config)

        # Docker socket mount should be allowed in YOLO mode
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/var/run/docker.sock": {"bind": "/docker.sock", "mode": "rw"}},
        )
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        mock_docker_client.client.containers.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_container_rejects_invalid_bind_config_non_dict(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test that non-dict bind config is rejected."""
        from mcp_docker.utils.errors import ValidationError

        tool = CreateContainerTool(mock_docker_client, safety_config)

        # Use a string instead of dict for bind config (invalid)
        # Note: We need to bypass Pydantic validation to test this, so we'll
        # construct the volumes dict directly
        input_data = CreateContainerInput(image="ubuntu:latest")
        # Manually set invalid volumes after Pydantic validation
        input_data.volumes = {"/home/user/data": "invalid_bind_config"}  # type: ignore

        with pytest.raises(ValidationError, match="Volume bind config must be a dict"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_create_container_rejects_bind_config_missing_bind_key(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test that bind config without 'bind' key is rejected."""
        from mcp_docker.utils.errors import ValidationError

        tool = CreateContainerTool(mock_docker_client, safety_config)

        # Bind config missing required 'bind' key
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/home/user/data": {"mode": "rw"}},  # Missing 'bind' key
        )

        with pytest.raises(ValidationError, match="Volume bind config must contain 'bind' key"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_create_container_yolo_mode_skips_bind_config_validation(
        self, mock_docker_client: Any, mock_container: Any
    ) -> None:
        """Test that YOLO mode skips bind config validation."""
        from mcp_docker.config import SafetyConfig

        # Create safety config with YOLO mode enabled
        yolo_config = SafetyConfig(yolo_mode=True)
        mock_docker_client.client.containers.create.return_value = mock_container

        tool = CreateContainerTool(mock_docker_client, yolo_config)

        # Invalid bind config should be allowed in YOLO mode
        input_data = CreateContainerInput(
            image="ubuntu:latest",
            volumes={"/home/user/data": {"mode": "rw"}},  # Missing 'bind' key
        )
        result = await tool.execute(input_data)

        # Should succeed in YOLO mode (no validation)
        assert result.container_id == "abc123def456"
        mock_docker_client.client.containers.create.assert_called_once()


class TestStartContainerTool:
    """Tests for StartContainerTool."""

    @pytest.mark.asyncio
    async def test_start_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container start."""
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_container.status = "exited"  # Container is stopped
        # Simulate container becoming running after start() and reload()
        mock_container.reload.side_effect = lambda: setattr(mock_container, "status", "running")

        tool = StartContainerTool(mock_docker_client, safety_config)
        input_data = StartContainerInput(container_id="abc123")
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.status == "running"
        mock_container.start.assert_called_once()
        mock_container.reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test starting non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = StartContainerTool(mock_docker_client, safety_config)
        input_data = StartContainerInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_start_container_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test handling of API errors."""
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_container.status = "exited"  # Container is stopped
        mock_container.start.side_effect = APIError("API error")

        tool = StartContainerTool(mock_docker_client, safety_config)
        input_data = StartContainerInput(container_id="abc123")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_start_container_already_running_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test idempotent behavior when container already running."""
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_container.status = "running"  # Container already running

        tool = StartContainerTool(mock_docker_client, safety_config)
        input_data = StartContainerInput(container_id="abc123")
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.status == "running"
        # Verify start was NOT called (idempotent check)
        mock_container.start.assert_not_called()
        mock_container.reload.assert_not_called()


class TestStopContainerTool:
    """Tests for StopContainerTool."""

    @pytest.mark.asyncio
    async def test_stop_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container stop."""
        mock_container.status = "running"  # Container is running
        # Simulate container becoming stopped after stop() and reload()
        mock_container.reload.side_effect = lambda: setattr(mock_container, "status", "exited")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = StopContainerTool(mock_docker_client, safety_config)
        input_data = StopContainerInput(container_id="abc123", timeout=10)
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.status == "exited"
        mock_container.stop.assert_called_once_with(timeout=10)
        mock_container.reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_container_custom_timeout(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test stopping container with custom timeout."""
        mock_container.status = "running"  # Container is running
        # Simulate container becoming stopped after stop() and reload()
        mock_container.reload.side_effect = lambda: setattr(mock_container, "status", "exited")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = StopContainerTool(mock_docker_client, safety_config)
        input_data = StopContainerInput(container_id="abc123", timeout=30)
        await tool.execute(input_data)

        mock_container.stop.assert_called_once_with(timeout=30)

    @pytest.mark.asyncio
    async def test_stop_container_already_stopped_idempotent(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test idempotent behavior when container already stopped."""
        mock_container.status = "exited"  # Container already stopped
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = StopContainerTool(mock_docker_client, safety_config)
        input_data = StopContainerInput(container_id="abc123", timeout=10)
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.status == "exited"
        # Verify stop was NOT called (idempotent check)
        mock_container.stop.assert_not_called()
        mock_container.reload.assert_not_called()

    @pytest.mark.asyncio
    async def test_stop_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test stopping non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = StopContainerTool(mock_docker_client, safety_config)
        input_data = StopContainerInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)


class TestRestartContainerTool:
    """Tests for RestartContainerTool."""

    @pytest.mark.asyncio
    async def test_restart_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container restart."""
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = RestartContainerTool(mock_docker_client, safety_config)
        input_data = RestartContainerInput(container_id="abc123", timeout=10)
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.status == "running"
        mock_container.restart.assert_called_once_with(timeout=10)
        mock_container.reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test restarting non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = RestartContainerTool(mock_docker_client, safety_config)
        input_data = RestartContainerInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)


class TestRemoveContainerTool:
    """Tests for RemoveContainerTool."""

    @pytest.mark.asyncio
    async def test_remove_container_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful container removal."""
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = RemoveContainerTool(mock_docker_client, safety_config)
        input_data = RemoveContainerInput(container_id="abc123")
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert result.removed_volumes is False
        mock_container.remove.assert_called_once_with(force=False, v=False)

    @pytest.mark.asyncio
    async def test_remove_container_with_force(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test force removing a running container."""
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = RemoveContainerTool(mock_docker_client, safety_config)
        input_data = RemoveContainerInput(container_id="abc123", force=True, volumes=True)
        result = await tool.execute(input_data)

        assert result.removed_volumes is True
        mock_container.remove.assert_called_once_with(force=True, v=True)

    @pytest.mark.asyncio
    async def test_remove_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test removing non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = RemoveContainerTool(mock_docker_client, safety_config)
        input_data = RemoveContainerInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)


class TestContainerLogsTool:
    """Tests for ContainerLogsTool."""

    @pytest.mark.asyncio
    async def test_get_logs_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful log retrieval."""
        mock_container.logs.return_value = b"log line 1\nlog line 2\n"
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="abc123", tail=10)
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert "log line 1" in result.logs
        assert "log line 2" in result.logs
        mock_container.logs.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_logs_with_timestamps(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test log retrieval with timestamps."""
        mock_container.logs.return_value = b"2024-01-01 log line\n"
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="abc123", timestamps=True)
        result = await tool.execute(input_data)

        assert "2024-01-01" in result.logs
        call_kwargs = mock_container.logs.call_args[1]
        assert call_kwargs["timestamps"] is True

    @pytest.mark.asyncio
    async def test_get_logs_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test log retrieval for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_get_logs_with_follow_mode(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test log retrieval with follow mode (generator)."""

        # Mock follow mode returns a generator
        def log_generator() -> Generator[bytes, None, None]:
            yield b"log line 1\n"
            yield b"log line 2\n"
            yield b"log line 3\n"

        mock_container.logs.return_value = log_generator()
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="abc123", follow=True, tail=10)
        result = await tool.execute(input_data)

        # Should collect all lines from generator
        assert "log line 1" in result.logs
        assert "log line 2" in result.logs
        assert "log line 3" in result.logs
        assert result.container_id == "abc123def456"
        call_kwargs = mock_container.logs.call_args[1]
        assert call_kwargs["follow"] is True

    @pytest.mark.asyncio
    async def test_get_logs_follow_mode_max_lines(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test log retrieval with follow mode hitting max line limit."""

        # Create a generator that yields more than max_lines (10000)
        def large_log_generator() -> Generator[bytes, None, None]:
            for i in range(15000):
                yield f"log line {i}\n".encode()

        mock_container.logs.return_value = large_log_generator()
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="abc123", follow=True)
        result = await tool.execute(input_data)

        # Should stop at max_lines (10000)
        assert "log line 0" in result.logs
        assert "log line 9999" in result.logs
        # Should not include lines beyond max_lines
        assert "log line 10000" not in result.logs
        assert result.container_id == "abc123def456"

    @pytest.mark.asyncio
    async def test_get_logs_follow_mode_error(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test log retrieval with follow mode when generator raises error."""

        # Create a generator that raises an error
        def failing_generator() -> Generator[bytes, None, None]:
            yield b"log line 1\n"
            raise RuntimeError("Generator error")

        mock_container.logs.return_value = failing_generator()
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerLogsTool(mock_docker_client, safety_config)
        input_data = ContainerLogsInput(container_id="abc123", follow=True)
        result = await tool.execute(input_data)

        # Should return error message
        assert "Error collecting logs" in result.logs
        assert "Generator error" in result.logs
        assert result.container_id == "abc123def456"


class TestExecCommandTool:
    """Tests for ExecCommandTool."""

    @pytest.mark.asyncio
    async def test_exec_command_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful command execution."""
        mock_container.exec_run.return_value = (0, b"command output")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(container_id="abc123", command="echo hello")
        result = await tool.execute(input_data)

        assert result.exit_code == 0
        assert result.output == "command output"
        mock_container.exec_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_exec_command_with_options(
        self, mock_docker_client: Any, mock_container: Any
    ) -> None:
        """Test command execution with additional options."""
        from mcp_docker.config import SafetyConfig

        # Create config that allows privileged containers for this test
        safety_config = SafetyConfig(allow_privileged_containers=True)

        mock_container.exec_run.return_value = (0, b"output")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(
            container_id="abc123",
            command="ls",
            workdir="/app",
            user="www-data",
            environment={"VAR": "value"},
            privileged=True,
        )
        result = await tool.execute(input_data)

        assert result.exit_code == 0
        call_kwargs = mock_container.exec_run.call_args[1]
        assert call_kwargs["workdir"] == "/app"
        assert call_kwargs["user"] == "www-data"
        assert call_kwargs["privileged"] is True

    @pytest.mark.asyncio
    async def test_exec_command_non_zero_exit(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test command execution with non-zero exit code."""
        mock_container.exec_run.return_value = (1, b"error output")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(container_id="abc123", command="false")
        result = await tool.execute(input_data)

        assert result.exit_code == 1
        assert result.output == "error output"

    @pytest.mark.asyncio
    async def test_exec_command_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test command execution on non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(container_id="nonexistent", command="echo test")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_exec_command_privileged_blocked_when_not_allowed(
        self, mock_docker_client: Any, mock_container: Any
    ) -> None:
        """Test that privileged exec is blocked when not allowed by config."""
        from mcp_docker.config import SafetyConfig
        from mcp_docker.utils.errors import UnsafeOperationError

        # Create config that disallows privileged containers
        safety_config = SafetyConfig(allow_privileged_containers=False)

        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(container_id="abc123", command="ls", privileged=True)

        # Should raise UnsafeOperationError
        with pytest.raises(UnsafeOperationError, match="Privileged containers are not allowed"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_exec_command_privileged_allowed_in_yolo_mode(
        self, mock_docker_client: Any, mock_container: Any
    ) -> None:
        """Test that YOLO mode bypasses privileged exec restrictions."""
        from mcp_docker.config import SafetyConfig

        # Create config with YOLO mode enabled but privileged containers disabled
        safety_config = SafetyConfig(yolo_mode=True, allow_privileged_containers=False)

        mock_container.exec_run.return_value = (0, b"privileged output")
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ExecCommandTool(mock_docker_client, safety_config)
        input_data = ExecCommandInput(container_id="abc123", command="ls", privileged=True)

        # Should succeed in YOLO mode despite allow_privileged_containers=False
        result = await tool.execute(input_data)
        assert result.exit_code == 0
        assert result.output == "privileged output"


class TestContainerStatsTool:
    """Tests for ContainerStatsTool."""

    @pytest.mark.asyncio
    async def test_get_stats_success(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test successful stats retrieval."""
        stats_data = {
            "cpu_stats": {"cpu_usage": {"total_usage": 1000000}},
            "memory_stats": {"usage": 52428800},
        }
        # When stream=False, Docker returns dict directly (not an iterator)
        mock_container.stats.return_value = stats_data
        mock_docker_client.client.containers.get.return_value = mock_container

        tool = ContainerStatsTool(mock_docker_client, safety_config)
        input_data = ContainerStatsInput(container_id="abc123", stream=False)
        result = await tool.execute(input_data)

        assert result.container_id == "abc123def456"
        assert "cpu_stats" in result.stats
        assert "memory_stats" in result.stats
        mock_container.stats.assert_called_once_with(stream=False)

    @pytest.mark.asyncio
    async def test_get_stats_container_not_found(
        self, mock_docker_client: Any, safety_config: Any
    ) -> None:
        """Test stats retrieval for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        tool = ContainerStatsTool(mock_docker_client, safety_config)
        input_data = ContainerStatsInput(container_id="nonexistent")

        with pytest.raises(ContainerNotFound):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_get_stats_api_error(
        self, mock_docker_client: Any, safety_config: Any, mock_container: Any
    ) -> None:
        """Test handling of API errors during stats retrieval."""
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_container.stats.side_effect = APIError("API error")

        tool = ContainerStatsTool(mock_docker_client, safety_config)
        input_data = ContainerStatsInput(container_id="abc123")

        with pytest.raises(DockerOperationError):
            await tool.execute(input_data)
