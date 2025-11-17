"""Unit tests for fastmcp_tools/container_inspection.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.container_inspection import (
    ContainerLogsInput,
    ContainerLogsOutput,
    ContainerStatsInput,
    ContainerStatsOutput,
    ExecCommandInput,
    ExecCommandOutput,
    InspectContainerInput,
    InspectContainerOutput,
    ListContainersInput,
    ListContainersOutput,
    create_container_logs_tool,
    create_container_stats_tool,
    create_exec_command_tool,
    create_inspect_container_tool,
    create_list_containers_tool,
)
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError
from mcp_docker.utils.safety import OperationSafety


class TestInputOutputModels:
    """Test Pydantic input/output models."""

    def test_list_containers_input_defaults(self):
        """Test ListContainersInput default values."""
        input_model = ListContainersInput()
        assert input_model.all is False
        assert input_model.filters is None

    def test_list_containers_input_with_filters(self):
        """Test ListContainersInput with filters."""
        filters = {"status": ["running"], "label": ["env=prod"]}
        input_model = ListContainersInput(all=True, filters=filters)
        assert input_model.all is True
        assert input_model.filters == filters

    def test_list_containers_output_structure(self):
        """Test ListContainersOutput structure."""
        output = ListContainersOutput(containers=[{"id": "abc123"}], count=1)
        assert output.containers == [{"id": "abc123"}]
        assert output.count == 1
        assert output.truncation_info == {}

    def test_inspect_container_input_validation(self):
        """Test InspectContainerInput validation."""
        input_model = InspectContainerInput(container_id="test-container")
        assert input_model.container_id == "test-container"

    def test_inspect_container_output_structure(self):
        """Test InspectContainerOutput structure."""
        info = {"Id": "abc123", "State": {"Status": "running"}}
        output = InspectContainerOutput(container_info=info)
        assert output.container_info == info
        assert output.truncation_info == {}

    def test_container_logs_input_defaults(self):
        """Test ContainerLogsInput default values."""
        input_model = ContainerLogsInput(container_id="test")
        assert input_model.container_id == "test"
        assert input_model.tail == "all"
        assert input_model.since is None
        assert input_model.until is None
        assert input_model.timestamps is False
        assert input_model.follow is False

    def test_container_logs_input_with_params(self):
        """Test ContainerLogsInput with all parameters."""
        input_model = ContainerLogsInput(
            container_id="test",
            tail=100,
            since="1h",
            until="2024-01-01",
            timestamps=True,
            follow=True,
        )
        assert input_model.tail == 100
        assert input_model.since == "1h"
        assert input_model.until == "2024-01-01"
        assert input_model.timestamps is True
        assert input_model.follow is True

    def test_container_logs_output_structure(self):
        """Test ContainerLogsOutput structure."""
        output = ContainerLogsOutput(logs="test logs", container_id="abc123")
        assert output.logs == "test logs"
        assert output.container_id == "abc123"
        assert output.truncation_info == {}

    def test_container_stats_input_validation(self):
        """Test ContainerStatsInput validation."""
        input_model = ContainerStatsInput(container_id="test", stream=False)
        assert input_model.container_id == "test"
        assert input_model.stream is False

    def test_container_stats_output_structure(self):
        """Test ContainerStatsOutput structure."""
        stats = {"cpu_stats": {}, "memory_stats": {}}
        output = ContainerStatsOutput(stats=stats, container_id="abc123")
        assert output.stats == stats
        assert output.container_id == "abc123"

    def test_exec_command_input_validation(self):
        """Test ExecCommandInput validation."""
        input_model = ExecCommandInput(container_id="test", command=["ls", "-la"])
        assert input_model.container_id == "test"
        assert input_model.command == ["ls", "-la"]
        assert input_model.workdir is None
        assert input_model.user is None
        assert input_model.environment is None
        assert input_model.privileged is False

    def test_exec_command_input_with_options(self):
        """Test ExecCommandInput with all options."""
        input_model = ExecCommandInput(
            container_id="test",
            command=["pwd"],
            workdir="/app",
            user="root",
            environment={"FOO": "bar"},
            privileged=True,
        )
        assert input_model.workdir == "/app"
        assert input_model.user == "root"
        assert input_model.environment == {"FOO": "bar"}
        assert input_model.privileged is True

    def test_exec_command_output_structure(self):
        """Test ExecCommandOutput structure."""
        output = ExecCommandOutput(exit_code=0, output="success")
        assert output.exit_code == 0
        assert output.output == "success"
        assert output.truncation_info == {}


class TestToolMetadata:
    """Test tool metadata and registration."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_list_containers_tool_metadata(self, mock_docker_client, safety_config):
        """Test docker_list_containers tool metadata."""
        name, description, safety_level, idempotent, open_world, func = create_list_containers_tool(
            mock_docker_client, safety_config
        )

        assert name == "docker_list_containers"
        assert "List Docker containers" in description
        assert safety_level == OperationSafety.SAFE
        assert idempotent is True
        assert open_world is False
        assert callable(func)

    def test_inspect_container_tool_metadata(self, mock_docker_client, safety_config):
        """Test docker_inspect_container tool metadata."""
        name, description, safety_level, idempotent, open_world, func = (
            create_inspect_container_tool(mock_docker_client)
        )

        assert name == "docker_inspect_container"
        assert description == "Get detailed information about a Docker container"
        assert safety_level == OperationSafety.SAFE
        assert idempotent is True
        assert open_world is False
        assert callable(func)

    def test_logs_tool_metadata(self, mock_docker_client, safety_config):
        """Test docker_container_logs tool metadata."""
        name, description, safety_level, idempotent, open_world, func = create_container_logs_tool(
            mock_docker_client, safety_config
        )

        assert name == "docker_container_logs"
        assert description == "Get logs from a Docker container"
        assert safety_level == OperationSafety.SAFE
        assert idempotent is True
        assert open_world is False
        assert callable(func)

    def test_stats_tool_metadata(self, mock_docker_client, safety_config):
        """Test docker_container_stats tool metadata."""
        name, description, safety_level, idempotent, open_world, func = create_container_stats_tool(
            mock_docker_client
        )

        assert name == "docker_container_stats"
        assert description == "Get resource usage statistics for a Docker container"
        assert safety_level == OperationSafety.SAFE
        assert idempotent is True
        assert open_world is False
        assert callable(func)

    def test_exec_command_tool_metadata(self, mock_docker_client, safety_config):
        """Test docker_exec_command tool metadata."""
        name, description, safety_level, idempotent, open_world, func = create_exec_command_tool(
            mock_docker_client, safety_config
        )

        assert name == "docker_exec_command"
        assert description == "Execute a command in a running Docker container"
        assert safety_level == OperationSafety.MODERATE
        assert idempotent is False
        assert open_world is True  # Commands may access external networks/APIs
        assert callable(func)


class TestListContainersTool:
    """Test docker_list_containers tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_list_containers_success(self, mock_docker_client, safety_config):
        """Test successful container listing."""
        # Mock image object
        mock_image = Mock()
        mock_image.tags = ["nginx:latest"]
        mock_image.id = "sha256:image123"

        # Mock container object
        mock_container = Mock()
        mock_container.id = "abc123"
        mock_container.name = "/test-container"
        mock_container.short_id = "abc1"
        mock_container.status = "running"
        mock_container.image = mock_image
        mock_container.labels = {"env": "test"}

        mock_docker_client.client.containers.list.return_value = [mock_container]

        # Get the list function
        *_, list_func = create_list_containers_tool(mock_docker_client, safety_config)

        # Execute
        result = list_func()

        # Verify
        assert result["count"] == 1
        assert len(result["containers"]) == 1
        assert result["containers"][0]["id"] == "abc123"
        assert result["containers"][0]["name"] == "/test-container"
        assert result["containers"][0]["image"] == "nginx:latest"
        assert result["containers"][0]["status"] == "running"

    def test_list_containers_with_filters(self, mock_docker_client, safety_config):
        """Test container listing with filters."""
        mock_docker_client.client.containers.list.return_value = []

        # Get the list function
        *_, list_func = create_list_containers_tool(mock_docker_client, safety_config)

        # Execute with filters
        filters = {"status": ["running"]}
        result = list_func(filters=filters)

        # Verify filters were passed
        mock_docker_client.client.containers.list.assert_called_once_with(
            all=False, filters=filters
        )
        assert result["count"] == 0

    def test_list_containers_api_error(self, mock_docker_client, safety_config):
        """Test container listing with API error."""
        mock_docker_client.client.containers.list.side_effect = APIError("List failed")

        # Get the list function
        *_, list_func = create_list_containers_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to list containers"):
            list_func()


class TestInspectContainerTool:
    """Test docker_inspect_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_inspect_container_not_found(self, mock_docker_client, safety_config):
        """Test inspecting non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the inspect function
        *_, inspect_func = create_inspect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound):
            inspect_func(container_id="nonexistent")

    def test_inspect_container_api_error(self, mock_docker_client, safety_config):
        """Test container inspection with API error."""
        mock_docker_client.client.containers.get.side_effect = APIError("Inspect failed")

        # Get the inspect function
        *_, inspect_func = create_inspect_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to inspect container"):
            inspect_func(container_id="test")


class TestContainerLogsTool:
    """Test docker_container_logs tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_logs_container_not_found(self, mock_docker_client, safety_config):
        """Test logs for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the logs function
        *_, logs_func = create_container_logs_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(ContainerNotFound):
            logs_func(container_id="nonexistent")

    def test_logs_api_error(self, mock_docker_client, safety_config):
        """Test logs with API error."""
        mock_container = Mock()
        mock_container.logs.side_effect = APIError("Logs failed")

        mock_docker_client.client.containers.get.return_value = mock_container

        # Get the logs function
        *_, logs_func = create_container_logs_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to get container logs"):
            logs_func(container_id="test")


class TestContainerStatsTool:
    """Test docker_container_stats tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_stats_container_not_found(self, mock_docker_client, safety_config):
        """Test stats for non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the stats function
        *_, stats_func = create_container_stats_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound):
            stats_func(container_id="nonexistent")


class TestExecCommandTool:
    """Test docker_exec_command tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    @pytest.fixture
    def safety_config(self):
        """Create safety config."""
        return SafetyConfig()

    def test_exec_container_not_found(self, mock_docker_client, safety_config):
        """Test exec on non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the exec function
        *_, exec_func = create_exec_command_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(ContainerNotFound):
            exec_func(container_id="nonexistent", command=["ls"])

    def test_exec_api_error(self, mock_docker_client, safety_config):
        """Test exec with API error."""
        mock_container = Mock()
        mock_container.exec_run.side_effect = APIError("Exec failed")

        mock_docker_client.client.containers.get.return_value = mock_container

        # Get the exec function
        *_, exec_func = create_exec_command_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to execute command"):
            exec_func(container_id="test", command=["ls"])
