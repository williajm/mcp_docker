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


# Module-level fixtures to avoid duplication across test classes
@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = Mock()
    client.client.containers = Mock()
    return client


@pytest.fixture
def safety_config():
    """Create safety config."""
    return SafetyConfig()


class TestInputOutputModels:
    """Test Pydantic input/output models."""

    @pytest.mark.parametrize(
        "model_class,kwargs,expected",
        [
            # ListContainersInput tests
            (ListContainersInput, {}, {"all": False, "filters": None}),
            (
                ListContainersInput,
                {"all": True, "filters": {"status": ["running"]}},
                {"all": True, "filters": {"status": ["running"]}},
            ),
            # ListContainersOutput tests
            (
                ListContainersOutput,
                {"containers": [{"id": "abc123"}], "count": 1},
                {"containers": [{"id": "abc123"}], "count": 1, "truncation_info": {}},
            ),
            # InspectContainerInput tests
            (
                InspectContainerInput,
                {"container_id": "test-container"},
                {"container_id": "test-container"},
            ),
            # InspectContainerOutput tests
            (
                InspectContainerOutput,
                {"container_info": {"Id": "abc123"}},
                {"container_info": {"Id": "abc123"}, "truncation_info": {}},
            ),
            # ContainerLogsInput defaults
            (
                ContainerLogsInput,
                {"container_id": "test"},
                {
                    "container_id": "test",
                    "tail": "all",
                    "since": None,
                    "until": None,
                    "timestamps": False,
                    "follow": False,
                },
            ),
            # ContainerLogsInput with all params
            (
                ContainerLogsInput,
                {
                    "container_id": "test",
                    "tail": 100,
                    "since": "1h",
                    "until": "2024-01-01",
                    "timestamps": True,
                    "follow": True,
                },
                {
                    "container_id": "test",
                    "tail": 100,
                    "since": "1h",
                    "until": "2024-01-01",
                    "timestamps": True,
                    "follow": True,
                },
            ),
            # ContainerLogsOutput tests
            (
                ContainerLogsOutput,
                {"logs": "test logs", "container_id": "abc123"},
                {"logs": "test logs", "container_id": "abc123", "truncation_info": {}},
            ),
            # ContainerStatsInput tests
            (
                ContainerStatsInput,
                {"container_id": "test", "stream": False},
                {"container_id": "test", "stream": False},
            ),
            # ContainerStatsOutput tests
            (
                ContainerStatsOutput,
                {"stats": {"cpu_stats": {}}, "container_id": "abc123"},
                {"stats": {"cpu_stats": {}}, "container_id": "abc123"},
            ),
            # ExecCommandInput defaults
            (
                ExecCommandInput,
                {"container_id": "test", "command": ["ls", "-la"]},
                {
                    "container_id": "test",
                    "command": ["ls", "-la"],
                    "workdir": None,
                    "user": None,
                    "environment": None,
                    "privileged": False,
                },
            ),
            # ExecCommandInput with options
            (
                ExecCommandInput,
                {
                    "container_id": "test",
                    "command": ["pwd"],
                    "workdir": "/app",
                    "user": "root",
                    "environment": {"FOO": "bar"},
                    "privileged": True,
                },
                {
                    "container_id": "test",
                    "command": ["pwd"],
                    "workdir": "/app",
                    "user": "root",
                    "environment": {"FOO": "bar"},
                    "privileged": True,
                },
            ),
            # ExecCommandOutput tests
            (
                ExecCommandOutput,
                {"exit_code": 0, "output": "success"},
                {"exit_code": 0, "output": "success", "truncation_info": {}},
            ),
        ],
    )
    def test_model_structure(self, model_class, kwargs, expected):
        """Test model structure and defaults."""
        instance = model_class(**kwargs)
        for field, expected_value in expected.items():
            assert getattr(instance, field) == expected_value


class TestToolMetadata:
    """Test tool metadata and registration."""

    @pytest.mark.parametrize(
        "tool_creator,expected_name,expected_safety,idempotent,open_world,needs_safety_config",
        [
            (
                create_list_containers_tool,
                "docker_list_containers",
                OperationSafety.SAFE,
                True,
                False,
                True,
            ),
            (
                create_inspect_container_tool,
                "docker_inspect_container",
                OperationSafety.SAFE,
                True,
                False,
                False,
            ),
            (
                create_container_logs_tool,
                "docker_container_logs",
                OperationSafety.SAFE,
                True,
                False,
                True,
            ),
            (
                create_container_stats_tool,
                "docker_container_stats",
                OperationSafety.SAFE,
                True,
                False,
                False,
            ),
            (
                create_exec_command_tool,
                "docker_exec_command",
                OperationSafety.MODERATE,
                False,
                True,
                True,
            ),
        ],
    )
    def test_tool_metadata(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        expected_name,
        expected_safety,
        idempotent,
        open_world,
        needs_safety_config,
    ):
        """Test tool metadata for container inspection tools."""
        if needs_safety_config:
            result = tool_creator(mock_docker_client, safety_config)
        else:
            result = tool_creator(mock_docker_client)

        name, description, safety_level, is_idempotent, is_open_world, func = result

        assert name == expected_name
        assert isinstance(description, str) and len(description) > 0
        assert safety_level == expected_safety
        assert is_idempotent == idempotent
        assert is_open_world == open_world
        assert callable(func)


class TestContainerNotFoundErrors:
    """Test container not found error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs",
        [
            (create_inspect_container_tool, False, {"container_id": "nonexistent"}),
            (create_container_logs_tool, True, {"container_id": "nonexistent"}),
            (create_container_stats_tool, False, {"container_id": "nonexistent"}),
            (
                create_exec_command_tool,
                True,
                {"container_id": "nonexistent", "command": ["ls"]},
            ),
        ],
    )
    def test_container_not_found(
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        call_kwargs,
    ):
        """Test that ContainerNotFound is raised when container doesn't exist."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(ContainerNotFound):
            func(**call_kwargs)


class TestAPIErrors:
    """Test API error handling across tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,call_kwargs,error_match,setup_error_on",
        [
            (
                create_list_containers_tool,
                True,
                {},
                "Failed to list containers",
                "containers.list",
            ),
            (
                create_inspect_container_tool,
                False,
                {"container_id": "test"},
                "Failed to inspect container",
                "containers.get",
            ),
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
        if setup_error_on == "containers.list":
            mock_docker_client.client.containers.list.side_effect = APIError("API failed")
        elif setup_error_on == "containers.get":
            mock_docker_client.client.containers.get.side_effect = APIError("API failed")

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
        else:
            *_, func = tool_creator(mock_docker_client)

        with pytest.raises(DockerOperationError, match=error_match):
            func(**call_kwargs)

    def test_logs_api_error(self, mock_docker_client, safety_config):
        """Test logs API error after getting container."""
        mock_container = Mock()
        mock_container.logs.side_effect = APIError("Logs failed")
        mock_docker_client.client.containers.get.return_value = mock_container

        *_, logs_func = create_container_logs_tool(mock_docker_client, safety_config)

        with pytest.raises(DockerOperationError, match="Failed to get container logs"):
            logs_func(container_id="test")

    def test_exec_api_error(self, mock_docker_client, safety_config):
        """Test exec API error after getting container."""
        mock_container = Mock()
        mock_container.exec_run.side_effect = APIError("Exec failed")
        mock_docker_client.client.containers.get.return_value = mock_container

        *_, exec_func = create_exec_command_tool(mock_docker_client, safety_config)

        with pytest.raises(DockerOperationError, match="Failed to execute command"):
            exec_func(container_id="test", command=["ls"])


class TestListContainersTool:
    """Test docker_list_containers tool functionality."""

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

        *_, list_func = create_list_containers_tool(mock_docker_client, safety_config)
        result = list_func()

        assert result["count"] == 1
        assert len(result["containers"]) == 1
        assert result["containers"][0]["id"] == "abc123"
        assert result["containers"][0]["name"] == "/test-container"
        assert result["containers"][0]["image"] == "nginx:latest"
        assert result["containers"][0]["status"] == "running"

    def test_list_containers_with_filters(self, mock_docker_client, safety_config):
        """Test container listing with filters."""
        mock_docker_client.client.containers.list.return_value = []

        *_, list_func = create_list_containers_tool(mock_docker_client, safety_config)
        filters = {"status": ["running"]}
        result = list_func(filters=filters)

        mock_docker_client.client.containers.list.assert_called_once_with(
            all=False, filters=filters
        )
        assert result["count"] == 0
