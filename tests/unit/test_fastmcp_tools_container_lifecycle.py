"""Unit tests for fastmcp_tools/container_lifecycle.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.container_lifecycle import (
    CreateContainerInput,
    _prepare_create_container_kwargs,
    _validate_create_container_inputs,
    _validate_environment_vars,
    _validate_port_mappings,
    _validate_volume_mounts,
    create_create_container_tool,
    create_remove_container_tool,
    create_restart_container_tool,
    create_start_container_tool,
    create_stop_container_tool,
)
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    UnsafeOperationError,
    ValidationError,
)


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


class TestCreateContainerInputValidation:
    """Test CreateContainerInput Pydantic model validation."""

    @pytest.mark.parametrize(
        "field,json_value,expected",
        [
            ("ports", '{"80": 8080}', {"80": 8080}),
            (
                "environment",
                '{"DEBUG": "true", "PORT": "3000"}',
                {"DEBUG": "true", "PORT": "3000"},
            ),
            (
                "volumes",
                '{"/host/path": {"bind": "/container/path", "mode": "rw"}}',
                {"/host/path": {"bind": "/container/path", "mode": "rw"}},
            ),
        ],
    )
    def test_json_string_parsing(self, field, json_value, expected):
        """Test that JSON string fields are parsed correctly."""
        input_data = CreateContainerInput(image="nginx", **{field: json_value})
        assert getattr(input_data, field) == expected

    def test_dict_passthrough(self):
        """Test that dict values are passed through."""
        input_data = CreateContainerInput(
            image="nginx",
            ports={"80": 8080},
            environment={"DEBUG": "true"},
            volumes={"/host/path": {"bind": "/container/path"}},
        )
        assert input_data.ports == {"80": 8080}
        assert input_data.environment == {"DEBUG": "true"}
        assert input_data.volumes == {"/host/path": {"bind": "/container/path"}}


class TestValidatePortMappings:
    """Test _validate_port_mappings helper function."""

    @pytest.mark.parametrize(
        "ports",
        [
            {"80": 8080, "443": 8443},  # Basic mapping
            {"80/tcp": 8080},  # TCP protocol
            {"80": None},  # Expose without mapping
            {"80": ("127.0.0.1", 8080)},  # Tuple value
        ],
    )
    def test_validate_port_mappings_success(self, ports):
        """Test successful port mapping validation."""
        _validate_port_mappings(ports)  # Should not raise


class TestValidateVolumeMounts:
    """Test _validate_volume_mounts helper function."""

    @pytest.mark.parametrize(
        "volumes,yolo_mode,should_pass,error_match",
        [
            ({"/tmp/data": {"bind": "/data", "mode": "rw"}}, False, True, None),
            ({"/etc": {"bind": "/host-etc", "mode": "ro"}}, True, True, None),
            ({"/etc": {"bind": "/host-etc", "mode": "rw"}}, False, False, "blocked"),
        ],
    )
    def test_validate_volume_mounts(self, volumes, yolo_mode, should_pass, error_match):
        """Test volume mount validation."""
        config = SafetyConfig(yolo_mode=yolo_mode)
        if should_pass:
            _validate_volume_mounts(volumes, config)
        else:
            with pytest.raises(UnsafeOperationError, match=error_match):
                _validate_volume_mounts(volumes, config)

    def test_validate_volume_mounts_allowlist(self):
        """Test volume mount validation with allowlist."""
        volumes = {"/custom/path": {"bind": "/data", "mode": "rw"}}
        config = SafetyConfig(volume_mount_allowlist=["/tmp", "/var/tmp"], yolo_mode=False)
        with pytest.raises(UnsafeOperationError, match="not in allowed paths"):
            _validate_volume_mounts(volumes, config)


class TestValidateEnvironmentVars:
    """Test _validate_environment_vars helper function."""

    @pytest.mark.parametrize(
        "env,should_pass,error_match",
        [
            ({"DEBUG": "true", "PORT": "3000"}, True, None),
            ({"PATH": "/usr/bin"}, True, None),
            ({"CMD": "$(rm -rf /)"}, False, "dangerous character"),
            ({"CMD": "`whoami`"}, False, "dangerous character"),
            ({"CMD": "echo hello; rm -rf /"}, False, "dangerous character"),
        ],
    )
    def test_validate_environment_vars(self, env, should_pass, error_match):
        """Test environment variable validation."""
        if should_pass:
            _validate_environment_vars(env)
        else:
            with pytest.raises(ValidationError, match=error_match):
                _validate_environment_vars(env)


class TestValidateCreateContainerInputs:
    """Test _validate_create_container_inputs helper function."""

    @pytest.mark.parametrize(
        "kwargs,should_pass,error_match",
        [
            # Full valid input
            (
                {
                    "image": "nginx",
                    "name": "my-nginx",
                    "command": ["nginx", "-g", "daemon off;"],
                    "mem_limit": "512m",
                    "ports": {"80": 8080},
                    "volumes": {"/tmp/data": {"bind": "/data", "mode": "rw"}},
                    "environment": {"DEBUG": "false"},
                },
                True,
                None,
            ),
            # Minimal input
            ({"image": "nginx"}, True, None),
            # Invalid name
            ({"image": "nginx", "name": "Invalid Name!"}, False, None),
            # Invalid command
            ({"image": "nginx", "command": "echo hello && rm -rf /"}, False, "dangerous patterns"),
            # Invalid memory
            ({"image": "nginx", "mem_limit": "invalid"}, False, None),
        ],
    )
    def test_validate_create_container_inputs(self, kwargs, should_pass, error_match):
        """Test container creation input validation."""
        input_data = CreateContainerInput(**kwargs)
        config = SafetyConfig()
        if should_pass:
            _validate_create_container_inputs(input_data, config)
        elif error_match:
            with pytest.raises(ValidationError, match=error_match):
                _validate_create_container_inputs(input_data, config)
        else:
            with pytest.raises(ValidationError):
                _validate_create_container_inputs(input_data, config)


class TestPrepareCreateContainerKwargs:
    """Test _prepare_create_container_kwargs helper function."""

    def test_prepare_minimal_kwargs(self):
        """Test preparing kwargs with minimal fields."""
        input_data = CreateContainerInput(image="nginx")
        kwargs = _prepare_create_container_kwargs(input_data)
        assert kwargs == {"image": "nginx"}

    def test_prepare_all_kwargs(self):
        """Test preparing kwargs with all fields."""
        input_data = CreateContainerInput(
            image="nginx",
            name="my-nginx",
            command=["nginx", "-g", "daemon off;"],
            environment={"DEBUG": "false"},
            ports={"80": 8080},
            volumes={"/tmp/data": {"bind": "/data"}},
            mem_limit="512m",
            cpu_shares=512,
            remove=True,
        )
        kwargs = _prepare_create_container_kwargs(input_data)

        assert kwargs["image"] == "nginx"
        assert kwargs["name"] == "my-nginx"
        assert kwargs["command"] == ["nginx", "-g", "daemon off;"]
        assert kwargs["environment"] == {"DEBUG": "false"}
        assert kwargs["ports"] == {"80": 8080}
        assert kwargs["volumes"] == {"/tmp/data": {"bind": "/data"}}
        assert kwargs["mem_limit"] == "512m"
        assert kwargs["cpu_shares"] == 512
        assert kwargs["auto_remove"] is True

    def test_prepare_without_remove(self):
        """Test preparing kwargs without auto_remove."""
        input_data = CreateContainerInput(image="nginx", remove=False)
        kwargs = _prepare_create_container_kwargs(input_data)
        assert "auto_remove" not in kwargs


class TestContainerNotFoundErrors:
    """Test container not found error handling across lifecycle tools."""

    @pytest.mark.parametrize(
        "tool_creator,call_kwargs",
        [
            (create_start_container_tool, {"container_id": "nonexistent"}),
            (create_stop_container_tool, {"container_id": "nonexistent"}),
            (create_restart_container_tool, {"container_id": "nonexistent"}),
            (create_remove_container_tool, {"container_id": "nonexistent"}),
        ],
    )
    def test_container_not_found(self, mock_docker_client, tool_creator, call_kwargs):
        """Test that ContainerNotFound is raised when container doesn't exist."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")
        *_, func = tool_creator(mock_docker_client)

        with pytest.raises(ContainerNotFound, match="Container not found"):
            func(**call_kwargs)


class TestAPIErrors:
    """Test API error handling across lifecycle tools."""

    @pytest.mark.parametrize(
        "tool_creator,needs_safety_config,container_method,error_match",
        [
            (create_create_container_tool, True, "create", "Failed to create container"),
            (create_start_container_tool, False, "start", "Failed to start container"),
            (create_stop_container_tool, False, "stop", "Failed to stop container"),
            (create_restart_container_tool, False, "restart", "Failed to restart container"),
            (create_remove_container_tool, False, "remove", "Failed to remove container"),
        ],
    )
    def test_api_error(  # noqa: PLR0913
        self,
        mock_docker_client,
        safety_config,
        tool_creator,
        needs_safety_config,
        container_method,
        error_match,
    ):
        """Test that DockerOperationError is raised on API errors."""
        if container_method == "create":
            mock_docker_client.client.containers.create.side_effect = APIError("API failed")
        else:
            container = Mock()
            container.status = "running" if container_method != "start" else "exited"
            getattr(container, container_method).side_effect = APIError("API failed")
            mock_docker_client.client.containers.get.return_value = container

        if needs_safety_config:
            *_, func = tool_creator(mock_docker_client, safety_config)
            call_kwargs = {"image": "nginx"} if container_method == "create" else {}
        else:
            *_, func = tool_creator(mock_docker_client)
            call_kwargs = {"container_id": "abc123"}

        with pytest.raises(DockerOperationError, match=error_match):
            func(**call_kwargs)


class TestCreateContainerTool:
    """Test docker_create_container tool."""

    def test_create_container_minimal(self, mock_docker_client, safety_config):
        """Test creating container with minimal parameters."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"
        mock_docker_client.client.containers.create.return_value = container

        *_, create_func = create_create_container_tool(mock_docker_client, safety_config)
        result = create_func(image="nginx")

        assert result["container_id"] == "abc123"
        assert result["name"] == "my-nginx"
        mock_docker_client.client.containers.create.assert_called_once_with(image="nginx")

    @pytest.mark.parametrize(
        "extra_kwargs,expected_call_kwarg",
        [
            ({"name": "custom-name"}, ("name", "custom-name")),
            (
                {"command": ["nginx", "-g", "daemon off;"]},
                ("command", ["nginx", "-g", "daemon off;"]),
            ),
            ({"environment": {"DEBUG": "false"}}, ("environment", {"DEBUG": "false"})),
            ({"ports": {"80": 8080}}, ("ports", {"80": 8080})),
            (
                {"volumes": {"/tmp/data": {"bind": "/data"}}},
                ("volumes", {"/tmp/data": {"bind": "/data"}}),
            ),
            ({"mem_limit": "512m"}, ("mem_limit", "512m")),
            ({"cpu_shares": 512}, ("cpu_shares", 512)),
            ({"remove": True}, ("auto_remove", True)),
        ],
    )
    def test_create_container_with_options(
        self, mock_docker_client, safety_config, extra_kwargs, expected_call_kwarg
    ):
        """Test creating container with various options."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"
        mock_docker_client.client.containers.create.return_value = container

        *_, create_func = create_create_container_tool(mock_docker_client, safety_config)
        create_func(image="nginx", **extra_kwargs)

        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        key, value = expected_call_kwarg
        assert call_kwargs[key] == value


class TestStartContainerTool:
    """Test docker_start_container tool."""

    def test_start_container_success(self, mock_docker_client):
        """Test successfully starting a stopped container."""
        container = Mock()
        container.id = "abc123"
        container.status = "exited"
        container.reload = Mock(side_effect=lambda: setattr(container, "status", "running"))
        mock_docker_client.client.containers.get.return_value = container

        *_, start_func = create_start_container_tool(mock_docker_client)
        result = start_func(container_id="abc123")

        assert result["container_id"] == "abc123"
        assert result["status"] == "running"
        container.start.assert_called_once()

    def test_start_container_already_running(self, mock_docker_client):
        """Test starting an already running container (idempotent)."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        mock_docker_client.client.containers.get.return_value = container

        *_, start_func = create_start_container_tool(mock_docker_client)
        result = start_func(container_id="abc123")

        assert result["status"] == "running"


class TestStopContainerTool:
    """Test docker_stop_container tool."""

    def test_stop_container_success(self, mock_docker_client):
        """Test successfully stopping a running container."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.reload = Mock(side_effect=lambda: setattr(container, "status", "exited"))
        mock_docker_client.client.containers.get.return_value = container

        *_, stop_func = create_stop_container_tool(mock_docker_client)
        result = stop_func(container_id="abc123")

        assert result["status"] == "exited"
        container.stop.assert_called_once_with(timeout=10)

    def test_stop_container_with_custom_timeout(self, mock_docker_client):
        """Test stopping container with custom timeout."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.reload = Mock(side_effect=lambda: setattr(container, "status", "exited"))
        mock_docker_client.client.containers.get.return_value = container

        *_, stop_func = create_stop_container_tool(mock_docker_client)
        stop_func(container_id="abc123", timeout=30)

        container.stop.assert_called_once_with(timeout=30)

    @pytest.mark.parametrize("status", ["exited", "created"])
    def test_stop_container_already_stopped(self, mock_docker_client, status):
        """Test stopping an already stopped container (idempotent)."""
        container = Mock()
        container.id = "abc123"
        container.status = status
        mock_docker_client.client.containers.get.return_value = container

        *_, stop_func = create_stop_container_tool(mock_docker_client)
        result = stop_func(container_id="abc123")

        assert result["status"] == status


class TestRestartContainerTool:
    """Test docker_restart_container tool."""

    def test_restart_container_success(self, mock_docker_client):
        """Test successfully restarting a container."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        mock_docker_client.client.containers.get.return_value = container

        *_, restart_func = create_restart_container_tool(mock_docker_client)
        result = restart_func(container_id="abc123")

        assert result["status"] == "running"
        container.restart.assert_called_once_with(timeout=10)

    def test_restart_container_with_custom_timeout(self, mock_docker_client):
        """Test restarting container with custom timeout."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        mock_docker_client.client.containers.get.return_value = container

        *_, restart_func = create_restart_container_tool(mock_docker_client)
        restart_func(container_id="abc123", timeout=30)

        container.restart.assert_called_once_with(timeout=30)


class TestRemoveContainerTool:
    """Test docker_remove_container tool."""

    def test_remove_container_success(self, mock_docker_client):
        """Test successfully removing a container."""
        container = Mock()
        container.id = "abc123"
        mock_docker_client.client.containers.get.return_value = container

        *_, remove_func = create_remove_container_tool(mock_docker_client)
        result = remove_func(container_id="abc123")

        assert result["container_id"] == "abc123"
        assert result["removed_volumes"] is False
        container.remove.assert_called_once_with(force=False, v=False)

    @pytest.mark.parametrize(
        "kwargs,expected_call",
        [
            ({"force": True}, {"force": True, "v": False}),
            ({"volumes": True}, {"force": False, "v": True}),
            ({"force": True, "volumes": True}, {"force": True, "v": True}),
        ],
    )
    def test_remove_container_with_options(self, mock_docker_client, kwargs, expected_call):
        """Test removing container with various options."""
        container = Mock()
        container.id = "abc123"
        mock_docker_client.client.containers.get.return_value = container

        *_, remove_func = create_remove_container_tool(mock_docker_client)
        remove_func(container_id="abc123", **kwargs)

        container.remove.assert_called_once_with(**expected_call)
