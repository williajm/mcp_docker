"""Unit tests for fastmcp_tools/container_lifecycle.py."""

from unittest.mock import Mock

import pytest
from docker.errors import APIError, NotFound

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.container_lifecycle import (
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


class TestCreateContainerInputValidation:
    """Test CreateContainerInput Pydantic model validation."""

    def test_json_string_parsing_ports(self):
        """Test that ports JSON string is parsed correctly."""
        input_data = CreateContainerInput(
            image="nginx",
            ports='{"80": 8080}',
        )
        assert input_data.ports == {"80": 8080}

    def test_json_string_parsing_environment(self):
        """Test that environment JSON string is parsed correctly."""
        input_data = CreateContainerInput(
            image="nginx",
            environment='{"DEBUG": "true", "PORT": "3000"}',
        )
        assert input_data.environment == {"DEBUG": "true", "PORT": "3000"}

    def test_json_string_parsing_volumes(self):
        """Test that volumes JSON string is parsed correctly."""
        input_data = CreateContainerInput(
            image="nginx",
            volumes='{"/host/path": {"bind": "/container/path", "mode": "rw"}}',
        )
        assert input_data.volumes == {"/host/path": {"bind": "/container/path", "mode": "rw"}}

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

    def test_validate_port_mappings_success(self):
        """Test successful port mapping validation."""
        ports = {"80": 8080, "443": 8443}
        # Should not raise
        _validate_port_mappings(ports)

    def test_validate_port_mappings_tcp_protocol(self):
        """Test port mapping with explicit TCP protocol."""
        ports = {"80/tcp": 8080}
        # Should not raise
        _validate_port_mappings(ports)

    def test_validate_port_mappings_none_value(self):
        """Test port mapping with None value (expose without mapping)."""
        ports = {"80": None}
        # Should not raise (None values are skipped in validation)
        _validate_port_mappings(ports)

    def test_validate_port_mappings_tuple_value(self):
        """Test port mapping with tuple value."""
        ports = {"80": ("127.0.0.1", 8080)}
        # Should not raise (tuple values are skipped in validation)
        _validate_port_mappings(ports)


class TestValidateVolumeMounts:
    """Test _validate_volume_mounts helper function."""

    def test_validate_volume_mounts_success(self):
        """Test successful volume mount validation."""
        volumes = {"/tmp/data": {"bind": "/data", "mode": "rw"}}
        safety_config = SafetyConfig()
        # Should not raise
        _validate_volume_mounts(volumes, safety_config)

    def test_validate_volume_mounts_yolo_mode(self):
        """Test volume mount validation in YOLO mode."""
        volumes = {"/etc": {"bind": "/host-etc", "mode": "ro"}}
        safety_config = SafetyConfig(yolo_mode=True)
        # Should not raise in YOLO mode
        _validate_volume_mounts(volumes, safety_config)

    def test_validate_volume_mounts_blocked_path(self):
        """Test volume mount validation with blocked path."""
        volumes = {"/etc": {"bind": "/host-etc", "mode": "rw"}}
        safety_config = SafetyConfig(yolo_mode=False)
        # Should raise UnsafeOperationError for /etc
        with pytest.raises(UnsafeOperationError, match="blocked"):
            _validate_volume_mounts(volumes, safety_config)

    def test_validate_volume_mounts_allowlist(self):
        """Test volume mount validation with allowlist."""
        volumes = {"/custom/path": {"bind": "/data", "mode": "rw"}}
        safety_config = SafetyConfig(
            volume_mount_allowlist=["/tmp", "/var/tmp"],
            yolo_mode=False,
        )
        # Should raise UnsafeOperationError (not in allowlist)
        with pytest.raises(UnsafeOperationError, match="not in allowed paths"):
            _validate_volume_mounts(volumes, safety_config)


class TestValidateEnvironmentVars:
    """Test _validate_environment_vars helper function."""

    def test_validate_environment_vars_success(self):
        """Test successful environment variable validation."""
        environment = {"DEBUG": "true", "PORT": "3000", "DATABASE_URL": "postgres://localhost"}
        # Should not raise
        _validate_environment_vars(environment)

    def test_validate_environment_vars_with_path(self):
        """Test environment variable with PATH key (should be allowed)."""
        environment = {"PATH": "/usr/bin"}
        # Should not raise (PATH is allowed)
        _validate_environment_vars(environment)

    def test_validate_environment_vars_command_substitution(self):
        """Test environment variable with command substitution."""
        environment = {"CMD": "$(rm -rf /)"}
        # Should raise ValidationError for command substitution
        with pytest.raises(ValidationError, match="dangerous character"):
            _validate_environment_vars(environment)

    def test_validate_environment_vars_backtick(self):
        """Test environment variable with backtick."""
        environment = {"CMD": "`whoami`"}
        # Should raise ValidationError for backtick
        with pytest.raises(ValidationError, match="dangerous character"):
            _validate_environment_vars(environment)

    def test_validate_environment_vars_semicolon(self):
        """Test environment variable with semicolon."""
        environment = {"CMD": "echo hello; rm -rf /"}
        # Should raise ValidationError for semicolon
        with pytest.raises(ValidationError, match="dangerous character"):
            _validate_environment_vars(environment)


class TestValidateCreateContainerInputs:
    """Test _validate_create_container_inputs helper function."""

    def test_validate_all_inputs_success(self):
        """Test validation of all container creation inputs."""
        input_data = CreateContainerInput(
            image="nginx",
            name="my-nginx",
            command=["nginx", "-g", "daemon off;"],  # Use list format
            mem_limit="512m",
            ports={"80": 8080},
            volumes={"/tmp/data": {"bind": "/data", "mode": "rw"}},
            environment={"DEBUG": "false"},
        )
        safety_config = SafetyConfig()
        # Should not raise
        _validate_create_container_inputs(input_data, safety_config)

    def test_validate_without_optional_fields(self):
        """Test validation with minimal required fields."""
        input_data = CreateContainerInput(image="nginx")
        safety_config = SafetyConfig()
        # Should not raise
        _validate_create_container_inputs(input_data, safety_config)

    def test_validate_invalid_name(self):
        """Test validation with invalid container name."""
        input_data = CreateContainerInput(image="nginx", name="Invalid Name!")
        safety_config = SafetyConfig()
        # Should raise ValidationError for invalid name
        with pytest.raises(ValidationError):
            _validate_create_container_inputs(input_data, safety_config)

    def test_validate_invalid_command(self):
        """Test validation with command containing special characters."""
        input_data = CreateContainerInput(image="nginx", command="echo hello && rm -rf /")
        safety_config = SafetyConfig()
        # Should raise ValidationError for command with &&
        with pytest.raises(ValidationError, match="dangerous patterns"):
            _validate_create_container_inputs(input_data, safety_config)

    def test_validate_invalid_memory(self):
        """Test validation with invalid memory limit."""
        input_data = CreateContainerInput(image="nginx", mem_limit="invalid")
        safety_config = SafetyConfig()
        # Should raise ValidationError for invalid memory format
        with pytest.raises(ValidationError):
            _validate_create_container_inputs(input_data, safety_config)


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


class TestCreateContainerTool:
    """Test docker_create_container tool."""

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

    def test_create_container_minimal(self, mock_docker_client, safety_config):
        """Test creating container with minimal parameters."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute
        result = create_func(image="nginx")

        # Verify
        assert result["container_id"] == "abc123"
        assert result["name"] == "my-nginx"
        assert result["warnings"] is None
        mock_docker_client.client.containers.create.assert_called_once_with(image="nginx")

    def test_create_container_with_name(self, mock_docker_client, safety_config):
        """Test creating container with custom name."""
        container = Mock()
        container.id = "abc123"
        container.name = "custom-name"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute
        create_func(image="nginx", name="custom-name")

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["name"] == "custom-name"

    def test_create_container_with_command(self, mock_docker_client, safety_config):
        """Test creating container with command."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with command (use list format to avoid special characters validation)
        create_func(image="nginx", command=["nginx", "-g", "daemon off;"])

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["command"] == ["nginx", "-g", "daemon off;"]

    def test_create_container_with_environment(self, mock_docker_client, safety_config):
        """Test creating container with environment variables."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with environment
        env = {"DEBUG": "false", "PORT": "3000"}
        create_func(image="nginx", environment=env)

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["environment"] == env

    def test_create_container_with_ports(self, mock_docker_client, safety_config):
        """Test creating container with port mappings."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with ports
        ports = {"80": 8080, "443": 8443}
        create_func(image="nginx", ports=ports)

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["ports"] == ports

    def test_create_container_with_volumes(self, mock_docker_client, safety_config):
        """Test creating container with volume mounts."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with volumes
        volumes = {"/tmp/data": {"bind": "/data", "mode": "rw"}}
        create_func(image="nginx", volumes=volumes)

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["volumes"] == volumes

    def test_create_container_with_resource_limits(self, mock_docker_client, safety_config):
        """Test creating container with resource limits."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with resource limits
        create_func(image="nginx", mem_limit="512m", cpu_shares=512)

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["mem_limit"] == "512m"
        assert call_kwargs["cpu_shares"] == 512

    def test_create_container_with_remove(self, mock_docker_client, safety_config):
        """Test creating container with auto_remove flag."""
        container = Mock()
        container.id = "abc123"
        container.name = "my-nginx"

        mock_docker_client.client.containers.create.return_value = container

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute with remove=True
        create_func(image="nginx", remove=True)

        # Verify
        call_kwargs = mock_docker_client.client.containers.create.call_args.kwargs
        assert call_kwargs["auto_remove"] is True

    def test_create_container_api_error(self, mock_docker_client, safety_config):
        """Test container creation with API error."""
        mock_docker_client.client.containers.create.side_effect = APIError("Create failed")

        # Get the create function
        _, _, _, _, _, create_func = create_create_container_tool(mock_docker_client, safety_config)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to create container"):
            create_func(image="nginx")


class TestStartContainerTool:
    """Test docker_start_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    def test_start_container_success(self, mock_docker_client):
        """Test successfully starting a stopped container."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "exited"
        container.start = Mock()
        container.reload = Mock()

        # After reload, status should be running
        def reload_side_effect():
            container.status = "running"

        container.reload.side_effect = reload_side_effect

        mock_docker_client.client.containers.get.return_value = container

        # Get the start function
        _, _, _, _, _, start_func = create_start_container_tool(mock_docker_client)

        # Execute
        result = start_func(container_id="abc123")

        # Verify
        assert result["container_id"] == "abc123"
        assert result["status"] == "running"
        container.start.assert_called_once()
        container.reload.assert_called_once()

    def test_start_container_already_running(self, mock_docker_client):
        """Test starting an already running container (idempotent)."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "running"

        mock_docker_client.client.containers.get.return_value = container

        # Get the start function
        _, _, _, _, _, start_func = create_start_container_tool(mock_docker_client)

        # Execute
        result = start_func(container_id="abc123")

        # Verify - should return success without calling start()
        assert result["container_id"] == "abc123"
        assert result["status"] == "running"

    def test_start_container_not_found(self, mock_docker_client):
        """Test starting non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the start function
        _, _, _, _, _, start_func = create_start_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            start_func(container_id="nonexistent")

    def test_start_container_api_error(self, mock_docker_client):
        """Test starting container with API error."""
        container = Mock()
        container.status = "exited"
        container.start.side_effect = APIError("Start failed")

        mock_docker_client.client.containers.get.return_value = container

        # Get the start function
        _, _, _, _, _, start_func = create_start_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to start container"):
            start_func(container_id="abc123")


class TestStopContainerTool:
    """Test docker_stop_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    def test_stop_container_success(self, mock_docker_client):
        """Test successfully stopping a running container."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.stop = Mock()
        container.reload = Mock()

        # After reload, status should be exited
        def reload_side_effect():
            container.status = "exited"

        container.reload.side_effect = reload_side_effect

        mock_docker_client.client.containers.get.return_value = container

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute
        result = stop_func(container_id="abc123")

        # Verify
        assert result["container_id"] == "abc123"
        assert result["status"] == "exited"
        container.stop.assert_called_once_with(timeout=10)
        container.reload.assert_called_once()

    def test_stop_container_with_custom_timeout(self, mock_docker_client):
        """Test stopping container with custom timeout."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.stop = Mock()
        container.reload = Mock()

        def reload_side_effect():
            container.status = "exited"

        container.reload.side_effect = reload_side_effect

        mock_docker_client.client.containers.get.return_value = container

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute with custom timeout
        stop_func(container_id="abc123", timeout=30)

        # Verify timeout was used
        container.stop.assert_called_once_with(timeout=30)

    def test_stop_container_already_stopped(self, mock_docker_client):
        """Test stopping an already stopped container (idempotent)."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "exited"

        mock_docker_client.client.containers.get.return_value = container

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute
        result = stop_func(container_id="abc123")

        # Verify - should return success without calling stop()
        assert result["container_id"] == "abc123"
        assert result["status"] == "exited"

    def test_stop_container_created_status(self, mock_docker_client):
        """Test stopping a container in created status (idempotent)."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "created"

        mock_docker_client.client.containers.get.return_value = container

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute
        result = stop_func(container_id="abc123")

        # Verify - should return success without calling stop()
        assert result["container_id"] == "abc123"
        assert result["status"] == "created"

    def test_stop_container_not_found(self, mock_docker_client):
        """Test stopping non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            stop_func(container_id="nonexistent")

    def test_stop_container_api_error(self, mock_docker_client):
        """Test stopping container with API error."""
        container = Mock()
        container.status = "running"
        container.stop.side_effect = APIError("Stop failed")

        mock_docker_client.client.containers.get.return_value = container

        # Get the stop function
        _, _, _, _, _, stop_func = create_stop_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to stop container"):
            stop_func(container_id="abc123")


class TestRestartContainerTool:
    """Test docker_restart_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    def test_restart_container_success(self, mock_docker_client):
        """Test successfully restarting a container."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.restart = Mock()
        container.reload = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the restart function
        _, _, _, _, _, restart_func = create_restart_container_tool(mock_docker_client)

        # Execute
        result = restart_func(container_id="abc123")

        # Verify
        assert result["container_id"] == "abc123"
        assert result["status"] == "running"
        container.restart.assert_called_once_with(timeout=10)
        container.reload.assert_called_once()

    def test_restart_container_with_custom_timeout(self, mock_docker_client):
        """Test restarting container with custom timeout."""
        container = Mock()
        container.id = "abc123"
        container.status = "running"
        container.restart = Mock()
        container.reload = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the restart function
        _, _, _, _, _, restart_func = create_restart_container_tool(mock_docker_client)

        # Execute with custom timeout
        restart_func(container_id="abc123", timeout=30)

        # Verify timeout was used
        container.restart.assert_called_once_with(timeout=30)

    def test_restart_container_not_found(self, mock_docker_client):
        """Test restarting non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the restart function
        _, _, _, _, _, restart_func = create_restart_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            restart_func(container_id="nonexistent")

    def test_restart_container_api_error(self, mock_docker_client):
        """Test restarting container with API error."""
        container = Mock()
        container.restart.side_effect = APIError("Restart failed")

        mock_docker_client.client.containers.get.return_value = container

        # Get the restart function
        _, _, _, _, _, restart_func = create_restart_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to restart container"):
            restart_func(container_id="abc123")


class TestRemoveContainerTool:
    """Test docker_remove_container tool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create a mock Docker client."""
        client = Mock(spec=DockerClientWrapper)
        client.client = Mock()
        client.client.containers = Mock()
        return client

    def test_remove_container_success(self, mock_docker_client):
        """Test successfully removing a container."""
        # Mock container object
        container = Mock()
        container.id = "abc123"
        container.remove = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute
        result = remove_func(container_id="abc123")

        # Verify
        assert result["container_id"] == "abc123"
        assert result["removed_volumes"] is False
        container.remove.assert_called_once_with(force=False, v=False)

    def test_remove_container_with_force(self, mock_docker_client):
        """Test removing container with force flag."""
        container = Mock()
        container.id = "abc123"
        container.remove = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute with force
        remove_func(container_id="abc123", force=True)

        # Verify force was used
        container.remove.assert_called_once_with(force=True, v=False)

    def test_remove_container_with_volumes(self, mock_docker_client):
        """Test removing container with volumes."""
        container = Mock()
        container.id = "abc123"
        container.remove = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute with volumes
        result = remove_func(container_id="abc123", volumes=True)

        # Verify volumes flag was used
        assert result["removed_volumes"] is True
        container.remove.assert_called_once_with(force=False, v=True)

    def test_remove_container_with_force_and_volumes(self, mock_docker_client):
        """Test removing container with both force and volumes."""
        container = Mock()
        container.id = "abc123"
        container.remove = Mock()

        mock_docker_client.client.containers.get.return_value = container

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute with force and volumes
        remove_func(container_id="abc123", force=True, volumes=True)

        # Verify both flags were used
        container.remove.assert_called_once_with(force=True, v=True)

    def test_remove_container_not_found(self, mock_docker_client):
        """Test removing non-existent container."""
        mock_docker_client.client.containers.get.side_effect = NotFound("Container not found")

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(ContainerNotFound, match="Container not found"):
            remove_func(container_id="nonexistent")

    def test_remove_container_api_error(self, mock_docker_client):
        """Test removing container with API error."""
        container = Mock()
        container.id = "abc123"
        container.remove.side_effect = APIError("Remove failed")

        mock_docker_client.client.containers.get.return_value = container

        # Get the remove function
        _, _, _, _, _, remove_func = create_remove_container_tool(mock_docker_client)

        # Execute and expect error
        with pytest.raises(DockerOperationError, match="Failed to remove container"):
            remove_func(container_id="abc123")
