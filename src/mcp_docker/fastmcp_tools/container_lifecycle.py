"""FastMCP container lifecycle tools (MODERATE and DESTRUCTIVE operations).

This module contains container lifecycle management tools migrated to FastMCP 2.0.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.safety import (
    OperationSafety,
    validate_environment_variable,
    validate_mount_path,
)
from mcp_docker.utils.validation import (
    validate_command,
    validate_container_name,
    validate_memory,
    validate_port_mapping,
)

logger = get_logger(__name__)

# Common field descriptions (avoid string duplication per SonarCloud S1192)
DESC_CONTAINER_ID = "Container ID or name"

# Input/Output Models


class CreateContainerInput(BaseModel):
    """Input for creating a container."""

    image: str = Field(description="Image name to create container from")
    name: str | None = Field(default=None, description="Optional container name")
    command: str | list[str] | None = Field(default=None, description="Command to run")
    environment: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Environment variables as key-value pairs. "
            "Example: {'DATABASE_URL': 'postgres://localhost', 'DEBUG': 'true'}"
        ),
    )
    ports: dict[str, int | tuple[str, int] | None] | str | None = Field(
        default=None,
        description=(
            "Port mappings from container to host. "
            "Examples: {'80': 8080} maps container port 80 to host port 8080, "
            "{'80/tcp': 8080} explicitly specifies TCP, "
            "{'443/tcp': null} exposes port 443 without mapping to host"
        ),
    )
    volumes: dict[str, dict[str, str]] | str | None = Field(
        default=None,
        description=(
            "Volume mappings from host to container. "
            "Example: {'/host/path': {'bind': '/container/path', 'mode': 'rw'}}"
        ),
    )
    detach: bool = Field(default=True, description="Run container in background")
    remove: bool = Field(default=False, description="Remove container when it exits")
    mem_limit: str | None = Field(default=None, description="Memory limit (e.g., '512m', '2g')")
    cpu_shares: int | None = Field(default=None, description="CPU shares (relative weight)")

    @field_validator("ports", "environment", "volumes", mode="before")
    @classmethod
    def parse_json_strings(cls, v: Any, info: Any) -> Any:
        """Parse JSON strings to objects (workaround for MCP client serialization bug)."""
        field_name = info.field_name if hasattr(info, "field_name") else "field"
        return parse_json_string_field(v, field_name)


class CreateContainerOutput(BaseModel):
    """Output for creating a container."""

    container_id: str = Field(description="Created container ID")
    name: str | None = Field(description="Container name")
    warnings: list[str] | None = Field(default=None, description="Any warnings from creation")


class StartContainerInput(BaseModel):
    """Input for starting a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)


class StartContainerOutput(BaseModel):
    """Output for starting a container."""

    container_id: str = Field(description="Started container ID")
    status: str = Field(description="Container status after start")


class StopContainerInput(BaseModel):
    """Input for stopping a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class StopContainerOutput(BaseModel):
    """Output for stopping a container."""

    container_id: str = Field(description="Stopped container ID")
    status: str = Field(description="Container status after stop")


class RestartContainerInput(BaseModel):
    """Input for restarting a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class RestartContainerOutput(BaseModel):
    """Output for restarting a container."""

    container_id: str = Field(description="Restarted container ID")
    status: str = Field(description="Container status after restart")


class RemoveContainerInput(BaseModel):
    """Input for removing a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
    force: bool = Field(default=False, description="Force removal of running container")
    volumes: bool = Field(default=False, description="Remove associated volumes")


class RemoveContainerOutput(BaseModel):
    """Output for removing a container."""

    container_id: str = Field(description="Removed container ID")
    removed_volumes: bool = Field(description="Whether volumes were removed")


# FastMCP Tool Functions


def _validate_create_container_inputs(
    input_data: CreateContainerInput,
    safety_config: SafetyConfig,
) -> None:
    """Validate all input parameters for container creation.

    Args:
        input_data: Container creation parameters
        safety_config: Safety configuration for validation

    Raises:
        ValidationError: If any parameter is invalid
    """
    if input_data.name:
        validate_container_name(input_data.name)
    if input_data.command:
        validate_command(input_data.command)
    if input_data.mem_limit:
        validate_memory(input_data.mem_limit)
    if input_data.ports and isinstance(input_data.ports, dict):
        _validate_port_mappings(input_data.ports)
    if input_data.volumes and isinstance(input_data.volumes, dict):
        _validate_volume_mounts(input_data.volumes, safety_config)
    if input_data.environment and isinstance(input_data.environment, dict):
        _validate_environment_vars(input_data.environment)


def _validate_port_mappings(ports: dict[str, int | tuple[str, int] | None]) -> None:
    """Validate port mappings.

    Args:
        ports: Port mappings to validate
    """
    assert isinstance(ports, dict)
    for container_port, host_port in ports.items():
        if isinstance(host_port, int):
            validate_port_mapping(container_port, host_port)


def _validate_volume_mounts(
    volumes: dict[str, dict[str, str]],
    safety_config: SafetyConfig,
) -> None:
    """Validate volume mounts.

    Args:
        volumes: Volume mappings to validate
        safety_config: Safety configuration for mount validation
    """
    assert isinstance(volumes, dict)
    for mount_path in volumes:
        # Config validators ensure these are always lists, safe to cast
        blocklist = (
            list(safety_config.volume_mount_blocklist)
            if safety_config.volume_mount_blocklist
            else []
        )
        allowlist = (
            list(safety_config.volume_mount_allowlist)
            if safety_config.volume_mount_allowlist
            else None
        )
        validate_mount_path(
            mount_path,
            blocked_paths=blocklist,
            allowed_paths=allowlist,
            yolo_mode=safety_config.yolo_mode,
        )


def _validate_environment_vars(environment: dict[str, str]) -> None:
    """Validate environment variables.

    Args:
        environment: Environment variables to validate
    """
    assert isinstance(environment, dict)
    for key, value in environment.items():
        validate_environment_variable(key, value)


def _prepare_create_container_kwargs(input_data: CreateContainerInput) -> dict[str, Any]:
    """Prepare kwargs dictionary for container creation.

    Args:
        input_data: Container creation parameters

    Returns:
        Kwargs dictionary for Docker API
    """
    kwargs: dict[str, Any] = {"image": input_data.image}

    if input_data.name:
        kwargs["name"] = input_data.name
    if input_data.command:
        kwargs["command"] = input_data.command
    if input_data.environment:
        assert isinstance(input_data.environment, dict)
        kwargs["environment"] = input_data.environment
    if input_data.ports:
        assert isinstance(input_data.ports, dict)
        kwargs["ports"] = input_data.ports
    if input_data.volumes:
        assert isinstance(input_data.volumes, dict)
        kwargs["volumes"] = input_data.volumes
    if input_data.mem_limit:
        kwargs["mem_limit"] = input_data.mem_limit
    if input_data.cpu_shares:
        kwargs["cpu_shares"] = input_data.cpu_shares
    if input_data.remove:
        kwargs["auto_remove"] = input_data.remove

    return kwargs


def create_create_container_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the create_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def create_container(  # noqa: PLR0913 - Docker API requires these parameters
        image: str,
        name: str | None = None,
        command: str | list[str] | None = None,
        environment: dict[str, str] | None = None,
        ports: dict[str, int | tuple[str, int] | None] | None = None,
        volumes: dict[str, dict[str, str]] | None = None,
        detach: bool = True,
        remove: bool = False,
        mem_limit: str | None = None,
        cpu_shares: int | None = None,
    ) -> dict[str, Any]:
        """Create a new Docker container from an image.

        Args:
            image: Image name to create container from
            name: Optional container name
            command: Command to run
            environment: Environment variables as key-value pairs
            ports: Port mappings from container to host
            volumes: Volume mappings from host to container
            detach: Run container in background
            remove: Remove container when it exits
            mem_limit: Memory limit (e.g., '512m', '2g')
            cpu_shares: CPU shares (relative weight)

        Returns:
            Dictionary with container ID, name, and warnings

        Raises:
            DockerOperationError: If creation fails
        """
        try:
            # Create input model for validation
            input_data = CreateContainerInput(
                image=image,
                name=name,
                command=command,
                environment=environment,
                ports=ports,
                volumes=volumes,
                detach=detach,
                remove=remove,
                mem_limit=mem_limit,
                cpu_shares=cpu_shares,
            )

            # Validate inputs
            _validate_create_container_inputs(input_data, safety_config)

            logger.info(f"Creating container from image: {image}")

            # Prepare kwargs for container creation
            kwargs = _prepare_create_container_kwargs(input_data)

            # Create the container
            container = docker_client.client.containers.create(**kwargs)

            logger.info(f"Successfully created container: {container.id}")

            # Convert to output model for validation
            output = CreateContainerOutput(
                container_id=str(container.id),
                name=container.name,
                warnings=None,
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to create container: {e}")
            raise DockerOperationError(f"Failed to create container: {e}") from e

    return (
        "docker_create_container",
        "Create a new Docker container from an image",
        OperationSafety.MODERATE,
        False,  # not idempotent (creates new container each time)
        False,  # not open_world
        create_container,
    )


def create_start_container_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the start_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def start_container(
        container_id: str,
    ) -> dict[str, Any]:
        """Start a stopped Docker container.

        Args:
            container_id: Container ID or name

        Returns:
            Dictionary with container ID and status

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If start fails
        """
        try:
            logger.info(f"Starting container: {container_id}")
            container = docker_client.client.containers.get(container_id)

            # Check if already running (idempotent: safe to retry)
            if container.status == "running":
                logger.info(f"Container {container_id} already running")
                output = StartContainerOutput(
                    container_id=str(container.id),
                    status=container.status,
                )
                return output.model_dump()

            # Not running - start it
            container.start()
            container.reload()

            logger.info(f"Successfully started container: {container_id}")

            # Convert to output model for validation
            output = StartContainerOutput(
                container_id=str(container.id),
                status=container.status,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to start container: {e}")
            raise DockerOperationError(f"Failed to start container: {e}") from e

    return (
        "docker_start_container",
        "Start a stopped Docker container",
        OperationSafety.MODERATE,
        True,  # idempotent - starting converges to running state
        False,  # not open_world
        start_container,
    )


def create_stop_container_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the stop_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def stop_container(
        container_id: str,
        timeout: int = 10,
    ) -> dict[str, Any]:
        """Stop a running Docker container gracefully.

        Args:
            container_id: Container ID or name
            timeout: Timeout in seconds before killing

        Returns:
            Dictionary with container ID and status

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If stop fails
        """
        try:
            logger.info(f"Stopping container: {container_id} (timeout={timeout})")
            container = docker_client.client.containers.get(container_id)

            # Check if already stopped (idempotent: safe to retry)
            if container.status in ("exited", "created"):
                logger.info(f"Container {container_id} already stopped")
                output = StopContainerOutput(
                    container_id=str(container.id),
                    status=container.status,
                )
                return output.model_dump()

            # Still running - stop it
            container.stop(timeout=timeout)
            container.reload()

            logger.info(f"Successfully stopped container: {container_id}")

            # Convert to output model for validation
            output = StopContainerOutput(
                container_id=str(container.id),
                status=container.status,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to stop container: {e}")
            raise DockerOperationError(f"Failed to stop container: {e}") from e

    return (
        "docker_stop_container",
        "Stop a running Docker container gracefully",
        OperationSafety.MODERATE,
        True,  # idempotent - stopping converges to stopped state
        False,  # not open_world
        stop_container,
    )


def create_restart_container_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the restart_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def restart_container(
        container_id: str,
        timeout: int = 10,
    ) -> dict[str, Any]:
        """Restart a Docker container.

        Args:
            container_id: Container ID or name
            timeout: Timeout in seconds before killing

        Returns:
            Dictionary with container ID and status

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If restart fails
        """
        try:
            logger.info(f"Restarting container: {container_id} (timeout={timeout})")
            container = docker_client.client.containers.get(container_id)
            container.restart(timeout=timeout)
            container.reload()

            logger.info(f"Successfully restarted container: {container_id}")

            # Convert to output model for validation
            output = RestartContainerOutput(
                container_id=str(container.id),
                status=container.status,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to restart container: {e}")
            raise DockerOperationError(f"Failed to restart container: {e}") from e

    return (
        "docker_restart_container",
        "Restart a Docker container",
        OperationSafety.MODERATE,
        True,  # idempotent - restart operation can be safely retried
        False,  # not open_world
        restart_container,
    )


def create_remove_container_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the remove_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def remove_container(
        container_id: str,
        force: bool = False,
        volumes: bool = False,
    ) -> dict[str, Any]:
        """Remove a Docker container.

        Args:
            container_id: Container ID or name
            force: Force removal of running container
            volumes: Remove associated volumes

        Returns:
            Dictionary with container ID and removal info

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(f"Removing container: {container_id} (force={force}, volumes={volumes})")
            container = docker_client.client.containers.get(container_id)
            container_id_full = str(container.id)
            container.remove(force=force, v=volumes)

            logger.info(f"Successfully removed container: {container_id}")

            # Convert to output model for validation
            output = RemoveContainerOutput(
                container_id=container_id_full,
                removed_volumes=volumes,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to remove container: {e}")
            raise DockerOperationError(f"Failed to remove container: {e}") from e

    return (
        "docker_remove_container",
        "Remove a Docker container",
        OperationSafety.DESTRUCTIVE,
        False,  # not idempotent (container is gone after first removal)
        False,  # not open_world
        remove_container,
    )


def register_container_lifecycle_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all container lifecycle tools with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        List of registered tool names
    """
    tools = [
        create_create_container_tool(docker_client, safety_config),
        create_start_container_tool(docker_client),
        create_stop_container_tool(docker_client),
        create_restart_container_tool(docker_client),
        create_remove_container_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
