"""Container lifecycle management tools for Docker MCP server.

This module provides tools for managing the lifecycle of Docker containers:
create, start, stop, restart, and remove operations.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.safety import OperationSafety
from mcp_docker.utils.validation import (
    validate_command,
    validate_container_name,
    validate_memory,
    validate_port_mapping,
)

logger = get_logger(__name__)

# Constants
CONTAINER_ID_DESCRIPTION = "Container ID or name"


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

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)


class StartContainerOutput(BaseModel):
    """Output for starting a container."""

    container_id: str = Field(description="Started container ID")
    status: str = Field(description="Container status after start")


class StopContainerInput(BaseModel):
    """Input for stopping a container."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class StopContainerOutput(BaseModel):
    """Output for stopping a container."""

    container_id: str = Field(description="Stopped container ID")
    status: str = Field(description="Container status after stop")


class RestartContainerInput(BaseModel):
    """Input for restarting a container."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class RestartContainerOutput(BaseModel):
    """Output for restarting a container."""

    container_id: str = Field(description="Restarted container ID")
    status: str = Field(description="Container status after restart")


class RemoveContainerInput(BaseModel):
    """Input for removing a container."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
    force: bool = Field(default=False, description="Force removal of running container")
    volumes: bool = Field(default=False, description="Remove associated volumes")


class RemoveContainerOutput(BaseModel):
    """Output for removing a container."""

    container_id: str = Field(description="Removed container ID")
    removed_volumes: bool = Field(description="Whether volumes were removed")


# Tool Implementations


class CreateContainerTool(BaseTool):
    """Create a new Docker container."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_create_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Create a new Docker container from an image"

    @property
    def input_schema(self) -> type[CreateContainerInput]:
        """Input schema."""
        return CreateContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    def _validate_inputs(self, input_data: CreateContainerInput) -> None:
        """Validate all input parameters.

        Args:
            input_data: Input parameters to validate

        Raises:
            ValidationError: If validation fails
        """
        if input_data.name:
            validate_container_name(input_data.name)
        if input_data.command:
            validate_command(input_data.command)
        if input_data.mem_limit:
            validate_memory(input_data.mem_limit)
        if input_data.ports:
            # After field validation, ports is always a dict or None (never str)
            assert isinstance(input_data.ports, dict)
            for container_port, host_port in input_data.ports.items():
                if isinstance(host_port, int):
                    validate_port_mapping(container_port, host_port)

    def _prepare_kwargs(self, input_data: CreateContainerInput) -> dict[str, Any]:
        """Prepare kwargs dictionary for container creation.

        Args:
            input_data: Input parameters

        Returns:
            kwargs dictionary for Docker API
        """
        kwargs: dict[str, Any] = {"image": input_data.image}

        if input_data.name:
            kwargs["name"] = input_data.name
        if input_data.command:
            kwargs["command"] = input_data.command
        if input_data.environment:
            # After field validation, environment is always a dict or None (never str)
            assert isinstance(input_data.environment, dict)
            kwargs["environment"] = input_data.environment
        if input_data.ports:
            # After field validation, ports is always a dict or None (never str)
            assert isinstance(input_data.ports, dict)
            kwargs["ports"] = input_data.ports
        if input_data.volumes:
            # After field validation, volumes is always a dict or None (never str)
            assert isinstance(input_data.volumes, dict)
            kwargs["volumes"] = input_data.volumes
        if input_data.mem_limit:
            kwargs["mem_limit"] = input_data.mem_limit
        if input_data.cpu_shares:
            kwargs["cpu_shares"] = input_data.cpu_shares
        if input_data.remove:
            kwargs["auto_remove"] = input_data.remove

        return kwargs

    async def execute(self, input_data: CreateContainerInput) -> CreateContainerOutput:
        """Execute the create container operation.

        Args:
            input_data: Input parameters

        Returns:
            Created container information

        Raises:
            DockerOperationError: If creation fails
        """
        try:
            # Validate inputs
            self._validate_inputs(input_data)

            logger.info(f"Creating container from image: {input_data.image}")

            # Prepare kwargs for container creation
            kwargs = self._prepare_kwargs(input_data)

            # Create the container
            container = self.docker.client.containers.create(**kwargs)

            logger.info(f"Successfully created container: {container.id}")
            return CreateContainerOutput(
                container_id=str(container.id), name=container.name, warnings=None
            )

        except APIError as e:
            logger.error(f"Failed to create container: {e}")
            raise DockerOperationError(f"Failed to create container: {e}") from e


class StartContainerTool(BaseTool):
    """Start a Docker container."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_start_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Start a stopped Docker container"

    @property
    def input_schema(self) -> type[StartContainerInput]:
        """Input schema."""
        return StartContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: StartContainerInput) -> StartContainerOutput:
        """Execute the start container operation.

        Args:
            input_data: Input parameters

        Returns:
            Started container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If start fails
        """
        try:
            logger.info(f"Starting container: {input_data.container_id}")
            container = self.docker.client.containers.get(input_data.container_id)
            container.start()
            container.reload()

            logger.info(f"Successfully started container: {input_data.container_id}")
            return StartContainerOutput(container_id=str(container.id), status=container.status)

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to start container: {e}")
            raise DockerOperationError(f"Failed to start container: {e}") from e


class StopContainerTool(BaseTool):
    """Stop a running Docker container."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_stop_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Stop a running Docker container gracefully"

    @property
    def input_schema(self) -> type[StopContainerInput]:
        """Input schema."""
        return StopContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: StopContainerInput) -> StopContainerOutput:
        """Execute the stop container operation.

        Args:
            input_data: Input parameters

        Returns:
            Stopped container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If stop fails
        """
        try:
            logger.info(
                f"Stopping container: {input_data.container_id} (timeout={input_data.timeout})"
            )
            container = self.docker.client.containers.get(input_data.container_id)
            container.stop(timeout=input_data.timeout)
            container.reload()

            logger.info(f"Successfully stopped container: {input_data.container_id}")
            return StopContainerOutput(container_id=str(container.id), status=container.status)

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to stop container: {e}")
            raise DockerOperationError(f"Failed to stop container: {e}") from e


class RestartContainerTool(BaseTool):
    """Restart a Docker container."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_restart_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Restart a Docker container"

    @property
    def input_schema(self) -> type[RestartContainerInput]:
        """Input schema."""
        return RestartContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: RestartContainerInput) -> RestartContainerOutput:
        """Execute the restart container operation.

        Args:
            input_data: Input parameters

        Returns:
            Restarted container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If restart fails
        """
        try:
            logger.info(
                f"Restarting container: {input_data.container_id} (timeout={input_data.timeout})"
            )
            container = self.docker.client.containers.get(input_data.container_id)
            container.restart(timeout=input_data.timeout)
            container.reload()

            logger.info(f"Successfully restarted container: {input_data.container_id}")
            return RestartContainerOutput(container_id=str(container.id), status=container.status)

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to restart container: {e}")
            raise DockerOperationError(f"Failed to restart container: {e}") from e


class RemoveContainerTool(BaseTool):
    """Remove a Docker container."""

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_remove_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Remove a Docker container"

    @property
    def input_schema(self) -> type[RemoveContainerInput]:
        """Input schema."""
        return RemoveContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

    async def execute(self, input_data: RemoveContainerInput) -> RemoveContainerOutput:
        """Execute the remove container operation.

        Args:
            input_data: Input parameters

        Returns:
            Removed container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If removal fails
        """
        try:
            logger.info(
                f"Removing container: {input_data.container_id} (force={input_data.force}, "
                f"volumes={input_data.volumes})"
            )
            container = self.docker.client.containers.get(input_data.container_id)
            container_id = container.id
            container.remove(force=input_data.force, v=input_data.volumes)

            logger.info(f"Successfully removed container: {container_id}")
            return RemoveContainerOutput(
                container_id=str(container_id), removed_volumes=input_data.volumes
            )

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to remove container: {e}")
            raise DockerOperationError(f"Failed to remove container: {e}") from e


# Export all tools
__all__ = [
    "CreateContainerTool",
    "StartContainerTool",
    "StopContainerTool",
    "RestartContainerTool",
    "RemoveContainerTool",
]
