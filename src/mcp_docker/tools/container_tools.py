"""Container management tools for Docker MCP server.

This module provides tools for managing Docker containers, including
listing, inspecting, creating, starting, stopping, and executing commands.
"""

import json
from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety
from mcp_docker.utils.validation import (
    validate_command,
    validate_container_name,
    validate_memory,
    validate_port_mapping,
)

logger = get_logger(__name__)


def parse_json_string_field(v: Any, field_name: str = "field") -> Any:
    """Parse JSON strings to objects (workaround for MCP client serialization bug).

    Args:
        v: The value to parse (dict or JSON string)
        field_name: Name of the field for error messages

    Returns:
        Parsed dict if v was a string, otherwise returns v unchanged

    Raises:
        ValueError: If v is a string but not valid JSON
    """
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            logger.warning(
                f"Received JSON string instead of object for {field_name}, auto-parsing. "
                "This is a workaround for MCP client serialization issues."
            )
            return parsed
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Received invalid JSON string for {field_name}: {v[:100]}... "
                f"Expected an object/dict, not a string. Error: {e}"
            ) from e
    return v


# Input/Output Models


class ListContainersInput(BaseModel):
    """Input for listing containers."""

    all: bool = Field(default=False, description="Show all containers (default shows just running)")
    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs. "
            "Examples: {'status': ['running']}, {'name': 'my-container'}, "
            "{'label': ['env=prod', 'app=web']}"
        ),
    )


class ListContainersOutput(BaseModel):
    """Output for listing containers."""

    containers: list[dict[str, Any]] = Field(description="List of containers with basic info")
    count: int = Field(description="Total number of containers")


class InspectContainerInput(BaseModel):
    """Input for inspecting a container."""

    container_id: str = Field(description="Container ID or name")


class InspectContainerOutput(BaseModel):
    """Output for inspecting a container."""

    details: dict[str, Any] = Field(description="Detailed container information")


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

    container_id: str = Field(description="Container ID or name")


class StartContainerOutput(BaseModel):
    """Output for starting a container."""

    container_id: str = Field(description="Started container ID")
    status: str = Field(description="Container status after start")


class StopContainerInput(BaseModel):
    """Input for stopping a container."""

    container_id: str = Field(description="Container ID or name")
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class StopContainerOutput(BaseModel):
    """Output for stopping a container."""

    container_id: str = Field(description="Stopped container ID")
    status: str = Field(description="Container status after stop")


class RestartContainerInput(BaseModel):
    """Input for restarting a container."""

    container_id: str = Field(description="Container ID or name")
    timeout: int = Field(default=10, description="Timeout in seconds before killing")


class RestartContainerOutput(BaseModel):
    """Output for restarting a container."""

    container_id: str = Field(description="Restarted container ID")
    status: str = Field(description="Container status after restart")


class RemoveContainerInput(BaseModel):
    """Input for removing a container."""

    container_id: str = Field(description="Container ID or name")
    force: bool = Field(default=False, description="Force removal of running container")
    volumes: bool = Field(default=False, description="Remove associated volumes")


class RemoveContainerOutput(BaseModel):
    """Output for removing a container."""

    container_id: str = Field(description="Removed container ID")
    removed_volumes: bool = Field(description="Whether volumes were removed")


class ContainerLogsInput(BaseModel):
    """Input for getting container logs."""

    container_id: str = Field(description="Container ID or name")
    tail: int | str = Field(default="all", description="Number of lines to show from end")
    since: str | None = Field(
        default=None, description="Show logs since timestamp or relative (e.g., '1h')"
    )
    until: str | None = Field(default=None, description="Show logs until timestamp")
    timestamps: bool = Field(default=False, description="Show timestamps")
    follow: bool = Field(default=False, description="Follow log output")


class ContainerLogsOutput(BaseModel):
    """Output for getting container logs."""

    logs: str = Field(description="Container logs")
    container_id: str = Field(description="Container ID")


class ExecCommandInput(BaseModel):
    """Input for executing a command in a container."""

    container_id: str = Field(description="Container ID or name")
    command: str | list[str] = Field(description="Command to execute")
    workdir: str | None = Field(default=None, description="Working directory for command")
    user: str | None = Field(default=None, description="User to run command as")
    environment: dict[str, str] | str | None = Field(
        default=None,
        description=(
            "Environment variables for the command as key-value pairs. "
            "Example: {'PATH': '/usr/local/bin:/usr/bin', 'MY_VAR': 'value'}"
        ),
    )
    privileged: bool = Field(default=False, description="Run with elevated privileges")

    @field_validator("environment", mode="before")
    @classmethod
    def parse_environment_json(cls, v: Any, info: Any) -> Any:
        """Parse JSON strings to objects (workaround for MCP client serialization bug)."""
        field_name = info.field_name if hasattr(info, "field_name") else "environment"
        return parse_json_string_field(v, field_name)


class ExecCommandOutput(BaseModel):
    """Output for executing a command in a container."""

    exit_code: int = Field(description="Command exit code")
    output: str = Field(description="Command output (stdout and stderr combined)")


class ContainerStatsInput(BaseModel):
    """Input for getting container stats."""

    container_id: str = Field(description="Container ID or name")
    stream: bool = Field(default=False, description="Stream stats continuously")


class ContainerStatsOutput(BaseModel):
    """Output for getting container stats."""

    stats: dict[str, Any] = Field(description="Container resource usage statistics")
    container_id: str = Field(description="Container ID")


# Tool Implementations


class ListContainersTool(BaseTool):
    """List Docker containers with optional filters."""

    # Keep output_model for documentation (not used by BaseTool but helpful)
    output_model = ListContainersOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_list_containers"

    @property
    def description(self) -> str:
        """Tool description."""
        return "List Docker containers with optional filters"

    @property
    def input_schema(self) -> type[ListContainersInput]:
        """Input schema."""
        return ListContainersInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ListContainersInput) -> ListContainersOutput:
        """Execute the list containers operation.

        Args:
            input_data: Input parameters

        Returns:
            List of containers with basic info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing containers (all={input_data.all}, filters={input_data.filters})")
            containers = self.docker.client.containers.list(
                all=input_data.all, filters=input_data.filters
            )

            container_list = [
                {
                    "id": c.id,
                    "short_id": c.short_id,
                    "name": c.name,
                    "image": c.image.tags[0] if c.image.tags else c.image.id,
                    "status": c.status,
                    "labels": c.labels,
                }
                for c in containers
            ]

            logger.info(f"Found {len(container_list)} containers")
            return ListContainersOutput(containers=container_list, count=len(container_list))

        except APIError as e:
            logger.error(f"Failed to list containers: {e}")
            raise DockerOperationError(f"Failed to list containers: {e}") from e


class InspectContainerTool(BaseTool):
    """Inspect a Docker container to get detailed information."""

    output_model = InspectContainerOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_inspect_container"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get detailed information about a Docker container"

    @property
    def input_schema(self) -> type[InspectContainerInput]:
        """Input schema."""
        return InspectContainerInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: InspectContainerInput) -> InspectContainerOutput:
        """Execute the inspect container operation.

        Args:
            input_data: Input parameters

        Returns:
            Detailed container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting container: {input_data.container_id}")
            container = self.docker.client.containers.get(input_data.container_id)
            details = container.attrs

            logger.info(f"Successfully inspected container: {input_data.container_id}")
            return InspectContainerOutput(details=details)

        except NotFound as e:
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to inspect container: {e}")
            raise DockerOperationError(f"Failed to inspect container: {e}") from e


class CreateContainerTool(BaseTool):
    """Create a new Docker container."""

    output_model = CreateContainerOutput

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

    async def execute(  # noqa: PLR0912
        self, input_data: CreateContainerInput
    ) -> CreateContainerOutput:
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
            if input_data.name:
                validate_container_name(input_data.name)
            if input_data.command and isinstance(input_data.command, str):
                validate_command(input_data.command)
            if input_data.mem_limit:
                validate_memory(input_data.mem_limit)
            if input_data.ports:
                # After field validation, ports is always a dict or None (never str)
                assert isinstance(input_data.ports, dict)
                for container_port, host_port in input_data.ports.items():
                    if isinstance(host_port, int):
                        validate_port_mapping(container_port, host_port)

            logger.info(f"Creating container from image: {input_data.image}")

            # Prepare kwargs for container creation
            # Note: containers.create() does not support 'detach' or 'remove' - those are for run()
            kwargs: dict[str, Any] = {
                "image": input_data.image,
            }

            if input_data.name:
                kwargs["name"] = input_data.name
            if input_data.command:
                kwargs["command"] = input_data.command
            if input_data.environment:
                # After field validation, environment is always a dict or None (never str)
                assert isinstance(input_data.environment, dict)
                kwargs["environment"] = input_data.environment

            # Port mappings for binding to host
            if input_data.ports:
                # Assertion already added above
                kwargs["ports"] = input_data.ports

            if input_data.volumes:
                # After field validation, volumes is always a dict or None (never str)
                assert isinstance(input_data.volumes, dict)
                kwargs["volumes"] = input_data.volumes
            if input_data.mem_limit:
                kwargs["mem_limit"] = input_data.mem_limit
            if input_data.cpu_shares:
                kwargs["cpu_shares"] = input_data.cpu_shares
            # auto_remove parameter replaces 'remove' for create()
            if input_data.remove:
                kwargs["auto_remove"] = input_data.remove

            container = self.docker.client.containers.create(**kwargs)

            logger.info(f"Successfully created container: {container.id}")
            # container.id and container.name are always present for created containers
            return CreateContainerOutput(
                container_id=str(container.id), name=container.name, warnings=None
            )

        except APIError as e:
            logger.error(f"Failed to create container: {e}")
            raise DockerOperationError(f"Failed to create container: {e}") from e


class StartContainerTool(BaseTool):
    """Start a Docker container."""

    output_model = StartContainerOutput

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
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to start container: {e}")
            raise DockerOperationError(f"Failed to start container: {e}") from e


class StopContainerTool(BaseTool):
    """Stop a running Docker container."""

    output_model = StopContainerOutput

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
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to stop container: {e}")
            raise DockerOperationError(f"Failed to stop container: {e}") from e


class RestartContainerTool(BaseTool):
    """Restart a Docker container."""

    output_model = RestartContainerOutput

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
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to restart container: {e}")
            raise DockerOperationError(f"Failed to restart container: {e}") from e


class RemoveContainerTool(BaseTool):
    """Remove a Docker container."""

    output_model = RemoveContainerOutput

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
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to remove container: {e}")
            raise DockerOperationError(f"Failed to remove container: {e}") from e


class ContainerLogsTool(BaseTool):
    """Get logs from a Docker container."""

    output_model = ContainerLogsOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_container_logs"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get logs from a Docker container"

    @property
    def input_schema(self) -> type[ContainerLogsInput]:
        """Input schema."""
        return ContainerLogsInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ContainerLogsInput) -> ContainerLogsOutput:
        """Execute the get container logs operation.

        Args:
            input_data: Input parameters

        Returns:
            Container logs

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If log retrieval fails
        """
        try:
            logger.info(f"Getting logs for container: {input_data.container_id}")
            container = self.docker.client.containers.get(input_data.container_id)

            # Prepare kwargs for logs
            kwargs: dict[str, Any] = {
                "timestamps": input_data.timestamps,
                "follow": input_data.follow,
            }

            if input_data.tail != "all":
                kwargs["tail"] = int(input_data.tail)
            if input_data.since:
                kwargs["since"] = input_data.since
            if input_data.until:
                kwargs["until"] = input_data.until

            logs = container.logs(**kwargs)

            # Handle different return types based on follow mode
            if input_data.follow:
                # When follow=True, logs returns a generator
                # Collect logs with a reasonable limit to avoid memory issues
                log_lines = []
                max_lines = 10000  # Safety limit
                try:
                    for line in logs:
                        log_lines.append(line)
                        if len(log_lines) >= max_lines:
                            logger.warning(
                                f"Reached max line limit ({max_lines}) for follow mode, "
                                "stopping collection"
                            )
                            break
                    logs_bytes = b"".join(log_lines)
                    logs_str = logs_bytes.decode("utf-8")
                except Exception as e:
                    logger.error(f"Error collecting logs in follow mode: {e}")
                    logs_str = f"Error collecting logs: {e}"
            else:
                # When follow=False, logs returns bytes or string directly
                logs_str = logs.decode("utf-8") if isinstance(logs, bytes) else str(logs)

            logger.info(f"Successfully retrieved logs for container: {input_data.container_id}")
            return ContainerLogsOutput(logs=logs_str, container_id=str(container.id))

        except NotFound as e:
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to get container logs: {e}")
            raise DockerOperationError(f"Failed to get container logs: {e}") from e


class ExecCommandTool(BaseTool):
    """Execute a command in a running Docker container."""

    output_model = ExecCommandOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_exec_command"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Execute a command in a running Docker container"

    @property
    def input_schema(self) -> type[ExecCommandInput]:
        """Input schema."""
        return ExecCommandInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ExecCommandInput) -> ExecCommandOutput:
        """Execute the exec command operation.

        Args:
            input_data: Input parameters

        Returns:
            Command execution results

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If command execution fails
        """
        try:
            # Validate command
            if isinstance(input_data.command, str):
                validate_command(input_data.command)

            logger.info(
                f"Executing command in container: {input_data.container_id}, "
                f"command: {input_data.command}"
            )
            container = self.docker.client.containers.get(input_data.container_id)

            # Prepare kwargs for exec
            kwargs: dict[str, Any] = {
                "cmd": input_data.command,
                "privileged": input_data.privileged,
            }

            if input_data.workdir:
                kwargs["workdir"] = input_data.workdir
            if input_data.user:
                kwargs["user"] = input_data.user
            if input_data.environment:
                kwargs["environment"] = input_data.environment

            # Execute command
            exit_code, output = container.exec_run(**kwargs)

            # Convert bytes to string
            output_str = output.decode("utf-8") if isinstance(output, bytes) else str(output)

            logger.info(
                f"Command executed in container: {input_data.container_id}, exit_code: {exit_code}"
            )
            return ExecCommandOutput(exit_code=exit_code, output=output_str)

        except NotFound as e:
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to execute command: {e}")
            raise DockerOperationError(f"Failed to execute command: {e}") from e


class ContainerStatsTool(BaseTool):
    """Get resource usage statistics for a Docker container."""

    output_model = ContainerStatsOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_container_stats"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get resource usage statistics for a Docker container"

    @property
    def input_schema(self) -> type[ContainerStatsInput]:
        """Input schema."""
        return ContainerStatsInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ContainerStatsInput) -> ContainerStatsOutput:
        """Execute the get container stats operation.

        Args:
            input_data: Input parameters

        Returns:
            Container resource usage statistics

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If stats retrieval fails
        """
        try:
            logger.info(f"Getting stats for container: {input_data.container_id}")
            container = self.docker.client.containers.get(input_data.container_id)

            # Get stats - behavior differs based on stream parameter
            # When stream=False, returns a dict directly
            # When stream=True, returns a generator of dicts
            if input_data.stream:
                # Get first stats snapshot from the stream
                stats_gen = container.stats(stream=True, decode=True)  # type: ignore[no-untyped-call]
                stats = next(stats_gen)
                # Close the generator to avoid resource leaks
                stats_gen.close()
            else:
                # Returns a dict directly when stream=False
                stats = container.stats(stream=False, decode=True)  # type: ignore[no-untyped-call]

            logger.info(f"Successfully retrieved stats for container: {input_data.container_id}")
            return ContainerStatsOutput(stats=stats, container_id=str(container.id))

        except NotFound as e:
            logger.error(f"Container not found: {input_data.container_id}")
            raise ContainerNotFound(f"Container not found: {input_data.container_id}") from e
        except APIError as e:
            logger.error(f"Failed to get container stats: {e}")
            raise DockerOperationError(f"Failed to get container stats: {e}") from e


# Export all tools
__all__ = [
    "ListContainersTool",
    "InspectContainerTool",
    "CreateContainerTool",
    "StartContainerTool",
    "StopContainerTool",
    "RestartContainerTool",
    "RemoveContainerTool",
    "ContainerLogsTool",
    "ExecCommandTool",
    "ContainerStatsTool",
]
