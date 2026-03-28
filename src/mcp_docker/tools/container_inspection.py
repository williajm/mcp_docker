"""FastMCP container inspection tools."""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import (
    OperationSafety,
    validate_command_safety,
    validate_environment_variable,
)
from mcp_docker.tools.common import (
    DESC_CONTAINER_ID,
    TIMEOUT_MEDIUM,
    FiltersInput,
    ToolSpec,
)
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError, UnsafeOperationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.validation import validate_command

logger = get_logger(__name__)

# Constants
MAX_STREAMING_LOG_LINES = 10000  # Prevents OOM when collecting streaming logs


def _build_logs_kwargs(
    tail: int | str,
    since: str | None,
    until: str | None,
    timestamps: bool,
    follow: bool,
) -> dict[str, Any]:
    """Build kwargs dict for container.logs() call.

    Args:
        tail: Number of lines to show from end
        since: Show logs since timestamp
        until: Show logs until timestamp
        timestamps: Show timestamps
        follow: Follow log output

    Returns:
        Dictionary of kwargs for container.logs()
    """
    kwargs: dict[str, Any] = {
        "timestamps": timestamps,
        "follow": follow,
    }
    if tail != "all":
        kwargs["tail"] = int(tail)
    if since:
        kwargs["since"] = since
    if until:
        kwargs["until"] = until
    return kwargs


def _decode_static_logs(logs: bytes | str) -> str:
    """Decode static logs (non-streaming mode).

    Args:
        logs: Raw logs as bytes or string

    Returns:
        Decoded log string
    """
    return logs.decode("utf-8") if isinstance(logs, bytes) else str(logs)


def _collect_streaming_logs(logs: Any) -> str:
    """Collect streaming logs with safety limits.

    Args:
        logs: Streaming log generator from Docker

    Returns:
        Collected log string, or error message on failure
    """
    log_lines = []
    try:
        for line in logs:
            log_lines.append(line)
            if len(log_lines) >= MAX_STREAMING_LOG_LINES:
                logger.warning(
                    f"Reached max line limit ({MAX_STREAMING_LOG_LINES}) for follow mode, "
                    "stopping collection"
                )
                break
        logs_bytes = b"".join(log_lines)
        return logs_bytes.decode("utf-8")
    except Exception as e:
        logger.error(f"Error collecting logs in follow mode: {e}")
        return f"Error collecting logs: {e}"


def _retrieve_and_process_logs(  # noqa: PLR0913 - Docker API parameters
    container: Any,
    tail: int | str,
    since: str | None,
    until: str | None,
    timestamps: bool,
    follow: bool,
) -> str:
    """Retrieve logs from container and process based on mode.

    Args:
        container: Docker container object
        tail: Number of lines to show from end
        since: Show logs since timestamp
        until: Show logs until timestamp
        timestamps: Show timestamps
        follow: Follow log output (streaming mode)

    Returns:
        Processed log string
    """
    kwargs = _build_logs_kwargs(tail, since, until, timestamps, follow)
    logs = container.logs(**kwargs)

    if follow:
        # Streaming mode - ensure generator is closed to release connection
        try:
            return _collect_streaming_logs(logs)
        finally:
            if hasattr(logs, "close"):
                logs.close()
    else:
        return _decode_static_logs(logs)


# Input/Output Models (reused from legacy tools)


class ListContainersInput(FiltersInput):
    """Input for listing containers."""

    all: bool = Field(default=False, description="Show all containers (default shows just running)")


class ListContainersOutput(BaseModel):
    """Output for listing containers."""

    containers: list[dict[str, Any]] = Field(description="List of containers")
    count: int = Field(description="Total number of containers found")


class InspectContainerInput(BaseModel):
    """Input for inspecting a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)


class InspectContainerOutput(BaseModel):
    """Output for inspecting a container."""

    container_info: dict[str, Any] = Field(description="Detailed container information")


class ContainerLogsInput(BaseModel):
    """Input for getting container logs."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
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


class ContainerStatsInput(BaseModel):
    """Input for getting container stats."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
    stream: bool = Field(default=False, description="Stream stats continuously")


class ContainerStatsOutput(BaseModel):
    """Output for getting container stats."""

    stats: dict[str, Any] = Field(description="Container resource usage statistics")
    container_id: str = Field(description="Container ID")


class ExecCommandInput(BaseModel):
    """Input for executing a command in a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)
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


# FastMCP Tool Functions


def create_list_containers_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the list_containers tool."""

    def list_containers(
        all: bool = False,
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker containers with optional filters."""
        try:
            logger.info(f"Listing containers (all={all}, filters={filters})")
            containers = docker_client.client.containers.list(all=all, filters=filters)

            container_list = [
                {
                    "id": c.id,
                    "short_id": c.short_id,
                    "name": c.name,
                    "image": (
                        c.image.tags[0]
                        if c.image and c.image.tags
                        else (c.image.id if c.image else "unknown")
                    ),
                    "status": c.status,
                    "labels": c.labels,
                }
                for c in containers
            ]

            logger.info(f"Found {len(container_list)} containers")

            output = ListContainersOutput(
                containers=container_list,
                count=len(container_list),
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list containers: {e}")
            raise DockerOperationError(f"Failed to list containers: {e}") from e

    return ToolSpec(
        name="docker_list_containers",
        description="List Docker containers with optional filters",
        safety=OperationSafety.SAFE,
        func=list_containers,
        idempotent=True,
    )


def create_inspect_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the inspect_container tool."""

    def inspect_container(
        container_id: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker container."""
        try:
            logger.info(f"Inspecting container: {container_id}")
            container = docker_client.client.containers.get(container_id)
            container_info = container.attrs

            logger.info(f"Successfully inspected container: {container_id}")

            output = InspectContainerOutput(container_info=container_info)

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to inspect container {container_id}: {e}")
            raise DockerOperationError(f"Failed to inspect container: {e}") from e

    return ToolSpec(
        name="docker_inspect_container",
        description="Get detailed information about a Docker container",
        safety=OperationSafety.SAFE,
        func=inspect_container,
        idempotent=True,
    )


def create_container_logs_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the container_logs tool."""

    def container_logs(  # noqa: PLR0913 - Docker API requires these parameters
        container_id: str,
        tail: int | str = "all",
        since: str | None = None,
        until: str | None = None,
        timestamps: bool = False,
        follow: bool = False,
    ) -> dict[str, Any]:
        """Get logs from a Docker container."""
        try:
            logger.info(f"Getting logs for container: {container_id}")
            container = docker_client.client.containers.get(container_id)

            # Retrieve and process logs (handles streaming vs static mode)
            logs_str = _retrieve_and_process_logs(container, tail, since, until, timestamps, follow)

            logger.info(f"Successfully retrieved logs for container: {container_id}")

            output = ContainerLogsOutput(
                logs=logs_str,
                container_id=str(container.id),
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to get container logs: {e}")
            raise DockerOperationError(f"Failed to get container logs: {e}") from e

    return ToolSpec(
        name="docker_container_logs",
        description="Get logs from a Docker container",
        safety=OperationSafety.SAFE,
        func=container_logs,
        idempotent=True,
        timeout=TIMEOUT_MEDIUM,
    )


def create_container_stats_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the container_stats tool."""

    def container_stats(
        container_id: str,
        stream: bool = False,
    ) -> dict[str, Any]:
        """Get resource usage statistics for a Docker container."""
        try:
            logger.info(f"Getting stats for container: {container_id}")
            container = docker_client.client.containers.get(container_id)

            # Get stats - behavior differs based on stream parameter
            if stream:
                # Get first stats snapshot from the stream, then close to release connection
                stats_gen = container.stats(stream=True, decode=True)
                try:
                    stats: dict[str, Any] = next(iter(stats_gen))  # type: ignore[arg-type]
                finally:
                    # Close generator to release Docker API connection
                    if hasattr(stats_gen, "close"):
                        stats_gen.close()
            else:
                # Returns a dict directly when stream=False
                stats_data = container.stats(stream=False)
                # Handle union type - stream=False returns dict directly
                stats = stats_data if isinstance(stats_data, dict) else next(iter(stats_data))

            logger.info(f"Successfully retrieved stats for container: {container_id}")

            output = ContainerStatsOutput(stats=stats, container_id=str(container.id))

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to get container stats: {e}")
            raise DockerOperationError(f"Failed to get container stats: {e}") from e

    return ToolSpec(
        name="docker_container_stats",
        description="Get resource usage statistics for a Docker container",
        safety=OperationSafety.SAFE,
        func=container_stats,
        idempotent=True,
    )


def _validate_exec_inputs(
    command: str | list[str],
    environment: dict[str, str] | None,
) -> None:
    """Validate command and environment inputs for exec.

    Args:
        command: Command to validate
        environment: Environment variables to validate

    Raises:
        ValidationError: If command or environment is invalid
    """
    # Validate command - SECURITY: Check for dangerous patterns
    validate_command_safety(command)
    validate_command(command)

    # Validate environment variables - SECURITY: Prevent command injection
    if environment:
        for key, value in environment.items():
            validate_environment_variable(key, value)


def _build_exec_kwargs(
    command: str | list[str],
    privileged: bool,
    workdir: str | None,
    user: str | None,
    environment: dict[str, str] | None,
) -> dict[str, Any]:
    """Build kwargs dict for container.exec_run() call.

    Args:
        command: Command to execute
        privileged: Run with elevated privileges
        workdir: Working directory for command
        user: User to run command as
        environment: Environment variables for the command

    Returns:
        Kwargs dictionary for exec_run
    """
    kwargs: dict[str, Any] = {
        "cmd": command,
        "privileged": privileged,
    }

    if workdir:
        kwargs["workdir"] = workdir
    if user:
        kwargs["user"] = user
    if environment:
        kwargs["environment"] = environment

    return kwargs


def create_exec_command_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> ToolSpec:
    """Create the exec_command tool."""

    def exec_command(  # noqa: PLR0913 - Docker API requires these parameters
        container_id: str,
        command: str | list[str],
        workdir: str | None = None,
        user: str | None = None,
        environment: dict[str, str] | None = None,
        privileged: bool = False,
    ) -> dict[str, Any]:
        """Execute a command in a running Docker container."""
        try:
            # Validate all inputs
            _validate_exec_inputs(command, environment)

            # Check if privileged exec is allowed
            if privileged and not safety_config.allow_privileged_containers:
                logger.warning("Privileged exec command blocked by safety config")
                raise UnsafeOperationError(
                    "Privileged containers are not allowed. "
                    "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
                )

            logger.info(f"Executing command in container: {container_id}, command: {command}")
            container = docker_client.client.containers.get(container_id)

            # Build kwargs and execute command
            kwargs = _build_exec_kwargs(command, privileged, workdir, user, environment)
            raw_exit_code, output = container.exec_run(**kwargs)

            # Convert bytes to string
            output_str = output.decode("utf-8") if isinstance(output, bytes) else str(output)

            logger.info(f"Successfully executed command in container: {container_id}")

            # Docker SDK returns int | None; treat None as -1 (unknown)
            exit_code: int = raw_exit_code if raw_exit_code is not None else -1

            output_model = ExecCommandOutput(
                exit_code=exit_code,
                output=output_str,
            )

            return output_model.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to execute command: {e}")
            raise DockerOperationError(f"Failed to execute command: {e}") from e

    return ToolSpec(
        name="docker_exec_command",
        description="Execute a command in a running Docker container",
        safety=OperationSafety.MODERATE,
        func=exec_command,
        open_world=True,
        timeout=TIMEOUT_MEDIUM,
    )


def register_container_inspection_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all container inspection tools with FastMCP."""
    tools = [
        create_list_containers_tool(docker_client),
        create_inspect_container_tool(docker_client),
        create_container_logs_tool(docker_client),
        create_container_stats_tool(docker_client),
        create_exec_command_tool(docker_client, safety_config),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
