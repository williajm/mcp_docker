"""FastMCP container inspection tools (SAFE operations).

This module contains read-only container inspection tools migrated to FastMCP 2.0.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError, UnsafeOperationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    truncate_lines,
    truncate_list,
    truncate_text,
)
from mcp_docker.utils.safety import (
    OperationSafety,
    validate_command_safety,
    validate_environment_variable,
)
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


def _apply_log_truncation(
    logs_str: str,
    follow: bool,
    safety_config: SafetyConfig,
) -> tuple[str, dict[str, Any]]:
    """Apply truncation limits to logs if needed.

    Args:
        logs_str: Log string to potentially truncate
        follow: Whether in follow mode
        safety_config: Safety configuration with max_log_lines

    Returns:
        Tuple of (truncated_logs, truncation_info_dict)
    """
    truncation_info: dict[str, Any] = {}

    if not follow and safety_config.max_log_lines > 0:
        original_lines = len(logs_str.splitlines())
        truncation_msg = (
            f"\n[Output truncated: showing first {safety_config.max_log_lines} of "
            f"{original_lines} lines. "
            f"Set SAFETY_MAX_LOG_LINES=0 to disable limit.]"
        )
        logs_str, was_truncated = truncate_lines(
            logs_str,
            safety_config.max_log_lines,
            truncation_message=truncation_msg,
        )

        if was_truncated:
            truncation_info = create_truncation_metadata(
                was_truncated=True,
                original_count=original_lines,
                truncated_count=safety_config.max_log_lines,
            )

    return logs_str, truncation_info


# Common field descriptions (avoid string duplication per SonarCloud S1192)
DESC_CONTAINER_ID = "Container ID or name"
DESC_TRUNCATION_INFO = "Information about output truncation if applied"

# Input/Output Models (reused from legacy tools)


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

    containers: list[dict[str, Any]] = Field(description="List of containers")
    count: int = Field(description="Total number of containers found")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


class InspectContainerInput(BaseModel):
    """Input for inspecting a container."""

    container_id: str = Field(description=DESC_CONTAINER_ID)


class InspectContainerOutput(BaseModel):
    """Output for inspecting a container."""

    container_info: dict[str, Any] = Field(description="Detailed container information")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


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
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


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
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


# FastMCP Tool Functions


def create_list_containers_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the list_containers FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def list_containers(
        all: bool = False,
        filters: dict[str, str | list[str]] | None = None,
    ) -> dict[str, Any]:
        """List Docker containers with optional filters.

        Args:
            all: Show all containers (default shows just running)
            filters: Filters to apply (e.g., {'status': ['running']})

        Returns:
            Dictionary with containers list, count, and truncation info

        Raises:
            DockerOperationError: If listing fails
        """
        try:
            logger.info(f"Listing containers (all={all}, filters={filters})")
            containers = docker_client.client.containers.list(all=all, filters=filters)

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

            # Apply output limits
            original_count = len(container_list)
            truncation_info: dict[str, Any] = {}
            if safety_config.max_list_results > 0:
                container_list, was_truncated = truncate_list(
                    container_list,
                    safety_config.max_list_results,
                )
                if was_truncated:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_count=original_count,
                        truncated_count=len(container_list),
                    )
                    truncation_info["message"] = (
                        f"Results truncated: showing {len(container_list)} of {original_count} "
                        f"containers. Set SAFETY_MAX_LIST_RESULTS=0 to disable limit."
                    )

            logger.info(f"Found {len(container_list)} containers (total: {original_count})")

            # Convert to output model for validation
            output = ListContainersOutput(
                containers=container_list,
                count=original_count,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to list containers: {e}")
            raise DockerOperationError(f"Failed to list containers: {e}") from e

    return (
        "docker_list_containers",
        "List Docker containers with optional filters",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        list_containers,
    )


def create_inspect_container_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the inspect_container FastMCP tool.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def inspect_container(
        container_id: str,
    ) -> dict[str, Any]:
        """Get detailed information about a Docker container.

        Args:
            container_id: Container ID or name

        Returns:
            Dictionary with detailed container information

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If inspection fails
        """
        try:
            logger.info(f"Inspecting container: {container_id}")
            container = docker_client.client.containers.get(container_id)
            container_info = container.attrs

            # Apply output limits (truncate large fields)
            truncation_info: dict[str, Any] = {}
            # Note: truncate_dict_fields would be imported if we use it
            # For now, returning full info

            logger.info(f"Successfully inspected container: {container_id}")

            # Convert to output model for validation
            output = InspectContainerOutput(
                container_info=container_info,
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to inspect container {container_id}: {e}")
            raise DockerOperationError(f"Failed to inspect container: {e}") from e

    return (
        "docker_inspect_container",
        "Get detailed information about a Docker container",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        inspect_container,
    )


def create_container_logs_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the container_logs FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def _decode_static_logs(logs: bytes | str) -> str:
        """Decode static logs (non-streaming mode)."""
        return logs.decode("utf-8") if isinstance(logs, bytes) else str(logs)

    def _collect_streaming_logs(logs: Any) -> str:
        """Collect streaming logs with safety limits."""
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

    def container_logs(  # noqa: PLR0913 - Docker API requires these parameters
        container_id: str,
        tail: int | str = "all",
        since: str | None = None,
        until: str | None = None,
        timestamps: bool = False,
        follow: bool = False,
    ) -> dict[str, Any]:
        """Get logs from a Docker container.

        Args:
            container_id: Container ID or name
            tail: Number of lines to show from end (default: "all")
            since: Show logs since timestamp or relative (e.g., '1h')
            until: Show logs until timestamp
            timestamps: Show timestamps
            follow: Follow log output

        Returns:
            Dictionary with logs and container ID

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If log retrieval fails
        """
        try:
            logger.info(f"Getting logs for container: {container_id}")
            container = docker_client.client.containers.get(container_id)

            # Prepare kwargs for logs
            kwargs = _build_logs_kwargs(tail, since, until, timestamps, follow)
            logs = container.logs(**kwargs)

            # Handle different return types based on follow mode
            logs_str = _collect_streaming_logs(logs) if follow else _decode_static_logs(logs)

            # Apply output limits (non-streaming logs only)
            logs_str, truncation_info = _apply_log_truncation(logs_str, follow, safety_config)

            logger.info(f"Successfully retrieved logs for container: {container_id}")

            output = ContainerLogsOutput(
                logs=logs_str,
                container_id=str(container.id),
                truncation_info=truncation_info,
            )

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to get container logs: {e}")
            raise DockerOperationError(f"Failed to get container logs: {e}") from e

    return (
        "docker_container_logs",
        "Get logs from a Docker container",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        container_logs,
    )


def create_container_stats_tool(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the container_stats FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def container_stats(
        container_id: str,
        stream: bool = False,
    ) -> dict[str, Any]:
        """Get resource usage statistics for a Docker container.

        Args:
            container_id: Container ID or name
            stream: Stream stats continuously (returns first snapshot)

        Returns:
            Dictionary with resource usage statistics

        Raises:
            ContainerNotFound: If container doesn't exist
            DockerOperationError: If stats retrieval fails
        """
        try:
            logger.info(f"Getting stats for container: {container_id}")
            container = docker_client.client.containers.get(container_id)

            # Get stats - behavior differs based on stream parameter
            if stream:
                # Get first stats snapshot from the stream
                stats_gen = container.stats(stream=True, decode=True)  # type: ignore[no-untyped-call]
                stats = next(stats_gen)
                # Close the generator to avoid resource leaks
                stats_gen.close()
            else:
                # Returns a dict directly when stream=False
                stats = container.stats(stream=False)  # type: ignore[no-untyped-call]

            logger.info(f"Successfully retrieved stats for container: {container_id}")

            output = ContainerStatsOutput(stats=stats, container_id=str(container.id))

            return output.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to get container stats: {e}")
            raise DockerOperationError(f"Failed to get container stats: {e}") from e

    return (
        "docker_container_stats",
        "Get resource usage statistics for a Docker container",
        OperationSafety.SAFE,
        True,  # idempotent
        False,  # not open_world
        container_stats,
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


def _apply_exec_output_truncation(
    output_str: str,
    safety_config: SafetyConfig,
) -> tuple[str, dict[str, Any]]:
    """Apply truncation limits to exec output if needed.

    Args:
        output_str: Raw command output
        safety_config: Safety configuration with limits

    Returns:
        Tuple of (truncated_output, truncation_metadata)
    """
    truncation_info: dict[str, Any] = {}

    if safety_config.max_exec_output_bytes > 0:
        original_bytes = len(output_str.encode("utf-8"))
        truncation_msg = (
            f"\n[Output truncated: showing first "
            f"{safety_config.max_exec_output_bytes} bytes of {original_bytes} bytes. "
            f"Set SAFETY_MAX_EXEC_OUTPUT_BYTES=0 to disable limit.]"
        )
        output_str, was_truncated = truncate_text(
            output_str,
            safety_config.max_exec_output_bytes,
            truncation_message=truncation_msg,
        )

        if was_truncated:
            truncation_info = create_truncation_metadata(
                was_truncated=True,
                original_count=original_bytes,
                truncated_count=safety_config.max_exec_output_bytes,
            )

    return output_str, truncation_info


def create_exec_command_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, OperationSafety, bool, bool, Any]:
    """Create the exec_command FastMCP tool.

    Args:
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Tuple of (name, description, safety_level, idempotent, open_world, function)
    """

    def exec_command(  # noqa: PLR0913 - Docker API requires these parameters
        container_id: str,
        command: str | list[str],
        workdir: str | None = None,
        user: str | None = None,
        environment: dict[str, str] | None = None,
        privileged: bool = False,
    ) -> dict[str, Any]:
        """Execute a command in a running Docker container.

        Args:
            container_id: Container ID or name
            command: Command to execute
            workdir: Working directory for command
            user: User to run command as
            environment: Environment variables for the command
            privileged: Run with elevated privileges

        Returns:
            Dictionary with exit code, output, and truncation info

        Raises:
            ContainerNotFound: If container doesn't exist
            UnsafeOperationError: If privileged exec is not allowed
            DockerOperationError: If command execution fails
        """
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
            exit_code, output = container.exec_run(**kwargs)

            # Convert bytes to string
            output_str = output.decode("utf-8") if isinstance(output, bytes) else str(output)

            # Apply output limits
            output_str, truncation_info = _apply_exec_output_truncation(output_str, safety_config)

            logger.info(f"Successfully executed command in container: {container_id}")

            # Convert to output model for validation
            output_model = ExecCommandOutput(
                exit_code=exit_code,
                output=output_str,
                truncation_info=truncation_info,
            )

            return output_model.model_dump()

        except NotFound as e:
            logger.error(f"Container not found: {container_id}")
            raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
        except APIError as e:
            logger.error(f"Failed to execute command: {e}")
            raise DockerOperationError(f"Failed to execute command: {e}") from e

    return (
        "docker_exec_command",
        "Execute a command in a running Docker container",
        OperationSafety.MODERATE,
        False,  # not idempotent (same command may have different effects)
        True,  # open_world (commands may access external networks/APIs)
        exec_command,
    )


def register_container_inspection_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register all container inspection tools with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        List of registered tool names
    """
    tools = [
        create_list_containers_tool(docker_client, safety_config),
        create_inspect_container_tool(docker_client),
        create_container_logs_tool(docker_client, safety_config),
        create_container_stats_tool(docker_client),
        create_exec_command_tool(docker_client, safety_config),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
