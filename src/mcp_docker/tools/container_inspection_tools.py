"""Container inspection and debugging tools for Docker MCP server.

This module provides tools for inspecting and debugging Docker containers:
list, inspect, logs, exec, and stats operations.
"""

from typing import Any

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field, field_validator

from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError, UnsafeOperationError
from mcp_docker.utils.json_parsing import parse_json_string_field
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    truncate_dict_fields,
    truncate_lines,
    truncate_list,
    truncate_text,
)
from mcp_docker.utils.safety import OperationSafety, validate_command_safety
from mcp_docker.utils.validation import validate_command

logger = get_logger(__name__)


# Constants for container inspection operations
# Safety limit for log streaming to prevent memory exhaustion in follow mode
MAX_STREAMING_LOG_LINES = 10000  # Prevents OOM when collecting streaming logs
CONTAINER_ID_DESCRIPTION = "Container ID or name"
TRUNCATION_INFO_DESCRIPTION = "Information about output truncation if applied"


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
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=TRUNCATION_INFO_DESCRIPTION,
    )


class InspectContainerInput(BaseModel):
    """Input for inspecting a container."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)


class InspectContainerOutput(BaseModel):
    """Output for inspecting a container."""

    details: dict[str, Any] = Field(description="Detailed container information")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=TRUNCATION_INFO_DESCRIPTION,
    )


class ContainerLogsInput(BaseModel):
    """Input for getting container logs."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
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
        description=TRUNCATION_INFO_DESCRIPTION,
    )


class ExecCommandInput(BaseModel):
    """Input for executing a command in a container."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
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
        description=TRUNCATION_INFO_DESCRIPTION,
    )


class ContainerStatsInput(BaseModel):
    """Input for getting container stats."""

    container_id: str = Field(description=CONTAINER_ID_DESCRIPTION)
    stream: bool = Field(default=False, description="Stream stats continuously")


class ContainerStatsOutput(BaseModel):
    """Output for getting container stats."""

    stats: dict[str, Any] = Field(description="Container resource usage statistics")
    container_id: str = Field(description="Container ID")


# Tool Implementations


class ListContainersTool(BaseTool):
    """List Docker containers with optional filters."""

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

            # Apply output limits
            original_count = len(container_list)
            truncation_info = {}
            if self.safety.max_list_results > 0:
                container_list, was_truncated = truncate_list(
                    container_list,
                    self.safety.max_list_results,
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
            return ListContainersOutput(
                containers=container_list,
                count=original_count,
                truncation_info=truncation_info,
            )

        except APIError as e:
            logger.error(f"Failed to list containers: {e}")
            raise DockerOperationError(f"Failed to list containers: {e}") from e


class InspectContainerTool(BaseTool):
    """Inspect a Docker container to get detailed information."""

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

            # Apply output limits if enabled
            truncation_info = {}
            if self.safety.truncate_inspect_output:
                details, truncated_fields = truncate_dict_fields(
                    details,
                    self.safety.max_inspect_field_bytes,
                )
                if truncated_fields:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        truncated_fields=truncated_fields,
                    )

            logger.info(f"Successfully inspected container: {input_data.container_id}")
            return InspectContainerOutput(details=details, truncation_info=truncation_info)

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to inspect container: {e}")
            raise DockerOperationError(f"Failed to inspect container: {e}") from e


class ContainerLogsTool(BaseTool):
    """Get logs from a Docker container."""

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

    @staticmethod
    def _decode_static_logs(logs: bytes | str) -> str:
        """Decode static logs (non-streaming mode).

        Args:
            logs: Logs as bytes or string

        Returns:
            Decoded log string

        """
        return logs.decode("utf-8") if isinstance(logs, bytes) else str(logs)

    @staticmethod
    def _collect_streaming_logs(logs: Any) -> str:
        """Collect streaming logs with safety limits.

        Args:
            logs: Generator returning log lines

        Returns:
            Collected and decoded log string

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
            # Use guard clause pattern for cleaner flow
            if input_data.follow:
                logs_str = self._collect_streaming_logs(logs)
            else:
                logs_str = self._decode_static_logs(logs)

            # Apply output limits (non-streaming logs only)
            truncation_info = {}
            if not input_data.follow and self.safety.max_log_lines > 0:
                original_lines = len(logs_str.splitlines())
                truncation_msg = (
                    f"\n[Output truncated: showing first {self.safety.max_log_lines} of "
                    f"{original_lines} lines. "
                    f"Set SAFETY_MAX_LOG_LINES=0 to disable limit.]"
                )
                logs_str, was_truncated = truncate_lines(
                    logs_str,
                    self.safety.max_log_lines,
                    truncation_message=truncation_msg,
                )

                if was_truncated:
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_count=original_lines,
                        truncated_count=self.safety.max_log_lines,
                    )

            logger.info(f"Successfully retrieved logs for container: {input_data.container_id}")
            return ContainerLogsOutput(
                logs=logs_str,
                container_id=str(container.id),
                truncation_info=truncation_info,
            )

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to get container logs: {e}")
            raise DockerOperationError(f"Failed to get container logs: {e}") from e


class ExecCommandTool(BaseTool):
    """Execute a command in a running Docker container."""

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

    def check_privileged_arguments(self, arguments: dict[str, Any]) -> None:
        """Check if privileged exec command is allowed.

        Args:
            arguments: Tool arguments

        Raises:
            PermissionError: If privileged exec is not allowed
        """
        privileged = arguments.get("privileged", False)
        if privileged and not self.safety.allow_privileged_containers:
            logger.warning("Privileged exec command blocked by safety config")
            raise UnsafeOperationError(
                "Privileged containers are not allowed. "
                "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
            )

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
            # Validate command - SECURITY: Check for dangerous patterns in ALL formats
            validate_command_safety(input_data.command)

            # Validate command structure and enforce length limits for ALL types
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

            # Apply output limits
            truncation_info = {}
            if self.safety.max_exec_output_bytes > 0:
                original_bytes = len(output_str.encode("utf-8"))
                truncation_msg = (
                    f"\n[Output truncated: showing first "
                    f"{self.safety.max_exec_output_bytes} bytes of {original_bytes} bytes. "
                    f"Set SAFETY_MAX_EXEC_OUTPUT_BYTES=0 to disable limit.]"
                )
                output_str, was_truncated = truncate_text(
                    output_str,
                    self.safety.max_exec_output_bytes,
                    truncation_message=truncation_msg,
                )

                if was_truncated:
                    truncated_bytes = len(output_str.encode("utf-8"))
                    truncation_info = create_truncation_metadata(
                        was_truncated=True,
                        original_size=original_bytes,
                        truncated_size=truncated_bytes,
                    )

            logger.info(
                f"Command executed in container: {input_data.container_id}, exit_code: {exit_code}"
            )
            return ExecCommandOutput(
                exit_code=exit_code,
                output=output_str,
                truncation_info=truncation_info,
            )

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to execute command: {e}")
            raise DockerOperationError(f"Failed to execute command: {e}") from e


class ContainerStatsTool(BaseTool):
    """Get resource usage statistics for a Docker container."""

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
                # Returns a dict directly when stream=False (decode not supported here)
                stats = container.stats(stream=False)  # type: ignore[no-untyped-call]

            logger.info(f"Successfully retrieved stats for container: {input_data.container_id}")
            return ContainerStatsOutput(stats=stats, container_id=str(container.id))

        except NotFound as e:
            logger.error(ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id))
            raise ContainerNotFound(
                ERROR_CONTAINER_NOT_FOUND.format(input_data.container_id)
            ) from e
        except APIError as e:
            logger.error(f"Failed to get container stats: {e}")
            raise DockerOperationError(f"Failed to get container stats: {e}") from e


# Export all tools
__all__ = [
    "ListContainersTool",
    "InspectContainerTool",
    "ContainerLogsTool",
    "ExecCommandTool",
    "ContainerStatsTool",
]
