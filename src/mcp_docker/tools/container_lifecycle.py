"""FastMCP container lifecycle tools."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from docker.errors import APIError, NotFound
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import DESC_CONTAINER_ID, ToolSpec
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import ContainerNotFound, DockerOperationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND

logger = get_logger(__name__)

# Constants
DEFAULT_CONTAINER_TIMEOUT_SECONDS = 10  # Default timeout for stop/restart operations

TStatusOutput = TypeVar("TStatusOutput", bound="ContainerStatusOutput")


class ContainerRefInput(BaseModel):
    """Base input referencing a container by ID or name."""

    container_id: str = Field(description=DESC_CONTAINER_ID)


class TimedContainerRefInput(ContainerRefInput):
    """Base input for operations that require an optional timeout."""

    timeout: int = Field(
        default=DEFAULT_CONTAINER_TIMEOUT_SECONDS,
        description="Timeout in seconds before killing",
    )


class ContainerStatusOutput(BaseModel):
    """Base output for container lifecycle commands returning status."""

    container_id: str = Field(description="Container ID")
    status: str = Field(description="Container status")


# Input/Output Models


class StartContainerInput(ContainerRefInput):
    """Input for starting a container."""


class StartContainerOutput(ContainerStatusOutput):
    """Output for starting a container."""


class StopContainerInput(TimedContainerRefInput):
    """Input for stopping a container."""


class StopContainerOutput(ContainerStatusOutput):
    """Output for stopping a container."""


class RestartContainerInput(TimedContainerRefInput):
    """Input for restarting a container."""


class RestartContainerOutput(ContainerStatusOutput):
    """Output for restarting a container."""


# FastMCP Tool Functions


@dataclass(slots=True)
class ContainerActionSettings:
    start_log: str
    success_log: str
    error_action: str
    already_ok_statuses: tuple[str, ...] | None = None
    already_ok_message: str | None = None
    log_suffix: str = ""


def _execute_container_action(
    docker_client: DockerClientWrapper,
    container_id: str,
    action: Callable[[Any], None],
    output_model: type[TStatusOutput],
    settings: ContainerActionSettings,
) -> TStatusOutput:
    """Run common container lifecycle operations (start/stop/restart)."""

    try:
        logger.info(f"{settings.start_log} container: {container_id}{settings.log_suffix}")
        container = docker_client.client.containers.get(container_id)

        if settings.already_ok_statuses and container.status in settings.already_ok_statuses:
            message = settings.already_ok_message or (
                f"Container {container_id} already {container.status}"
            )
            logger.info(message)
            return output_model(
                container_id=str(container.id),
                status=container.status,
            )

        action(container)
        container.reload()

        logger.info(f"{settings.success_log} container: {container_id}")
        return output_model(
            container_id=str(container.id),
            status=container.status,
        )

    except NotFound as e:
        logger.error(f"Container not found: {container_id}")
        raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
    except APIError as e:
        logger.error(f"Failed to {settings.error_action} container: {e}")
        raise DockerOperationError(f"Failed to {settings.error_action} container: {e}") from e


def create_start_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the start_container tool."""

    def start_container(
        container_id: str,
    ) -> dict[str, Any]:
        """Start a stopped Docker container."""
        result = _execute_container_action(
            docker_client,
            container_id,
            action=lambda container: container.start(),
            output_model=StartContainerOutput,
            settings=ContainerActionSettings(
                start_log="Starting",
                success_log="Successfully started",
                error_action="start",
                already_ok_statuses=("running",),
                already_ok_message=f"Container {container_id} already running",
            ),
        )
        return result.model_dump()

    return ToolSpec(
        name="docker_start_container",
        description="Start a stopped Docker container",
        safety=OperationSafety.MODERATE,
        func=start_container,
        idempotent=True,
    )


def create_stop_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the stop_container tool."""

    def stop_container(
        container_id: str,
        timeout: int = DEFAULT_CONTAINER_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Stop a running Docker container gracefully."""
        result = _execute_container_action(
            docker_client,
            container_id,
            action=lambda container: container.stop(timeout=timeout),
            output_model=StopContainerOutput,
            settings=ContainerActionSettings(
                start_log="Stopping",
                success_log="Successfully stopped",
                error_action="stop",
                already_ok_statuses=("exited", "created"),
                already_ok_message=f"Container {container_id} already stopped",
                log_suffix=f" (timeout={timeout})",
            ),
        )
        return result.model_dump()

    return ToolSpec(
        name="docker_stop_container",
        description="Stop a running Docker container gracefully",
        safety=OperationSafety.MODERATE,
        func=stop_container,
        idempotent=True,
    )


def create_restart_container_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the restart_container tool."""

    def restart_container(
        container_id: str,
        timeout: int = DEFAULT_CONTAINER_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Restart a Docker container."""
        result = _execute_container_action(
            docker_client,
            container_id,
            action=lambda container: container.restart(timeout=timeout),
            output_model=RestartContainerOutput,
            settings=ContainerActionSettings(
                start_log="Restarting",
                success_log="Successfully restarted",
                error_action="restart",
                log_suffix=f" (timeout={timeout})",
            ),
        )
        return result.model_dump()

    return ToolSpec(
        name="docker_restart_container",
        description="Restart a Docker container",
        safety=OperationSafety.MODERATE,
        func=restart_container,
        idempotent=True,
    )


def register_container_lifecycle_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> list[str]:
    """Register reversible container lifecycle tools with FastMCP."""
    tools = [
        create_start_container_tool(docker_client),
        create_stop_container_tool(docker_client),
        create_restart_container_tool(docker_client),
    ]

    return register_tools_with_filtering(app, tools, safety_config)
