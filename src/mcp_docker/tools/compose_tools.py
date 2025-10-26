"""Docker Compose management tools for MCP server.

This module provides tools for managing Docker Compose projects and services,
including starting, stopping, scaling, and inspecting multi-container applications.
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from mcp_docker.tools.compose_base import ComposeBaseTool
from mcp_docker.utils.compose_validation import (
    validate_compose_content_quality,
    validate_full_compose_file,
)
from mcp_docker.utils.errors import DockerOperationError, UnsafeOperationError, ValidationError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)


# Input/Output Models - Project Management


class ComposeUpInput(BaseModel):
    """Input for starting compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to start (default: all services)",
    )
    detach: bool = Field(
        default=True,
        description="Run containers in background",
    )
    build: bool = Field(
        default=False,
        description="Build images before starting",
    )
    force_recreate: bool = Field(
        default=False,
        description="Recreate containers even if config hasn't changed",
    )
    remove_orphans: bool = Field(
        default=False,
        description="Remove containers for services not in compose file",
    )


class ComposeUpOutput(BaseModel):
    """Output for starting compose services."""

    success: bool = Field(description="Whether operation succeeded")
    message: str = Field(description="Status message")
    services_started: list[str] = Field(
        default_factory=list,
        description="List of services that were started",
    )


class ComposeDownInput(BaseModel):
    """Input for stopping and removing compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    remove_volumes: bool = Field(
        default=False,
        description="Remove named volumes declared in volumes section",
    )
    remove_orphans: bool = Field(
        default=False,
        description="Remove containers for services not in compose file",
    )
    timeout: int | None = Field(
        default=None,
        description="Timeout in seconds for container shutdown",
    )


class ComposeDownOutput(BaseModel):
    """Output for stopping compose services."""

    success: bool = Field(description="Whether operation succeeded")
    message: str = Field(description="Status message")


class ComposeRestartInput(BaseModel):
    """Input for restarting compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to restart (default: all services)",
    )
    timeout: int | None = Field(
        default=None,
        description="Timeout in seconds for container shutdown",
    )


class ComposeRestartOutput(BaseModel):
    """Output for restarting compose services."""

    success: bool = Field(description="Whether operation succeeded")
    message: str = Field(description="Status message")


class ComposeStopInput(BaseModel):
    """Input for stopping compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to stop (default: all services)",
    )
    timeout: int | None = Field(
        default=None,
        description="Timeout in seconds for container shutdown",
    )


class ComposeStopOutput(BaseModel):
    """Output for stopping compose services."""

    success: bool = Field(description="Whether operation succeeded")
    message: str = Field(description="Status message")


# Input/Output Models - Service Management


class ComposeScaleInput(BaseModel):
    """Input for scaling compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    service_replicas: dict[str, int] = Field(
        description="Service names mapped to desired replica counts. Example: {'web': 3, 'api': 2}",
    )


class ComposeScaleOutput(BaseModel):
    """Output for scaling compose services."""

    success: bool = Field(description="Whether operation succeeded")
    message: str = Field(description="Status message")
    scaled_services: dict[str, int] = Field(
        description="Services that were scaled with their replica counts",
    )


class ComposePsInput(BaseModel):
    """Input for listing compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to list (default: all services)",
    )
    all: bool = Field(
        default=False,
        description="Show all containers (including stopped)",
    )


class ComposePsOutput(BaseModel):
    """Output for listing compose services."""

    services: list[dict[str, Any]] = Field(description="List of services with their status")
    count: int = Field(description="Total number of services")


class ComposeLogsInput(BaseModel):
    """Input for getting compose service logs."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to get logs from (default: all services)",
    )
    follow: bool = Field(
        default=False,
        description="Follow log output",
    )
    tail: int | str = Field(
        default="all",
        description="Number of lines to show from end",
    )
    timestamps: bool = Field(
        default=False,
        description="Show timestamps",
    )


class ComposeLogsOutput(BaseModel):
    """Output for getting compose logs."""

    logs: str = Field(description="Combined logs from services")
    services: list[str] = Field(description="Services included in logs")


class ComposeExecInput(BaseModel):
    """Input for executing command in compose service."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    service: str = Field(description="Service name to execute command in")
    command: str | list[str] = Field(description="Command to execute")
    workdir: str | None = Field(
        default=None,
        description="Working directory for command",
    )
    user: str | None = Field(
        default=None,
        description="User to run command as",
    )
    environment: dict[str, str] | None = Field(
        default=None,
        description="Environment variables for the command",
    )
    index: int = Field(
        default=1,
        description="Container index if service has multiple instances",
    )


class ComposeExecOutput(BaseModel):
    """Output for executing command in service."""

    exit_code: int = Field(description="Command exit code")
    output: str = Field(description="Command output (stdout and stderr)")
    service: str = Field(description="Service name")


# Input/Output Models - Configuration


class ComposeValidateInput(BaseModel):
    """Input for validating compose file."""

    compose_file: str = Field(description="Path to docker-compose.yml file")


class ComposeValidateOutput(BaseModel):
    """Output for validating compose file."""

    valid: bool = Field(description="Whether the compose file is valid")
    error: str | None = Field(
        default=None,
        description="Error message if validation failed",
    )
    file: str = Field(description="Path to validated file")


class ComposeConfigInput(BaseModel):
    """Input for viewing resolved compose configuration."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Show configuration for specific services",
    )
    resolve_image_digests: bool = Field(
        default=False,
        description="Pin image tags to their digests",
    )


class ComposeConfigOutput(BaseModel):
    """Output for compose configuration."""

    config: dict[str, Any] = Field(description="Resolved compose configuration")


class ComposeBuildInput(BaseModel):
    """Input for building compose services."""

    compose_file: str = Field(description="Path to docker-compose.yml file")
    project_name: str | None = Field(
        default=None,
        description="Project name (default: directory name)",
    )
    services: list[str] | None = Field(
        default=None,
        description="Specific services to build (default: all services with build config)",
    )
    no_cache: bool = Field(
        default=False,
        description="Do not use cache when building",
    )
    pull: bool = Field(
        default=False,
        description="Always pull newer versions of base images",
    )
    parallel: bool = Field(
        default=True,
        description="Build images in parallel",
    )


class ComposeBuildOutput(BaseModel):
    """Output for building compose services."""

    success: bool = Field(description="Whether build succeeded")
    message: str = Field(description="Build status message")
    services_built: list[str] = Field(
        default_factory=list,
        description="List of services that were built",
    )


# Tool Implementations - Project Management


class ComposeUpTool(ComposeBaseTool):
    """Start services defined in a compose file."""

    output_model = ComposeUpOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_up"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Start services defined in a Docker Compose file"

    @property
    def input_schema(self) -> type[ComposeUpInput]:
        """Input schema."""
        return ComposeUpInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeUpInput) -> ComposeUpOutput:
        """Execute compose up operation.

        Args:
            input_data: Input parameters

        Returns:
            Result of starting services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Starting compose services from {file_path}")

            # Build command args
            args = ["up"]

            if input_data.detach:
                args.append("-d")

            if input_data.build:
                args.append("--build")

            if input_data.force_recreate:
                args.append("--force-recreate")

            if input_data.remove_orphans:
                args.append("--remove-orphans")

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command
            result = self.compose.execute(
                subcommand="",  # Args already include 'up'
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logger.success(f"Successfully started compose services from {file_path}")
                return ComposeUpOutput(
                    success=True,
                    message="Services started successfully",
                    services_started=input_data.services or [],
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to start services: {error_msg}")
            raise DockerOperationError(f"Failed to start services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error starting compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeDownTool(ComposeBaseTool):
    """Stop and remove compose services."""

    output_model = ComposeDownOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_down"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Stop and remove Docker Compose services"

    @property
    def input_schema(self) -> type[ComposeDownInput]:
        """Input schema."""
        return ComposeDownInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.DESTRUCTIVE

    async def execute(self, input_data: ComposeDownInput) -> ComposeDownOutput:
        """Execute compose down operation.

        Args:
            input_data: Input parameters

        Returns:
            Result of stopping services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            logger.info(f"Stopping compose services from {file_path}")

            # Build command args
            args = ["down"]

            if input_data.remove_volumes:
                args.append("--volumes")

            if input_data.remove_orphans:
                args.append("--remove-orphans")

            if input_data.timeout is not None:
                args.extend(["--timeout", str(input_data.timeout)])

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logger.success(f"Successfully stopped compose services from {file_path}")
                return ComposeDownOutput(
                    success=True,
                    message="Services stopped and removed successfully",
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to stop services: {error_msg}")
            raise DockerOperationError(f"Failed to stop services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error stopping compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeRestartTool(ComposeBaseTool):
    """Restart compose services."""

    output_model = ComposeRestartOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_restart"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Restart Docker Compose services"

    @property
    def input_schema(self) -> type[ComposeRestartInput]:
        """Input schema."""
        return ComposeRestartInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeRestartInput) -> ComposeRestartOutput:
        """Execute compose restart operation.

        Args:
            input_data: Input parameters

        Returns:
            Result of restarting services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Restarting compose services from {file_path}")

            # Build command args
            args = ["restart"]

            if input_data.timeout is not None:
                args.extend(["--timeout", str(input_data.timeout)])

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logger.success(f"Successfully restarted compose services from {file_path}")
                return ComposeRestartOutput(
                    success=True,
                    message="Services restarted successfully",
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to restart services: {error_msg}")
            raise DockerOperationError(f"Failed to restart services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error restarting compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeStopTool(ComposeBaseTool):
    """Stop compose services without removing them."""

    output_model = ComposeStopOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_stop"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Stop Docker Compose services without removing them"

    @property
    def input_schema(self) -> type[ComposeStopInput]:
        """Input schema."""
        return ComposeStopInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeStopInput) -> ComposeStopOutput:
        """Execute compose stop operation.

        Args:
            input_data: Input parameters

        Returns:
            Result of stopping services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Stopping compose services from {file_path}")

            # Build command args
            args = ["stop"]

            if input_data.timeout is not None:
                args.extend(["--timeout", str(input_data.timeout)])

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logger.success(f"Successfully stopped compose services from {file_path}")
                return ComposeStopOutput(
                    success=True,
                    message="Services stopped successfully",
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to stop services: {error_msg}")
            raise DockerOperationError(f"Failed to stop services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error stopping compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


# Tool Implementations - Service Management


class ComposeScaleTool(ComposeBaseTool):
    """Scale compose services to specified number of replicas."""

    output_model = ComposeScaleOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_scale"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Scale Docker Compose services to specified number of replicas"

    @property
    def input_schema(self) -> type[ComposeScaleInput]:
        """Input schema."""
        return ComposeScaleInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeScaleInput) -> ComposeScaleOutput:
        """Execute compose scale operation.

        Args:
            input_data: Input parameters

        Returns:
            Result of scaling services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names and replica counts
            for service, replicas in input_data.service_replicas.items():
                self.validate_service_name(service)
                if replicas < 0:
                    raise ValidationError(f"Replica count must be >= 0, got: {replicas}")

            logger.info(f"Scaling compose services from {file_path}: {input_data.service_replicas}")

            # Build command args - docker compose up -d --scale service=replicas
            args = ["up", "-d", "--no-recreate"]

            for service, replicas in input_data.service_replicas.items():
                args.extend(["--scale", f"{service}={replicas}"])

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logger.success(f"Successfully scaled compose services from {file_path}")
                return ComposeScaleOutput(
                    success=True,
                    message="Services scaled successfully",
                    scaled_services=input_data.service_replicas,
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to scale services: {error_msg}")
            raise DockerOperationError(f"Failed to scale services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error scaling compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposePsTool(ComposeBaseTool):
    """List compose services and their status."""

    output_model = ComposePsOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_ps"

    @property
    def description(self) -> str:
        """Tool description."""
        return "List Docker Compose services and their status"

    @property
    def input_schema(self) -> type[ComposePsInput]:
        """Input schema."""
        return ComposePsInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ComposePsInput) -> ComposePsOutput:
        """Execute compose ps operation.

        Args:
            input_data: Input parameters

        Returns:
            List of services with their status

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Listing compose services from {file_path}")

            # Build command args
            args = ["ps", "--format", "json"]

            if input_data.all:
                args.append("--all")

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
                parse_json=True,
            )

            if result["success"]:
                # Parse service data
                services_data = result.get("data", [])
                if not isinstance(services_data, list):
                    services_data = [services_data] if services_data else []

                logger.success(f"Found {len(services_data)} compose services")
                return ComposePsOutput(
                    services=services_data,
                    count=len(services_data),
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to list services: {error_msg}")
            raise DockerOperationError(f"Failed to list services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error listing compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeLogsTool(ComposeBaseTool):
    """Get logs from compose services."""

    output_model = ComposeLogsOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_logs"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Get logs from Docker Compose services"

    @property
    def input_schema(self) -> type[ComposeLogsInput]:
        """Input schema."""
        return ComposeLogsInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ComposeLogsInput) -> ComposeLogsOutput:
        """Execute compose logs operation.

        Args:
            input_data: Input parameters

        Returns:
            Logs from services

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            # Follow mode is not supported in subprocess execution
            if input_data.follow:
                raise ValidationError(
                    "Follow mode is not supported for compose logs. "
                    "Use tail parameter to get recent logs."
                )

            logger.info(f"Getting compose logs from {file_path}")

            # Build command args
            args = ["logs", "--no-color"]

            if input_data.timestamps:
                args.append("--timestamps")

            if input_data.tail != "all":
                args.extend(["--tail", str(input_data.tail)])

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            if result["success"]:
                logs = result.get("stdout", "")
                logger.success(f"Retrieved compose logs from {file_path}")
                return ComposeLogsOutput(
                    logs=logs,
                    services=input_data.services or [],
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to get logs: {error_msg}")
            raise DockerOperationError(f"Failed to get logs: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting compose logs: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeExecTool(ComposeBaseTool):
    """Execute command in a compose service container."""

    output_model = ComposeExecOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_exec"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Execute command in a Docker Compose service container"

    @property
    def input_schema(self) -> type[ComposeExecInput]:
        """Input schema."""
        return ComposeExecInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeExecInput) -> ComposeExecOutput:
        """Execute compose exec operation.

        Args:
            input_data: Input parameters

        Returns:
            Command execution result

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service name
            self.validate_service_name(input_data.service)

            logger.info(f"Executing command in compose service {input_data.service}")

            # Build command args
            args = ["exec", "-T"]  # -T disables TTY allocation

            if input_data.workdir:
                args.extend(["--workdir", input_data.workdir])

            if input_data.user:
                args.extend(["--user", input_data.user])

            if input_data.environment:
                for key, value in input_data.environment.items():
                    args.extend(["--env", f"{key}={value}"])

            if input_data.index != 1:
                args.extend(["--index", str(input_data.index)])

            # Add service name
            args.append(input_data.service)

            # Add command
            if isinstance(input_data.command, str):
                args.append(input_data.command)
            else:
                args.extend(input_data.command)

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
            )

            # Compose exec returns the exit code from the command
            exit_code = result["exit_code"]
            output = result.get("stdout", "") + result.get("stderr", "")

            logger.info(
                f"Command executed in service {input_data.service} with exit code {exit_code}"
            )

            return ComposeExecOutput(
                exit_code=exit_code,
                output=output,
                service=input_data.service,
            )

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error executing command in compose service: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


# Tool Implementations - Configuration


class ComposeValidateTool(ComposeBaseTool):
    """Validate a Docker Compose file."""

    output_model = ComposeValidateOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_validate"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Validate a Docker Compose file"

    @property
    def input_schema(self) -> type[ComposeValidateInput]:
        """Input schema."""
        return ComposeValidateInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ComposeValidateInput) -> ComposeValidateOutput:
        """Execute compose validation.

        Args:
            input_data: Input parameters

        Returns:
            Validation result

        Raises:
            ValidationError: If file path is invalid

        """
        try:
            # Validate file path exists and is safe
            file_path = self.validate_compose_file(input_data.compose_file)

            logger.info(f"Validating compose file: {file_path}")

            # Use compose client to validate
            result = self.compose.validate_compose_file(file_path)

            if result["valid"]:
                logger.success(f"Compose file is valid: {file_path}")
            else:
                logger.warning(f"Compose file validation failed: {result.get('error')}")

            return ComposeValidateOutput(
                valid=result["valid"],
                error=result.get("error"),
                file=str(file_path),
            )

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error validating compose file: {e}")
            # Return validation failure instead of raising
            return ComposeValidateOutput(
                valid=False,
                error=str(e),
                file=input_data.compose_file,
            )


class ComposeConfigTool(ComposeBaseTool):
    """View resolved Docker Compose configuration."""

    output_model = ComposeConfigOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_config"

    @property
    def description(self) -> str:
        """Tool description."""
        return "View resolved Docker Compose configuration"

    @property
    def input_schema(self) -> type[ComposeConfigInput]:
        """Input schema."""
        return ComposeConfigInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    async def execute(self, input_data: ComposeConfigInput) -> ComposeConfigOutput:
        """Execute compose config operation.

        Args:
            input_data: Input parameters

        Returns:
            Resolved configuration

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Getting compose configuration from {file_path}")

            # Build command args
            args = ["config", "--format", "json"]

            if input_data.resolve_image_digests:
                args.append("--resolve-image-digests")

            if input_data.services:
                args.append("--services")

            # Execute command
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
                parse_json=True,
            )

            if result["success"]:
                config_data = result.get("data", {})
                logger.success(f"Retrieved compose configuration from {file_path}")
                return ComposeConfigOutput(config=config_data)
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to get configuration: {error_msg}")
            raise DockerOperationError(f"Failed to get configuration: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting compose configuration: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


class ComposeBuildTool(ComposeBaseTool):
    """Build or rebuild compose services."""

    output_model = ComposeBuildOutput

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_build"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Build or rebuild Docker Compose services"

    @property
    def input_schema(self) -> type[ComposeBuildInput]:
        """Input schema."""
        return ComposeBuildInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    async def execute(self, input_data: ComposeBuildInput) -> ComposeBuildOutput:
        """Execute compose build operation.

        Args:
            input_data: Input parameters

        Returns:
            Build result

        Raises:
            DockerOperationError: If operation fails
            ValidationError: If inputs are invalid

        """
        try:
            # Validate compose file
            file_path = self.validate_compose_file(input_data.compose_file)

            # Validate project name if provided
            if input_data.project_name:
                self.validate_project_name(input_data.project_name)

            # Validate service names if provided
            if input_data.services:
                for service in input_data.services:
                    self.validate_service_name(service)

            logger.info(f"Building compose services from {file_path}")

            # Build command args
            args = ["build"]

            if input_data.no_cache:
                args.append("--no-cache")

            if input_data.pull:
                args.append("--pull")

            if input_data.parallel:
                args.append("--parallel")

            # Add specific services if requested
            if input_data.services:
                args.extend(input_data.services)

            # Execute command with longer timeout for builds
            result = self.compose.execute(
                subcommand="",
                args=args,
                compose_file=file_path,
                project_name=input_data.project_name,
                timeout=600,  # 10 minutes for builds
            )

            if result["success"]:
                logger.success(f"Successfully built compose services from {file_path}")
                return ComposeBuildOutput(
                    success=True,
                    message="Services built successfully",
                    services_built=input_data.services or [],
                )
            error_msg = result.get("stderr", "Unknown error")
            logger.error(f"Failed to build services: {error_msg}")
            raise DockerOperationError(f"Failed to build services: {error_msg}")

        except ValidationError:
            raise
        except DockerOperationError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error building compose services: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e


# Compose File Management


class ComposeWriteFileInput(BaseModel):
    """Input for writing a compose file."""

    filename: str = Field(
        description="Filename for the compose file (will be created in compose_files/ directory)",
    )
    content: str | dict[str, Any] = Field(
        description="Compose file content as YAML string or dictionary",
    )
    validate_content: bool = Field(
        default=True,
        description="Validate compose file content before writing",
    )


class ComposeWriteFileOutput(BaseModel):
    """Output from writing a compose file."""

    success: bool = Field(description="Whether file was written successfully")
    file_path: str = Field(description="Absolute path to the written file")
    message: str = Field(description="Success or error message")
    validation_result: dict[str, Any] | None = Field(
        default=None,
        description="Validation results if validation was performed",
    )
    warnings: list[str] | None = Field(
        default=None,
        description="Best practice warnings and recommendations (non-blocking)",
    )


class ComposeWriteFileTool(ComposeBaseTool):
    """Write a Docker Compose file to the compose_files directory.

    This tool allows creating custom compose files that are automatically validated
    for security and correctness. Files can only be written to the compose_files/
    directory to prevent arbitrary file system access.

    Security features:
    - Restricted to compose_files/ directory only
    - Path traversal prevention
    - Full compose file validation (syntax, volumes, ports, networks)
    - Dangerous volume mount detection
    """

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_write_file"

    @property
    def description(self) -> str:
        """Tool description."""
        return (
            "Write a Docker Compose file to the compose_files directory with automatic validation and best practice checks.\n\n"
            "BEST PRACTICES - Follow these for reliable services:\n"
            "✅ DO:\n"
            "  • Use official stable images (nginx:alpine, postgres:15-alpine, redis:7-alpine)\n"
            "  • Add healthchecks to databases and critical services\n"
            "  • Use named volumes for data persistence\n"
            "  • Define custom networks for service isolation\n"
            "  • Add restart policies (restart: unless-stopped)\n"
            "  • Use environment variables for configuration\n\n"
            "❌ AVOID:\n"
            "  • Complex inline code with 'python -c', 'node -e', 'ruby -e' - these are fragile!\n"
            "  • Multi-line commands with semicolons in command: fields\n"
            "  • Exposing database ports externally unless required\n"
            "  • Missing healthchecks for databases\n\n"
            "EXAMPLES:\n"
            "Good: image: nginx:alpine, ports: ['80:80'], volumes: ['./html:/usr/share/nginx/html']\n"
            "Bad:  command: python -c 'from flask import Flask; app=Flask(__name__); ...' # Will likely fail!\n\n"
            "Better approach for custom apps: Use a Dockerfile with COPY app.py /app/ and CMD ['python', '/app/app.py']\n\n"
            "The tool validates syntax but cannot detect runtime errors in application code. "
            "You'll receive warnings for anti-patterns and best practice recommendations."
        )

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level - MODERATE as it creates files but with restrictions."""
        return OperationSafety.MODERATE

    @property
    def input_schema(self) -> type[ComposeWriteFileInput]:
        """Input schema for the tool."""
        return ComposeWriteFileInput

    def _get_compose_files_dir(self) -> Path:
        """Get the absolute path to the compose_files directory.

        Returns:
            Absolute path to compose_files directory

        """
        # Get the project root (where pyproject.toml is)
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent
        compose_dir = project_root / "compose_files"

        # Create directory if it doesn't exist
        compose_dir.mkdir(exist_ok=True)

        return compose_dir

    def _validate_filename(self, filename: str) -> str:
        """Validate filename for security.

        Args:
            filename: Filename to validate

        Returns:
            Validated filename

        Raises:
            UnsafeOperationError: If filename contains unsafe patterns

        """
        # Remove any path components
        filename = Path(filename).name

        # Check for dangerous patterns
        if ".." in filename or "/" in filename or "\\" in filename:
            raise UnsafeOperationError(f"Filename contains unsafe path components: {filename}")

        # Check for hidden files
        if filename.startswith("."):
            raise UnsafeOperationError(f"Hidden files not allowed: {filename}")

        # Ensure it has a valid extension
        if not filename.endswith((".yml", ".yaml")):
            filename = f"{filename}.yml"

        # Prefix with 'user-' if not already prefixed
        if not filename.startswith("user-"):
            filename = f"user-{filename}"

        return filename

    async def execute(  # noqa: PLR0911
        self, input_data: ComposeWriteFileInput
    ) -> ComposeWriteFileOutput:
        """Write a compose file to compose_files directory.

        Args:
            input_data: Write file input parameters

        Returns:
            Write file output with file path

        Raises:
            ValidationError: If filename or content is invalid
            UnsafeOperationError: If filename contains unsafe patterns
            DockerOperationError: If file write fails

        """
        try:
            # Validate and sanitize filename
            safe_filename = self._validate_filename(input_data.filename)
            compose_dir = self._get_compose_files_dir()
            file_path = compose_dir / safe_filename

            logger.info(f"Writing compose file to {file_path}")

            # Convert content to dict if it's a string
            if isinstance(input_data.content, str):
                try:
                    compose_data = yaml.safe_load(input_data.content)
                except yaml.YAMLError as e:
                    raise ValidationError(f"Invalid YAML content: {e}") from e
            else:
                compose_data = input_data.content

            # Validate content if requested
            validation_result = None
            if input_data.validate_content:
                logger.info("Validating compose file content")
                # Write to temp file for validation
                temp_path = compose_dir / f".temp-{safe_filename}"
                try:
                    with temp_path.open("w") as f:
                        yaml.dump(compose_data, f, default_flow_style=False)

                    # Validate using existing utilities
                    validate_full_compose_file(temp_path)
                    validation_result = {"valid": True, "message": "Validation passed"}
                    logger.success("Compose file validation passed")

                finally:
                    # Clean up temp file
                    if temp_path.exists():
                        temp_path.unlink()

            # Write the actual file
            with file_path.open("w") as f:
                yaml.dump(compose_data, f, default_flow_style=False, sort_keys=False)

            logger.success(f"Successfully wrote compose file to {file_path}")

            # Perform quality validation to provide best practice recommendations
            content_str = yaml.dump(compose_data, default_flow_style=False, sort_keys=False)
            quality_check = validate_compose_content_quality(content_str)
            warnings = quality_check.get("warnings")

            # Build result message
            message = f"Compose file written to {file_path}"
            if warnings:
                logger.warning(f"Found {len(warnings)} best practice recommendations")
                message += f". Note: {len(warnings)} best practice recommendations provided."

            return ComposeWriteFileOutput(
                success=True,
                file_path=str(file_path),
                message=message,
                validation_result=validation_result,
                warnings=warnings if warnings else None,
            )

        except ValidationError:
            raise
        except UnsafeOperationError:
            raise
        except Exception as e:
            logger.error(f"Failed to write compose file: {e}")
            raise DockerOperationError(f"Failed to write compose file: {e}") from e
