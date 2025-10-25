"""Stack management tools for Docker Compose.

This module provides tools for managing complete compose stacks,
including starting (up), stopping (down), and listing projects.
"""

from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.tools.base import OperationSafety, ToolResult
from mcp_docker.tools.compose.base import ComposeToolBase, ComposeToolInput
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


# ============= ComposeUp Tool =============


class ComposeUpInput(ComposeToolInput):
    """Input model for docker compose up."""

    services: list[str] | None = Field(default=None, description="Specific services to start")
    detach: bool = Field(default=True, description="Run containers in background")
    build: bool = Field(default=False, description="Build images before starting")
    force_recreate: bool = Field(
        default=False, description="Recreate containers even if config unchanged"
    )
    no_deps: bool = Field(default=False, description="Don't start linked services")
    remove_orphans: bool = Field(
        default=False, description="Remove containers for undefined services"
    )
    scale: dict[str, int] | None = Field(
        default=None, description="Scale services (service_name: count)"
    )
    timeout: int = Field(default=60, description="Timeout in seconds")
    wait: bool = Field(default=False, description="Wait for services to be healthy")
    pull: str | None = Field(
        default=None, description="Pull image before running ('always', 'missing', 'never')"
    )


class ComposeUpOutput(BaseModel):
    """Output model for docker compose up."""

    project_name: str = Field(description="Name of the compose project")
    services_started: list[str] = Field(description="List of services that were started")
    output: str = Field(description="Command output")


class ComposeUpTool(ComposeToolBase):
    """Start services defined in a docker-compose file.

    This tool starts up services according to a docker-compose.yml configuration,
    creating and starting containers as needed. Supports service scaling, building,
    and various startup options.
    """

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_up"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Start services defined in a docker-compose file"

    @property
    def input_schema(self) -> type[ComposeUpInput]:
        """Input schema."""
        return ComposeUpInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    @property
    def compose_command(self) -> str:
        """Compose command."""
        return "up"

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute docker compose up.

        Args:
            arguments: Validated input arguments

        Returns:
            ToolResult with operation outcome

        """
        try:
            input_data = ComposeUpInput(**arguments)

            # Validate inputs
            compose_path = self.validate_compose_file_path(input_data.compose_file)
            project_name = self.validate_project_name(input_data.project_name)

            # Validate compose file
            self.compose.validate_compose_file(compose_path)

            # Build command
            cmd = [self.compose_command]

            if input_data.detach:
                cmd.append("-d")

            if input_data.build:
                cmd.append("--build")

            if input_data.force_recreate:
                cmd.append("--force-recreate")

            if input_data.no_deps:
                cmd.append("--no-deps")

            if input_data.remove_orphans:
                cmd.append("--remove-orphans")

            if input_data.pull:
                cmd.extend(["--pull", input_data.pull])

            if input_data.wait:
                cmd.append("--wait")

            if input_data.timeout:
                cmd.extend(["--timeout", str(input_data.timeout)])

            # Handle scaling
            if input_data.scale:
                for service, count in input_data.scale.items():
                    cmd.extend(["--scale", f"{service}={count}"])

            # Add specific services if requested
            if input_data.services:
                cmd.extend(input_data.services)

            logger.info(
                f"Starting compose project{f' {project_name}' if project_name else ''}: "
                f"{compose_path}"
            )

            # Execute command
            output = await self.compose.run_compose_command(
                compose_file=compose_path,
                command=cmd,
                project_name=project_name,
            )

            # Determine actual project name (from directory if not specified)
            actual_project_name = project_name or compose_path.parent.name

            # Get list of services from config
            config = self.compose.validate_compose_file(compose_path)
            all_services = list(config.get("services", {}).keys())

            # Filter to requested services if specified
            started_services = (
                [s for s in all_services if s in input_data.services]
                if input_data.services
                else all_services
            )

            return ToolResult.success_result(
                data=ComposeUpOutput(
                    project_name=actual_project_name,
                    services_started=started_services,
                    output=output,
                ).model_dump(),
                operation="compose_up",
                compose_file=str(compose_path),
            )

        except Exception as e:
            return await self.handle_compose_error(e, "up")


# ============= ComposeDown Tool =============


class ComposeDownInput(ComposeToolInput):
    """Input model for docker compose down."""

    remove_images: str | None = Field(
        default=None, description="Remove images: 'local' or 'all'"
    )
    volumes: bool = Field(default=False, description="Remove named volumes")
    remove_orphans: bool = Field(default=True, description="Remove orphaned containers")
    timeout: int = Field(default=10, description="Timeout in seconds")


class ComposeDownOutput(BaseModel):
    """Output model for docker compose down."""

    project_name: str = Field(description="Name of the compose project")
    services_stopped: list[str] = Field(description="List of services that were stopped")
    output: str = Field(description="Command output")


class ComposeDownTool(ComposeToolBase):
    """Stop and remove services defined in a docker-compose file.

    This tool stops running services and removes containers, networks, and
    optionally volumes and images associated with a compose project.
    """

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_down"

    @property
    def description(self) -> str:
        """Tool description."""
        return "Stop and remove services defined in a docker-compose file"

    @property
    def input_schema(self) -> type[ComposeDownInput]:
        """Input schema."""
        return ComposeDownInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.MODERATE

    @property
    def compose_command(self) -> str:
        """Compose command."""
        return "down"

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute docker compose down.

        Args:
            arguments: Validated input arguments

        Returns:
            ToolResult with operation outcome

        """
        try:
            input_data = ComposeDownInput(**arguments)

            # Validate inputs
            compose_path = self.validate_compose_file_path(input_data.compose_file)
            project_name = self.validate_project_name(input_data.project_name)

            # Get services before stopping (for output)
            config = self.compose.validate_compose_file(compose_path)
            services = list(config.get("services", {}).keys())

            # Build command
            cmd = [self.compose_command]

            if input_data.remove_images:
                if input_data.remove_images not in ["local", "all"]:
                    return ToolResult.error_result(
                        "remove_images must be 'local' or 'all'"
                    )
                cmd.extend(["--rmi", input_data.remove_images])

            if input_data.volumes:
                cmd.append("--volumes")
                logger.warning("Removing volumes - this may result in data loss!")

            if input_data.remove_orphans:
                cmd.append("--remove-orphans")

            if input_data.timeout:
                cmd.extend(["--timeout", str(input_data.timeout)])

            logger.info(
                f"Stopping compose project{f' {project_name}' if project_name else ''}: "
                f"{compose_path}"
            )

            # Execute command
            output = await self.compose.run_compose_command(
                compose_file=compose_path,
                command=cmd,
                project_name=project_name,
            )

            # Determine actual project name
            actual_project_name = project_name or compose_path.parent.name

            return ToolResult.success_result(
                data=ComposeDownOutput(
                    project_name=actual_project_name,
                    services_stopped=services,
                    output=output,
                ).model_dump(),
                operation="compose_down",
                compose_file=str(compose_path),
            )

        except Exception as e:
            return await self.handle_compose_error(e, "down")


# ============= ComposeList Tool =============


class ComposeListInput(ComposeToolInput):
    """Input model for listing compose projects."""

    all: bool = Field(default=False, description="Include stopped projects")
    format: str | None = Field(default=None, description="Output format (json, table)")


class ComposeProjectInfo(BaseModel):
    """Information about a compose project."""

    name: str = Field(description="Project name")
    status: str = Field(description="Overall project status")
    config_files: list[str] = Field(description="Compose configuration files")
    services: list[str] = Field(description="List of services in project")
    containers: int = Field(description="Number of containers")


class ComposeListOutput(BaseModel):
    """Output model for listing compose projects."""

    projects: list[ComposeProjectInfo] = Field(description="List of compose projects")
    total: int = Field(description="Total number of projects")


class ComposeListTool(ComposeToolBase):
    """List Docker Compose projects.

    This tool lists all compose projects currently managed by Docker,
    including their status, services, and container counts.
    """

    @property
    def name(self) -> str:
        """Tool name."""
        return "docker_compose_list"

    @property
    def description(self) -> str:
        """Tool description."""
        return "List Docker Compose projects"

    @property
    def input_schema(self) -> type[ComposeListInput]:
        """Input schema."""
        return ComposeListInput

    @property
    def safety_level(self) -> OperationSafety:
        """Safety level."""
        return OperationSafety.SAFE

    @property
    def compose_command(self) -> str:
        """Compose command."""
        return "ls"

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """List compose projects.

        Args:
            arguments: Validated input arguments

        Returns:
            ToolResult with list of projects

        """
        try:
            input_data = ComposeListInput(**arguments)

            # Get all containers with compose labels
            containers = self.docker.client.containers.list(all=input_data.all)

            # Group by compose project
            projects_dict: dict[str, dict[str, Any]] = {}

            for container in containers:
                labels = container.labels
                project_name = labels.get("com.docker.compose.project")

                if not project_name:
                    continue

                if project_name not in projects_dict:
                    config_file = labels.get("com.docker.compose.project.config_files", "")
                    projects_dict[project_name] = {
                        "name": project_name,
                        "status": "stopped",
                        "config_files": config_file.split(",") if config_file else [],
                        "services": set(),
                        "containers": 0,
                    }

                service_name = labels.get("com.docker.compose.service")
                if service_name:
                    projects_dict[project_name]["services"].add(service_name)

                projects_dict[project_name]["containers"] += 1

                # Update status to running if any container is running
                if container.status == "running":
                    projects_dict[project_name]["status"] = "running"

            # Convert to list and sort
            projects_list = []
            for project_data in projects_dict.values():
                # Convert services set to list
                project_data["services"] = sorted(project_data["services"])

                projects_list.append(
                    ComposeProjectInfo(
                        name=project_data["name"],
                        status=project_data["status"],
                        config_files=project_data["config_files"],
                        services=project_data["services"],
                        containers=project_data["containers"],
                    )
                )

            # Sort by name
            projects_list.sort(key=lambda p: p.name)

            return ToolResult.success_result(
                data=ComposeListOutput(
                    projects=projects_list,
                    total=len(projects_list),
                ).model_dump(),
                operation="compose_list",
            )

        except Exception as e:
            return await self.handle_compose_error(e, "list")
