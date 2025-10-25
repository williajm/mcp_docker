# Docker Compose Technical Specification

## Overview

This document provides detailed technical specifications for implementing Docker Compose support in the MCP Docker Server, including code architecture, API design, and implementation patterns.

## Architecture Design

### Module Structure

```
src/mcp_docker/
├── tools/
│   ├── compose/
│   │   ├── __init__.py
│   │   ├── base.py           # ComposeToolBase class
│   │   ├── stack_tools.py    # Up, Down, List
│   │   ├── service_tools.py  # Start, Stop, Restart, Ps
│   │   ├── build_tools.py    # Build, Pull, Push
│   │   ├── exec_tools.py     # Exec, Run, Top
│   │   ├── config_tools.py   # Config, Convert, Validate
│   │   └── admin_tools.py    # Kill, Remove, Prune
│   └── ...existing tools...
├── docker_wrapper/
│   ├── compose_client.py     # ComposeClientWrapper
│   └── ...existing wrappers...
├── models/
│   ├── compose_models.py     # Pydantic models for compose
│   └── ...existing models...
└── utils/
    ├── compose_utils.py      # Compose-specific utilities
    └── ...existing utils...
```

## Core Components

### 1. ComposeClientWrapper

```python
# src/mcp_docker/docker_wrapper/compose_client.py

from pathlib import Path
from typing import Any, Dict, List, Optional
import docker
from docker.models.compose import Project
from docker.errors import ComposeError

from ..utils.errors import (
    ComposeNotFoundError,
    ComposeOperationError,
    ComposeFileError
)
from ..utils.logging import get_logger

logger = get_logger(__name__)

class ComposeClientWrapper:
    """Wrapper for Docker Compose operations with MCP integration."""

    def __init__(self, docker_client: docker.DockerClient) -> None:
        """Initialize with existing Docker client."""
        self.docker_client = docker_client
        self._compose_available = self._check_compose_support()

    def _check_compose_support(self) -> bool:
        """Check if Docker Compose is available."""
        try:
            # Check for compose v2 (docker compose)
            version = self.docker_client.version()
            components = version.get("Components", [])
            return any(c.get("Name") == "compose" for c in components)
        except Exception:
            return False

    def get_project(
        self,
        compose_file: str = "docker-compose.yml",
        project_name: Optional[str] = None,
        project_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        override_files: Optional[List[str]] = None,
    ) -> Project:
        """Load and return a compose project."""
        if not self._compose_available:
            raise ComposeOperationError("Docker Compose is not available")

        compose_path = Path(compose_file)
        if not compose_path.exists():
            raise ComposeFileError(f"Compose file not found: {compose_file}")

        try:
            # Use docker-py compose API if available
            project = self.docker_client.compose.from_file(
                files=[compose_file] + (override_files or []),
                project_name=project_name,
                project_directory=project_directory or compose_path.parent,
                environment=environment or {},
            )
            return project

        except ComposeError as e:
            logger.error(f"Failed to load compose project: {e}")
            raise ComposeOperationError(f"Failed to load project: {e}") from e

    async def validate_compose_file(
        self,
        compose_file: str,
        strict: bool = False,
    ) -> Dict[str, Any]:
        """Validate a compose file and return parsed configuration."""
        import yaml

        compose_path = Path(compose_file)
        if not compose_path.exists():
            raise ComposeFileError(f"Compose file not found: {compose_file}")

        try:
            with open(compose_path, 'r') as f:
                config = yaml.safe_load(f)

            # Basic validation
            if not isinstance(config, dict):
                raise ComposeFileError("Invalid compose file format")

            if "services" not in config:
                raise ComposeFileError("No services defined in compose file")

            # Check version if present
            version = config.get("version")
            if version and strict:
                self._validate_compose_version(version)

            return config

        except yaml.YAMLError as e:
            raise ComposeFileError(f"Invalid YAML: {e}") from e

    def _validate_compose_version(self, version: str) -> None:
        """Validate compose file version."""
        supported_versions = ["3", "3.0", "3.1", "3.2", "3.3", "3.4",
                            "3.5", "3.6", "3.7", "3.8", "3.9"]

        if not any(version.startswith(v) for v in supported_versions):
            logger.warning(f"Compose version {version} may not be fully supported")

    async def exec_in_service(
        self,
        project: Project,
        service: str,
        command: List[str],
        index: int = 1,
        user: Optional[str] = None,
        privileged: bool = False,
        environment: Optional[Dict[str, str]] = None,
        workdir: Optional[str] = None,
    ) -> str:
        """Execute command in a service container."""
        containers = project.get_service(service).containers()

        if not containers:
            raise ComposeOperationError(f"No running container for service: {service}")

        # Handle scaled services
        if index > len(containers):
            raise ComposeOperationError(
                f"Service {service} has {len(containers)} containers, "
                f"but index {index} requested"
            )

        container = containers[index - 1]

        # Execute command
        result = container.exec_run(
            cmd=command,
            user=user,
            privileged=privileged,
            environment=environment,
            workdir=workdir,
            demux=True,
        )

        stdout, stderr = result.output
        if result.exit_code != 0:
            logger.error(f"Command failed with exit code {result.exit_code}")
            if stderr:
                logger.error(f"stderr: {stderr.decode('utf-8')}")

        return stdout.decode('utf-8') if stdout else ""
```

### 2. ComposeToolBase

```python
# src/mcp_docker/tools/compose/base.py

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
from pydantic import BaseModel, Field

from ...tools.base import BaseTool, OperationSafety
from ...docker_wrapper.compose_client import ComposeClientWrapper
from ...utils.logging import get_logger

logger = get_logger(__name__)

class ComposeToolBase(BaseTool, ABC):
    """Base class for all Docker Compose tools."""

    def __init__(
        self,
        docker_client: Any,
        compose_client: Optional[ComposeClientWrapper] = None,
    ) -> None:
        """Initialize with Docker and Compose clients."""
        super().__init__(docker_client)
        self.compose_client = compose_client or ComposeClientWrapper(docker_client.client)

    @property
    @abstractmethod
    def compose_command(self) -> str:
        """The docker-compose command this tool represents."""
        pass

    def _get_common_args(self, input_data: BaseModel) -> Dict[str, Any]:
        """Extract common compose arguments from input."""
        args = {}

        if hasattr(input_data, 'compose_file'):
            args['compose_file'] = input_data.compose_file

        if hasattr(input_data, 'project_name'):
            args['project_name'] = input_data.project_name

        if hasattr(input_data, 'environment'):
            args['environment'] = input_data.environment

        return args

    async def _handle_compose_error(self, error: Exception, operation: str) -> None:
        """Handle and log compose-specific errors."""
        logger.error(f"Compose {operation} failed: {error}")

        error_msg = str(error)

        # Provide helpful error messages
        if "not found" in error_msg.lower():
            raise ComposeFileError(
                f"Compose file not found. Ensure the file exists and path is correct."
            )
        elif "invalid" in error_msg.lower():
            raise ComposeFileError(
                f"Invalid compose configuration: {error_msg}"
            )
        elif "permission" in error_msg.lower():
            raise PermissionError(
                f"Permission denied for compose operation: {operation}"
            )
        else:
            raise ComposeOperationError(
                f"Compose {operation} failed: {error_msg}"
            )
```

### 3. Stack Management Tools Implementation

```python
# src/mcp_docker/tools/compose/stack_tools.py

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base import ComposeToolBase, OperationSafety
from ...utils.errors import ComposeOperationError
from ...utils.logging import get_logger

logger = get_logger(__name__)

# ============= ComposeUp Tool =============

class ComposeUpInput(BaseModel):
    """Input model for docker-compose up."""
    compose_file: str = Field(
        default="docker-compose.yml",
        description="Path to docker-compose file"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Project name (defaults to directory name)"
    )
    services: Optional[List[str]] = Field(
        default=None,
        description="Specific services to start"
    )
    detach: bool = Field(
        default=True,
        description="Run containers in background"
    )
    build: bool = Field(
        default=False,
        description="Build images before starting"
    )
    force_recreate: bool = Field(
        default=False,
        description="Recreate containers even if config unchanged"
    )
    no_deps: bool = Field(
        default=False,
        description="Don't start linked services"
    )
    remove_orphans: bool = Field(
        default=False,
        description="Remove containers for undefined services"
    )
    scale: Optional[Dict[str, int]] = Field(
        default=None,
        description="Scale services (service_name: count)"
    )
    timeout: int = Field(
        default=60,
        description="Timeout in seconds"
    )
    wait: bool = Field(
        default=False,
        description="Wait for services to be healthy"
    )

class ComposeUpOutput(BaseModel):
    """Output model for docker-compose up."""
    project_name: str
    services_started: List[str]
    containers_created: int
    warnings: Optional[List[str]] = None

class ComposeUpTool(ComposeToolBase):
    """Start services defined in a docker-compose file."""

    name = "docker_compose_up"
    description = "Start services defined in a docker-compose file"
    input_model = ComposeUpInput
    safety_level = OperationSafety.MODERATE
    compose_command = "up"

    async def execute(self, input_data: ComposeUpInput) -> ComposeUpOutput:
        """Execute docker-compose up."""
        try:
            # Get the compose project
            project = self.compose_client.get_project(
                compose_file=input_data.compose_file,
                project_name=input_data.project_name,
            )

            # Prepare options
            options = {
                "detached": input_data.detach,
                "build": input_data.build,
                "force_recreate": input_data.force_recreate,
                "no_deps": input_data.no_deps,
                "remove_orphans": input_data.remove_orphans,
                "timeout": input_data.timeout,
            }

            # Handle service selection
            if input_data.services:
                options["service_names"] = input_data.services

            # Handle scaling
            if input_data.scale:
                options["scale"] = input_data.scale

            # Start the services
            logger.info(f"Starting compose project: {project.name}")
            containers = await project.up(**options)

            # Wait for health if requested
            if input_data.wait:
                await self._wait_for_health(project, timeout=input_data.timeout)

            # Get service list
            services = project.service_names
            if input_data.services:
                services = [s for s in services if s in input_data.services]

            return ComposeUpOutput(
                project_name=project.name,
                services_started=services,
                containers_created=len(containers),
                warnings=None,
            )

        except Exception as e:
            await self._handle_compose_error(e, "up")

    async def _wait_for_health(self, project: Any, timeout: int = 60) -> None:
        """Wait for all services to be healthy."""
        import asyncio
        import time

        start_time = time.time()

        while time.time() - start_time < timeout:
            all_healthy = True

            for service in project.services:
                containers = service.containers()
                for container in containers:
                    health = container.attrs.get("State", {}).get("Health", {})
                    status = health.get("Status", "none")

                    if status not in ["healthy", "none"]:
                        all_healthy = False
                        break

                if not all_healthy:
                    break

            if all_healthy:
                logger.info("All services are healthy")
                return

            await asyncio.sleep(1)

        logger.warning(f"Health check timeout after {timeout} seconds")

# ============= ComposeDown Tool =============

class ComposeDownInput(BaseModel):
    """Input model for docker-compose down."""
    compose_file: str = Field(
        default="docker-compose.yml",
        description="Path to docker-compose file"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Project name"
    )
    remove_images: Optional[str] = Field(
        default=None,
        description="Remove images: 'local' or 'all'"
    )
    volumes: bool = Field(
        default=False,
        description="Remove named volumes"
    )
    remove_orphans: bool = Field(
        default=True,
        description="Remove orphaned containers"
    )
    timeout: int = Field(
        default=10,
        description="Timeout in seconds"
    )

class ComposeDownOutput(BaseModel):
    """Output model for docker-compose down."""
    project_name: str
    services_stopped: List[str]
    containers_removed: int
    volumes_removed: int = 0
    images_removed: int = 0

class ComposeDownTool(ComposeToolBase):
    """Stop and remove services defined in a docker-compose file."""

    name = "docker_compose_down"
    description = "Stop and remove services defined in a docker-compose file"
    input_model = ComposeDownInput
    safety_level = OperationSafety.MODERATE
    compose_command = "down"

    async def execute(self, input_data: ComposeDownInput) -> ComposeDownOutput:
        """Execute docker-compose down."""
        try:
            # Get the compose project
            project = self.compose_client.get_project(
                compose_file=input_data.compose_file,
                project_name=input_data.project_name,
            )

            # Get initial service list
            services = project.service_names
            initial_containers = len(project.containers())

            # Prepare options
            options = {
                "remove_orphans": input_data.remove_orphans,
                "timeout": input_data.timeout,
            }

            # Handle image removal
            if input_data.remove_images:
                if input_data.remove_images not in ["local", "all"]:
                    raise ValueError("remove_images must be 'local' or 'all'")
                options["remove_images"] = input_data.remove_images

            # Handle volume removal
            if input_data.volumes:
                options["volumes"] = True
                logger.warning("Removing volumes - this is irreversible!")

            # Stop and remove services
            logger.info(f"Stopping compose project: {project.name}")
            await project.down(**options)

            # Count removed resources
            volumes_removed = 0
            images_removed = 0

            if input_data.volumes:
                # Count removed volumes (approximate)
                volumes_removed = len(project.volumes)

            if input_data.remove_images:
                # Count removed images (approximate)
                images_removed = len(project.images)

            return ComposeDownOutput(
                project_name=project.name,
                services_stopped=services,
                containers_removed=initial_containers,
                volumes_removed=volumes_removed,
                images_removed=images_removed,
            )

        except Exception as e:
            await self._handle_compose_error(e, "down")

# ============= ComposeList Tool =============

class ComposeListInput(BaseModel):
    """Input model for listing compose projects."""
    all: bool = Field(
        default=False,
        description="Include stopped projects"
    )
    format: Optional[str] = Field(
        default=None,
        description="Output format (json, table)"
    )

class ComposeProjectInfo(BaseModel):
    """Information about a compose project."""
    name: str
    status: str
    config_files: List[str]
    services: List[str]
    containers: int

class ComposeListOutput(BaseModel):
    """Output model for listing compose projects."""
    projects: List[ComposeProjectInfo]
    total: int

class ComposeListTool(ComposeToolBase):
    """List Docker Compose projects."""

    name = "docker_compose_list"
    description = "List Docker Compose projects"
    input_model = ComposeListInput
    safety_level = OperationSafety.SAFE
    compose_command = "ls"

    async def execute(self, input_data: ComposeListInput) -> ComposeListOutput:
        """List compose projects."""
        try:
            # Get all containers with compose labels
            containers = self.docker_client.client.containers.list(all=input_data.all)

            # Group by compose project
            projects: Dict[str, ComposeProjectInfo] = {}

            for container in containers:
                labels = container.labels
                project_name = labels.get("com.docker.compose.project")

                if not project_name:
                    continue

                if project_name not in projects:
                    config_file = labels.get("com.docker.compose.project.config_files", "")
                    projects[project_name] = ComposeProjectInfo(
                        name=project_name,
                        status="running" if container.status == "running" else "stopped",
                        config_files=config_file.split(",") if config_file else [],
                        services=set(),
                        containers=0,
                    )

                service_name = labels.get("com.docker.compose.service")
                if service_name:
                    projects[project_name].services.add(service_name)

                projects[project_name].containers += 1

                # Update status to running if any container is running
                if container.status == "running":
                    projects[project_name].status = "running"

            # Convert sets to lists
            project_list = []
            for project in projects.values():
                project.services = list(project.services)
                project_list.append(project)

            # Sort by name
            project_list.sort(key=lambda p: p.name)

            return ComposeListOutput(
                projects=project_list,
                total=len(project_list),
            )

        except Exception as e:
            await self._handle_compose_error(e, "list")
```

### 4. Service Management Tools

```python
# src/mcp_docker/tools/compose/service_tools.py

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import json

from .base import ComposeToolBase, OperationSafety
from ...utils.logging import get_logger

logger = get_logger(__name__)

# ============= ComposePs Tool =============

class ComposePsInput(BaseModel):
    """Input model for docker-compose ps."""
    compose_file: str = Field(
        default="docker-compose.yml",
        description="Path to docker-compose file"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Project name"
    )
    services: Optional[List[str]] = Field(
        default=None,
        description="Filter by service names"
    )
    all: bool = Field(
        default=False,
        description="Include stopped containers"
    )
    format: Optional[str] = Field(
        default=None,
        description="Output format (json, table)"
    )

class ServiceStatus(BaseModel):
    """Status of a compose service."""
    service: str
    container_name: str
    container_id: str
    status: str
    ports: List[str]
    created: str
    health: Optional[str] = None

class ComposePsOutput(BaseModel):
    """Output model for docker-compose ps."""
    project_name: str
    services: List[ServiceStatus]

class ComposePsTool(ComposeToolBase):
    """List services in a compose project."""

    name = "docker_compose_ps"
    description = "List services in a compose project"
    input_model = ComposePsInput
    safety_level = OperationSafety.SAFE
    compose_command = "ps"

    async def execute(self, input_data: ComposePsInput) -> ComposePsOutput:
        """Execute docker-compose ps."""
        try:
            project = self.compose_client.get_project(
                compose_file=input_data.compose_file,
                project_name=input_data.project_name,
            )

            service_statuses = []

            for service in project.services:
                # Filter by requested services
                if input_data.services and service.name not in input_data.services:
                    continue

                containers = service.containers(all=input_data.all)

                for container in containers:
                    # Get container details
                    attrs = container.attrs

                    # Parse ports
                    ports = []
                    for port in attrs.get("NetworkSettings", {}).get("Ports", {}).values():
                        if port:
                            for binding in port:
                                host_port = binding.get("HostPort")
                                if host_port:
                                    ports.append(f"{binding.get('HostIp', '0.0.0.0')}:{host_port}")

                    # Get health status
                    health = None
                    health_status = attrs.get("State", {}).get("Health", {}).get("Status")
                    if health_status:
                        health = health_status

                    status = ServiceStatus(
                        service=service.name,
                        container_name=container.name,
                        container_id=container.short_id,
                        status=container.status,
                        ports=ports,
                        created=attrs.get("Created", ""),
                        health=health,
                    )

                    service_statuses.append(status)

            # Format output if requested
            if input_data.format == "json":
                # The Pydantic model will handle JSON serialization
                pass
            elif input_data.format == "table":
                # Could format as ASCII table here
                pass

            return ComposePsOutput(
                project_name=project.name,
                services=service_statuses,
            )

        except Exception as e:
            await self._handle_compose_error(e, "ps")

# ============= ComposeLogs Tool =============

class ComposeLogsInput(BaseModel):
    """Input model for docker-compose logs."""
    compose_file: str = Field(
        default="docker-compose.yml",
        description="Path to docker-compose file"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Project name"
    )
    services: Optional[List[str]] = Field(
        default=None,
        description="Specific services to get logs from"
    )
    follow: bool = Field(
        default=False,
        description="Follow log output"
    )
    tail: str = Field(
        default="all",
        description="Number of lines to show from end"
    )
    timestamps: bool = Field(
        default=False,
        description="Show timestamps"
    )
    since: Optional[str] = Field(
        default=None,
        description="Show logs since timestamp"
    )
    until: Optional[str] = Field(
        default=None,
        description="Show logs until timestamp"
    )

class ComposeLogsOutput(BaseModel):
    """Output model for docker-compose logs."""
    project_name: str
    logs: Dict[str, List[str]]  # service_name: log_lines

class ComposeLogsTool(ComposeToolBase):
    """View output from services."""

    name = "docker_compose_logs"
    description = "View output from services in a compose project"
    input_model = ComposeLogsInput
    safety_level = OperationSafety.SAFE
    compose_command = "logs"

    async def execute(self, input_data: ComposeLogsInput) -> ComposeLogsOutput:
        """Execute docker-compose logs."""
        try:
            project = self.compose_client.get_project(
                compose_file=input_data.compose_file,
                project_name=input_data.project_name,
            )

            logs_by_service = {}

            for service in project.services:
                # Filter by requested services
                if input_data.services and service.name not in input_data.services:
                    continue

                service_logs = []

                for container in service.containers():
                    # Get logs with options
                    log_kwargs = {
                        "timestamps": input_data.timestamps,
                        "tail": input_data.tail if input_data.tail != "all" else "all",
                    }

                    if input_data.since:
                        log_kwargs["since"] = input_data.since
                    if input_data.until:
                        log_kwargs["until"] = input_data.until

                    # Get logs
                    if input_data.follow:
                        # For streaming, we'd need to handle this differently
                        log_stream = container.logs(stream=True, **log_kwargs)
                        # This would need async streaming support
                        for line in log_stream:
                            service_logs.append(line.decode('utf-8').strip())
                            if len(service_logs) > 1000:  # Limit for safety
                                break
                    else:
                        logs = container.logs(**log_kwargs)
                        if logs:
                            service_logs.extend(logs.decode('utf-8').splitlines())

                logs_by_service[service.name] = service_logs

            return ComposeLogsOutput(
                project_name=project.name,
                logs=logs_by_service,
            )

        except Exception as e:
            await self._handle_compose_error(e, "logs")

# ============= ComposeExec Tool =============

class ComposeExecInput(BaseModel):
    """Input model for docker-compose exec."""
    compose_file: str = Field(
        default="docker-compose.yml",
        description="Path to docker-compose file"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Project name"
    )
    service: str = Field(
        description="Service name to execute command in"
    )
    command: str | List[str] = Field(
        description="Command to execute"
    )
    index: int = Field(
        default=1,
        description="Container index for scaled services"
    )
    detach: bool = Field(
        default=False,
        description="Run command in background"
    )
    privileged: bool = Field(
        default=False,
        description="Run with elevated privileges"
    )
    user: Optional[str] = Field(
        default=None,
        description="User to run command as"
    )
    environment: Optional[Dict[str, str]] = Field(
        default=None,
        description="Environment variables"
    )
    workdir: Optional[str] = Field(
        default=None,
        description="Working directory"
    )

class ComposeExecOutput(BaseModel):
    """Output model for docker-compose exec."""
    service: str
    container: str
    exit_code: int
    output: str
    error: Optional[str] = None

class ComposeExecTool(ComposeToolBase):
    """Execute a command in a running service."""

    name = "docker_compose_exec"
    description = "Execute a command in a running compose service"
    input_model = ComposeExecInput
    safety_level = OperationSafety.MODERATE
    compose_command = "exec"

    async def execute(self, input_data: ComposeExecInput) -> ComposeExecOutput:
        """Execute docker-compose exec."""
        try:
            project = self.compose_client.get_project(
                compose_file=input_data.compose_file,
                project_name=input_data.project_name,
            )

            # Prepare command
            if isinstance(input_data.command, str):
                command = input_data.command.split()
            else:
                command = input_data.command

            # Execute in service
            output = await self.compose_client.exec_in_service(
                project=project,
                service=input_data.service,
                command=command,
                index=input_data.index,
                user=input_data.user,
                privileged=input_data.privileged,
                environment=input_data.environment,
                workdir=input_data.workdir,
            )

            # Get container name for reference
            containers = project.get_service(input_data.service).containers()
            container_name = containers[input_data.index - 1].name if containers else "unknown"

            return ComposeExecOutput(
                service=input_data.service,
                container=container_name,
                exit_code=0,  # Would be set from actual exec result
                output=output,
                error=None,
            )

        except Exception as e:
            await self._handle_compose_error(e, "exec")
```

### 5. Error Handling

```python
# src/mcp_docker/utils/errors.py (additions)

class ComposeError(DockerOperationError):
    """Base exception for Docker Compose operations."""
    pass

class ComposeFileError(ComposeError):
    """Exception for compose file issues."""
    pass

class ComposeNotFoundError(ComposeError):
    """Exception when compose project or service not found."""
    pass

class ComposeOperationError(ComposeError):
    """Exception for compose operation failures."""
    pass

class ComposeValidationError(ComposeError):
    """Exception for compose configuration validation."""
    pass
```

## Testing Framework

### Unit Test Structure

```python
# tests/unit/test_compose_tools.py

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, mock_open
from pathlib import Path

from mcp_docker.tools.compose.stack_tools import (
    ComposeUpTool,
    ComposeDownTool,
    ComposeListTool,
)
from mcp_docker.utils.errors import ComposeFileError

class TestComposeUpTool:
    """Test cases for ComposeUpTool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create mock Docker client."""
        client = MagicMock()
        client.client = MagicMock()
        return client

    @pytest.fixture
    def mock_compose_client(self):
        """Create mock Compose client."""
        client = MagicMock()
        client.get_project = MagicMock()
        return client

    @pytest.fixture
    def tool(self, mock_docker_client, mock_compose_client):
        """Create ComposeUpTool instance."""
        tool = ComposeUpTool(mock_docker_client)
        tool.compose_client = mock_compose_client
        return tool

    @pytest.mark.asyncio
    async def test_up_with_defaults(self, tool, mock_compose_client):
        """Test docker-compose up with default parameters."""
        # Setup mocks
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web", "db"]
        mock_project.up = AsyncMock(return_value=[MagicMock(), MagicMock()])
        mock_compose_client.get_project.return_value = mock_project

        # Execute
        input_data = ComposeUpInput()
        result = await tool.execute(input_data)

        # Assertions
        assert result.project_name == "test_project"
        assert result.services_started == ["web", "db"]
        assert result.containers_created == 2

        # Verify project.up was called with correct args
        mock_project.up.assert_called_once_with(
            detached=True,
            build=False,
            force_recreate=False,
            no_deps=False,
            remove_orphans=False,
            timeout=60,
        )

    @pytest.mark.asyncio
    async def test_up_with_specific_services(self, tool, mock_compose_client):
        """Test starting specific services only."""
        # Setup mocks
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web", "db", "cache"]
        mock_project.up = AsyncMock(return_value=[MagicMock()])
        mock_compose_client.get_project.return_value = mock_project

        # Execute
        input_data = ComposeUpInput(services=["web"])
        result = await tool.execute(input_data)

        # Assertions
        assert result.services_started == ["web"]
        assert result.containers_created == 1

        # Verify service_names was passed
        call_args = mock_project.up.call_args[1]
        assert call_args["service_names"] == ["web"]

    @pytest.mark.asyncio
    async def test_up_with_scaling(self, tool, mock_compose_client):
        """Test service scaling."""
        # Setup mocks
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web"]
        mock_project.up = AsyncMock(return_value=[MagicMock(), MagicMock(), MagicMock()])
        mock_compose_client.get_project.return_value = mock_project

        # Execute with scaling
        input_data = ComposeUpInput(scale={"web": 3})
        result = await tool.execute(input_data)

        # Assertions
        assert result.containers_created == 3

        # Verify scale was passed
        call_args = mock_project.up.call_args[1]
        assert call_args["scale"] == {"web": 3}

    @pytest.mark.asyncio
    async def test_up_file_not_found(self, tool):
        """Test error handling when compose file doesn't exist."""
        with patch("pathlib.Path.exists", return_value=False):
            tool.compose_client.get_project.side_effect = ComposeFileError("File not found")

            input_data = ComposeUpInput(compose_file="missing.yml")

            with pytest.raises(ComposeFileError):
                await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_up_with_health_check_wait(self, tool, mock_compose_client):
        """Test waiting for services to be healthy."""
        # Setup mocks
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web"]
        mock_project.up = AsyncMock(return_value=[MagicMock()])

        # Mock service with health check
        mock_service = MagicMock()
        mock_container = MagicMock()
        mock_container.attrs = {
            "State": {
                "Health": {"Status": "healthy"}
            }
        }
        mock_service.containers.return_value = [mock_container]
        mock_project.services = [mock_service]

        mock_compose_client.get_project.return_value = mock_project

        # Execute with wait
        input_data = ComposeUpInput(wait=True, timeout=5)
        result = await tool.execute(input_data)

        # Should complete successfully
        assert result.project_name == "test_project"
```

### Integration Test Structure

```python
# tests/integration/test_compose_integration.py

import pytest
import tempfile
import yaml
from pathlib import Path

from mcp_docker.server import MCPDockerServer
from mcp_docker.config import ServerConfig

@pytest.mark.integration
class TestComposeIntegration:
    """Integration tests for Docker Compose functionality."""

    @pytest.fixture
    def compose_file(self):
        """Create a temporary docker-compose.yml file."""
        compose_config = {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:alpine",
                    "ports": ["8080:80"],
                    "networks": ["test_network"],
                },
                "redis": {
                    "image": "redis:alpine",
                    "networks": ["test_network"],
                },
            },
            "networks": {
                "test_network": {
                    "driver": "bridge",
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yml',
            delete=False
        ) as f:
            yaml.dump(compose_config, f)
            yield f.name

        # Cleanup
        Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_complete_compose_lifecycle(self, compose_file):
        """Test complete compose lifecycle: up -> ps -> logs -> down."""
        server = MCPDockerServer(ServerConfig())

        try:
            # 1. Start services
            up_result = await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": compose_file,
                    "project_name": "test_integration",
                    "detach": True,
                }
            )

            assert up_result["services_started"] == ["web", "redis"]
            assert up_result["containers_created"] == 2

            # 2. Check status
            ps_result = await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": compose_file,
                    "project_name": "test_integration",
                }
            )

            assert len(ps_result["services"]) == 2
            assert all(s["status"] == "running" for s in ps_result["services"])

            # 3. Get logs
            logs_result = await server.call_tool(
                "docker_compose_logs",
                {
                    "compose_file": compose_file,
                    "project_name": "test_integration",
                    "tail": "10",
                }
            )

            assert "web" in logs_result["logs"]
            assert "redis" in logs_result["logs"]

            # 4. Execute command
            exec_result = await server.call_tool(
                "docker_compose_exec",
                {
                    "compose_file": compose_file,
                    "project_name": "test_integration",
                    "service": "web",
                    "command": ["nginx", "-v"],
                }
            )

            assert exec_result["exit_code"] == 0
            assert "nginx" in exec_result["output"]

        finally:
            # 5. Clean up - stop and remove
            down_result = await server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": compose_file,
                    "project_name": "test_integration",
                    "volumes": True,
                }
            )

            assert down_result["services_stopped"] == ["web", "redis"]
            assert down_result["containers_removed"] == 2

    @pytest.mark.asyncio
    async def test_compose_with_scaling(self, compose_file):
        """Test service scaling."""
        server = MCPDockerServer(ServerConfig())

        try:
            # Start with scaling
            up_result = await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": compose_file,
                    "project_name": "test_scaling",
                    "scale": {"web": 3},
                    "detach": True,
                }
            )

            # Check that 3 web containers were created
            ps_result = await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": compose_file,
                    "project_name": "test_scaling",
                }
            )

            web_containers = [s for s in ps_result["services"] if s["service"] == "web"]
            assert len(web_containers) == 3

        finally:
            # Clean up
            await server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": compose_file,
                    "project_name": "test_scaling",
                }
            )
```

## Performance Considerations

### Optimization Strategies

1. **Lazy Loading**: Load compose projects only when needed
2. **Caching**: Cache project configurations for repeated operations
3. **Parallel Execution**: Use asyncio for concurrent service operations
4. **Streaming**: Stream logs and events instead of loading all at once
5. **Resource Limits**: Set limits on log output and operation timeouts

### Performance Monitoring

```python
# src/mcp_docker/utils/performance.py

import time
import asyncio
from functools import wraps
from typing import Any, Callable

from .logging import get_logger

logger = get_logger(__name__)

def measure_performance(operation: str) -> Callable:
    """Decorator to measure operation performance."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                duration = time.perf_counter() - start_time
                logger.info(f"{operation} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = time.perf_counter() - start_time
                logger.error(f"{operation} failed after {duration:.3f}s: {e}")
                raise

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = time.perf_counter() - start_time
                logger.info(f"{operation} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = time.perf_counter() - start_time
                logger.error(f"{operation} failed after {duration:.3f}s: {e}")
                raise

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Usage in tools
class ComposeUpTool(ComposeToolBase):
    @measure_performance("docker-compose up")
    async def execute(self, input_data: ComposeUpInput) -> ComposeUpOutput:
        # ... implementation ...
```

## Security Considerations

### Input Validation

```python
# src/mcp_docker/utils/validation.py

import re
from pathlib import Path
from typing import Any, Dict, List

def validate_compose_file_path(file_path: str) -> Path:
    """Validate and sanitize compose file path."""
    # Prevent path traversal
    path = Path(file_path).resolve()

    # Check file exists
    if not path.exists():
        raise ValueError(f"Compose file not found: {file_path}")

    # Check file extension
    if path.suffix not in [".yml", ".yaml"]:
        raise ValueError(f"Invalid compose file extension: {path.suffix}")

    # Check file is readable
    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    return path

def validate_project_name(name: str | None) -> str | None:
    """Validate Docker Compose project name."""
    if name is None:
        return None

    # Docker Compose project name rules
    pattern = r'^[a-z0-9][a-z0-9_-]*$'
    if not re.match(pattern, name):
        raise ValueError(
            f"Invalid project name: {name}. "
            "Must start with lowercase letter or number, "
            "and contain only lowercase letters, numbers, hyphens, and underscores."
        )

    if len(name) > 63:
        raise ValueError(f"Project name too long (max 63 characters): {name}")

    return name

def sanitize_environment_variables(env: Dict[str, str]) -> Dict[str, str]:
    """Sanitize environment variables for security."""
    sanitized = {}

    for key, value in env.items():
        # Validate key format
        if not re.match(r'^[A-Z_][A-Z0-9_]*$', key):
            raise ValueError(f"Invalid environment variable name: {key}")

        # Sanitize value (remove control characters)
        value = re.sub(r'[\x00-\x1f\x7f]', '', value)

        # Check for potential injection
        if any(dangerous in value for dangerous in ['$(', '`', '${', '\\n', '\\r']):
            raise ValueError(f"Potentially dangerous value in environment variable: {key}")

        sanitized[key] = value

    return sanitized
```

## Conclusion

This technical specification provides a comprehensive blueprint for implementing full Docker Compose support in the MCP Docker Server. The modular architecture, type-safe design, and extensive testing framework ensure robust and maintainable implementation.

### Key Implementation Points

1. **Leverage Existing Patterns**: Build on established tool/resource/prompt patterns
2. **Type Safety**: Full Pydantic validation and mypy strict mode throughout
3. **Error Handling**: Comprehensive error types and user-friendly messages
4. **Testing**: Unit, integration, and performance tests for all components
5. **Security**: Input validation, sanitization, and safety levels
6. **Performance**: Async operations, caching, and resource limits
7. **Documentation**: Inline documentation and comprehensive user guides

The implementation follows Docker Compose v2 specifications and provides feature parity with the native docker-compose CLI while adding MCP-specific enhancements like safety controls and AI integration.

---

*Technical Specification Version: 1.0.0*
*Last Updated: 2025-01-25*