"""MCP Resource providers for Docker operations.

This module provides resources that can be accessed through MCP URIs:
- container://logs/{container_id} - Container logs
- container://stats/{container_id} - Container resource statistics
- compose://config/{project_name} - Compose project configuration
- compose://services/{project_name} - Compose project services
- compose://logs/{project_name}/{service_name} - Compose service logs
"""

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.errors import ContainerNotFound, MCPDockerError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class ResourceMetadata(BaseModel):
    """Metadata for a resource."""

    uri: str = Field(description="Resource URI")
    name: str = Field(description="Resource display name")
    description: str = Field(description="Resource description")
    mime_type: str = Field(default="text/plain", description="MIME type of the resource")


class ResourceContent(BaseModel):
    """Content of a resource."""

    uri: str = Field(description="Resource URI")
    mime_type: str = Field(description="MIME type")
    text: str | None = Field(default=None, description="Text content")
    blob: bytes | None = Field(default=None, description="Binary content")


class ContainerLogsResource:
    """Resource provider for container logs."""

    URI_SCHEME = "container://logs/"

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the container logs resource.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

    def get_uri(self, container_id: str) -> str:
        """Get the resource URI for a container's logs.

        Args:
            container_id: Container ID or name

        Returns:
            Resource URI

        """
        return f"{self.URI_SCHEME}{container_id}"

    def get_metadata(self, container_id: str) -> ResourceMetadata:
        """Get metadata for container logs resource.

        Args:
            container_id: Container ID or name

        Returns:
            Resource metadata

        """
        return ResourceMetadata(
            uri=self.get_uri(container_id),
            name=f"Logs for {container_id}",
            description=f"Real-time logs from container {container_id}",
            mime_type="text/plain",
        )

    async def read(
        self,
        container_id: str,
        tail: int = 100,
        follow: bool = False,
    ) -> ResourceContent:
        """Read container logs.

        Args:
            container_id: Container ID or name
            tail: Number of lines to return from the end of logs
            follow: Whether to stream logs (not recommended for resources)

        Returns:
            Resource content with logs

        Raises:
            ContainerNotFound: If container doesn't exist
            MCPDockerError: If logs cannot be retrieved

        """
        try:
            container = self.docker.client.containers.get(container_id)
            logs = container.logs(tail=tail, follow=follow)

            # Decode bytes to string
            if isinstance(logs, bytes):
                log_text = logs.decode("utf-8", errors="replace")
            else:
                # If follow=True, logs is a generator
                log_text = ""
                for line in logs:
                    if isinstance(line, bytes):
                        log_text += line.decode("utf-8", errors="replace")
                    else:
                        log_text += str(line)

            logger.debug(f"Retrieved logs for container {container_id}")

            return ResourceContent(
                uri=self.get_uri(container_id),
                mime_type="text/plain",
                text=log_text,
            )

        except Exception as e:
            if "404" in str(e):
                raise ContainerNotFound(f"Container not found: {container_id}") from e
            logger.error(f"Failed to get logs for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container logs: {e}") from e


class ContainerStatsResource:
    """Resource provider for container statistics."""

    URI_SCHEME = "container://stats/"

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the container stats resource.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

    def get_uri(self, container_id: str) -> str:
        """Get the resource URI for a container's stats.

        Args:
            container_id: Container ID or name

        Returns:
            Resource URI

        """
        return f"{self.URI_SCHEME}{container_id}"

    def get_metadata(self, container_id: str) -> ResourceMetadata:
        """Get metadata for container stats resource.

        Args:
            container_id: Container ID or name

        Returns:
            Resource metadata

        """
        return ResourceMetadata(
            uri=self.get_uri(container_id),
            name=f"Stats for {container_id}",
            description=f"Resource usage statistics for container {container_id}",
            mime_type="application/json",
        )

    async def read(self, container_id: str) -> ResourceContent:
        """Read container statistics.

        Args:
            container_id: Container ID or name

        Returns:
            Resource content with statistics

        Raises:
            ContainerNotFound: If container doesn't exist
            MCPDockerError: If stats cannot be retrieved

        """
        try:
            container = self.docker.client.containers.get(container_id)

            # Get stats (stream=False for single snapshot)
            # Note: decode parameter can only be used with stream=True
            stats = container.stats(stream=False)  # type: ignore[no-untyped-call]

            # Format stats as readable text
            cpu_stats = stats.get("cpu_stats", {})
            memory_stats = stats.get("memory_stats", {})
            network_stats = stats.get("networks", {})

            # Calculate CPU percentage
            cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            system_delta = cpu_stats.get("system_cpu_usage", 0)
            cpu_count = cpu_stats.get("online_cpus", 1)

            # Calculate memory usage
            memory_usage = memory_stats.get("usage", 0)
            memory_limit = memory_stats.get("limit", 0)
            memory_percent = (memory_usage / memory_limit * 100) if memory_limit > 0 else 0

            # Format network stats
            network_text = ""
            for interface, stats_data in network_stats.items():
                rx_bytes = stats_data.get("rx_bytes", 0)
                tx_bytes = stats_data.get("tx_bytes", 0)
                network_text += (
                    f"\n  {interface}: RX {rx_bytes / 1024:.2f} KB, TX {tx_bytes / 1024:.2f} KB"
                )

            stats_text = f"""Container Statistics for {container_id}
==========================================

CPU:
  Online CPUs: {cpu_count}
  Total Usage: {cpu_delta}
  System Usage: {system_delta}

Memory:
  Usage: {memory_usage / 1024 / 1024:.2f} MB
  Limit: {memory_limit / 1024 / 1024:.2f} MB
  Percentage: {memory_percent:.2f}%

Network:{network_text if network_text else " No network interfaces"}

Block I/O:
  {stats.get("blkio_stats", "No block I/O stats available")}
"""

            logger.debug(f"Retrieved stats for container {container_id}")

            return ResourceContent(
                uri=self.get_uri(container_id),
                mime_type="text/plain",
                text=stats_text,
            )

        except Exception as e:
            if "404" in str(e):
                raise ContainerNotFound(f"Container not found: {container_id}") from e
            logger.error(f"Failed to get stats for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container stats: {e}") from e


class ComposeConfigResource:
    """Resource provider for compose project configuration."""

    URI_SCHEME = "compose://config/"

    def __init__(self, compose_client: ComposeClient) -> None:
        """Initialize the compose config resource.

        Args:
            compose_client: Compose client wrapper

        """
        self.compose = compose_client

    def get_uri(self, project_name: str) -> str:
        """Get the resource URI for a compose project's configuration.

        Args:
            project_name: Compose project name

        Returns:
            Resource URI

        """
        return f"{self.URI_SCHEME}{project_name}"

    def get_metadata(self, project_name: str) -> ResourceMetadata:
        """Get metadata for compose config resource.

        Args:
            project_name: Compose project name

        Returns:
            Resource metadata

        """
        return ResourceMetadata(
            uri=self.get_uri(project_name),
            name=f"Config for {project_name}",
            description=f"Resolved configuration for compose project {project_name}",
            mime_type="application/json",
        )

    async def read(self, project_name: str, compose_file: str | None = None) -> ResourceContent:
        """Read compose project configuration.

        Args:
            project_name: Compose project name
            compose_file: Path to compose file (optional)

        Returns:
            Resource content with configuration

        Raises:
            ValidationError: If project doesn't exist or config is invalid
            MCPDockerError: If config cannot be retrieved

        """
        try:
            # Get config as JSON using execute to pass project_name
            result = self.compose.execute(
                "config",
                args=["--format", "json"],
                compose_file=compose_file,
                project_name=project_name,
                parse_json=True,
            )

            if not result.get("success"):
                raise MCPDockerError(f"Failed to get config: {result.get('stderr')}")

            # Format config data
            config_data = result.get("data", {})
            config_text = (
                json.dumps(config_data, indent=2)
                if isinstance(config_data, dict)
                else str(config_data)
            )

            logger.debug(f"Retrieved config for project {project_name}")

            return ResourceContent(
                uri=self.get_uri(project_name),
                mime_type="application/json",
                text=config_text,
            )

        except Exception as e:
            logger.error(f"Failed to get config for project {project_name}: {e}")
            raise MCPDockerError(f"Failed to get compose config: {e}") from e


class ComposeServicesResource:
    """Resource provider for compose project services."""

    URI_SCHEME = "compose://services/"

    def __init__(self, compose_client: ComposeClient) -> None:
        """Initialize the compose services resource.

        Args:
            compose_client: Compose client wrapper

        """
        self.compose = compose_client

    def get_uri(self, project_name: str) -> str:
        """Get the resource URI for a compose project's services.

        Args:
            project_name: Compose project name

        Returns:
            Resource URI

        """
        return f"{self.URI_SCHEME}{project_name}"

    def get_metadata(self, project_name: str) -> ResourceMetadata:
        """Get metadata for compose services resource.

        Args:
            project_name: Compose project name

        Returns:
            Resource metadata

        """
        return ResourceMetadata(
            uri=self.get_uri(project_name),
            name=f"Services for {project_name}",
            description=f"List of services in compose project {project_name}",
            mime_type="application/json",
        )

    async def read(self, project_name: str, compose_file: str | None = None) -> ResourceContent:
        """Read compose project services.

        Args:
            project_name: Compose project name
            compose_file: Path to compose file (optional)

        Returns:
            Resource content with services list

        Raises:
            ValidationError: If project doesn't exist
            MCPDockerError: If services cannot be retrieved

        """
        try:
            # Get ps output as JSON
            result = self.compose.execute(
                "ps",
                args=["--format", "json"],
                compose_file=compose_file,
                project_name=project_name,
                parse_json=True,
            )

            if not result.get("success"):
                raise MCPDockerError(f"Failed to get services: {result.get('stderr')}")

            # Format services list
            services_data = result.get("data", [])
            services_text = json.dumps(services_data, indent=2)

            logger.debug(f"Retrieved services for project {project_name}")

            return ResourceContent(
                uri=self.get_uri(project_name),
                mime_type="application/json",
                text=services_text,
            )

        except Exception as e:
            logger.error(f"Failed to get services for project {project_name}: {e}")
            raise MCPDockerError(f"Failed to get compose services: {e}") from e


class ComposeServiceLogsResource:
    """Resource provider for compose service logs."""

    URI_SCHEME = "compose://logs/"

    def __init__(self, compose_client: ComposeClient) -> None:
        """Initialize the compose service logs resource.

        Args:
            compose_client: Compose client wrapper

        """
        self.compose = compose_client

    def get_uri(self, project_name: str, service_name: str) -> str:
        """Get the resource URI for a compose service's logs.

        Args:
            project_name: Compose project name
            service_name: Service name

        Returns:
            Resource URI

        """
        return f"{self.URI_SCHEME}{project_name}/{service_name}"

    def get_metadata(self, project_name: str, service_name: str) -> ResourceMetadata:
        """Get metadata for compose service logs resource.

        Args:
            project_name: Compose project name
            service_name: Service name

        Returns:
            Resource metadata

        """
        return ResourceMetadata(
            uri=self.get_uri(project_name, service_name),
            name=f"Logs for {project_name}/{service_name}",
            description=f"Logs from service {service_name} in project {project_name}",
            mime_type="text/plain",
        )

    async def read(
        self,
        project_name: str,
        service_name: str,
        compose_file: str | None = None,
        tail: int = 100,
    ) -> ResourceContent:
        """Read compose service logs.

        Args:
            project_name: Compose project name
            service_name: Service name
            compose_file: Path to compose file (optional)
            tail: Number of lines to return from the end of logs

        Returns:
            Resource content with logs

        Raises:
            ValidationError: If service doesn't exist
            MCPDockerError: If logs cannot be retrieved

        """
        try:
            # Get logs
            result = self.compose.execute(
                "logs",
                args=[service_name, "--tail", str(tail)],
                compose_file=compose_file,
                project_name=project_name,
            )

            if not result.get("success"):
                raise MCPDockerError(f"Failed to get logs: {result.get('stderr')}")

            logs_text = result.get("stdout", "")

            logger.debug(f"Retrieved logs for service {service_name} in project {project_name}")

            return ResourceContent(
                uri=self.get_uri(project_name, service_name),
                mime_type="text/plain",
                text=logs_text,
            )

        except Exception as e:
            logger.error(
                f"Failed to get logs for service {service_name} in project {project_name}: {e}"
            )
            raise MCPDockerError(f"Failed to get compose service logs: {e}") from e


class ResourceProvider:
    """Main resource provider that manages all Docker and Compose resources."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        compose_client: ComposeClient | None = None,
    ) -> None:
        """Initialize the resource provider.

        Args:
            docker_client: Docker client wrapper
            compose_client: Compose client wrapper (optional)

        """
        self.docker = docker_client
        self.logs_resource = ContainerLogsResource(docker_client)
        self.stats_resource = ContainerStatsResource(docker_client)

        # Initialize compose resources
        self.compose = compose_client or ComposeClient()
        self.compose_config_resource = ComposeConfigResource(self.compose)
        self.compose_services_resource = ComposeServicesResource(self.compose)
        self.compose_logs_resource = ComposeServiceLogsResource(self.compose)

        logger.debug("Initialized ResourceProvider")

    def _resolve_compose_file(
        self, project_name: str, query_params: dict[str, list[str]] | None = None
    ) -> str | None:
        """Resolve the compose file path for a project.

        Args:
            project_name: Compose project name
            query_params: Query parameters from URI (optional)

        Returns:
            Path to compose file, or None if not found

        """
        # First check if file is specified in query params
        if query_params and "file" in query_params:
            file_path = query_params["file"][0]
            if Path(file_path).exists():
                logger.debug(f"Using compose file from query params: {file_path}")
                return file_path

        # Try to find file in compose_files/ directory
        # Get the project root (where pyproject.toml should be)
        # Walk up from current file location
        current = Path(__file__).resolve()
        project_root = current.parent.parent.parent
        compose_dir = project_root / "compose_files"

        if compose_dir.exists():
            # Try exact match: user-{project_name}.yml
            exact_match = compose_dir / f"user-{project_name}.yml"
            if exact_match.exists():
                logger.debug(f"Found compose file: {exact_match}")
                return str(exact_match)

            # Try with .yaml extension
            exact_match_yaml = compose_dir / f"user-{project_name}.yaml"
            if exact_match_yaml.exists():
                logger.debug(f"Found compose file: {exact_match_yaml}")
                return str(exact_match_yaml)

        logger.debug(f"No compose file found for project: {project_name}")
        return None

    def list_resources(self) -> list[ResourceMetadata]:
        """List all available resources.

        Returns:
            List of resource metadata for all containers

        """
        resources = []

        try:
            # Get all containers
            containers = self.docker.client.containers.list(all=True)

            for container in containers:
                container_id = container.short_id

                # Add logs resource
                resources.append(self.logs_resource.get_metadata(container_id))

                # Add stats resource (only for running containers)
                if container.status == "running":
                    resources.append(self.stats_resource.get_metadata(container_id))

        except Exception as e:
            logger.error(f"Failed to list resources: {e}")

        logger.debug(f"Listed {len(resources)} resources")
        return resources

    async def read_resource(self, uri: str) -> ResourceContent:
        """Read a resource by URI.

        Args:
            uri: Resource URI

        Returns:
            Resource content

        Raises:
            ValueError: If URI scheme is not recognized
            ContainerNotFound: If container doesn't exist
            MCPDockerError: If resource cannot be read

        """
        if uri.startswith(ContainerLogsResource.URI_SCHEME):
            # Extract container ID from URI using proper URL parsing
            parsed = urlparse(uri)
            container_id = parsed.path.lstrip("/")
            return await self.logs_resource.read(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            # Extract container ID from URI using proper URL parsing
            parsed = urlparse(uri)
            container_id = parsed.path.lstrip("/")
            return await self.stats_resource.read(container_id)

        if uri.startswith(ComposeConfigResource.URI_SCHEME):
            # Extract project name from URI
            parsed = urlparse(uri)
            project_name = parsed.path.lstrip("/")
            query_params = parse_qs(parsed.query) if parsed.query else None
            compose_file = self._resolve_compose_file(project_name, query_params)
            return await self.compose_config_resource.read(project_name, compose_file=compose_file)

        if uri.startswith(ComposeServicesResource.URI_SCHEME):
            # Extract project name from URI
            parsed = urlparse(uri)
            project_name = parsed.path.lstrip("/")
            query_params = parse_qs(parsed.query) if parsed.query else None
            compose_file = self._resolve_compose_file(project_name, query_params)
            return await self.compose_services_resource.read(
                project_name, compose_file=compose_file
            )

        if uri.startswith(ComposeServiceLogsResource.URI_SCHEME):
            # Extract project name and service name from URI
            parsed = urlparse(uri)
            path_parts = parsed.path.lstrip("/").split("/", 1)
            if len(path_parts) != 2:
                raise ValueError(
                    f"Invalid compose logs URI: {uri} (expected format: compose://logs/project/service)"
                )
            project_name, service_name = path_parts
            query_params = parse_qs(parsed.query) if parsed.query else None
            compose_file = self._resolve_compose_file(project_name, query_params)
            return await self.compose_logs_resource.read(
                project_name, service_name, compose_file=compose_file
            )

        raise ValueError(f"Unknown resource URI scheme: {uri}")

    def get_resource_metadata(self, uri: str) -> ResourceMetadata:
        """Get metadata for a resource by URI.

        Args:
            uri: Resource URI

        Returns:
            Resource metadata

        Raises:
            ValueError: If URI scheme is not recognized

        """
        if uri.startswith(ContainerLogsResource.URI_SCHEME):
            # Extract container ID from URI using proper URL parsing
            parsed = urlparse(uri)
            container_id = parsed.path.lstrip("/")
            return self.logs_resource.get_metadata(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            # Extract container ID from URI using proper URL parsing
            parsed = urlparse(uri)
            container_id = parsed.path.lstrip("/")
            return self.stats_resource.get_metadata(container_id)

        if uri.startswith(ComposeConfigResource.URI_SCHEME):
            # Extract project name from URI
            parsed = urlparse(uri)
            project_name = parsed.path.lstrip("/")
            return self.compose_config_resource.get_metadata(project_name)

        if uri.startswith(ComposeServicesResource.URI_SCHEME):
            # Extract project name from URI
            parsed = urlparse(uri)
            project_name = parsed.path.lstrip("/")
            return self.compose_services_resource.get_metadata(project_name)

        if uri.startswith(ComposeServiceLogsResource.URI_SCHEME):
            # Extract project name and service name from URI
            parsed = urlparse(uri)
            path_parts = parsed.path.lstrip("/").split("/", 1)
            if len(path_parts) != 2:
                raise ValueError(
                    f"Invalid compose logs URI: {uri} (expected format: compose://logs/project/service)"
                )
            project_name, service_name = path_parts
            return self.compose_logs_resource.get_metadata(project_name, service_name)

        raise ValueError(f"Unknown resource URI scheme: {uri}")
