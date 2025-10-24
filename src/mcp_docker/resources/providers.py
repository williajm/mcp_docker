"""MCP Resource providers for Docker operations.

This module provides resources that can be accessed through MCP URIs:
- container://logs/{container_id} - Container logs
- container://stats/{container_id} - Container resource statistics
"""

from pydantic import BaseModel, Field

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


class ResourceProvider:
    """Main resource provider that manages all Docker resources."""

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the resource provider.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client
        self.logs_resource = ContainerLogsResource(docker_client)
        self.stats_resource = ContainerStatsResource(docker_client)
        logger.debug("Initialized ResourceProvider")

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
            # Extract container ID from URI
            container_id = uri[len(ContainerLogsResource.URI_SCHEME) :]
            return await self.logs_resource.read(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            # Extract container ID from URI
            container_id = uri[len(ContainerStatsResource.URI_SCHEME) :]
            return await self.stats_resource.read(container_id)

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
            container_id = uri[len(ContainerLogsResource.URI_SCHEME) :]
            return self.logs_resource.get_metadata(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            container_id = uri[len(ContainerStatsResource.URI_SCHEME) :]
            return self.stats_resource.get_metadata(container_id)

        raise ValueError(f"Unknown resource URI scheme: {uri}")
