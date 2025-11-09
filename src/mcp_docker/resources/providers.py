"""MCP Resource providers for Docker operations.

This module provides resources that can be accessed through MCP URIs:
- container://logs/{container_id} - Container logs
- container://stats/{container_id} - Container resource statistics
"""

import asyncio
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.resources.base import BaseResourceHelper
from mcp_docker.utils.errors import ContainerNotFound, MCPDockerError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.stats_formatter import (
    calculate_cpu_usage,
    calculate_memory_usage,
    format_network_stats,
)

logger = get_logger(__name__)

# Constants
MIME_TYPE_TEXT_PLAIN = "text/plain"


class ResourceMetadata(BaseModel):
    """Metadata for a resource."""

    uri: str = Field(description="Resource URI")
    name: str = Field(description="Resource display name")
    description: str = Field(description="Resource description")
    mime_type: str = Field(default=MIME_TYPE_TEXT_PLAIN, description="MIME type of the resource")


class ResourceContent(BaseModel):
    """Content of a resource."""

    uri: str = Field(description="Resource URI")
    mime_type: str = Field(description="MIME type")
    text: str | None = Field(default=None, description="Text content")
    blob: bytes | None = Field(default=None, description="Binary content")


class ContainerLogsResource(BaseResourceHelper):
    """Resource provider for container logs."""

    URI_SCHEME = "container://logs/"

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
            mime_type=MIME_TYPE_TEXT_PLAIN,
        )

    def _fetch_logs_blocking(self, container_id: str, tail: int, follow: bool) -> str:
        """Blocking helper to fetch container logs.

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name
            tail: Number of lines to return
            follow: Whether to stream logs

        Returns:
            Log text

        """
        container = self.docker.client.containers.get(container_id)
        logs = container.logs(tail=tail, follow=follow)

        # Decode bytes to string
        if isinstance(logs, bytes):
            return logs.decode("utf-8", errors="replace")

        # If follow=True, logs is a generator
        log_text = ""
        for line in logs:
            if isinstance(line, bytes):
                log_text += line.decode("utf-8", errors="replace")
            else:
                log_text += str(line)
        return log_text

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
            # Offload blocking Docker I/O to thread pool
            log_text = await asyncio.to_thread(
                self._fetch_logs_blocking, container_id, tail, follow
            )

            logger.debug(f"Retrieved logs for container {container_id}")

            return ResourceContent(
                uri=self.get_uri(container_id),
                mime_type=MIME_TYPE_TEXT_PLAIN,
                text=log_text,
            )

        except Exception as e:
            if "404" in str(e):
                raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
            logger.error(f"Failed to get logs for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container logs: {e}") from e


class ContainerStatsResource(BaseResourceHelper):
    """Resource provider for container statistics."""

    URI_SCHEME = "container://stats/"

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

    def _fetch_stats_blocking(self, container_id: str) -> dict[str, Any]:
        """Blocking helper to fetch container stats.

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name

        Returns:
            Stats dictionary

        """
        container = self.docker.client.containers.get(container_id)
        # Get stats (stream=False for single snapshot)
        # Note: decode parameter can only be used with stream=True
        stats: dict[str, Any] = container.stats(stream=False)  # type: ignore[no-untyped-call]
        return stats

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
            # Offload blocking Docker I/O to thread pool
            stats = await asyncio.to_thread(self._fetch_stats_blocking, container_id)

            # Format stats as readable text using stats formatter utilities
            cpu_info = calculate_cpu_usage(stats)
            memory_info = calculate_memory_usage(stats)
            network_text = format_network_stats(stats)

            stats_text = f"""Container Statistics for {container_id}
==========================================

CPU:
  Online CPUs: {cpu_info["online_cpus"]}
  Total Usage: {cpu_info["total_usage"]}
  System Usage: {cpu_info["system_usage"]}

Memory:
  Usage: {memory_info["usage_mb"]:.2f} MB
  Limit: {memory_info["limit_mb"]:.2f} MB
  Percentage: {memory_info["percent"]:.2f}%

Network:{network_text}

Block I/O:
  {stats.get("blkio_stats", "No block I/O stats available")}
"""

            logger.debug(f"Retrieved stats for container {container_id}")

            return ResourceContent(
                uri=self.get_uri(container_id),
                mime_type=MIME_TYPE_TEXT_PLAIN,
                text=stats_text,
            )

        except Exception as e:
            if "404" in str(e):
                raise ContainerNotFound(ERROR_CONTAINER_NOT_FOUND.format(container_id)) from e
            logger.error(f"Failed to get stats for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container stats: {e}") from e


class ResourceProvider:
    """Main resource provider that manages all Docker resources."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
    ) -> None:
        """Initialize the resource provider.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client
        self.logs_resource = ContainerLogsResource(docker_client)
        self.stats_resource = ContainerStatsResource(docker_client)

        logger.debug("Initialized ResourceProvider")

    def _parse_container_id_from_uri(self, uri: str) -> str:
        """Extract container ID from resource URI.

        Args:
            uri: Resource URI (e.g., container://logs/abc123)

        Returns:
            Container ID extracted from URI path

        """
        parsed = urlparse(uri)
        return parsed.path.lstrip("/")

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
            container_id = self._parse_container_id_from_uri(uri)
            return await self.logs_resource.read(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            container_id = self._parse_container_id_from_uri(uri)
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
            container_id = self._parse_container_id_from_uri(uri)
            return self.logs_resource.get_metadata(container_id)

        if uri.startswith(ContainerStatsResource.URI_SCHEME):
            container_id = self._parse_container_id_from_uri(uri)
            return self.stats_resource.get_metadata(container_id)

        raise ValueError(f"Unknown resource URI scheme: {uri}")
