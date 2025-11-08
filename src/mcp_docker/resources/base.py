"""Base classes and utilities for MCP resources."""

from typing import Any

from mcp_docker.docker_wrapper.client import DockerClientWrapper


class BaseResourceHelper:
    """Base class with common Docker data fetching utilities for resources."""

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the resource helper.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

    def _fetch_container_blocking(self, container_id: str) -> Any:
        """Fetch container object (BLOCKING - use with asyncio.to_thread).

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name

        Returns:
            Docker container object

        """
        return self.docker.client.containers.get(container_id)
