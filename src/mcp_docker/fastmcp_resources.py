"""FastMCP 2.0 resource implementations.

This module provides Docker resources using FastMCP's @mcp.resource() decorator:
- container://logs/{container_id} - Container logs
- container://stats/{container_id} - Container resource statistics
"""

import asyncio
from typing import Any

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.errors import ContainerNotFound, MCPDockerError
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.messages import ERROR_CONTAINER_NOT_FOUND
from mcp_docker.utils.stats_formatter import (
    calculate_cpu_usage,
    calculate_memory_usage,
    format_network_stats,
)

logger = get_logger(__name__)


def _decode_docker_logs(logs: bytes | Any) -> str:
    """Decode Docker logs to string.

    Args:
        logs: Docker logs (bytes or generator)

    Returns:
        Decoded log text
    """
    if isinstance(logs, bytes):
        return logs.decode("utf-8", errors="replace")

    # Handle generator case
    log_text = ""
    for line in logs:
        if isinstance(line, bytes):
            log_text += line.decode("utf-8", errors="replace")
        else:
            log_text += str(line)
    return log_text


def create_container_logs_resource(
    docker_client: DockerClientWrapper,
) -> tuple[str, Any]:
    """Create the container logs FastMCP resource.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (uri_template, async_function)
    """

    async def get_container_logs(container_id: str) -> str:
        """Get logs from a Docker container.

        Args:
            container_id: Container ID or name

        Returns:
            Container logs as text

        Raises:
            ContainerNotFound: If container doesn't exist
            MCPDockerError: If logs cannot be retrieved
        """
        try:
            # Offload blocking Docker I/O to thread pool
            def _fetch_logs() -> str:
                container = docker_client.client.containers.get(container_id)
                logs = container.logs(tail=100, follow=False)
                return _decode_docker_logs(logs)

            log_text = await asyncio.to_thread(_fetch_logs)

            logger.debug(f"Retrieved logs for container {container_id}")
            return log_text

        except Exception as e:
            if "404" in str(e):
                error_msg = ERROR_CONTAINER_NOT_FOUND.format(container_id)
                raise ContainerNotFound(error_msg) from e
            logger.error(f"Failed to get logs for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container logs: {e}") from e

    return ("container://logs/{container_id}", get_container_logs)


def create_container_stats_resource(
    docker_client: DockerClientWrapper,
) -> tuple[str, Any]:
    """Create the container stats FastMCP resource.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (uri_template, async_function)
    """

    async def get_container_stats(container_id: str) -> str:
        """Get resource usage statistics for a Docker container.

        Args:
            container_id: Container ID or name

        Returns:
            Container statistics as formatted text

        Raises:
            ContainerNotFound: If container doesn't exist
            MCPDockerError: If stats cannot be retrieved
        """
        try:
            # Offload blocking Docker I/O to thread pool
            def _fetch_stats() -> dict[str, Any]:
                container = docker_client.client.containers.get(container_id)
                # Get stats (stream=False for single snapshot)
                stats: dict[str, Any] = container.stats(stream=False)  # type: ignore[no-untyped-call]
                return stats

            stats = await asyncio.to_thread(_fetch_stats)

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
            return stats_text

        except Exception as e:
            if "404" in str(e):
                error_msg = ERROR_CONTAINER_NOT_FOUND.format(container_id)
                raise ContainerNotFound(error_msg) from e
            logger.error(f"Failed to get stats for container {container_id}: {e}")
            raise MCPDockerError(f"Failed to get container stats: {e}") from e

    return ("container://stats/{container_id}", get_container_stats)


def register_all_resources(app: Any, docker_client: DockerClientWrapper) -> dict[str, list[str]]:
    """Register all Docker resources with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper

    Returns:
        Dictionary mapping category names to lists of registered resource URIs
    """
    logger.info("Registering FastMCP resources...")

    registered: dict[str, list[str]] = {"container": []}

    # Register container logs resource
    logs_uri, logs_func = create_container_logs_resource(docker_client)
    app.resource(logs_uri)(logs_func)
    registered["container"].append(logs_uri)
    logger.debug(f"Registered resource: {logs_uri}")

    # Register container stats resource
    stats_uri, stats_func = create_container_stats_resource(docker_client)
    app.resource(stats_uri)(stats_func)
    registered["container"].append(stats_uri)
    logger.debug(f"Registered resource: {stats_uri}")

    total_resources = sum(len(resources) for resources in registered.values())
    logger.info(f"Successfully registered {total_resources} FastMCP resources")

    return registered
