"""Base classes and utilities for MCP prompts."""

from typing import Any

from mcp_docker.docker_wrapper.client import DockerClientWrapper


class BasePromptHelper:
    """Base class with common Docker data fetching utilities for prompts."""

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the prompt helper.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

    def _fetch_container_base_data_blocking(
        self,
        container_id: str,
        include_logs: bool = False,
        include_stats: bool = False,
        log_tail: int = 50,
    ) -> dict[str, Any]:
        """Fetch common container data (BLOCKING - use with asyncio.to_thread).

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name
            include_logs: Whether to fetch container logs
            include_stats: Whether to fetch stats (only if container is running)
            log_tail: Number of log lines to fetch if include_logs is True

        Returns:
            Dict with container data including short_id, name, status, attrs,
            and optionally logs and stats

        """
        container = self.docker.client.containers.get(container_id)

        data: dict[str, Any] = {
            "short_id": container.short_id,
            "name": container.name,
            "status": container.status,
            "attrs": container.attrs,
        }

        if include_logs:
            data["logs"] = container.logs(tail=log_tail).decode("utf-8", errors="replace")

        if include_stats and container.status == "running":
            data["stats"] = container.stats(stream=False)  # type: ignore[no-untyped-call]
        elif include_stats:
            data["stats"] = None

        return data
