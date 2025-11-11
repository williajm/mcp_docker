"""Docker client wrapper with connection management and health checks."""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import docker
from docker import DockerClient
from docker.errors import DockerException
from loguru import logger

from mcp_docker.config import DockerConfig
from mcp_docker.utils.errors import DockerConnectionError, DockerHealthCheckError


class DockerClientWrapper:
    """Thread-safe Docker client wrapper with health checks and connection management."""

    def __init__(self, config: DockerConfig) -> None:
        """Initialize Docker client wrapper.

        Args:
            config: Docker configuration settings

        """
        self.config = config
        self._client: DockerClient | None = None
        logger.debug(f"Initialized DockerClientWrapper with base_url={config.base_url}")

    @property
    def client(self) -> DockerClient:
        """Get Docker client with lazy initialization and health check.

        Returns:
            Initialized and healthy Docker client

        Raises:
            DockerConnectionError: If unable to connect to Docker daemon

        """
        if self._client is None:
            self._connect()
        assert self._client is not None  # _connect() raises on failure, so client is set
        return self._client

    def _connect(self) -> None:
        """Establish connection to Docker daemon with health check.

        Raises:
            DockerConnectionError: If connection fails

        """
        try:
            logger.info(f"Connecting to Docker daemon at {self.config.base_url}")

            # Check Unix socket permissions if applicable
            if self.config.base_url.startswith("unix://"):
                socket_path_str = self.config.base_url.replace("unix://", "")
                socket_path = Path(socket_path_str)
                if not socket_path.exists():
                    logger.error(f"Docker socket not found: {socket_path_str}")
                    raise DockerConnectionError(f"Docker socket not found: {socket_path_str}")

                # Check if socket is readable and writable
                try:
                    # Test read/write access by checking file stats
                    socket_path.stat()
                    # Note: Proper permission check would require os.access,
                    # but Path doesn't have equivalent
                    # We'll rely on the Docker SDK to fail if permissions are incorrect
                except OSError:
                    logger.warning(
                        f"Docker socket {socket_path} may not be accessible. "
                        f"Check file permissions and user group membership (docker group)."
                    )

            # Build TLS configuration if enabled
            tls_config = None
            if self.config.tls_verify:
                tls_config = docker.tls.TLSConfig(
                    client_cert=(
                        str(self.config.tls_client_cert),
                        str(self.config.tls_client_key),
                    )
                    if self.config.tls_client_cert and self.config.tls_client_key
                    else None,
                    ca_cert=str(self.config.tls_ca_cert) if self.config.tls_ca_cert else None,
                    verify=True,
                )

            # Create client
            self._client = docker.DockerClient(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
                tls=tls_config,
            )

            # Health check
            self._client.ping()  # type: ignore[no-untyped-call]
            logger.success("Successfully connected to Docker daemon")

        except DockerException as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            raise DockerConnectionError(f"Cannot connect to Docker daemon: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error connecting to Docker daemon: {e}")
            raise DockerConnectionError(f"Unexpected error: {e}") from e

    def health_check(self) -> dict[str, Any]:
        """Perform comprehensive health check of Docker daemon.

        Returns:
            Health status dictionary with daemon info

        Raises:
            DockerHealthCheckError: If health check fails

        """
        try:
            # Ping daemon
            self.client.ping()  # type: ignore[no-untyped-call]

            # Get daemon info
            info = self.client.info()  # type: ignore[no-untyped-call]
            version = self.client.version()  # type: ignore[no-untyped-call]

            health_status = {
                "status": "healthy",
                "daemon_info": {
                    "name": info.get("Name"),
                    "server_version": version.get("Version"),
                    "api_version": version.get("ApiVersion"),
                    "os": info.get("OperatingSystem"),
                    "architecture": info.get("Architecture"),
                    "total_memory": info.get("MemTotal"),
                    "cpus": info.get("NCPU"),
                },
                "containers": {
                    "total": info.get("Containers"),
                    "running": info.get("ContainersRunning"),
                    "paused": info.get("ContainersPaused"),
                    "stopped": info.get("ContainersStopped"),
                },
                "images": info.get("Images"),
            }

            logger.debug("Docker health check passed")
            return health_status

        except DockerException as e:
            logger.error(f"Docker health check failed: {e}")
            raise DockerHealthCheckError(f"Health check failed: {e}") from e

    def close(self) -> None:
        """Close the Docker client connection."""
        if self._client is not None:
            try:
                self._client.close()  # type: ignore[no-untyped-call]
                logger.debug("Docker client connection closed")
            except Exception as e:
                logger.warning(f"Error closing Docker client: {e}")
            finally:
                self._client = None

    @contextmanager
    def acquire(self) -> Generator[DockerClient, None, None]:
        """Context manager for Docker client access.

        Yields:
            Docker client instance

        Example:
            with wrapper.acquire() as client:
                containers = client.containers.list()

        """
        try:
            yield self.client
        except DockerException as e:
            logger.error(f"Docker operation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in Docker operation: {e}")
            raise

    def __enter__(self) -> "DockerClientWrapper":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager and close client."""
        self.close()

    def __repr__(self) -> str:
        """Return string representation."""
        status = "connected" if self._client is not None else "disconnected"
        return f"DockerClientWrapper(base_url={self.config.base_url}, status={status})"
