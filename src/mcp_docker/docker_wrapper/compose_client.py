"""Docker Compose client wrapper for managing compose operations."""

import subprocess
from pathlib import Path
from typing import Any

import yaml
from docker import DockerClient
from loguru import logger

from mcp_docker.utils.errors import (
    ComposeFileError,
    ComposeNotFoundError,
    ComposeOperationError,
    ComposeValidationError,
)


class ComposeClientWrapper:
    """Wrapper for Docker Compose operations with validation and error handling."""

    def __init__(self, docker_client: DockerClient) -> None:
        """Initialize the compose client wrapper.

        Args:
            docker_client: Initialized Docker client instance

        """
        self.docker_client = docker_client
        self._compose_available = self._check_compose_support()
        logger.debug("Initialized ComposeClientWrapper")

    def _check_compose_support(self) -> bool:
        """Check if Docker Compose v2 is available.

        Returns:
            True if compose is available, False otherwise

        """
        try:
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            logger.debug(f"Docker Compose check: {result.stdout.strip()}")
            return "Docker Compose version" in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Docker Compose v2 not available")
            return False

    def validate_compose_file(
        self, compose_file: str | Path, strict: bool = False
    ) -> dict[str, Any]:
        """Validate and parse a compose file.

        Args:
            compose_file: Path to docker-compose.yml file
            strict: If True, perform strict validation

        Returns:
            Parsed compose configuration

        Raises:
            ComposeFileError: If file doesn't exist or is invalid
            ComposeValidationError: If validation fails

        """
        compose_path = Path(compose_file)

        if not compose_path.exists():
            raise ComposeFileError(f"Compose file not found: {compose_file}")

        if not compose_path.is_file():
            raise ComposeFileError(f"Not a file: {compose_file}")

        try:
            with compose_path.open("r") as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                raise ComposeValidationError("Invalid compose file format: must be a YAML object")

            if "services" not in config:
                raise ComposeValidationError("No services defined in compose file")

            # Check version if present and strict mode enabled
            version = config.get("version")
            if version and strict:
                self._validate_compose_version(str(version))

            logger.debug(f"Validated compose file: {compose_file}")
            return config

        except yaml.YAMLError as e:
            raise ComposeFileError(f"Invalid YAML in compose file: {e}") from e

    def _validate_compose_version(self, version: str) -> None:
        """Validate the compose file version.

        Args:
            version: Compose file version string

        """
        supported_versions = [
            "3",
            "3.0",
            "3.1",
            "3.2",
            "3.3",
            "3.4",
            "3.5",
            "3.6",
            "3.7",
            "3.8",
            "3.9",
        ]

        if not any(version.startswith(v) for v in supported_versions):
            logger.warning(f"Compose version {version} may not be fully supported")

    async def run_compose_command(
        self,
        compose_file: str | Path,
        command: list[str],
        project_name: str | None = None,
        env: dict[str, str] | None = None,
        capture_output: bool = True,
    ) -> str:
        """Run a docker compose command using subprocess.

        Args:
            compose_file: Path to docker-compose.yml
            command: Compose command and arguments (e.g., ['up', '-d'])
            project_name: Optional project name override
            env: Optional environment variables
            capture_output: Whether to capture and return output

        Returns:
            Command output if capture_output=True

        Raises:
            ComposeOperationError: If command execution fails

        """
        if not self._compose_available:
            raise ComposeOperationError("Docker Compose is not available")

        compose_path = Path(compose_file)
        if not compose_path.exists():
            raise ComposeFileError(f"Compose file not found: {compose_file}")

        # Build command
        cmd = ["docker", "compose", "-f", str(compose_path)]

        if project_name:
            cmd.extend(["-p", project_name])

        cmd.extend(command)

        try:
            logger.debug(f"Running compose command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                check=True,
                env=env,
                cwd=compose_path.parent,
            )

            if capture_output:
                return result.stdout

            return ""

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.error(f"Compose command failed: {error_msg}")
            raise ComposeOperationError(f"Compose operation failed: {error_msg}") from e
        except Exception as e:
            logger.error(f"Unexpected error running compose command: {e}")
            raise ComposeOperationError(f"Unexpected error: {e}") from e

    def get_project_containers(
        self, project_name: str, all_containers: bool = False
    ) -> list[dict[str, Any]]:
        """Get containers for a compose project.

        Args:
            project_name: Name of the compose project
            all_containers: Include stopped containers

        Returns:
            List of container information dictionaries

        Raises:
            ComposeNotFoundError: If project not found

        """
        try:
            containers = self.docker_client.containers.list(
                all=all_containers,
                filters={"label": f"com.docker.compose.project={project_name}"},
            )

            if not containers and not all_containers:
                # Try with all=True to see if any exist
                all_containers_check = self.docker_client.containers.list(
                    all=True,
                    filters={"label": f"com.docker.compose.project={project_name}"},
                )
                if not all_containers_check:
                    raise ComposeNotFoundError(f"No project found with name: {project_name}")

            container_list = []
            for container in containers:
                labels = container.labels
                container_list.append(
                    {
                        "id": container.short_id,
                        "name": container.name,
                        "service": labels.get("com.docker.compose.service", "unknown"),
                        "project": labels.get("com.docker.compose.project", project_name),
                        "status": container.status,
                        "image": (
                            container.image.tags[0]
                            if container.image.tags
                            else container.image.short_id
                        )
                    }
                )

            return container_list

        except Exception as e:
            logger.error(f"Error getting project containers: {e}")
            raise ComposeOperationError(f"Failed to get project containers: {e}") from e

    def __repr__(self) -> str:
        """Return string representation."""
        status = "available" if self._compose_available else "unavailable"
        return f"ComposeClientWrapper(compose_status={status})"
