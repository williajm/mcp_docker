"""Base tool class for Docker Compose operations."""

from abc import ABC
from pathlib import Path

from loguru import logger

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.base import BaseTool
from mcp_docker.utils.compose_validation import (
    validate_compose_file_path,
    validate_full_compose_file,
)
from mcp_docker.utils.compose_validation import (
    validate_project_name as validate_project_name_util,
)
from mcp_docker.utils.compose_validation import (
    validate_service_name as validate_service_name_util,
)


class ComposeBaseTool(BaseTool, ABC):
    """Base class for Docker Compose tools with compose-specific functionality."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
        compose_client: ComposeClient | None = None,
    ) -> None:
        """Initialize the compose tool.

        Args:
            docker_client: Docker client wrapper (for container operations)
            safety_config: Safety configuration
            compose_client: Compose client wrapper (optional, uses default if not provided)

        """
        super().__init__(docker_client, safety_config)
        self.compose = compose_client or ComposeClient()
        logger.debug(f"Initialized compose tool: {self.name}")

    def validate_compose_file(
        self,
        file_path: str | Path,
        full_validation: bool = False,
    ) -> Path:
        """Validate compose file path exists and is safe to use.

        Args:
            file_path: Path to compose file
            full_validation: If True, perform comprehensive validation including
                content checks (format, volumes, ports, etc.)

        Returns:
            Validated Path object

        Raises:
            ValidationError: If file path is invalid or unsafe
            UnsafeOperationError: If file contains security risks

        """
        # Use comprehensive validation utility
        validated_path = validate_compose_file_path(file_path)

        # Optionally perform full content validation
        if full_validation:
            _ = validate_full_compose_file(validated_path)
            logger.debug(f"Full validation passed for compose file: {validated_path}")

        logger.debug(f"Validated compose file: {validated_path}")
        return validated_path

    def validate_service_name(self, service_name: str) -> str:
        """Validate service name for compose operations.

        Args:
            service_name: Service name to validate

        Returns:
            Validated service name

        Raises:
            ValidationError: If service name is invalid

        """
        # Use comprehensive validation utility
        validated_name = validate_service_name_util(service_name)
        logger.debug(f"Validated service name: {validated_name}")
        return validated_name

    def validate_project_name(self, project_name: str) -> str:
        """Validate project name for compose operations.

        Args:
            project_name: Project name to validate

        Returns:
            Validated project name

        Raises:
            ValidationError: If project name is invalid

        """
        # Use comprehensive validation utility
        validated_name = validate_project_name_util(project_name)
        logger.debug(f"Validated project name: {validated_name}")
        return validated_name

    def verify_compose_available(self) -> None:
        """Verify that Docker Compose v2 is available.

        Raises:
            DockerConnectionError: If compose v2 is not available

        """
        version_info = self.compose.verify_compose_v2()
        logger.info(f"Docker Compose verified: {version_info['version']}")
