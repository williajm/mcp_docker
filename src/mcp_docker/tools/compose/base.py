"""Base class for Docker Compose tools."""

import re
from abc import abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.docker_wrapper.compose_client import ComposeClientWrapper
from mcp_docker.tools.base import BaseTool, ToolInput, ToolResult
from mcp_docker.utils.errors import ComposeFileError, ComposeValidationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class ComposeToolInput(ToolInput):
    """Base input model for compose tools with common parameters."""

    compose_file: str = Field(
        default="docker-compose.yml", description="Path to docker-compose file"
    )
    project_name: str | None = Field(
        default=None, description="Project name (defaults to directory name)"
    )


class ComposeToolBase(BaseTool):
    """Base class for all Docker Compose tools.

    Extends BaseTool with compose-specific functionality including
    compose file validation, project management, and compose client access.
    """

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
        compose_client: ComposeClientWrapper | None = None,
    ) -> None:
        """Initialize the compose tool.

        Args:
            docker_client: Docker client wrapper
            safety_config: Safety configuration
            compose_client: Optional compose client wrapper (created if not provided)

        """
        super().__init__(docker_client, safety_config)
        self.compose = compose_client or ComposeClientWrapper(docker_client.client)
        logger.debug(f"Initialized compose tool: {self.name}")

    @property
    @abstractmethod
    def compose_command(self) -> str:
        """The docker compose command this tool represents.

        Returns:
            Command name (e.g., 'up', 'down', 'ps')

        """

    def validate_compose_file_path(self, file_path: str | Path) -> Path:
        """Validate and resolve compose file path.

        Args:
            file_path: Path to compose file

        Returns:
            Resolved Path object

        Raises:
            ComposeFileError: If file doesn't exist or invalid

        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise ComposeFileError(f"Compose file not found: {file_path}")

        if not path.is_file():
            raise ComposeFileError(f"Not a file: {file_path}")

        if path.suffix not in [".yml", ".yaml"]:
            raise ComposeFileError(
                f"Invalid compose file extension: {path.suffix}. Must be .yml or .yaml"
            )

        return path

    def validate_project_name(self, name: str | None) -> str | None:
        """Validate Docker Compose project name.

        Args:
            name: Project name to validate

        Returns:
            Validated project name or None

        Raises:
            ComposeValidationError: If name is invalid

        """
        if name is None:
            return None

        # Docker Compose project name rules:
        # - Must start with lowercase letter or digit
        # - Can contain lowercase letters, digits, hyphens, and underscores
        # - Max 63 characters
        pattern = r"^[a-z0-9][a-z0-9_-]*$"
        if not re.match(pattern, name):
            raise ComposeValidationError(
                f"Invalid project name: '{name}'. "
                "Must start with lowercase letter or number, "
                "and contain only lowercase letters, numbers, hyphens, and underscores."
            )

        if len(name) > 63:
            raise ComposeValidationError(
                f"Project name too long (max 63 characters): '{name}'"
            )

        return name

    def get_common_args(self, input_data: BaseModel) -> dict[str, Any]:
        """Extract common compose arguments from input.

        Args:
            input_data: Tool input data

        Returns:
            Dictionary of common arguments

        """
        args: dict[str, Any] = {}

        if hasattr(input_data, "compose_file"):
            args["compose_file"] = input_data.compose_file

        if hasattr(input_data, "project_name"):
            args["project_name"] = input_data.project_name

        if hasattr(input_data, "environment"):
            args["environment"] = input_data.environment

        return args

    async def handle_compose_error(self, error: Exception, operation: str) -> ToolResult:
        """Handle and format compose-specific errors.

        Args:
            error: The exception that occurred
            operation: The operation that failed

        Returns:
            ToolResult with formatted error message

        """
        logger.error(f"Compose {operation} failed: {error}")

        error_msg = str(error)

        # Provide helpful error messages based on error type
        if "not found" in error_msg.lower():
            return ToolResult.error_result(
                f"Compose {operation} failed: Resource not found. "
                "Ensure the file/project exists and path is correct."
            )
        if "invalid" in error_msg.lower():
            return ToolResult.error_result(
                f"Compose {operation} failed: Invalid configuration. {error_msg}"
            )
        if "permission" in error_msg.lower():
            return ToolResult.error_result(
                f"Compose {operation} failed: Permission denied. "
                "Check file permissions and Docker daemon access."
            )
        return ToolResult.error_result(f"Compose {operation} failed: {error_msg}")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"{self.__class__.__name__}("
            f"name={self.name}, "
            f"command={self.compose_command}, "
            f"safety={self.safety_level.value})"
        )
