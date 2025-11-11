"""Base tool class and abstractions for MCP Docker tools."""

from abc import ABC, abstractmethod
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.errors import UnsafeOperationError
from mcp_docker.utils.safety import OperationSafety


class ToolInput(BaseModel):
    """Base input model for tools."""

    model_config = {"extra": "forbid"}


class ToolResult(BaseModel):
    """Base result model for tools."""

    success: bool = Field(description="Whether the operation succeeded")
    data: Any = Field(default=None, description="Result data")
    error: str | None = Field(default=None, description="Error message if failed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @classmethod
    def success_result(cls, data: Any, **metadata: Any) -> "ToolResult":
        """Create a successful result.

        Args:
            data: Result data
            **metadata: Additional metadata

        Returns:
            ToolResult with success=True

        """
        return cls(success=True, data=data, metadata=metadata)

    @classmethod
    def error_result(cls, error: str, **metadata: Any) -> "ToolResult":
        """Create an error result.

        Args:
            error: Error message
            **metadata: Additional metadata

        Returns:
            ToolResult with success=False

        """
        return cls(success=False, error=error, metadata=metadata)


class BaseTool(ABC):
    """Base class for all Docker tools with safety controls."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
    ) -> None:
        """Initialize the tool.

        Args:
            docker_client: Docker client wrapper
            safety_config: Safety configuration

        """
        self.docker = docker_client
        self.safety = safety_config
        logger.debug(f"Initialized tool: {self.name}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name used in MCP protocol.

        Returns:
            Tool name string

        """

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description for MCP protocol.

        Returns:
            Tool description string

        """

    @property
    @abstractmethod
    def input_schema(self) -> type[BaseModel]:
        """Pydantic model for input validation.

        Returns:
            Input model class (must inherit from ToolInput)

        """

    @property
    @abstractmethod
    def safety_level(self) -> OperationSafety:
        """Safety classification of this tool.

        Returns:
            Operation safety level

        """

    def check_safety(self) -> None:
        """Check if this operation is allowed based on safety configuration.

        Raises:
            PermissionError: If operation is not allowed

        """
        if (
            self.safety_level == OperationSafety.MODERATE
            and not self.safety.allow_moderate_operations
        ):
            raise UnsafeOperationError(
                f"Moderate operation '{self.name}' is not allowed in read-only mode. "
                "Set SAFETY_ALLOW_MODERATE_OPERATIONS=true to enable state-changing operations."
            )

        if self.safety_level == OperationSafety.DESTRUCTIVE:
            if not self.safety.allow_destructive_operations:
                raise UnsafeOperationError(
                    f"Destructive operation '{self.name}' is not allowed. "
                    "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
                )

            if self.safety.require_confirmation_for_destructive:
                logger.warning(
                    f"Destructive operation '{self.name}' requires confirmation. "
                    "This would normally prompt for user confirmation."
                )

    def check_privileged_arguments(self, arguments: dict[str, Any]) -> None:  # noqa: B027
        """Check if privileged operation arguments are allowed.

        This method can be overridden by tools that support privileged operations
        to enforce safety restrictions on privileged mode.

        Args:
            arguments: Tool arguments to check

        Raises:
            PermissionError: If privileged operation is not allowed

        """
        # Default implementation: no privileged argument checks
        pass

    @abstractmethod
    async def execute(self, input_data: Any) -> Any:
        """Execute the tool with validated arguments.

        Args:
            input_data: Validated input data (Pydantic model instance)

        Returns:
            Tool execution result (Pydantic model instance)

        Raises:
            Exception: Tool-specific exceptions

        """

    async def run(self, arguments: dict[str, Any]) -> Any:
        """Run the tool with safety checks and error handling.

        Args:
            arguments: Tool arguments (dict)

        Returns:
            Tool execution result (Pydantic model)

        Raises:
            Exception: Re-raises exceptions from execute() for server to handle

        """
        # Safety checks
        self.check_safety()
        self.check_privileged_arguments(arguments)

        # Validate input
        validated_input = self.input_schema(**arguments)
        logger.info(f"Executing tool '{self.name}' with safety level: {self.safety_level.value}")

        # Execute and return result
        result = await self.execute(validated_input)
        logger.success(f"Tool '{self.name}' completed successfully")
        return result

    def __repr__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__}(name={self.name}, safety={self.safety_level.value})"
