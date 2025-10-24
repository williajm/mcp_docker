"""Base tool class and abstractions for MCP Docker tools."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper


class OperationSafety(str, Enum):
    """Classification of operation safety levels."""

    SAFE = "safe"  # Read-only operations (list, inspect, logs)
    MODERATE = "moderate"  # State-changing but reversible (start, stop, pause)
    DESTRUCTIVE = "destructive"  # Permanent changes (rm, prune, rmi)


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
    def input_schema(self) -> type[ToolInput]:
        """Pydantic model for input validation.

        Returns:
            Input model class

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
        if self.safety_level == OperationSafety.DESTRUCTIVE:
            if not self.safety.allow_destructive_operations:
                raise PermissionError(
                    f"Destructive operation '{self.name}' is not allowed. "
                    "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
                )

            if self.safety.require_confirmation_for_destructive:
                logger.warning(
                    f"Destructive operation '{self.name}' requires confirmation. "
                    "This would normally prompt for user confirmation."
                )

    @abstractmethod
    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute the tool with validated arguments.

        Args:
            arguments: Tool arguments (will be validated against input_schema)

        Returns:
            Tool execution result

        """

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        """Run the tool with safety checks and error handling.

        Args:
            arguments: Tool arguments

        Returns:
            Tool execution result

        """
        try:
            # Safety check
            self.check_safety()

            # Validate input
            validated_input = self.input_schema(**arguments)
            logger.info(
                f"Executing tool '{self.name}' with safety level: {self.safety_level.value}"
            )

            # Execute
            result = await self.execute(validated_input.model_dump())

            if result.success:
                logger.success(f"Tool '{self.name}' completed successfully")
            else:
                logger.error(f"Tool '{self.name}' failed: {result.error}")

            return result

        except PermissionError as e:
            logger.error(f"Permission denied for tool '{self.name}': {e}")
            return ToolResult.error_result(str(e))
        except Exception as e:
            logger.exception(f"Unexpected error in tool '{self.name}': {e}")
            return ToolResult.error_result(f"Unexpected error: {type(e).__name__}: {e}")

    def __repr__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__}(name={self.name}, safety={self.safety_level.value})"
