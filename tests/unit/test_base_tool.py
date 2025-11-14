"""Unit tests for base tool classes."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.base import BaseTool, ToolInput, ToolResult
from mcp_docker.utils.safety import OperationSafety


class TestToolInput:
    """Test base ToolInput model."""

    def test_forbid_extra_fields(self) -> None:
        """Test that extra fields are forbidden."""

        class SimpleInput(ToolInput):
            name: str

        # Valid input
        valid = SimpleInput(name="test")
        assert valid.name == "test"

        # Extra field should raise error (Pydantic validation)
        with pytest.raises((TypeError, ValueError)):  # Pydantic raises TypeError for extra fields
            SimpleInput(name="test", extra_field="value")  # type: ignore[call-arg]


class TestToolResult:
    """Test ToolResult model."""

    def test_success_result(self) -> None:
        """Test creating a success result."""
        result = ToolResult.success_result(data={"key": "value"}, operation="test")
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None
        assert result.metadata == {"operation": "test"}

    def test_error_result(self) -> None:
        """Test creating an error result."""
        result = ToolResult.error_result(error="Something went wrong", code=500)
        assert result.success is False
        assert result.data is None
        assert result.error == "Something went wrong"
        assert result.metadata == {"code": 500}

    def test_default_values(self) -> None:
        """Test default values in ToolResult."""
        result = ToolResult(success=True)
        assert result.success is True
        assert result.data is None
        assert result.error is None
        assert result.metadata == {}


class MockInput(ToolInput):
    """Mock input model for testing."""

    test_field: str


class MockTool(BaseTool):
    """Mock tool for testing."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
        safety_level: OperationSafety = OperationSafety.SAFE,
    ) -> None:
        super().__init__(docker_client, safety_config)
        self._safety_level = safety_level

    @property
    def name(self) -> str:
        return "mock_tool"

    @property
    def description(self) -> str:
        return "A mock tool for testing"

    @property
    def input_schema(self) -> type[ToolInput]:
        return MockInput

    @property
    def safety_level(self) -> OperationSafety:
        return self._safety_level

    async def execute(self, input_data: MockInput) -> MockInput:
        # Just echo back the validated input
        return input_data


@pytest.fixture
def mock_docker_client() -> DockerClientWrapper:
    """Create a mock Docker client wrapper."""
    return MagicMock(spec=DockerClientWrapper)


@pytest.fixture
def safety_config() -> SafetyConfig:
    """Create a safety configuration."""
    return SafetyConfig(
        allow_moderate_operations=True,
        allow_destructive_operations=False,
        require_confirmation_for_destructive=True,
    )


@pytest.fixture
def permissive_safety_config() -> SafetyConfig:
    """Create a permissive safety configuration."""
    return SafetyConfig(
        allow_moderate_operations=True,
        allow_destructive_operations=True,
        require_confirmation_for_destructive=False,
    )


class TestBaseTool:
    """Test BaseTool abstract class."""

    def test_initialization(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test tool initialization."""
        tool = MockTool(mock_docker_client, safety_config)
        assert tool.docker == mock_docker_client
        assert tool.safety == safety_config
        assert tool.name == "mock_tool"
        assert tool.description == "A mock tool for testing"

    @pytest.mark.asyncio
    async def test_run_safe_operation(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test running a safe operation."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        result = await tool.run({"test_field": "value"})
        # BaseTool.run() now returns the model directly
        assert result.test_field == "value"

    @pytest.mark.asyncio
    async def test_run_moderate_operation(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test running a moderate operation."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.MODERATE)
        result = await tool.run({"test_field": "value"})
        # BaseTool.run() now returns the model directly
        assert result.test_field == "value"

    @pytest.mark.asyncio
    async def test_run_moderate_operation_blocked_in_readonly_mode(
        self, mock_docker_client: DockerClientWrapper, read_only_safety_config: SafetyConfig
    ) -> None:
        """Test that moderate operations are blocked in read-only mode."""
        from mcp_docker.utils.errors import UnsafeOperationError

        tool = MockTool(mock_docker_client, read_only_safety_config, OperationSafety.MODERATE)
        # Should raise UnsafeOperationError since moderate operations not allowed in read-only mode
        with pytest.raises(UnsafeOperationError, match="read-only mode"):
            await tool.run({"test_field": "value"})

    @pytest.mark.asyncio
    async def test_run_destructive_operation_blocked(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that destructive operations are blocked by default."""
        from mcp_docker.utils.errors import UnsafeOperationError

        tool = MockTool(mock_docker_client, safety_config, OperationSafety.DESTRUCTIVE)
        # Should raise UnsafeOperationError since destructive operations not allowed
        with pytest.raises(UnsafeOperationError, match="not allowed"):
            await tool.run({"test_field": "value"})

    @pytest.mark.asyncio
    async def test_run_destructive_operation_allowed(
        self, mock_docker_client: DockerClientWrapper, permissive_safety_config: SafetyConfig
    ) -> None:
        """Test that destructive operations work when allowed."""
        tool = MockTool(mock_docker_client, permissive_safety_config, OperationSafety.DESTRUCTIVE)
        result = await tool.run({"test_field": "value"})
        # BaseTool.run() now returns the model directly
        assert result.test_field == "value"

    @pytest.mark.asyncio
    async def test_run_validation_error(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that validation errors are handled."""
        tool = MockTool(mock_docker_client, safety_config)
        # Missing required field - should raise ValidationError from Pydantic
        with pytest.raises(ValueError):  # Pydantic raises ValueError for missing required fields
            await tool.run({})

    @pytest.mark.asyncio
    async def test_run_exception_handling(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that exceptions are caught and returned as error results."""

        class FailingTool(MockTool):
            async def execute(self, arguments: Any) -> Any:
                raise RuntimeError("Something went wrong")

        tool = FailingTool(mock_docker_client, safety_config)
        # Exceptions should propagate for the server to handle
        with pytest.raises(RuntimeError, match="Something went wrong"):
            await tool.run({"test_field": "value"})

    def test_check_safety_safe(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test safety check for safe operations."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        tool.check_safety()  # Should not raise

    def test_check_safety_moderate(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test safety check for moderate operations."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.MODERATE)
        tool.check_safety()  # Should not raise

    def test_check_safety_moderate_blocked_in_readonly(
        self, mock_docker_client: DockerClientWrapper, read_only_safety_config: SafetyConfig
    ) -> None:
        """Test safety check blocks moderate operations in read-only mode."""
        from mcp_docker.utils.errors import UnsafeOperationError

        tool = MockTool(mock_docker_client, read_only_safety_config, OperationSafety.MODERATE)
        with pytest.raises(UnsafeOperationError, match="read-only mode"):
            tool.check_safety()

    def test_check_safety_destructive_blocked(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test safety check blocks destructive operations."""
        from mcp_docker.utils.errors import UnsafeOperationError

        tool = MockTool(mock_docker_client, safety_config, OperationSafety.DESTRUCTIVE)
        with pytest.raises(UnsafeOperationError, match="not allowed"):
            tool.check_safety()

    def test_check_safety_destructive_allowed(
        self, mock_docker_client: DockerClientWrapper, permissive_safety_config: SafetyConfig
    ) -> None:
        """Test safety check allows destructive operations when configured."""
        tool = MockTool(mock_docker_client, permissive_safety_config, OperationSafety.DESTRUCTIVE)
        tool.check_safety()  # Should not raise

    def test_repr(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test string representation."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        repr_str = repr(tool)
        assert "MockTool" in repr_str
        assert "mock_tool" in repr_str
        assert "safe" in repr_str


class TestToolAnnotations:
    """Test MCP tool annotation properties."""

    def test_read_only_default_for_safe_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that SAFE operations default to read_only=True."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        assert tool.read_only is True

    def test_read_only_default_for_moderate_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that MODERATE operations default to read_only=False."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.MODERATE)
        assert tool.read_only is False

    def test_read_only_default_for_destructive_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that DESTRUCTIVE operations default to read_only=False."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.DESTRUCTIVE)
        assert tool.read_only is False

    def test_destructive_default_for_safe_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that SAFE operations default to destructive=False."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        assert tool.destructive is False

    def test_destructive_default_for_moderate_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that MODERATE operations default to destructive=False."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.MODERATE)
        assert tool.destructive is False

    def test_destructive_default_for_destructive_operations(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that DESTRUCTIVE operations default to destructive=True."""
        tool = MockTool(mock_docker_client, safety_config, OperationSafety.DESTRUCTIVE)
        assert tool.destructive is True

    def test_idempotent_defaults_to_false(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that idempotent defaults to False (conservative)."""
        tool = MockTool(mock_docker_client, safety_config)
        assert tool.idempotent is False

    def test_open_world_interaction_defaults_to_false(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that open_world_interaction defaults to False."""
        tool = MockTool(mock_docker_client, safety_config)
        assert tool.open_world_interaction is False

    def test_annotation_property_overrides(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that tools can override annotation properties."""

        class CustomTool(MockTool):
            @property
            def idempotent(self) -> bool:
                return True

            @property
            def open_world_interaction(self) -> bool:
                return True

        tool = CustomTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        assert tool.idempotent is True
        assert tool.open_world_interaction is True
        assert tool.read_only is True  # Still inherits default from SAFE
        assert tool.destructive is False

    def test_read_only_override(
        self, mock_docker_client: DockerClientWrapper, safety_config: SafetyConfig
    ) -> None:
        """Test that read_only can be overridden."""

        class NonReadOnlyTool(MockTool):
            @property
            def read_only(self) -> bool:
                return False

        tool = NonReadOnlyTool(mock_docker_client, safety_config, OperationSafety.SAFE)
        assert tool.read_only is False  # Overridden even though SAFE


class TestOperationSafety:
    """Test OperationSafety enum."""

    def test_enum_values(self) -> None:
        """Test that enum has expected values."""
        assert OperationSafety.SAFE.value == "safe"
        assert OperationSafety.MODERATE.value == "moderate"
        assert OperationSafety.DESTRUCTIVE.value == "destructive"

    def test_enum_comparison(self) -> None:
        """Test enum comparison."""
        # Use runtime comparison to avoid mypy literal type error
        safe: OperationSafety = OperationSafety.SAFE
        destructive: OperationSafety = OperationSafety.DESTRUCTIVE
        moderate: OperationSafety = OperationSafety.MODERATE
        assert safe != destructive
        assert moderate != safe
