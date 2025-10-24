"""Unit tests for custom error classes."""

import pytest

from mcp_docker.utils.errors import (
    DockerConnectionError,
    DockerHealthCheckError,
    DockerOperationError,
    MCPDockerError,
    SafetyError,
    ValidationError,
)


class TestErrorHierarchy:
    """Test error class hierarchy."""

    def test_mcp_docker_error_is_base(self) -> None:
        """Test that MCPDockerError is base exception."""
        error = MCPDockerError("Base error")
        assert isinstance(error, Exception)
        assert str(error) == "Base error"

    def test_docker_connection_error_inheritance(self) -> None:
        """Test DockerConnectionError inherits from MCPDockerError."""
        error = DockerConnectionError("Connection failed")
        assert isinstance(error, MCPDockerError)
        assert isinstance(error, Exception)
        assert str(error) == "Connection failed"

    def test_docker_health_check_error_inheritance(self) -> None:
        """Test DockerHealthCheckError inherits from MCPDockerError."""
        error = DockerHealthCheckError("Health check failed")
        assert isinstance(error, MCPDockerError)
        assert str(error) == "Health check failed"

    def test_docker_operation_error_inheritance(self) -> None:
        """Test DockerOperationError inherits from MCPDockerError."""
        error = DockerOperationError("Operation failed")
        assert isinstance(error, MCPDockerError)
        assert str(error) == "Operation failed"

    def test_validation_error_inheritance(self) -> None:
        """Test ValidationError inherits from MCPDockerError."""
        error = ValidationError("Validation failed")
        assert isinstance(error, MCPDockerError)
        assert str(error) == "Validation failed"

    def test_safety_error_inheritance(self) -> None:
        """Test SafetyError inherits from MCPDockerError."""
        error = SafetyError("Safety check failed")
        assert isinstance(error, MCPDockerError)
        assert str(error) == "Safety check failed"


class TestErrorRaising:
    """Test that errors can be raised and caught properly."""

    def test_raise_mcp_docker_error(self) -> None:
        """Test raising MCPDockerError."""
        with pytest.raises(MCPDockerError, match="Test error"):
            raise MCPDockerError("Test error")

    def test_raise_docker_connection_error(self) -> None:
        """Test raising DockerConnectionError."""
        with pytest.raises(DockerConnectionError, match="Connection test"):
            raise DockerConnectionError("Connection test")

    def test_catch_specific_error(self) -> None:
        """Test catching specific error type."""
        try:
            raise DockerConnectionError("Connection failed")
        except DockerConnectionError as e:
            assert str(e) == "Connection failed"

    def test_catch_base_error(self) -> None:
        """Test catching derived error with base class."""
        try:
            raise DockerConnectionError("Connection failed")
        except MCPDockerError as e:
            assert isinstance(e, DockerConnectionError)
            assert str(e) == "Connection failed"

    def test_error_with_cause(self) -> None:
        """Test error with cause chain."""
        original = ValueError("Original error")
        try:
            raise DockerConnectionError("Wrapped error") from original
        except DockerConnectionError as e:
            assert str(e) == "Wrapped error"
            assert isinstance(e.__cause__, ValueError)
            assert str(e.__cause__) == "Original error"


class TestErrorMessages:
    """Test error message handling."""

    def test_empty_message(self) -> None:
        """Test creating error with empty message."""
        error = MCPDockerError("")
        assert str(error) == ""

    def test_multiline_message(self) -> None:
        """Test error with multiline message."""
        message = "Line 1\nLine 2\nLine 3"
        error = DockerOperationError(message)
        assert str(error) == message

    def test_formatted_message(self) -> None:
        """Test error with formatted message."""
        container_id = "abc123"
        error = DockerOperationError(f"Container {container_id} not found")
        assert "abc123" in str(error)
        assert "not found" in str(error)
