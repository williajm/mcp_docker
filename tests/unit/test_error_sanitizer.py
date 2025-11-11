"""Unit tests for error sanitization utilities."""

from pydantic import ValidationError as PydanticValidationError

from mcp_docker.utils.error_sanitizer import (
    is_error_safe_to_expose,
    sanitize_error_for_client,
)
from mcp_docker.utils.errors import (
    DockerConnectionError,
    DockerOperationError,
    UnsafeOperationError,
)


class TestSanitizeErrorForClient:
    """Tests for sanitize_error_for_client function."""

    def test_sanitize_unsafe_operation_error(self) -> None:
        """Test that UnsafeOperationError messages are preserved."""
        error = UnsafeOperationError("This operation is blocked by safety policy")
        message, error_type = sanitize_error_for_client(error, "test_operation")

        assert message == "This operation is blocked by safety policy"
        assert error_type == "PermissionDenied"

    def test_sanitize_validation_error(self) -> None:
        """Test that ValidationError messages are preserved."""
        # Create a real Pydantic ValidationError
        from pydantic import BaseModel, Field

        class TestModel(BaseModel):
            name: str = Field(min_length=1)

        try:
            TestModel(name="")
        except PydanticValidationError as e:
            message, error_type = sanitize_error_for_client(e, "validate_input")
            assert "validation error" in message.lower()
            assert error_type == "ValidationError"

    def test_sanitize_docker_connection_error(self) -> None:
        """Test that DockerConnectionError is sanitized."""
        error = DockerConnectionError("Cannot connect to /var/run/docker.sock")
        message, error_type = sanitize_error_for_client(error, "connect")

        assert message == "Docker daemon is unavailable or unreachable"
        assert error_type == "ServiceUnavailable"
        assert "/var/run/docker.sock" not in message  # Path should be sanitized

    def test_sanitize_docker_operation_error(self) -> None:
        """Test that DockerOperationError is sanitized."""
        error = DockerOperationError("Internal container error at /internal/path")
        message, error_type = sanitize_error_for_client(error, "start_container")

        assert message == "Operation 'start_container' failed"
        assert error_type == "OperationFailed"
        assert "/internal/path" not in message  # Internal details sanitized

    def test_sanitize_container_not_found(self) -> None:
        """Test ContainerNotFound error sanitization."""

        # Simulate Docker SDK's NotFound exception
        class ContainerNotFound(Exception):  # noqa: N818
            pass

        ContainerNotFound.__name__ = "ContainerNotFound"
        error = ContainerNotFound("Container abc123 not found in /var/lib/docker")
        message, error_type = sanitize_error_for_client(error, "inspect")

        assert message == "The specified container was not found"
        assert error_type == "ResourceNotFound"
        assert "abc123" not in message  # Container ID sanitized
        assert "/var/lib/docker" not in message  # Path sanitized

    def test_sanitize_image_not_found(self) -> None:
        """Test ImageNotFound error sanitization."""

        class ImageNotFound(Exception):  # noqa: N818
            pass

        ImageNotFound.__name__ = "ImageNotFound"
        error = ImageNotFound("Image not found")
        message, error_type = sanitize_error_for_client(error, "inspect_image")

        assert message == "The specified image was not found"
        assert error_type == "ResourceNotFound"

    def test_sanitize_network_not_found(self) -> None:
        """Test NetworkNotFound error sanitization."""

        class NetworkNotFound(Exception):  # noqa: N818
            pass

        NetworkNotFound.__name__ = "NetworkNotFound"
        error = NetworkNotFound("Network not found")
        message, error_type = sanitize_error_for_client(error, "inspect_network")

        assert message == "The specified network was not found"
        assert error_type == "ResourceNotFound"

    def test_sanitize_volume_not_found(self) -> None:
        """Test VolumeNotFound error sanitization."""

        class VolumeNotFound(Exception):  # noqa: N818
            pass

        VolumeNotFound.__name__ = "VolumeNotFound"
        error = VolumeNotFound("Volume not found")
        message, error_type = sanitize_error_for_client(error, "inspect_volume")

        assert message == "The specified volume was not found"
        assert error_type == "ResourceNotFound"

    def test_sanitize_value_error(self) -> None:
        """Test ValueError sanitization (now uses generic message for security)."""
        error = ValueError("Invalid value provided")
        message, error_type = sanitize_error_for_client(error, "validate")

        # ValueError now sanitized to generic message (security improvement)
        assert message == "Invalid input parameter for operation 'validate'"
        assert error_type == "InvalidInput"

    def test_sanitize_key_error(self) -> None:
        """Test KeyError sanitization."""
        error = KeyError("missing_key")
        message, error_type = sanitize_error_for_client(error, "process_data")

        assert message == "Required parameter missing for operation 'process_data'"
        assert error_type == "InvalidInput"
        assert "missing_key" not in message  # Key name should be sanitized

    def test_sanitize_type_error(self) -> None:
        """Test TypeError sanitization."""
        error = TypeError("Expected str, got int")
        message, error_type = sanitize_error_for_client(error, "convert")

        assert message == "Invalid parameter type for operation 'convert'"
        assert error_type == "InvalidInput"
        assert "str" not in message  # Type details sanitized
        assert "int" not in message

    def test_sanitize_permission_error(self) -> None:
        """Test PermissionError sanitization."""
        error = PermissionError("Access denied to /var/run/docker.sock")
        message, error_type = sanitize_error_for_client(error, "access_resource")

        assert message == "Permission denied for this operation"
        assert error_type == "PermissionDenied"
        assert "/var/run/docker.sock" not in message  # Path sanitized

    def test_sanitize_timeout_error(self) -> None:
        """Test TimeoutError sanitization."""
        error = TimeoutError("Operation timed out after 30s")
        message, error_type = sanitize_error_for_client(error, "long_operation")

        assert message == "Operation 'long_operation' timed out"
        assert error_type == "Timeout"
        assert "30s" not in message  # Timing details sanitized

    def test_sanitize_rate_limit_exceeded(self) -> None:
        """Test RateLimitExceeded error sanitization."""

        class RateLimitExceeded(Exception):  # noqa: N818
            pass

        RateLimitExceeded.__name__ = "RateLimitExceeded"
        error = RateLimitExceeded("Rate limit: 60 requests per minute")
        message, error_type = sanitize_error_for_client(error, "api_call")

        assert message == "Rate limit: 60 requests per minute"
        assert error_type == "RateLimitExceeded"

    def test_sanitize_unknown_error(self) -> None:
        """Test sanitization of unknown error types."""

        class UnknownError(Exception):
            pass

        error = UnknownError("Some internal error with sensitive data /secret/path")
        message, error_type = sanitize_error_for_client(error, "unknown_operation")

        assert message == "An unexpected error occurred during 'unknown_operation'"
        assert error_type == "InternalError"
        assert "/secret/path" not in message  # Sensitive data sanitized
        assert "internal" not in message.lower()  # Internal details sanitized

    def test_sanitize_preserves_operation_name(self) -> None:
        """Test that operation name is included in error messages."""
        error = TypeError("Some error")
        message, _ = sanitize_error_for_client(error, "my_custom_operation")

        assert "my_custom_operation" in message

    def test_sanitize_multiple_errors_same_type(self) -> None:
        """Test sanitizing multiple errors of the same type."""
        error1 = DockerConnectionError("Error 1")
        error2 = DockerConnectionError("Error 2")

        message1, type1 = sanitize_error_for_client(error1, "op1")
        message2, type2 = sanitize_error_for_client(error2, "op2")

        assert message1 == message2  # Same generic message
        assert type1 == type2  # Same error type
        assert type1 == "ServiceUnavailable"

    def test_sanitize_error_with_sensitive_patterns(self) -> None:
        """Test that common sensitive patterns are sanitized."""

        class CustomError(Exception):
            pass

        # Error with file paths, IPs, and internal details
        error = CustomError(
            "Failed at /var/lib/docker/volumes on server 192.168.1.100 "
            "with container ID sha256:abc123def456"
        )
        message, error_type = sanitize_error_for_client(error, "custom_op")

        # Should be completely sanitized to generic message
        assert message == "An unexpected error occurred during 'custom_op'"
        assert error_type == "InternalError"
        assert "/var/lib/docker" not in message
        assert "192.168.1.100" not in message
        assert "sha256" not in message

    def test_sanitize_instance_check_before_string_check(self) -> None:
        """Test that isinstance checks happen before string name checks."""
        # This tests the early return for UnsafeOperationError
        error = UnsafeOperationError("Destructive operation blocked")
        message, error_type = sanitize_error_for_client(error, "remove_all")

        assert message == "Destructive operation blocked"
        assert error_type == "PermissionDenied"


class TestIsErrorSafeToExpose:
    """Tests for is_error_safe_to_expose function."""

    def test_unsafe_operation_error_is_safe(self) -> None:
        """Test that UnsafeOperationError is safe to expose."""
        error = UnsafeOperationError("This is a user-facing message")
        assert is_error_safe_to_expose(error) is True

    def test_validation_error_is_safe(self) -> None:
        """Test that ValidationError is safe to expose."""
        from pydantic import BaseModel, Field

        class TestModel(BaseModel):
            value: int = Field(ge=0)

        try:
            TestModel(value=-1)
        except PydanticValidationError as e:
            assert is_error_safe_to_expose(e) is True

    def test_docker_connection_error_is_not_safe(self) -> None:
        """Test that DockerConnectionError is not safe to expose."""
        error = DockerConnectionError("Connection failed at /var/run/docker.sock")
        assert is_error_safe_to_expose(error) is False

    def test_docker_operation_error_is_not_safe(self) -> None:
        """Test that DockerOperationError is not safe to expose."""
        error = DockerOperationError("Operation failed with internal details")
        assert is_error_safe_to_expose(error) is False

    def test_generic_exception_is_not_safe(self) -> None:
        """Test that generic exceptions are not safe to expose."""
        error = Exception("Some unexpected error")
        assert is_error_safe_to_expose(error) is False

    def test_value_error_is_not_safe(self) -> None:
        """Test that ValueError is not safe to expose (might have internal details)."""
        error = ValueError("Invalid value for internal field 'secret_key'")
        assert is_error_safe_to_expose(error) is False

    def test_type_error_is_not_safe(self) -> None:
        """Test that TypeError is not safe to expose."""
        error = TypeError("Type mismatch in internal method")
        assert is_error_safe_to_expose(error) is False


class TestErrorSanitizationSecurity:
    """Security-focused tests for error sanitization."""

    def test_no_file_paths_leaked(self) -> None:
        """Test that file paths are never leaked in error messages."""
        dangerous_paths = [
            "/var/run/docker.sock",
            "/var/lib/docker",
            "/home/user/.docker",
            "C:\\ProgramData\\Docker",
            "/etc/docker/daemon.json",
        ]

        for path in dangerous_paths:

            class PathError(Exception):
                pass

            error = PathError(f"Error accessing {path}")
            message, _ = sanitize_error_for_client(error, "test")

            assert path not in message, f"Path {path} was leaked in error message"

    def test_no_internal_ids_leaked(self) -> None:
        """Test that container/image IDs are not leaked."""
        sensitive_ids = [
            "sha256:abc123def456",
            "container-id-abc123",
            "image:tag@sha256:deadbeef",
        ]

        for id_value in sensitive_ids:

            class IDError(Exception):
                pass

            error = IDError(f"Error with {id_value}")
            message, _ = sanitize_error_for_client(error, "test")

            # Should be completely sanitized
            assert "An unexpected error occurred" in message

    def test_no_stack_traces_leaked(self) -> None:
        """Test that stack trace information is not leaked."""

        class TraceError(Exception):
            pass

        error = TraceError("Error in function _internal_method at line 123 in module docker.py")
        message, _ = sanitize_error_for_client(error, "test")

        assert "An unexpected error occurred" in message
        assert "_internal_method" not in message
        assert "line 123" not in message
        assert "docker.py" not in message

    def test_no_ip_addresses_leaked(self) -> None:
        """Test that IP addresses are not leaked."""
        ip_addresses = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]

        for ip in ip_addresses:

            class IPError(Exception):
                pass

            error = IPError(f"Connection to {ip} failed")
            message, _ = sanitize_error_for_client(error, "connect")

            assert ip not in message

    def test_consistent_error_messages(self) -> None:
        """Test that error messages are consistent to prevent timing attacks."""
        # Same error type should produce identical messages
        errors = [DockerConnectionError(f"Error {i}") for i in range(5)]

        messages = [sanitize_error_for_client(e, "test")[0] for e in errors]

        # All messages should be identical
        assert len(set(messages)) == 1
        assert messages[0] == "Docker daemon is unavailable or unreachable"

    def test_operation_name_is_safe_identifier(self) -> None:
        """Test that operation names in errors are safe identifiers."""
        safe_operations = [
            "list_containers",
            "start_container",
            "inspect_image",
            "remove_network",
        ]

        for operation in safe_operations:
            error = TimeoutError("Timeout")
            message, _ = sanitize_error_for_client(error, operation)

            assert operation in message
            # Operation name should be in a safe, predictable format
            assert message == f"Operation '{operation}' timed out"
