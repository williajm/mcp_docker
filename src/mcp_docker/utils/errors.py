"""Custom exceptions for MCP Docker."""


class MCPDockerError(Exception):
    """Base exception for all MCP Docker errors."""


class DockerConnectionError(MCPDockerError):
    """Raised when unable to connect to Docker daemon."""


class DockerHealthCheckError(MCPDockerError):
    """Raised when Docker health check fails."""


class DockerOperationError(MCPDockerError):
    """Raised when a Docker operation fails."""


class ValidationError(MCPDockerError):
    """Raised when input validation fails."""


class SafetyError(MCPDockerError):
    """Raised when a safety check fails."""


class UnsafeOperationError(SafetyError):
    """Raised when an unsafe operation is attempted."""


class ContainerNotFound(MCPDockerError):  # noqa: N818
    """Raised when a container is not found."""


class ImageNotFound(MCPDockerError):  # noqa: N818
    """Raised when an image is not found."""


class NetworkNotFound(MCPDockerError):  # noqa: N818
    """Raised when a network is not found."""


class VolumeNotFound(MCPDockerError):  # noqa: N818
    """Raised when a volume is not found."""
