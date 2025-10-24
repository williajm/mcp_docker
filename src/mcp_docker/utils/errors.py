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
