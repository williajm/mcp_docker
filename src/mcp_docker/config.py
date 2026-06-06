"""Configuration management for the local MCP Docker server."""

import platform

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_docker.version import __version__


def _get_default_docker_socket() -> str:
    """Detect OS and return the default Docker socket URL."""
    if platform.system().lower() == "windows":
        return "npipe:////./pipe/docker_engine"
    return "unix:///var/run/docker.sock"


class DockerConfig(BaseSettings):
    """Docker client configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DOCKER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base_url: str = Field(
        default_factory=_get_default_docker_socket,
        description="Docker daemon socket URL.",
    )
    timeout: int = Field(
        default=60,
        description="Default timeout for Docker operations in seconds.",
        gt=0,
    )

    @field_validator("base_url")
    @classmethod
    def validate_docker_socket(cls, url: str) -> str:
        """Reject insecure HTTP Docker daemon URLs."""
        if url.startswith("http://"):
            raise ValueError("Insecure HTTP Docker socket not allowed. Use a Unix socket or TLS.")
        return url


class SafetyConfig(BaseSettings):
    """Safety controls for the slim local server."""

    model_config = SettingsConfigDict(
        env_prefix="SAFETY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    allow_moderate_operations: bool = Field(
        default=True,
        description="Allow reversible operations such as start, stop, and restart.",
    )
    default_tool_timeout: float = Field(
        default=30.0,
        description="Default timeout in seconds for tool execution (0 = no timeout).",
        ge=0,
        le=3600,
    )
    max_response_bytes: int = Field(
        default=1048576,
        description="Maximum response size in bytes for tool results (0 = no limit).",
        ge=0,
        le=10485760,
    )


class ServerConfig(BaseSettings):
    """MCP server logging configuration."""

    model_config = SettingsConfigDict(
        env_prefix="MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    server_name: str = Field(default="mcp-docker", description="MCP server name.")
    server_version: str = Field(default=__version__, description="MCP server version.")
    log_level: str = Field(default="INFO", description="Logging level.")
    log_format: str = Field(
        default=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        description="Loguru format string.",
    )
    json_logging: bool = Field(default=False, description="Enable JSON structured logging.")
    debug_mode: bool = Field(default=False, description="Enable verbose local debugging.")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, level: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        level_upper = level.upper()
        if level_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {level}. Must be one of {valid_levels}")
        return level_upper


class Config:
    """Main configuration container."""

    def __init__(self) -> None:
        """Initialize configuration from environment and .env file."""
        self.docker = DockerConfig()
        self.safety = SafetyConfig()
        self.server = ServerConfig()

    def __repr__(self) -> str:
        """Return string representation of config."""
        return f"Config(docker={self.docker!r}, safety={self.safety!r}, server={self.server!r})"
