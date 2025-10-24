"""Configuration management for MCP Docker server."""

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DockerConfig(BaseSettings):
    """Docker client configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DOCKER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base_url: str = Field(
        default="unix:///var/run/docker.sock",
        description="Docker daemon socket URL",
    )
    timeout: int = Field(
        default=60,
        description="Default timeout for Docker operations in seconds",
        gt=0,
    )
    tls_verify: bool = Field(
        default=False,
        description="Enable TLS verification for Docker daemon",
    )
    tls_ca_cert: Path | None = Field(
        default=None,
        description="Path to CA certificate for TLS",
    )
    tls_client_cert: Path | None = Field(
        default=None,
        description="Path to client certificate for TLS",
    )
    tls_client_key: Path | None = Field(
        default=None,
        description="Path to client key for TLS",
    )

    @field_validator("tls_ca_cert", "tls_client_cert", "tls_client_key")
    @classmethod
    def validate_cert_paths(cls, v: Path | None) -> Path | None:
        """Validate that certificate paths exist if provided."""
        if v is not None and not v.exists():
            raise ValueError(f"Certificate file not found: {v}")
        return v


class SafetyConfig(BaseSettings):
    """Safety and operation control configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SAFETY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    allow_destructive_operations: bool = Field(
        default=False,
        description="Allow destructive operations (rm, prune, etc.)",
    )
    allow_privileged_containers: bool = Field(
        default=False,
        description="Allow creating privileged containers",
    )
    require_confirmation_for_destructive: bool = Field(
        default=True,
        description="Require explicit confirmation for destructive operations",
    )
    max_concurrent_operations: int = Field(
        default=10,
        description="Maximum number of concurrent Docker operations",
        gt=0,
        le=100,
    )


class ServerConfig(BaseSettings):
    """MCP server configuration."""

    model_config = SettingsConfigDict(
        env_prefix="MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    server_name: str = Field(
        default="mcp-docker",
        description="MCP server name",
    )
    server_version: str = Field(
        default="0.1.0",
        description="MCP server version",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    log_format: str = Field(
        default=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        description="Log format string for loguru",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper


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
