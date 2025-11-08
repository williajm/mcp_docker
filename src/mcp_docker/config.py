"""Configuration management for MCP Docker server."""

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_docker.version import __version__

# SSH Authentication Constants
DEFAULT_SSH_SIGNATURE_MAX_AGE_SECONDS = 300  # 5 minutes
MAX_SSH_SIGNATURE_AGE_SECONDS = 3600  # 1 hour


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
    def validate_cert_paths(cls, cert_path: Path | None) -> Path | None:
        """Validate that certificate paths exist if provided."""
        if cert_path is not None and not cert_path.exists():
            raise ValueError(f"Certificate file not found: {cert_path}")
        return cert_path


class SafetyConfig(BaseSettings):
    """Safety and operation control configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SAFETY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    allow_moderate_operations: bool = Field(
        default=True,
        description="Allow moderate operations (create, start, stop, pull, etc.)",
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


class SecurityConfig(BaseSettings):
    """Security configuration for authentication, authorization, and audit."""

    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Authentication
    auth_enabled: bool = Field(
        default=False,
        description="Enable authentication (recommended for production)",
    )
    api_keys_file: Path = Field(
        default=Path(".mcp_keys.json"),
        description="Path to API keys configuration file",
    )
    api_key_header: str = Field(
        default="X-MCP-API-Key",
        description="HTTP header name for API key authentication",
    )

    # Rate Limiting
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting per client",
    )
    rate_limit_rpm: int = Field(
        default=60,
        description="Maximum requests per minute per client",
        gt=0,
        le=1000,
    )
    rate_limit_concurrent: int = Field(
        default=3,
        description="Maximum concurrent requests per client",
        gt=0,
        le=50,
    )

    # Audit Logging
    audit_log_enabled: bool = Field(
        default=True,
        description="Enable audit logging of all operations",
    )
    audit_log_file: Path = Field(
        default=Path("mcp_audit.log"),
        description="Path to audit log file",
    )

    # Network Security
    allowed_client_ips: list[str] = Field(
        default_factory=list,
        description="Allowed client IP addresses (empty list = allow all)",
    )

    # SSH Authentication
    ssh_auth_enabled: bool = Field(
        default=False,
        description="Enable SSH key-based authentication",
    )
    ssh_authorized_keys_file: Path = Field(
        default=Path.home() / ".ssh" / "mcp_authorized_keys",
        description="Path to authorized SSH public keys file (OpenSSH format)",
    )
    ssh_signature_max_age: int = Field(
        default=DEFAULT_SSH_SIGNATURE_MAX_AGE_SECONDS,
        description="Maximum age of SSH signature timestamp in seconds (replay protection)",
        gt=0,
        le=MAX_SSH_SIGNATURE_AGE_SECONDS,
    )

    @field_validator("api_keys_file")
    @classmethod
    def validate_keys_file_parent_exists(cls, keys_file_path: Path) -> Path:
        """Validate that parent directory exists for API keys file."""
        if not keys_file_path.parent.exists():
            raise ValueError(f"Parent directory does not exist for keys file: {keys_file_path}")
        return keys_file_path

    @field_validator("audit_log_file")
    @classmethod
    def validate_audit_log_parent_exists(cls, audit_log_path: Path) -> Path:
        """Validate that parent directory exists for audit log file."""
        if not audit_log_path.parent.exists():
            raise ValueError(f"Parent directory does not exist for audit log: {audit_log_path}")
        return audit_log_path


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
        default=__version__,
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
        self.security = SecurityConfig()
        self.server = ServerConfig()

    def __repr__(self) -> str:
        """Return string representation of config."""
        return (
            f"Config(docker={self.docker!r}, safety={self.safety!r}, "
            f"security={self.security!r}, server={self.server!r})"
        )
