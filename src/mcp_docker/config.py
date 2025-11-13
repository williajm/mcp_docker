"""Configuration management for MCP Docker server."""

import json
import platform
import warnings
from pathlib import Path

from pydantic import Field, HttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_docker.version import __version__

# HTTP Stream Transport constants
EVENT_STORE_MAX_EVENTS_DEFAULT = 1000
EVENT_STORE_MAX_EVENTS_LIMIT = 10000
EVENT_STORE_TTL_SECONDS_DEFAULT = 300  # 5 minutes
EVENT_STORE_TTL_SECONDS_MIN = 60  # 1 minute
EVENT_STORE_TTL_SECONDS_MAX = 3600  # 1 hour

# CORS constants
CORS_MAX_AGE_DEFAULT = 3600  # 1 hour


def _parse_comma_separated_list(value: str | list[str] | None) -> list[str]:
    """Parse comma-separated string or JSON array into list of strings.

    Supports multiple input formats:
    - JSON array: '["value1","value2"]' or '["value1", "value2"]'
    - Comma-separated: 'value1,value2' or 'value1, value2'
    - Already a list: ['value1', 'value2']
    - None or empty string: []

    Args:
        value: Input value (string, list, or None)

    Returns:
        List of strings
    """
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        # Try to parse as JSON first
        value_stripped = value.strip()
        if value_stripped.startswith("[") and value_stripped.endswith("]"):
            try:
                parsed = json.loads(value_stripped)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except json.JSONDecodeError:
                # If JSON parsing fails, fall back to comma-separated parsing below
                pass
        # Fall back to comma-separated parsing
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _get_default_docker_socket() -> str:
    """Detect OS and return appropriate Docker socket URL.

    Returns:
        str: Platform-specific Docker socket URL:
            - Windows: npipe:////./pipe/docker_engine
            - Linux/macOS/WSL: unix:///var/run/docker.sock
    """
    system = platform.system().lower()
    if system == "windows":
        return "npipe:////./pipe/docker_engine"
    # Linux, macOS, WSL all use Unix socket
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
        description=(
            "Docker daemon socket URL (auto-detected based on OS, overridable via DOCKER_BASE_URL)"
        ),
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

    @field_validator("base_url")
    @classmethod
    def validate_docker_socket_security(cls, url: str) -> str:
        """Validate Docker socket URL for security concerns."""
        # Warn on insecure network-exposed configurations
        if url.startswith("tcp://") and not url.startswith("tcp://127.0.0.1"):
            warnings.warn(
                f"⚠️  SECURITY: Docker socket exposed on network: {url}. "
                "This allows unauthenticated root access. Use TLS or unix socket.",
                UserWarning,
                stacklevel=2,
            )

        # Block insecure HTTP
        if url.startswith("http://"):
            raise ValueError(
                "Insecure HTTP Docker socket not allowed. Use HTTPS with TLS verification."
            )

        return url

    @field_validator("tls_ca_cert", "tls_client_cert", "tls_client_key")
    @classmethod
    def validate_cert_paths(cls, cert_path: Path | None) -> Path | None:
        """Validate that certificate paths exist if provided."""
        if cert_path is not None and not cert_path.exists():
            raise ValueError(f"Certificate file not found: {cert_path}")
        return cert_path

    @model_validator(mode="after")
    def validate_tls_config(self) -> "DockerConfig":
        """Validate TLS configuration consistency."""
        # Inform users when TLS verification uses system CA bundle
        if self.tls_verify and not self.tls_ca_cert:
            warnings.warn(
                "TLS verification enabled without custom CA certificate. "
                "Will use system CA bundle for certificate verification. "
                "This is appropriate for publicly trusted certificates but may not work "
                "for self-signed or internal CA certificates.",
                stacklevel=2,
            )

        # Warn if certificates are provided without TLS verification
        if not self.tls_verify and (
            self.tls_ca_cert or self.tls_client_cert or self.tls_client_key
        ):
            warnings.warn(
                "TLS certificates configured but tls_verify=False. "
                "Set DOCKER_TLS_VERIFY=true to enable TLS verification.",
                UserWarning,
                stacklevel=2,
            )

        return self


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

    # Output size limits (prevent resource exhaustion and token limit issues)
    max_log_lines: int = Field(
        default=10000,
        description="Maximum number of log lines to return from containers (0 = unlimited)",
        ge=0,
        le=100000,
    )
    max_exec_output_bytes: int = Field(
        default=1048576,  # 1 MB
        description="Maximum bytes of output from exec commands (0 = unlimited)",
        ge=0,
        le=10485760,  # 10 MB max
    )
    max_list_results: int = Field(
        default=1000,
        description="Maximum number of items to return from list operations (0 = unlimited)",
        ge=0,
        le=10000,
    )
    truncate_inspect_output: bool = Field(
        default=False,
        description="Truncate large inspect output fields to prevent token limit issues",
    )
    max_inspect_field_bytes: int = Field(
        default=65536,  # 64 KB
        description="Maximum bytes for individual inspect output fields when truncation enabled",
        ge=1024,  # 1 KB minimum
        le=1048576,  # 1 MB maximum
    )

    # Tool filtering (works alongside safety level restrictions)
    allowed_tools: list[str] = Field(
        default_factory=list,
        description=(
            "Allowed tool names (empty list = allow all based on safety level). "
            "Example: ['docker_list_containers', 'docker_inspect_container']. "
            "Can be set via SAFETY_ALLOWED_TOOLS as comma-separated string."
        ),
    )
    denied_tools: list[str] = Field(
        default_factory=list,
        description=(
            "Denied tool names (takes precedence over allowed_tools). "
            "Example: ['docker_remove_container', 'docker_prune_images']. "
            "Can be set via SAFETY_DENIED_TOOLS as comma-separated string."
        ),
    )

    @field_validator("allowed_tools", "denied_tools", mode="before")
    @classmethod
    def parse_tool_list(cls, value: str | list[str] | None) -> list[str]:
        """Parse tool list from comma-separated string or list.

        Handles environment variable input as comma-separated strings
        and normalizes them to lists.

        Args:
            value: Tool list as string (comma-separated), list, or None

        Returns:
            Normalized list of tool names (empty list if None/empty)
        """
        if value is None or value == "":
            return []
        if isinstance(value, str):
            # Split by comma, strip whitespace, filter empty strings
            return [tool.strip() for tool in value.split(",") if tool.strip()]
        if isinstance(value, list):
            # Already a list, just filter empty strings and strip
            return [tool.strip() for tool in value if tool and tool.strip()]
        return []


class SecurityConfig(BaseSettings):
    """Security configuration for authentication, authorization, and audit."""

    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
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
    trusted_proxies: list[str] = Field(
        default_factory=list,
        description=(
            "Trusted proxy IP addresses/networks for X-Forwarded-For header. "
            "Empty list = don't trust any proxies (secure default). "
            "Supports CIDR notation (e.g., '10.0.0.0/24'). "
            "Only connections from these IPs will have their X-Forwarded-For header respected."
        ),
    )

    # OAuth/OIDC Authentication
    oauth_enabled: bool = Field(
        default=False,
        description=(
            "Enable OAuth/OIDC authentication for network transports (stdio always bypasses auth)"
        ),
    )
    oauth_issuer: HttpUrl | None = Field(
        default=None,
        description="OAuth/OIDC issuer URL (e.g., https://accounts.google.com, https://auth.example.com)",
    )
    oauth_audience: list[str] | str = Field(
        default=[],
        description=(
            "Expected audience values in JWT 'aud' claim. "
            "If empty, audience validation is skipped. "
            "Can be set via SECURITY_OAUTH_AUDIENCE as comma-separated string or JSON array."
        ),
    )
    oauth_jwks_url: HttpUrl | None = Field(
        default=None,
        description="JWKS endpoint URL for JWT signature verification (e.g., https://auth.example.com/.well-known/jwks.json)",
    )
    oauth_required_scopes: list[str] | str = Field(
        default=[],
        description=(
            "Required OAuth scopes for access. "
            "If empty, scope validation is skipped. "
            "Can be set via SECURITY_OAUTH_REQUIRED_SCOPES as comma-separated string or JSON array."
        ),
    )
    oauth_introspection_url: HttpUrl | None = Field(
        default=None,
        description="Token introspection endpoint URL (optional, for opaque tokens)",
    )
    oauth_client_id: str | None = Field(
        default=None,
        description="OAuth client ID for token introspection (optional)",
    )
    oauth_client_secret: str | None = Field(
        default=None,
        description="OAuth client secret for token introspection (optional, sensitive)",
    )
    oauth_clock_skew_seconds: int = Field(
        default=60,
        description="Allowed clock skew in seconds for JWT exp/nbf validation",
        ge=0,
        le=300,
    )

    @model_validator(mode="after")
    def parse_oauth_list_fields(self) -> "SecurityConfig":
        """Parse OAuth list fields from comma-separated strings to lists.

        Handles the case where oauth_audience and oauth_required_scopes
        are provided as comma-separated strings instead of JSON arrays.

        Returns:
            Self with parsed list fields
        """
        # Parse oauth_audience
        if isinstance(self.oauth_audience, str):
            self.oauth_audience = _parse_comma_separated_list(self.oauth_audience)

        # Parse oauth_required_scopes
        if isinstance(self.oauth_required_scopes, str):
            self.oauth_required_scopes = _parse_comma_separated_list(self.oauth_required_scopes)

        return self

    @field_validator("audit_log_file")
    @classmethod
    def validate_audit_log_path(cls, audit_log_path: Path) -> Path:
        """Ensure parent directory exists for audit log file.

        Creates the parent directory if it doesn't exist, which allows
        configurations like $HOME/.mcp-docker/mcp_audit.log to work
        without requiring manual directory creation.
        """
        if not audit_log_path.parent.exists():
            audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        return audit_log_path

    @model_validator(mode="after")
    def validate_oauth_config(self) -> "SecurityConfig":
        """Validate OAuth configuration consistency."""
        if self.oauth_enabled:
            # Require issuer and JWKS URL if OAuth is enabled
            if not self.oauth_issuer:
                raise ValueError(
                    "OAuth enabled but oauth_issuer not configured. "
                    "Set SECURITY_OAUTH_ISSUER to your OAuth provider's issuer URL."
                )
            if not self.oauth_jwks_url:
                raise ValueError(
                    "OAuth enabled but oauth_jwks_url not configured. "
                    "Set SECURITY_OAUTH_JWKS_URL to your OAuth provider's JWKS endpoint."
                )

            # Warn if introspection URL is set without client credentials
            if self.oauth_introspection_url and not (
                self.oauth_client_id and self.oauth_client_secret
            ):
                warnings.warn(
                    "OAuth introspection URL configured but client credentials missing. "
                    "Set SECURITY_OAUTH_CLIENT_ID and SECURITY_OAUTH_CLIENT_SECRET "
                    "for introspection.",
                    UserWarning,
                    stacklevel=2,
                )

        return self


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
    json_logging: bool = Field(
        default=False,
        description="Enable JSON structured logging (for SIEM/production)",
    )
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode (shows detailed errors, DO NOT use in production)",
    )
    tls_enabled: bool = Field(
        default=False,
        description="Enable TLS/HTTPS for SSE transport (required for production)",
    )
    tls_cert_file: Path | None = Field(
        default=None,
        description="Path to TLS certificate file",
    )
    tls_key_file: Path | None = Field(
        default=None,
        description="Path to TLS private key file",
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

    @field_validator("tls_cert_file", "tls_key_file")
    @classmethod
    def validate_tls_files(cls, tls_file: Path | None) -> Path | None:
        """Validate that TLS files exist if provided."""
        if tls_file is not None and not tls_file.exists():
            raise ValueError(f"TLS file not found: {tls_file}")
        return tls_file


class HttpStreamConfig(BaseSettings):
    """HTTP Stream Transport configuration settings.

    HTTP Stream Transport is the modern MCP transport that replaces SSE.
    It uses a single unified endpoint with built-in session management
    and resumability support via the MCP SDK.
    """

    model_config = SettingsConfigDict(
        env_prefix="HTTPSTREAM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    json_response_default: bool = Field(
        default=False,
        description="Default response mode: False for streaming (SSE), True for batch (JSON)",
    )

    stateless_mode: bool = Field(
        default=False,
        description="Disable session management (stateless mode)",
    )

    resumability_enabled: bool = Field(
        default=True,
        description="Enable message history and reconnection support",
    )

    event_store_max_events: int = Field(
        default=EVENT_STORE_MAX_EVENTS_DEFAULT,
        ge=1,
        le=EVENT_STORE_MAX_EVENTS_LIMIT,
        description="Maximum number of events to store in memory for resumability",
    )

    event_store_ttl_seconds: int = Field(
        default=EVENT_STORE_TTL_SECONDS_DEFAULT,
        ge=EVENT_STORE_TTL_SECONDS_MIN,
        le=EVENT_STORE_TTL_SECONDS_MAX,
        description="Time-to-live for stored events in seconds (default: 300 = 5 minutes)",
    )

    dns_rebinding_protection: bool = Field(
        default=True,
        description="Enable DNS rebinding protection (TransportSecuritySettings)",
    )

    allowed_hosts: list[str] = Field(
        default_factory=list,
        description=(
            "Additional allowed hostnames for DNS rebinding protection. "
            "By default, only localhost and 127.0.0.1 are allowed. "
            "Add your production hostnames here (e.g., ['my-api.company.com', '203.0.113.50']). "
            "Can be set via HTTPSTREAM_ALLOWED_HOSTS as JSON array string."
        ),
    )


class CORSConfig(BaseSettings):
    """CORS configuration for browser-based clients.

    SECURITY: CORS is disabled by default to prevent unintended exposure.
    When enabled with OAuth/authentication, you MUST specify explicit
    origins - wildcards are not allowed with credentials.
    """

    model_config = SettingsConfigDict(
        env_prefix="CORS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    enabled: bool = Field(
        default=False,
        description="Enable CORS headers (disabled by default for security)",
    )

    allow_origins: list[str] = Field(
        default_factory=list,
        description=(
            "Allowed origins - MUST be explicit domains, not wildcards. "
            "Example: ['https://app.example.com', 'https://admin.example.com']"
        ),
    )

    allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "OPTIONS"],
        description="Allowed HTTP methods",
    )

    allow_headers: list[str] = Field(
        default_factory=lambda: [
            "Content-Type",
            "Authorization",
            "mcp-session-id",
            "last-event-id",
        ],
        description="Allowed request headers",
    )

    expose_headers: list[str] = Field(
        default_factory=lambda: ["mcp-session-id"],
        description="Headers exposed to browser clients",
    )

    allow_credentials: bool = Field(
        default=True,
        description="Allow credentials (cookies, authorization headers)",
    )

    max_age: int = Field(
        default=CORS_MAX_AGE_DEFAULT,
        ge=0,
        description="Preflight cache duration in seconds",
    )

    @model_validator(mode="after")
    def validate_cors_credentials(self) -> "CORSConfig":
        """Validate that wildcard origins aren't used with credentials.

        This prevents the Starlette runtime error and security regression
        that occurs when using wildcard origins with credentials=True.
        """
        if self.enabled and self.allow_credentials:
            if "*" in self.allow_origins:
                raise ValueError(
                    "CORS: Cannot use wildcard origin ('*') with allow_credentials=True. "
                    "Specify explicit origins like ['https://app.example.com']"
                )
            if not self.allow_origins:
                raise ValueError(
                    "CORS: Must specify explicit allow_origins when enabled with credentials. "
                    "Set CORS_ALLOW_ORIGINS to a list of trusted domains."
                )
        return self

    @field_validator("allow_origins", mode="before")
    @classmethod
    def parse_allow_origins(cls, v: str | list[str] | None) -> list[str]:
        """Parse CORS_ALLOW_ORIGINS from comma-separated or JSON format."""
        return _parse_comma_separated_list(v)

    @field_validator("allow_methods", mode="before")
    @classmethod
    def parse_allow_methods(cls, v: str | list[str] | None) -> list[str]:
        """Parse CORS_ALLOW_METHODS from comma-separated or JSON format."""
        if v is None:
            return ["GET", "POST", "OPTIONS"]
        return _parse_comma_separated_list(v)

    @field_validator("allow_headers", mode="before")
    @classmethod
    def parse_allow_headers(cls, v: str | list[str] | None) -> list[str]:
        """Parse CORS_ALLOW_HEADERS from comma-separated or JSON format."""
        if v is None:
            return ["Content-Type", "Authorization", "mcp-session-id", "last-event-id"]
        return _parse_comma_separated_list(v)

    @field_validator("expose_headers", mode="before")
    @classmethod
    def parse_expose_headers(cls, v: str | list[str] | None) -> list[str]:
        """Parse CORS_EXPOSE_HEADERS from comma-separated or JSON format."""
        if v is None:
            return ["mcp-session-id"]
        return _parse_comma_separated_list(v)


class Config:
    """Main configuration container."""

    def __init__(self) -> None:
        """Initialize configuration from environment and .env file."""
        self.docker = DockerConfig()
        self.safety = SafetyConfig()
        self.security = SecurityConfig()
        self.server = ServerConfig()
        self.httpstream = HttpStreamConfig()
        self.cors = CORSConfig()

    def __repr__(self) -> str:
        """Return string representation of config."""
        return (
            f"Config(docker={self.docker!r}, safety={self.safety!r}, "
            f"security={self.security!r}, server={self.server!r}, "
            f"httpstream={self.httpstream!r}, cors={self.cors!r})"
        )
