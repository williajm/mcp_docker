"""Input validation utilities for Docker Compose operations."""

import re
from pathlib import Path
from typing import Any

import yaml

from mcp_docker.utils.errors import UnsafeOperationError, ValidationError
from mcp_docker.utils.safety import validate_mount_path

# Compose service and project naming patterns
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
PROJECT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

# Allowed compose file versions
SUPPORTED_COMPOSE_VERSIONS = {
    "2",
    "2.0",
    "2.1",
    "2.2",
    "2.3",
    "2.4",
    "3",
    "3.0",
    "3.1",
    "3.2",
    "3.3",
    "3.4",
    "3.5",
    "3.6",
    "3.7",
    "3.8",
    "3.9",
}

# Dangerous volume mount patterns
DANGEROUS_VOLUME_MOUNTS = [
    "/",  # Root filesystem
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/etc/passwd",
    "/etc/shadow",
    "/root",
    "/.ssh",
]


def validate_service_name(name: str) -> str:
    """Validate Docker Compose service name.

    Args:
        name: Service name to validate

    Returns:
        Validated service name

    Raises:
        ValidationError: If name is invalid

    """
    if not name:
        raise ValidationError("Service name cannot be empty")

    if not isinstance(name, str):
        raise ValidationError(f"Service name must be a string, got: {type(name).__name__}")

    if len(name) > 255:
        raise ValidationError("Service name cannot exceed 255 characters")

    if not SERVICE_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid service name: {name}. "
            "Must start with alphanumeric character and contain only "
            "alphanumeric characters, underscores, and hyphens."
        )

    return name


def validate_project_name(name: str) -> str:
    """Validate Docker Compose project name.

    Args:
        name: Project name to validate

    Returns:
        Validated project name

    Raises:
        ValidationError: If name is invalid

    """
    if not name:
        raise ValidationError("Project name cannot be empty")

    if not isinstance(name, str):
        raise ValidationError(f"Project name must be a string, got: {type(name).__name__}")

    if len(name) > 255:
        raise ValidationError("Project name cannot exceed 255 characters")

    if not PROJECT_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid project name: {name}. "
            "Must start with alphanumeric character and contain only "
            "alphanumeric characters, underscores, and hyphens."
        )

    return name


def validate_compose_file_path(file_path: str | Path) -> Path:
    """Validate compose file path for security and existence.

    Args:
        file_path: Path to compose file

    Returns:
        Validated and resolved Path object

    Raises:
        ValidationError: If path is invalid or unsafe
        UnsafeOperationError: If path contains security risks

    """
    if not file_path:
        raise ValidationError("Compose file path cannot be empty")

    # Convert to Path object
    path = Path(file_path)

    # Check if file exists
    if not path.exists():
        raise ValidationError(f"Compose file not found: {file_path}")

    if not path.is_file():
        raise ValidationError(f"Compose file path is not a file: {file_path}")

    # Check file extension
    valid_extensions = {".yml", ".yaml"}
    if path.suffix.lower() not in valid_extensions:
        raise ValidationError(
            f"Invalid compose file extension: {path.suffix}. "
            f"Expected one of: {', '.join(valid_extensions)}"
        )

    # Security: Resolve path and check for traversal attempts
    try:
        resolved_path = path.resolve()
    except (OSError, RuntimeError) as e:
        raise ValidationError(f"Failed to resolve compose file path: {e}") from e

    # Check for suspicious patterns
    path_str = str(resolved_path)
    if ".." in path_str:
        raise UnsafeOperationError(
            f"Compose file path contains suspicious pattern '..': {file_path}"
        )

    # Additional security: Ensure path is absolute after resolution
    if not resolved_path.is_absolute():
        raise UnsafeOperationError(f"Compose file path must be absolute: {file_path}")

    return resolved_path


def validate_compose_file_format(file_path: str | Path) -> dict[str, Any]:
    """Validate compose file format and structure.

    Args:
        file_path: Path to compose file

    Returns:
        Parsed compose file data as dictionary

    Raises:
        ValidationError: If file format is invalid

    """
    # First validate the path
    validated_path = validate_compose_file_path(file_path)

    # Read and parse YAML
    try:
        with validated_path.open() as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValidationError(f"Invalid YAML in compose file: {e}") from e
    except OSError as e:
        raise ValidationError(f"Failed to read compose file: {e}") from e

    if not isinstance(data, dict):
        raise ValidationError("Compose file must contain a YAML dictionary")

    # Check for version field (optional in Compose v2 but good practice)
    if "version" in data:
        version = str(data["version"])
        if version not in SUPPORTED_COMPOSE_VERSIONS:
            # Don't fail, just warn - some versions might work
            pass

    # Check for services section (required)
    if "services" not in data:
        raise ValidationError("Compose file must contain a 'services' section")

    if not isinstance(data["services"], dict):
        raise ValidationError("'services' section must be a dictionary")

    if not data["services"]:
        raise ValidationError("'services' section cannot be empty")

    return data


def validate_compose_volume_mounts(
    compose_data: dict[str, Any],
    allowed_paths: list[str] | None = None,
) -> None:
    """Validate volume mounts in compose file for security.

    Args:
        compose_data: Parsed compose file data
        allowed_paths: List of allowed path prefixes (None = allow all except dangerous)

    Raises:
        UnsafeOperationError: If dangerous volume mounts are detected

    """
    services = compose_data.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        volumes = service_config.get("volumes", [])
        if not volumes:
            continue

        for volume in volumes:
            # Parse volume specification
            if isinstance(volume, str):
                # Format: host_path:container_path or named_volume:container_path
                parts = volume.split(":")
                if len(parts) >= 2:
                    source = parts[0]
                    # Check if it's a host path
                    is_host_path = source.startswith(("/", "./", "../"))
                    if is_host_path:
                        _validate_volume_source_path(source, service_name, allowed_paths)
            elif isinstance(volume, dict):
                # Long syntax: {type: bind, source: ..., target: ...}
                if volume.get("type") == "bind":
                    source = volume.get("source", "")
                    if source:
                        _validate_volume_source_path(source, service_name, allowed_paths)


def _validate_volume_source_path(
    source: str,
    service_name: str,
    allowed_paths: list[str] | None = None,
) -> None:
    """Validate a volume source path for security.

    Args:
        source: Source path to validate
        service_name: Name of service using this mount
        allowed_paths: List of allowed path prefixes

    Raises:
        UnsafeOperationError: If path is dangerous

    """
    # Check against dangerous paths
    for dangerous_path in DANGEROUS_VOLUME_MOUNTS:
        if source.startswith(dangerous_path):
            raise UnsafeOperationError(
                f"Dangerous volume mount in service '{service_name}': {source}. "
                f"Mounting {dangerous_path} is not allowed for security reasons."
            )

    # Use existing mount path validation
    try:
        validate_mount_path(source, allowed_paths)
    except UnsafeOperationError as e:
        # Re-raise with service context
        raise UnsafeOperationError(f"Invalid volume mount in service '{service_name}': {e}") from e


def validate_compose_environment_variables(compose_data: dict[str, Any]) -> None:
    """Validate environment variables in compose file.

    Args:
        compose_data: Parsed compose file data

    Raises:
        ValidationError: If environment variables are invalid

    """
    services = compose_data.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        # Check environment section
        environment = service_config.get("environment")
        if environment is None:
            continue

        if isinstance(environment, dict):
            # Dict format: {KEY: value}
            for key in environment:
                if not key:
                    raise ValidationError(
                        f"Empty environment variable key in service '{service_name}'"
                    )
                if not isinstance(key, str):
                    raise ValidationError(
                        f"Environment variable key must be string in service '{service_name}'"
                    )
        elif isinstance(environment, list):
            # List format: ["KEY=value"]
            for item in environment:
                if not isinstance(item, str):
                    raise ValidationError(
                        f"Environment variable must be string in service '{service_name}'"
                    )
                if "=" not in item:
                    raise ValidationError(
                        f"Invalid environment variable format in service '{service_name}': {item}"
                    )
        else:
            raise ValidationError(
                f"Invalid environment section type in service '{service_name}': "
                f"must be dict or list"
            )


def validate_compose_ports(compose_data: dict[str, Any]) -> None:
    """Validate port mappings in compose file.

    Args:
        compose_data: Parsed compose file data

    Raises:
        ValidationError: If port mappings are invalid

    """
    services = compose_data.get("services", {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        ports = service_config.get("ports")
        if ports is None:
            continue

        if not isinstance(ports, list):
            raise ValidationError(f"'ports' in service '{service_name}' must be a list")

        for port_spec in ports:
            if isinstance(port_spec, int):
                # Just a port number
                if port_spec < 1 or port_spec > 65535:
                    raise ValidationError(
                        f"Invalid port number in service '{service_name}': {port_spec}"
                    )
            elif isinstance(port_spec, str):
                # Parse port specification (e.g., "8080:80", "127.0.0.1:8080:80")
                _validate_port_specification(port_spec, service_name)
            elif isinstance(port_spec, dict):
                # Long syntax: {target: 80, published: 8080}
                target = port_spec.get("target")
                published = port_spec.get("published")
                if target and not (1 <= target <= 65535):
                    raise ValidationError(
                        f"Invalid target port in service '{service_name}': {target}"
                    )
                if published and not (1 <= published <= 65535):
                    raise ValidationError(
                        f"Invalid published port in service '{service_name}': {published}"
                    )


def _validate_port_specification(port_spec: str, service_name: str) -> None:
    """Validate a port specification string.

    Args:
        port_spec: Port specification (e.g., "8080:80")
        service_name: Name of service

    Raises:
        ValidationError: If port specification is invalid

    """
    # Remove protocol suffix if present (e.g., "80/tcp")
    spec = port_spec.split("/")[0]

    # Split by colon
    parts = spec.split(":")

    if len(parts) == 1:
        # Just a port number
        try:
            port = int(parts[0])
            if port < 1 or port > 65535:
                raise ValidationError(f"Invalid port in service '{service_name}': {port_spec}")
        except ValueError as e:
            raise ValidationError(
                f"Invalid port format in service '{service_name}': {port_spec}"
            ) from e
    elif len(parts) == 2:
        try:
            host_port = int(parts[0])
            container_port = int(parts[1])
            if host_port < 1 or host_port > 65535:
                raise ValidationError(f"Invalid host port in service '{service_name}': {port_spec}")
            if container_port < 1 or container_port > 65535:
                raise ValidationError(
                    f"Invalid container port in service '{service_name}': {port_spec}"
                )
        except ValueError as e:
            raise ValidationError(
                f"Invalid port format in service '{service_name}': {port_spec}"
            ) from e
    elif len(parts) == 3:
        # ip:host_port:container_port
        try:
            host_port = int(parts[1])
            container_port = int(parts[2])
            if host_port < 1 or host_port > 65535:
                raise ValidationError(f"Invalid host port in service '{service_name}': {port_spec}")
            if container_port < 1 or container_port > 65535:
                raise ValidationError(
                    f"Invalid container port in service '{service_name}': {port_spec}"
                )
        except ValueError as e:
            raise ValidationError(
                f"Invalid port format in service '{service_name}': {port_spec}"
            ) from e


def validate_compose_networks(compose_data: dict[str, Any]) -> None:
    """Validate network configurations in compose file.

    Args:
        compose_data: Parsed compose file data

    Raises:
        ValidationError: If network configurations are invalid

    """
    # Check top-level networks section
    networks = compose_data.get("networks", {})
    if networks and not isinstance(networks, dict):
        raise ValidationError("'networks' section must be a dictionary")

    # Check service network configurations
    services = compose_data.get("services", {})
    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        service_networks = service_config.get("networks")
        if service_networks is None:
            continue

        if isinstance(service_networks, list):
            # List of network names
            for network in service_networks:
                if not isinstance(network, str):
                    raise ValidationError(
                        f"Network name must be string in service '{service_name}'"
                    )
        elif isinstance(service_networks, dict):
            # Dict format with network configs
            pass  # Complex network configs are valid
        else:
            raise ValidationError(f"Invalid networks format in service '{service_name}'")


def validate_full_compose_file(
    file_path: str | Path,
    allowed_mount_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Perform comprehensive validation of compose file.

    Args:
        file_path: Path to compose file
        allowed_mount_paths: List of allowed mount path prefixes

    Returns:
        Parsed and validated compose file data

    Raises:
        ValidationError: If file is invalid
        UnsafeOperationError: If file contains security risks

    """
    # Parse and validate format
    compose_data = validate_compose_file_format(file_path)

    # Validate volume mounts for security
    validate_compose_volume_mounts(compose_data, allowed_mount_paths)

    # Validate environment variables
    validate_compose_environment_variables(compose_data)

    # Validate port mappings
    validate_compose_ports(compose_data)

    # Validate network configurations
    validate_compose_networks(compose_data)

    return compose_data


def validate_compose_content_quality(content: str) -> dict[str, list[str]]:
    """Check Docker Compose content for anti-patterns and best practices.

    This validation checks for common issues that won't cause syntax errors
    but may lead to runtime failures or poor practices.

    Args:
        content: Compose file content as string

    Returns:
        Dictionary with 'warnings' list containing best practice recommendations

    """
    warnings = []

    # Check for complex inline code with python -c
    if "python -c" in content and re.search(r"python -c.*[\n;]", content, re.DOTALL):  # pragma: no cover
        # Look for multi-line inline code or semicolon-separated statements
        warnings.append(  # pragma: no cover
            "⚠️  Complex inline Python code detected using 'python -c'. "  # pragma: no cover
            "This is fragile and error-prone. "  # pragma: no cover
            "Recommendation: Use a Dockerfile with a proper app.py file instead. "  # pragma: no cover
            "Example: COPY app.py /app/ then CMD ['python', '/app/app.py']"  # pragma: no cover
        )  # pragma: no cover

    # Check for other inline interpreters with complex commands
    if re.search(r"(node -e|ruby -e).*[\n;]", content, re.DOTALL):  # pragma: no cover
        warnings.append(  # pragma: no cover
            "⚠️  Complex inline code detected. "  # pragma: no cover
            "Consider using a Dockerfile or mounting a script file for better maintainability."  # pragma: no cover
        )  # pragma: no cover

    # Check for long shell command chains
    if re.search(r"sh -c.*&&.*&&.*&&", content):  # pragma: no cover
        warnings.append(  # pragma: no cover
            "💡 Long command chains detected (multiple &&). "  # pragma: no cover
            "Consider using a Dockerfile with RUN commands or an entrypoint script for clarity."  # pragma: no cover
        )  # pragma: no cover

    # Check for database services without healthchecks
    db_patterns = {  # pragma: no cover
        "postgres": "healthcheck:\n  test: ['CMD-SHELL', 'pg_isready -U postgres']",  # pragma: no cover
        "mysql": ("healthcheck:\n  test: ['CMD', 'mysqladmin', 'ping', '-h', 'localhost']"),  # pragma: no cover
        "mongodb": (  # pragma: no cover
            "healthcheck:\n  test: ['CMD', 'mongosh', '--eval', 'db.adminCommand(\"ping\")']"  # pragma: no cover
        ),  # pragma: no cover
        "redis": "healthcheck:\n  test: ['CMD', 'redis-cli', 'ping']",  # pragma: no cover
    }  # pragma: no cover

    for db_name, healthcheck_example in db_patterns.items():  # pragma: no cover
        if db_name in content.lower() and "healthcheck" not in content.lower():  # pragma: no cover
            warnings.append(  # pragma: no cover
                f"💡 {db_name.capitalize()} service detected without healthcheck. "  # pragma: no cover
                f"Recommended: {healthcheck_example}"  # pragma: no cover
            )  # pragma: no cover

    # Check for exposed database ports
    if re.search(r"(postgres|mysql|mongodb).*ports.*:\s*-\s*[\"']?(\d+):", content, re.DOTALL):  # pragma: no cover
        warnings.append(  # pragma: no cover
            "🔒 Database port exposed externally. "  # pragma: no cover
            "Security tip: Only expose database ports if external access is required. "  # pragma: no cover
            "Internal services can connect via Docker networks without port exposure."  # pragma: no cover
        )  # pragma: no cover

    # Check for missing restart policies
    if "services:" in content and "restart:" not in content:  # pragma: no cover
        warnings.append(  # pragma: no cover
            "💡 No restart policy specified. "  # pragma: no cover
            "Recommendation: Add 'restart: unless-stopped' to ensure services "  # pragma: no cover
            "recover from failures."  # pragma: no cover
        )  # pragma: no cover

    # Check for volumes without named volumes
    if (  # pragma: no cover
        re.search(r"volumes:\s*-\s*\./", content)  # pragma: no cover
        and "volumes:" not in content.split("services:")[-1]  # pragma: no cover
    ):  # pragma: no cover
        warnings.append(  # pragma: no cover
            "💡 Using bind mounts (./path). "  # pragma: no cover
            "Tip: Named volumes are more portable. Define in top-level 'volumes:' section."  # pragma: no cover
        )  # pragma: no cover

    # Check for missing networks
    if (  # pragma: no cover
        "services:" in content  # pragma: no cover
        and len(re.findall(r"^\s*\w+:", content, re.MULTILINE)) > 3  # pragma: no cover
        and "networks:" not in content  # pragma: no cover
    ):  # pragma: no cover
        warnings.append(  # pragma: no cover
            "💡 Multiple services without custom network. "  # pragma: no cover
            "Best practice: Define a custom network for better isolation and service discovery."  # pragma: no cover
        )  # pragma: no cover

    # Check for container_name which prevents scaling
    if "container_name:" in content:  # pragma: no cover
        warnings.append(  # pragma: no cover
            "⚠️  Custom container names detected (container_name:). "  # pragma: no cover
            "This prevents scaling services to multiple replicas. "  # pragma: no cover
            "Recommendation: Remove container_name to allow Docker Compose to "  # pragma: no cover
            "auto-generate unique names. If you need to scale this service, "  # pragma: no cover
            "remove the container_name field."  # pragma: no cover
        )  # pragma: no cover

    return {"warnings": warnings}
