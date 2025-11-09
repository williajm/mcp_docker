"""MCP Prompt templates for Docker operations.

This module provides prompt templates that help users with common Docker tasks:
- troubleshoot_container: Diagnose container issues
- optimize_container: Suggest container optimizations
- generate_compose: Generate docker-compose.yml files
- debug_networking: Deep-dive network troubleshooting
- security_audit: Comprehensive security analysis
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.prompts.base import BasePromptHelper
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.stats_formatter import calculate_memory_usage

logger = get_logger(__name__)


# Constants for prompt template display limits with rationale
# These limits balance detail vs. readability and prevent token limit exhaustion

# Environment variable display limits
MAX_DISPLAYED_ENV_VARS = 5  # Show top 5 env vars before truncating (balance detail vs clutter)

# Port mapping display limits
MAX_DISPLAYED_PORTS = 3  # Show top 3 port mappings before truncating (most critical ports)

# Volume mount display limits
MAX_DISPLAYED_VOLUMES = 3  # Show top 3 volume mounts before truncating (key mounts only)

# Container audit limits
MAX_AUDIT_CONTAINERS = 20  # Max containers in security audit (prevent timeout and token limits)

# Log line display limits
MAX_NETWORK_LOG_LINES = 20  # Max network-related log lines shown (balance context vs noise)
MAX_TROUBLESHOOT_LOG_LINES = 50  # Log tail for troubleshooting (enough context for diagnosis)
MAX_DEBUG_LOG_LINES = 100  # Log tail for network debugging (deeper analysis needed)
MAX_STREAMING_LOG_LINES = 10000  # Safety limit for follow mode (prevent memory exhaustion)


# Display truncation limits for prompt templates
@dataclass(frozen=True)
class PromptDisplayLimits:
    """Display truncation limits for prompt templates.

    Using frozen=True makes this immutable to prevent accidental modification.
    These limits balance detail vs. readability and prevent token limit exhaustion.
    """

    env_vars: int = MAX_DISPLAYED_ENV_VARS
    ports: int = MAX_DISPLAYED_PORTS
    volumes: int = MAX_DISPLAYED_VOLUMES
    audit_containers: int = MAX_AUDIT_CONTAINERS
    network_log_lines: int = MAX_NETWORK_LOG_LINES


DISPLAY_LIMITS = PromptDisplayLimits()

# Security-sensitive path patterns for mount detection
SENSITIVE_PATH_PREFIXES = ["/etc", "/root", "/proc", "/sys"]  # System directory prefixes
SENSITIVE_FILES = ["/var/run/docker.sock"]  # Specific critical files
SENSITIVE_SSH_PATTERN = "/.ssh"  # SSH directory pattern (matches anywhere in path)

# Common network error patterns for log filtering
NETWORK_ERROR_PATTERNS = [
    "connection refused",
    "timeout",
    "no route to host",
    "network unreachable",
    "dns",
    "resolve",
    "connect",
    "dial tcp",
    "dial udp",
]


class PromptMetadata(BaseModel):
    """Metadata for a prompt."""

    name: str = Field(description="Prompt name")
    description: str = Field(description="Prompt description")
    arguments: list[dict[str, Any]] = Field(default_factory=list, description="Prompt arguments")


class PromptMessage(BaseModel):
    """A message in a prompt."""

    role: str = Field(description="Message role (user/assistant/system)")
    content: str = Field(description="Message content")


class PromptResult(BaseModel):
    """Result of a prompt."""

    description: str = Field(description="Prompt description")
    messages: list[PromptMessage] = Field(description="Prompt messages")


# Prompt argument dataclasses for type-safe parameter passing
@dataclass(frozen=True)
class TroubleshootOptions:
    """Arguments for troubleshoot_container prompt."""

    container_id: str


@dataclass(frozen=True)
class OptimizeOptions:
    """Arguments for optimize_container prompt."""

    container_id: str


@dataclass(frozen=True)
class GenerateComposeOptions:
    """Arguments for generate_compose prompt."""

    container_id: str | None = None
    service_description: str | None = None


@dataclass(frozen=True)
class DebugNetworkingOptions:
    """Arguments for debug_networking prompt."""

    container_id: str
    target_host: str | None = None


@dataclass(frozen=True)
class SecurityAuditOptions:
    """Arguments for security_audit prompt."""

    container_id: str | None = None


class TroubleshootContainerPrompt(BasePromptHelper):
    """Prompt for troubleshooting container issues."""

    NAME = "troubleshoot_container"
    DESCRIPTION = "Diagnose and troubleshoot container issues"

    def get_metadata(self) -> PromptMetadata:
        """Get prompt metadata.

        Returns:
            Prompt metadata

        """
        return PromptMetadata(
            name=self.NAME,
            description=self.DESCRIPTION,
            arguments=[
                {
                    "name": "container_id",
                    "description": "Container ID or name to troubleshoot",
                    "required": True,
                }
            ],
        )

    async def generate(self, options: TroubleshootOptions) -> PromptResult:
        """Generate troubleshooting prompt for a container.

        Args:
            options: Troubleshooting options containing container_id

        Returns:
            Prompt result with troubleshooting guidance

        """
        try:
            # Offload blocking Docker I/O to thread pool
            data = await asyncio.to_thread(
                self._fetch_container_base_data_blocking,
                options.container_id,
                include_logs=True,
                log_tail=MAX_TROUBLESHOOT_LOG_LINES,
            )

            # Extract data from helper
            container_attrs = data["attrs"]
            state = container_attrs.get("State") or {}
            config = container_attrs.get("Config") or {}
            host_config = container_attrs.get("HostConfig") or {}

            # Build troubleshooting context
            context = f"""Container Information:
- ID: {data["short_id"]}
- Name: {data["name"]}
- Status: {data["status"]}
- Image: {config.get("Image", "unknown")}
- Running: {state.get("Running", False)}
- Exit Code: {state.get("ExitCode", "N/A")}
- Error: {state.get("Error", "None")}

Configuration:
- Command: {config.get("Cmd", "default")}
- Entrypoint: {config.get("Entrypoint", "default")}
- Environment: {len(config.get("Env") or [])} variables
- Restart Policy: {(host_config.get("RestartPolicy") or {}).get("Name", "no")}

Recent Logs (last 50 lines):
{data["logs"]}
"""

            system_message = """You are a Docker troubleshooting expert. \
Analyze the container information provided and help diagnose any issues. Consider:
1. Container status and state
2. Exit codes and error messages
3. Log patterns and error indicators
4. Configuration issues
5. Resource constraints
6. Network or volume problems
7. Common Docker pitfalls

Provide specific, actionable recommendations to resolve the issues."""

            user_message = f"""Please analyze this container and help troubleshoot any issues:

{context}

What could be wrong and how can I fix it?"""

            logger.debug(f"Generated troubleshoot prompt for container {options.container_id}")

            return PromptResult(
                description=f"Troubleshooting guidance for container {options.container_id}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate troubleshoot prompt: {e}")
            # Return a fallback prompt
            return PromptResult(
                description=f"Error troubleshooting container {options.container_id}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help troubleshooting container {options.container_id}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class OptimizeContainerPrompt(BasePromptHelper):
    """Prompt for optimizing container configuration."""

    NAME = "optimize_container"
    DESCRIPTION = "Suggest optimizations for container configuration"

    def get_metadata(self) -> PromptMetadata:
        """Get prompt metadata.

        Returns:
            Prompt metadata

        """
        return PromptMetadata(
            name=self.NAME,
            description=self.DESCRIPTION,
            arguments=[
                {
                    "name": "container_id",
                    "description": "Container ID or name to optimize",
                    "required": True,
                }
            ],
        )

    async def generate(self, options: OptimizeOptions) -> PromptResult:
        """Generate optimization suggestions for a container.

        Args:
            options: Optimization options containing container_id

        Returns:
            Prompt result with optimization suggestions

        """
        try:
            # Offload blocking Docker I/O to thread pool
            data = await asyncio.to_thread(
                self._fetch_container_base_data_blocking,
                options.container_id,
                include_stats=True,
            )

            # Extract configuration
            container_attrs = data["attrs"]
            config = container_attrs.get("Config") or {}
            host_config = container_attrs.get("HostConfig") or {}

            # Process stats if available
            stats_info = "Container is not running - no stats available"
            if data.get("stats") is not None:
                stats = data["stats"]
                memory_info = calculate_memory_usage(stats)
                cpu_stats = stats.get("cpu_stats") or {}

                mem_usage = memory_info["usage_mb"]
                mem_limit = memory_info["limit_mb"]
                mem_percent = memory_info["percent"]
                stats_info = f"""Current Resource Usage:
- Memory: {mem_usage:.2f} MB / {mem_limit:.2f} MB ({mem_percent:.1f}%)
- CPU Stats: {cpu_stats.get("online_cpus", "unknown")} CPUs"""

            context = f"""Container Configuration:
- ID: {data["short_id"]}
- Name: {data["name"]}
- Image: {config.get("Image", "unknown")}
- Restart Policy: {(host_config.get("RestartPolicy") or {}).get("Name", "no")}
- Memory Limit: {host_config.get("Memory", "unlimited")}
- CPU Shares: {host_config.get("CpuShares", "default")}
- Privileged: {host_config.get("Privileged", False)}
- Network Mode: {host_config.get("NetworkMode", "default")}
- Port Bindings: {len(host_config.get("PortBindings") or {})} ports
- Volume Bindings: {len(host_config.get("Binds") or [])} volumes

{stats_info}
"""

            system_message = """You are a Docker optimization expert. \
Analyze the container configuration and suggest optimizations for:
1. Resource allocation (CPU, memory)
2. Restart policies for reliability
3. Security best practices
4. Network configuration
5. Volume management
6. Health checks
7. Image optimization
8. Environment variables

Provide specific, practical recommendations that improve performance, reliability, and security."""

            user_message = f"""Please analyze this container and suggest optimizations:

{context}

How can I optimize this container for better performance, reliability, and security?"""

            logger.debug(f"Generated optimization prompt for container {options.container_id}")

            return PromptResult(
                description=f"Optimization suggestions for container {options.container_id}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate optimize prompt: {e}")
            return PromptResult(
                description=f"Error optimizing container {options.container_id}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help optimizing container {options.container_id}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class GenerateComposePrompt(BasePromptHelper):
    """Prompt for generating docker-compose.yml files."""

    NAME = "generate_compose"
    DESCRIPTION = "Generate a docker-compose.yml file from container configuration"

    def get_metadata(self) -> PromptMetadata:
        """Get prompt metadata.

        Returns:
            Prompt metadata

        """
        return PromptMetadata(
            name=self.NAME,
            description=self.DESCRIPTION,
            arguments=[
                {
                    "name": "container_id",
                    "description": "Container ID or name to convert to docker-compose",
                    "required": False,
                },
                {
                    "name": "service_description",
                    "description": "Description of the services to include in docker-compose",
                    "required": False,
                },
            ],
        )

    def _get_container_compose_data_blocking(self, container_id: str) -> dict[str, Any]:
        """Blocking helper to fetch container data for compose generation.

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name

        Returns:
            Dict containing container data

        """
        container = self.docker.client.containers.get(container_id)
        container_attrs = container.attrs

        return {
            "name": container.name,
            "attrs": container_attrs,
        }

    async def generate(self, options: GenerateComposeOptions) -> PromptResult:
        """Generate docker-compose.yml from container or description.

        Args:
            options: Compose generation options with container_id and service_description

        Returns:
            Prompt result with compose file generation guidance

        """
        context = ""

        # If container_id provided, extract its configuration
        if options.container_id:
            try:
                # Offload blocking Docker I/O to thread pool
                data = await asyncio.to_thread(
                    self._get_container_compose_data_blocking, options.container_id
                )

                # Extract configuration
                container_attrs = data["attrs"]
                config = container_attrs.get("Config", {})
                host_config = container_attrs.get("HostConfig", {})

                # Extract key configuration elements
                image = config.get("Image", "")
                env_vars = config.get("Env") or []
                ports = host_config.get("PortBindings") or {}
                volumes = host_config.get("Binds") or []
                restart_policy = host_config.get("RestartPolicy", {}).get("Name", "no")
                network_mode = host_config.get("NetworkMode", "bridge")

                context = f"""Existing Container Configuration for {data["name"]}:
- Image: {image}
- Environment Variables: {len(env_vars)} variables
  {chr(10).join(f"  - {var}" for var in env_vars[: DISPLAY_LIMITS.env_vars])}
  {"  - ..." if len(env_vars) > DISPLAY_LIMITS.env_vars else ""}
- Port Mappings: {len(ports)} ports
  {chr(10).join(f"  - {k}: {v}" for k, v in list(ports.items())[: DISPLAY_LIMITS.ports])}
  {"  - ..." if len(ports) > DISPLAY_LIMITS.ports else ""}
- Volumes: {len(volumes)} mounts
  {chr(10).join(f"  - {vol}" for vol in volumes[: DISPLAY_LIMITS.volumes])}
  {"  - ..." if len(volumes) > DISPLAY_LIMITS.volumes else ""}
- Restart Policy: {restart_policy}
- Network Mode: {network_mode}
"""
            except Exception as e:
                logger.error(f"Failed to get container info: {e}")
                context = f"Note: Could not retrieve container {options.container_id}: {e}\n"

        # Add service description if provided
        if options.service_description:
            context += f"\nService Requirements:\n{options.service_description}\n"

        system_message = """You are a Docker Compose expert. \
Generate a docker-compose.yml file based on the provided information. \
Follow these best practices:
1. Use version 3.8+ syntax
2. Include appropriate service names
3. Configure networks properly
4. Set up volumes correctly
5. Use environment variables
6. Add health checks where appropriate
7. Set restart policies
8. Document the file with comments

Provide a complete, working docker-compose.yml file that's ready to use."""

        user_message = f"""Please generate a docker-compose.yml file:

{context if context else "I need a docker-compose file for a multi-container application."}

Generate a complete docker-compose.yml file with proper configuration."""

        logger.debug("Generated compose generation prompt")

        return PromptResult(
            description="Generate docker-compose.yml file",
            messages=[
                PromptMessage(role="system", content=system_message),
                PromptMessage(role="user", content=user_message),
            ],
        )


class DebugNetworkingPrompt(BasePromptHelper):
    """Prompt for debugging container networking issues."""

    NAME = "debug_networking"
    DESCRIPTION = "Deep-dive analysis of container networking problems"

    def get_metadata(self) -> PromptMetadata:
        """Get prompt metadata.

        Returns:
            Prompt metadata

        """
        return PromptMetadata(
            name=self.NAME,
            description=self.DESCRIPTION,
            arguments=[
                {
                    "name": "container_id",
                    "description": "Container ID or name to debug networking for",
                    "required": True,
                },
                {
                    "name": "target_host",
                    "description": "Optional target host/container to test connectivity to",
                    "required": False,
                },
            ],
        )

    def _get_container_network_data_blocking(self, container_id: str) -> dict[str, Any]:
        """Blocking helper to fetch container network debugging data.

        This is a blocking helper that performs synchronous Docker SDK calls.
        Always call with asyncio.to_thread() from async methods.

        Args:
            container_id: Container ID or name

        Returns:
            Dict containing container network data

        """
        container = self.docker.client.containers.get(container_id)
        container_attrs = container.attrs

        return {
            "short_id": container.short_id,
            "name": container.name,
            "status": container.status,
            "attrs": container_attrs,
            "logs": container.logs(tail=MAX_DEBUG_LOG_LINES).decode("utf-8", errors="replace"),
        }

    async def generate(self, options: DebugNetworkingOptions) -> PromptResult:
        """Generate network debugging prompt for a container.

        Args:
            options: Network debugging options with container_id and target_host

        Returns:
            Prompt result with network debugging guidance

        """
        try:
            # Offload blocking Docker I/O to thread pool
            data = await asyncio.to_thread(
                self._get_container_network_data_blocking, options.container_id
            )

            # Extract network configuration
            container_attrs = data["attrs"]
            networks = container_attrs.get("NetworkSettings", {}).get("Networks", {})
            ports = container_attrs.get("NetworkSettings", {}).get("Ports") or {}
            hostname = container_attrs.get("Config", {}).get("Hostname", "unknown")

            # Build network info
            network_info = []
            for net_name, net_config in networks.items():
                ip_addr = net_config.get("IPAddress", "N/A")
                gateway = net_config.get("Gateway", "N/A")
                mac = net_config.get("MacAddress", "N/A")
                network_info.append(
                    f"  Network: {net_name}\n"
                    f"    - IP Address: {ip_addr}\n"
                    f"    - Gateway: {gateway}\n"
                    f"    - MAC Address: {mac}"
                )

            network_summary = "\n".join(network_info) if network_info else "  No networks attached"

            # Build port mappings info
            port_info = []
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    for binding in host_bindings:
                        host_ip = binding.get("HostIp", "0.0.0.0")
                        host_port = binding.get("HostPort", "N/A")
                        port_info.append(f"  - {host_ip}:{host_port} -> {container_port}")
                else:
                    port_info.append(f"  - {container_port} (not published)")

            port_summary = "\n".join(port_info) if port_info else "  No port mappings"

            # Filter logs for network-related errors
            log_lines = data["logs"].split("\n")
            relevant_logs = [
                line
                for line in log_lines
                if any(pattern in line.lower() for pattern in NETWORK_ERROR_PATTERNS)
            ]

            if relevant_logs:
                network_logs = "\n".join(relevant_logs[-DISPLAY_LIMITS.network_log_lines :])
            else:
                network_logs = "No obvious network errors in recent logs"

            # Build context
            context = f"""Container Network Configuration:
- ID: {data["short_id"]}
- Name: {data["name"]}
- Hostname: {hostname}
- Status: {data["status"]}

Networks:
{network_summary}

Port Mappings:
{port_summary}

Network-Related Logs (last 100 lines):
{network_logs}
"""

            # Add target connectivity info if provided
            if options.target_host:
                context += f"\n\nTarget to test connectivity: {options.target_host}\n"

            system_message = (
                """You are a Docker networking expert specializing in container connectivity """
                """troubleshooting. Analyze the network configuration and help diagnose """
                """issues using a systematic approach:

1. **Network Layer (L3)** - IP connectivity
   - Check IP addresses and subnet configuration
   - Verify gateway accessibility
   - Identify IP conflicts or misconfigurations

2. **Transport Layer (L4)** - Port connectivity
   - Check port mappings and bindings
   - Identify port conflicts
   - Verify published ports vs listening ports

3. **DNS Resolution** - Name resolution
   - Check container hostname and DNS settings
   - Verify service discovery (container names)
   - Identify DNS resolution failures

4. **Network Driver Issues**
   - Bridge vs overlay vs host mode implications
   - Network isolation verification
   - Multi-host communication (overlay networks)

5. **Common Problems**
   - Firewall/iptables interference
   - Docker network driver issues
   - MTU misconfigurations
   - Network namespace problems

6. **Debugging Commands**
   - Suggest docker exec commands to test (ping, nc, nslookup, curl)
   - Recommend inspection steps
   - Propose systematic testing approach

Provide specific, actionable recommendations to resolve network connectivity issues."""
            )

            user_message = (
                f"""Please analyze this container's network configuration and help """
                f"""debug connectivity issues:

{context}

What network problems do you see and how can I diagnose and fix them?"""
            )

            logger.debug(f"Generated network debugging prompt for container {options.container_id}")

            return PromptResult(
                description=f"Network debugging guidance for container {options.container_id}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate network debugging prompt: {e}")
            return PromptResult(
                description=f"Error debugging network for container {options.container_id}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help debugging network issues for container "
                            f"{options.container_id}, but encountered an error: {e}"
                        ),
                    )
                ],
            )


class SecurityAuditPrompt(BasePromptHelper):
    """Prompt for comprehensive security audit of containers."""

    NAME = "security_audit"
    DESCRIPTION = "Comprehensive security analysis of containers and configurations"

    def get_metadata(self) -> PromptMetadata:
        """Get prompt metadata.

        Returns:
            Prompt metadata

        """
        return PromptMetadata(
            name=self.NAME,
            description=self.DESCRIPTION,
            arguments=[
                {
                    "name": "container_id",
                    "description": (
                        "Container ID or name to audit (optional - audits all if not provided)"
                    ),
                    "required": False,
                },
            ],
        )

    @staticmethod
    def _is_sensitive_mount(source: str) -> bool:
        """Check if a mount source path is sensitive.

        Sensitive paths include system directories, SSH directories, and critical files.

        Args:
            source: Mount source path

        Returns:
            True if path is sensitive

        """
        # Check system directory prefixes
        if any(source.startswith(path) for path in SENSITIVE_PATH_PREFIXES):
            return True

        # Check specific sensitive files
        if source in SENSITIVE_FILES:
            return True

        # Check for SSH directories (e.g., /root/.ssh, /home/user/.ssh)
        return SENSITIVE_SSH_PATTERN in source

    def _get_containers_and_system_info_blocking(
        self, container_id: str | None = None
    ) -> tuple[list[dict[str, Any]], bool, int, dict[str, Any]]:
        """Blocking helper to fetch container and system info.

        Args:
            container_id: Container ID or name (optional)

        Returns:
            Tuple of (container_attrs_list, truncated, total_count, system_info)

        """
        containers_to_audit = []
        truncated = False
        total_count = 0

        if container_id:
            # Audit single container
            container = self.docker.client.containers.get(container_id)
            containers_to_audit.append(container)
            total_count = 1
        else:
            # Audit all containers (including stopped ones)
            all_containers = self.docker.client.containers.list(all=True)

            # Cap at DISPLAY_LIMITS.audit_containers to avoid token limits and timeouts
            total_count = len(all_containers)
            containers_to_audit = all_containers[: DISPLAY_LIMITS.audit_containers]
            truncated = total_count > DISPLAY_LIMITS.audit_containers

        # Fetch attrs for all containers (blocking I/O) using list comprehension
        container_attrs_list = [
            {
                "name": container.name,
                "short_id": container.short_id,
                "attrs": container.attrs,  # Blocking property access
            }
            for container in containers_to_audit
        ]

        # Get system info (blocking I/O)
        system_info: dict[str, Any] = self.docker.client.info()  # type: ignore[no-untyped-call]

        return container_attrs_list, truncated, total_count, system_info

    def _analyze_exposed_ports(self, network_settings: dict[str, Any]) -> list[str]:
        """Analyze exposed ports from container network settings.

        Args:
            network_settings: Container network settings from attrs

        Returns:
            List of exposed port strings in format "host_ip:host_port -> container_port"

        """
        ports = network_settings.get("Ports") or {}
        exposed_ports = []
        for port, bindings in ports.items():
            if bindings:
                for binding in bindings:
                    host_ip = binding.get("HostIp", "0.0.0.0")
                    host_port = binding.get("HostPort")
                    exposed_ports.append(f"{host_ip}:{host_port} -> {port}")
        return exposed_ports

    def _analyze_sensitive_mounts(self, container_attrs: dict[str, Any]) -> list[str]:
        """Analyze container mounts for sensitive paths.

        Args:
            container_attrs: Container attributes dictionary

        Returns:
            List of sensitive mount strings in format "source -> dest (type, mode)"

        """
        mounts = container_attrs.get("Mounts") or []
        sensitive_mounts = []
        for mount in mounts:
            source = mount.get("Source", "")
            if self._is_sensitive_mount(source):
                mount_type = mount.get("Type", "unknown")
                destination = mount.get("Destination", "")
                rw = "rw" if mount.get("RW", True) else "ro"
                sensitive_mounts.append(f"{source} -> {destination} ({mount_type}, {rw})")
        return sensitive_mounts

    def _scan_for_secrets(self, config: dict[str, Any]) -> list[str]:
        """Scan environment variables for potential secrets.

        Args:
            config: Container config dictionary

        Returns:
            List of environment variable names that may contain secrets

        """
        env_vars = config.get("Env") or []
        potential_secrets = []
        secret_keywords = ["password", "secret", "token", "key", "api", "credential"]
        for env_var in env_vars:
            if any(keyword in env_var.lower() for keyword in secret_keywords):
                # Don't expose the actual value
                var_name = env_var.split("=")[0]
                potential_secrets.append(var_name)
        return potential_secrets

    def _format_resource_limits(self, host_config: dict[str, Any]) -> tuple[str, str]:
        """Format resource limit strings for display.

        Args:
            host_config: Container host config dictionary

        Returns:
            Tuple of (memory_string, cpu_string) with warnings for unlimited resources

        """
        memory_limit = host_config.get("Memory", 0)
        memory_str = f"{memory_limit // (1024 * 1024)} MB" if memory_limit > 0 else "⚠️ Unlimited"

        cpu_shares = host_config.get("CpuShares", 0)
        cpu_str = f"{cpu_shares}" if cpu_shares > 0 else "⚠️ Default (no limit)"

        return memory_str, cpu_str

    def _format_network_isolation(self, host_config: dict[str, Any]) -> str:
        """Format network isolation status for display.

        Args:
            host_config: Container host config dictionary

        Returns:
            Network isolation status string with warnings for shared modes

        """
        network_mode = host_config.get("NetworkMode", "default")
        # "default" means bridge network, container: means shared namespace
        shared_modes = ["host", "bridge", "default"]
        is_shared = network_mode in shared_modes or network_mode.startswith("container:")
        if is_shared:
            # Show actual mode for clarity (default = bridge)
            mode_display = "BRIDGE" if network_mode == "default" else network_mode.upper()
            if network_mode.startswith("container:"):
                mode_display = "CONTAINER (shared)"
            return f"⚠️ {mode_display} mode"
        return "✓ Isolated"

    def _build_container_security_report(
        self,
        container_data: dict[str, Any],
        analysis: dict[str, Any],
    ) -> str:
        """Build security audit report for a single container.

        Args:
            container_data: Container data dictionary with attrs, name, short_id
            analysis: Dictionary containing:
                - exposed_ports: List of exposed port strings
                - sensitive_mounts: List of sensitive mount strings
                - potential_secrets: List of potential secret variable names
                - memory_str: Formatted memory limit string
                - cpu_str: Formatted CPU shares string
                - network_isolation: Formatted network isolation string
                - restart_str: Formatted restart policy string

        Returns:
            Formatted security report string

        """
        exposed_ports = analysis["exposed_ports"]
        sensitive_mounts = analysis["sensitive_mounts"]
        potential_secrets = analysis["potential_secrets"]
        memory_str = analysis["memory_str"]
        cpu_str = analysis["cpu_str"]
        network_isolation = analysis["network_isolation"]
        restart_str = analysis["restart_str"]
        container_attrs = container_data["attrs"]
        container_name = container_data["name"]
        container_short_id = container_data["short_id"]
        config = container_attrs.get("Config", {})
        host_config = container_attrs.get("HostConfig", {})

        is_privileged = host_config.get("Privileged", False)
        user = config.get("User", "root")
        capabilities_add = host_config.get("CapAdd") or []
        capabilities_drop = host_config.get("CapDrop") or []
        security_opt = host_config.get("SecurityOpt") or []
        read_only_rootfs = host_config.get("ReadonlyRootfs", False)
        image = config.get("Image", "unknown")

        return f"""
Container: {container_name} ({container_short_id})
Image: {image}

Security Configuration:
- Privileged Mode: {"⚠️ YES" if is_privileged else "✓ NO"}
- User: {user if user else "⚠️ root (default)"}
- Read-Only Root Filesystem: {"✓ YES" if read_only_rootfs else "⚠️ NO"}
- Added Capabilities: {", ".join(capabilities_add) if capabilities_add else "None"}
- Dropped Capabilities: {", ".join(capabilities_drop) if capabilities_drop else "⚠️ None"}
- Security Options: {", ".join(security_opt) if security_opt else "⚠️ None"}

Resource Limits:
- Memory: {memory_str}
- CPU Shares: {cpu_str}

Network & Restart:
- Network Mode: {network_isolation}
- Restart Policy: {restart_str}

Exposed Ports: {len(exposed_ports)}
{chr(10).join(f"  - {port}" for port in exposed_ports[: DISPLAY_LIMITS.ports])}
{"  - ..." if len(exposed_ports) > DISPLAY_LIMITS.ports else ""}

Sensitive Mounts: {len(sensitive_mounts)}
{chr(10).join(f"  - {mount}" for mount in sensitive_mounts[: DISPLAY_LIMITS.volumes])}
{"  - ..." if len(sensitive_mounts) > DISPLAY_LIMITS.volumes else ""}

Potential Secrets in Environment: {len(potential_secrets)}
{chr(10).join(f"  - {var}" for var in potential_secrets[: DISPLAY_LIMITS.env_vars])}
{"  - ..." if len(potential_secrets) > DISPLAY_LIMITS.env_vars else ""}
"""

    def _analyze_container_security(self, container_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze security configuration for a single container.

        Args:
            container_data: Container data dictionary with attrs

        Returns:
            Dictionary containing all security analysis results

        """
        container_attrs = container_data["attrs"]
        config = container_attrs.get("Config", {})
        host_config = container_attrs.get("HostConfig", {})
        network_settings = container_attrs.get("NetworkSettings", {})

        # Analyze various security aspects
        exposed_ports = self._analyze_exposed_ports(network_settings)
        sensitive_mounts = self._analyze_sensitive_mounts(container_attrs)
        potential_secrets = self._scan_for_secrets(config)
        memory_str, cpu_str = self._format_resource_limits(host_config)
        network_isolation = self._format_network_isolation(host_config)

        # Format restart policy
        restart_policy = host_config.get("RestartPolicy", {})
        restart_name = restart_policy.get("Name", "no")
        restart_str = restart_name if restart_name != "no" else "⚠️ no"

        return {
            "exposed_ports": exposed_ports,
            "sensitive_mounts": sensitive_mounts,
            "potential_secrets": potential_secrets,
            "memory_str": memory_str,
            "cpu_str": cpu_str,
            "network_isolation": network_isolation,
            "restart_str": restart_str,
        }

    def _compile_audit_report(
        self,
        container_attrs_list: list[dict[str, Any]],
        system_info: dict[str, Any],
    ) -> str:
        """Compile full security audit report from container data.

        Args:
            container_attrs_list: List of container data dictionaries
            system_info: Docker system information

        Returns:
            Formatted audit report string with system info and container analysis

        """
        # Analyze each container and build individual reports
        audit_reports = []
        for container_data in container_attrs_list:
            analysis = self._analyze_container_security(container_data)
            report = self._build_container_security_report(container_data, analysis)
            audit_reports.append(report)

        # Combine all container reports
        combined_reports = "\n".join(audit_reports)

        # Add system information header
        docker_version = system_info.get("ServerVersion", "unknown")
        security_options = system_info.get("SecurityOptions") or []

        return f"""Docker System Information:
- Version: {docker_version}
- Security Features: {", ".join(security_options) if security_options else "None detected"}

Container Security Audit:
{combined_reports}
"""

    @staticmethod
    def _get_security_audit_system_message() -> str:
        """Get the system message for security audit prompts.

        Returns:
            System message with security analysis guidelines

        """
        return (
            """You are a Docker security expert specializing in container hardening and """
            """vulnerability assessment. Analyze the security configuration and identify """
            """vulnerabilities following industry best practices:

1. **Privileged Containers & Capabilities**
   - Identify privileged containers (full host access - CRITICAL)
   - Check for dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
   - Recommend least-privilege alternatives

2. **User & Access Control**
   - Identify containers running as root
   - Recommend non-root users
   - Check read-only root filesystems

3. **Network Security**
   - Identify exposed sensitive ports (22-SSH, 3306-MySQL, 5432-PostgreSQL, 6379-Redis)
   - Check for 0.0.0.0 bindings (expose to all interfaces)
   - Recommend network isolation and firewalls

4. **Secrets Management**
   - Identify secrets in environment variables (ANTI-PATTERN)
   - Recommend Docker secrets or external secret managers
   - Check for exposed credential files

5. **File System Security**
   - Identify dangerous bind mounts (/etc, /root, /var/run/docker.sock)
   - Check mount permissions (read-write vs read-only)
   - Recommend volume alternatives

6. **Security Features**
   - Check for AppArmor/SELinux profiles
   - Verify dropped capabilities
   - Recommend security options (no-new-privileges, etc.)

7. **Image Security**
   - Check for latest tags (unpinned versions)
   - Recommend image scanning for CVEs
   - Verify base image sources

8. **Compliance**
   - Map findings to CIS Docker Benchmark
   - Identify compliance violations (PCI-DSS, HIPAA, SOC2)
   - Prioritize findings (Critical, High, Medium, Low)

Provide specific, actionable recommendations to harden the security posture. """
            """Prioritize findings by severity."""
        )

    def _generate_truncation_warning(
        self, container_id: str | None, truncated: bool, total_count: int
    ) -> str:
        """Generate truncation warning if applicable.

        Args:
            container_id: Container ID if auditing specific container
            truncated: Whether results were truncated
            total_count: Total number of containers

        Returns:
            Truncation warning string or empty string

        """
        if container_id or not truncated:
            return ""

        max_containers = DISPLAY_LIMITS.audit_containers
        return (
            f"\n\n⚠️ NOTE: Only showing first {max_containers} of {total_count} "
            f"containers. Specify a container_id to audit a specific container.\n"
        )

    def _create_security_audit_user_message(
        self, full_context: str, truncation_warning: str
    ) -> str:
        """Create user message for security audit.

        Args:
            full_context: Full audit context with container data
            truncation_warning: Truncation warning string

        Returns:
            Formatted user message

        """
        return (
            f"""Please perform a comprehensive security audit of the following """
            f"""containers:

{full_context}
{truncation_warning}
What security vulnerabilities and misconfigurations do you identify? """
            f"""Prioritize by severity and provide remediation steps."""
        )

    async def generate(self, options: SecurityAuditOptions) -> PromptResult:
        """Generate security audit prompt for container(s).

        Args:
            options: Security audit options with optional container_id

        Returns:
            Prompt result with security audit guidance

        """
        try:
            # Fetch container and system data
            container_attrs_list, truncated, total_count, system_info = await asyncio.to_thread(
                self._get_containers_and_system_info_blocking, options.container_id
            )

            # Handle no containers case
            if not container_attrs_list:
                return PromptResult(
                    description="No containers to audit",
                    messages=[PromptMessage(role="user", content="No containers found to audit.")],
                )

            # Compile audit context and messages
            full_context = self._compile_audit_report(container_attrs_list, system_info)
            truncation_warning = self._generate_truncation_warning(
                options.container_id, truncated, total_count
            )
            system_message = self._get_security_audit_system_message()
            user_message = self._create_security_audit_user_message(
                full_context, truncation_warning
            )

            logger.debug(
                f"Generated security audit prompt for {len(container_attrs_list)} container(s)"
            )

            return PromptResult(
                description=f"Security audit for {len(container_attrs_list)} container(s)",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate security audit prompt: {e}")
            return PromptResult(
                description="Error performing security audit",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help auditing container security"
                            f"{f' for {options.container_id}' if options.container_id else ''}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class PromptProvider:
    """Main prompt provider that manages all Docker prompts."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
    ) -> None:
        """Initialize the prompt provider.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client
        self.troubleshoot_prompt = TroubleshootContainerPrompt(docker_client)
        self.optimize_prompt = OptimizeContainerPrompt(docker_client)
        self.generate_compose_prompt = GenerateComposePrompt(docker_client)
        self.debug_networking_prompt = DebugNetworkingPrompt(docker_client)
        self.security_audit_prompt = SecurityAuditPrompt(docker_client)

        self.prompts = {
            self.troubleshoot_prompt.NAME: self.troubleshoot_prompt,
            self.optimize_prompt.NAME: self.optimize_prompt,
            self.generate_compose_prompt.NAME: self.generate_compose_prompt,
            self.debug_networking_prompt.NAME: self.debug_networking_prompt,
            self.security_audit_prompt.NAME: self.security_audit_prompt,
        }

        # Dispatch methods for each prompt type
        self._dispatchers = {
            TroubleshootContainerPrompt.NAME: self._dispatch_troubleshoot,
            OptimizeContainerPrompt.NAME: self._dispatch_optimize,
            GenerateComposePrompt.NAME: self._dispatch_generate_compose,
            DebugNetworkingPrompt.NAME: self._dispatch_debug_networking,
            SecurityAuditPrompt.NAME: self._dispatch_security_audit,
        }

        logger.debug("Initialized PromptProvider")

    def _get_required_arg(self, arguments: dict[str, Any], arg_name: str, prompt_name: str) -> Any:
        """Extract and validate a required argument.

        Args:
            arguments: Argument dictionary
            arg_name: Name of the argument to extract
            prompt_name: Prompt name for error messages

        Returns:
            The argument value

        Raises:
            ValueError: If argument is missing or empty

        """
        value = arguments.get(arg_name)
        if not value:
            raise ValueError(f"{arg_name} is required for {prompt_name} prompt")
        return value

    async def _dispatch_troubleshoot(self, arguments: dict[str, Any]) -> PromptResult:
        """Dispatch to troubleshoot prompt.

        Args:
            arguments: Prompt arguments

        Returns:
            Prompt result

        """
        container_id = self._get_required_arg(
            arguments, "container_id", TroubleshootContainerPrompt.NAME
        )
        options = TroubleshootOptions(container_id=container_id)
        return await self.troubleshoot_prompt.generate(options)

    async def _dispatch_optimize(self, arguments: dict[str, Any]) -> PromptResult:
        """Dispatch to optimize prompt.

        Args:
            arguments: Prompt arguments

        Returns:
            Prompt result

        """
        container_id = self._get_required_arg(
            arguments, "container_id", OptimizeContainerPrompt.NAME
        )
        options = OptimizeOptions(container_id=container_id)
        return await self.optimize_prompt.generate(options)

    async def _dispatch_generate_compose(self, arguments: dict[str, Any]) -> PromptResult:
        """Dispatch to generate compose prompt.

        Args:
            arguments: Prompt arguments

        Returns:
            Prompt result

        """
        container_id = arguments.get("container_id")
        service_description = arguments.get("service_description")
        options = GenerateComposeOptions(
            container_id=container_id, service_description=service_description
        )
        return await self.generate_compose_prompt.generate(options)

    async def _dispatch_debug_networking(self, arguments: dict[str, Any]) -> PromptResult:
        """Dispatch to debug networking prompt.

        Args:
            arguments: Prompt arguments

        Returns:
            Prompt result

        """
        container_id = self._get_required_arg(arguments, "container_id", DebugNetworkingPrompt.NAME)
        target_host = arguments.get("target_host")
        options = DebugNetworkingOptions(container_id=container_id, target_host=target_host)
        return await self.debug_networking_prompt.generate(options)

    async def _dispatch_security_audit(self, arguments: dict[str, Any]) -> PromptResult:
        """Dispatch to security audit prompt.

        Args:
            arguments: Prompt arguments

        Returns:
            Prompt result

        """
        container_id = arguments.get("container_id")
        options = SecurityAuditOptions(container_id=container_id)
        return await self.security_audit_prompt.generate(options)

    def list_prompts(self) -> list[PromptMetadata]:
        """List all available prompts.

        Returns:
            List of prompt metadata

        """
        return [
            prompt.get_metadata()
            for prompt in self.prompts.values()
            if isinstance(
                prompt,
                (
                    TroubleshootContainerPrompt,
                    OptimizeContainerPrompt,
                    GenerateComposePrompt,
                    DebugNetworkingPrompt,
                    SecurityAuditPrompt,
                ),
            )
        ]

    async def get_prompt(self, name: str, arguments: dict[str, Any]) -> PromptResult:
        """Get a prompt by name with arguments.

        Args:
            name: Prompt name
            arguments: Prompt arguments

        Returns:
            Prompt result

        Raises:
            ValueError: If prompt name is not recognized

        """
        if name not in self._dispatchers:
            raise ValueError(f"Unknown prompt: {name}")

        # Dispatch to the appropriate handler
        return await self._dispatchers[name](arguments)
