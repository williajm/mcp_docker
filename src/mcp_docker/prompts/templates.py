"""MCP Prompt templates for Docker operations.

This module provides prompt templates that help users with common Docker tasks:
- troubleshoot_container: Diagnose container issues
- optimize_container: Suggest container optimizations
- generate_compose: Generate docker-compose.yml files
- troubleshoot_compose_stack: Diagnose compose project issues
- optimize_compose_config: Optimize compose configuration
"""

from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


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


class TroubleshootContainerPrompt:
    """Prompt for troubleshooting container issues."""

    NAME = "troubleshoot_container"
    DESCRIPTION = "Diagnose and troubleshoot container issues"

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the troubleshoot prompt.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

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

    async def generate(self, container_id: str) -> PromptResult:
        """Generate troubleshooting prompt for a container.

        Args:
            container_id: Container ID or name

        Returns:
            Prompt result with troubleshooting guidance

        """
        try:
            # Get container info
            container = self.docker.client.containers.get(container_id)
            container_attrs = container.attrs

            # Extract relevant info
            status = container.status
            state = container_attrs.get("State", {})
            config = container_attrs.get("Config", {})
            host_config = container_attrs.get("HostConfig", {})

            # Get logs
            logs = container.logs(tail=50).decode("utf-8", errors="replace")

            # Build troubleshooting context
            context = f"""Container Information:
- ID: {container.short_id}
- Name: {container.name}
- Status: {status}
- Image: {config.get("Image", "unknown")}
- Running: {state.get("Running", False)}
- Exit Code: {state.get("ExitCode", "N/A")}
- Error: {state.get("Error", "None")}

Configuration:
- Command: {config.get("Cmd", "default")}
- Entrypoint: {config.get("Entrypoint", "default")}
- Environment: {len(config.get("Env", []))} variables
- Restart Policy: {host_config.get("RestartPolicy", {}).get("Name", "no")}

Recent Logs (last 50 lines):
{logs}
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

            logger.debug(f"Generated troubleshoot prompt for container {container_id}")

            return PromptResult(
                description=f"Troubleshooting guidance for container {container_id}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate troubleshoot prompt: {e}")
            # Return a fallback prompt
            return PromptResult(
                description=f"Error troubleshooting container {container_id}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help troubleshooting container {container_id}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class OptimizeContainerPrompt:
    """Prompt for optimizing container configuration."""

    NAME = "optimize_container"
    DESCRIPTION = "Suggest optimizations for container configuration"

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the optimize prompt.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

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

    async def generate(self, container_id: str) -> PromptResult:
        """Generate optimization suggestions for a container.

        Args:
            container_id: Container ID or name

        Returns:
            Prompt result with optimization suggestions

        """
        try:
            # Get container info
            container = self.docker.client.containers.get(container_id)
            container_attrs = container.attrs

            # Get stats if container is running
            stats_info = "Container is not running - no stats available"
            if container.status == "running":
                stats = container.stats(stream=False)  # type: ignore[no-untyped-call]
                memory_usage = stats.get("memory_stats", {}).get("usage", 0)
                memory_limit = stats.get("memory_stats", {}).get("limit", 0)
                memory_percent = (memory_usage / memory_limit * 100) if memory_limit > 0 else 0

                memory_mb = memory_usage / 1024 / 1024
                limit_mb = memory_limit / 1024 / 1024
                stats_info = f"""Current Resource Usage:
- Memory: {memory_mb:.2f} MB / {limit_mb:.2f} MB ({memory_percent:.1f}%)
- CPU Stats: {stats.get("cpu_stats", {}).get("online_cpus", "unknown")} CPUs"""

            # Extract configuration
            config = container_attrs.get("Config", {})
            host_config = container_attrs.get("HostConfig", {})

            context = f"""Container Configuration:
- ID: {container.short_id}
- Name: {container.name}
- Image: {config.get("Image", "unknown")}
- Restart Policy: {host_config.get("RestartPolicy", {}).get("Name", "no")}
- Memory Limit: {host_config.get("Memory", "unlimited")}
- CPU Shares: {host_config.get("CpuShares", "default")}
- Privileged: {host_config.get("Privileged", False)}
- Network Mode: {host_config.get("NetworkMode", "default")}
- Port Bindings: {len(host_config.get("PortBindings", {}))} ports
- Volume Bindings: {len(host_config.get("Binds", []))} volumes

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

            logger.debug(f"Generated optimization prompt for container {container_id}")

            return PromptResult(
                description=f"Optimization suggestions for container {container_id}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate optimize prompt: {e}")
            return PromptResult(
                description=f"Error optimizing container {container_id}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help optimizing container {container_id}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class GenerateComposePrompt:
    """Prompt for generating docker-compose.yml files."""

    NAME = "generate_compose"
    DESCRIPTION = "Generate a docker-compose.yml file from container configuration"

    def __init__(self, docker_client: DockerClientWrapper) -> None:
        """Initialize the generate compose prompt.

        Args:
            docker_client: Docker client wrapper

        """
        self.docker = docker_client

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

    async def generate(
        self,
        container_id: str | None = None,
        service_description: str | None = None,
    ) -> PromptResult:
        """Generate docker-compose.yml from container or description.

        Args:
            container_id: Container ID or name (optional)
            service_description: Description of services (optional)

        Returns:
            Prompt result with compose file generation guidance

        """
        context = ""

        # If container_id provided, extract its configuration
        if container_id:
            try:
                container = self.docker.client.containers.get(container_id)
                container_attrs = container.attrs
                config = container_attrs.get("Config", {})
                host_config = container_attrs.get("HostConfig", {})

                # Extract key configuration elements
                image = config.get("Image", "")
                env_vars = config.get("Env", [])
                ports = host_config.get("PortBindings", {})
                volumes = host_config.get("Binds", [])
                restart_policy = host_config.get("RestartPolicy", {}).get("Name", "no")
                network_mode = host_config.get("NetworkMode", "bridge")

                context = f"""Existing Container Configuration for {container.name}:
- Image: {image}
- Environment Variables: {len(env_vars)} variables
  {chr(10).join(f"  - {var}" for var in env_vars[:5])}
  {"  - ..." if len(env_vars) > 5 else ""}
- Port Mappings: {len(ports)} ports
  {chr(10).join(f"  - {k}: {v}" for k, v in list(ports.items())[:3])}
  {"  - ..." if len(ports) > 3 else ""}
- Volumes: {len(volumes)} mounts
  {chr(10).join(f"  - {vol}" for vol in volumes[:3])}
  {"  - ..." if len(volumes) > 3 else ""}
- Restart Policy: {restart_policy}
- Network Mode: {network_mode}
"""
            except Exception as e:
                logger.error(f"Failed to get container info: {e}")
                context = f"Note: Could not retrieve container {container_id}: {e}\n"

        # Add service description if provided
        if service_description:
            context += f"\nService Requirements:\n{service_description}\n"

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


class TroubleshootComposeStackPrompt:
    """Prompt for troubleshooting Docker Compose stack issues."""

    NAME = "troubleshoot_compose_stack"
    DESCRIPTION = "Diagnose and troubleshoot Docker Compose project issues"

    def __init__(self, compose_client: ComposeClient) -> None:
        """Initialize the troubleshoot compose prompt.

        Args:
            compose_client: Compose client wrapper

        """
        self.compose = compose_client

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
                    "name": "project_name",
                    "description": "Compose project name to troubleshoot",
                    "required": True,
                },
                {
                    "name": "compose_file",
                    "description": "Path to docker-compose.yml file",
                    "required": False,
                },
            ],
        )

    async def generate(self, project_name: str, compose_file: str | None = None) -> PromptResult:
        """Generate troubleshooting prompt for a compose project.

        Args:
            project_name: Compose project name
            compose_file: Path to compose file (optional)

        Returns:
            Prompt result with troubleshooting guidance

        """
        try:
            # Get compose config using execute
            config_exec = self.compose.execute(
                "config",
                args=["--format", "json"],
                compose_file=compose_file,
                project_name=project_name,
                parse_json=True,
            )

            config_data: dict[str, Any] = {}
            if config_exec.get("success") and isinstance(config_exec.get("data"), dict):
                config_data = config_exec["data"]

            # Get services status
            ps_result = self.compose.execute(
                "ps",
                args=["--format", "json"],
                compose_file=compose_file,
                project_name=project_name,
                parse_json=True,
            )

            # Get logs from all services
            logs_result = self.compose.execute(
                "logs",
                args=["--tail", "50"],
                compose_file=compose_file,
                project_name=project_name,
            )

            # Build context
            services_info = "Services status not available"
            if ps_result.get("success") and ps_result.get("data"):
                services = ps_result["data"]
                services_info = "\n".join(
                    f"- {s.get('Name', 'unknown')}: {s.get('State', 'unknown')} "
                    f"(Health: {s.get('Health', 'N/A')})"
                    for s in (services if isinstance(services, list) else [services])
                )

            logs = logs_result.get("stdout", "Logs not available")[:2000]  # Limit size

            context = f"""Compose Project: {project_name}

Services Status:
{services_info}

Recent Logs (last 50 lines):
{logs}

Configuration Overview:
- Services: {len(config_data.get("services", {}))} services defined
- Networks: {len(config_data.get("networks", {}))} networks
- Volumes: {len(config_data.get("volumes", {}))} volumes
"""

            system_message = """You are a Docker Compose troubleshooting expert. \
Analyze the compose project information and help diagnose issues. Consider:
1. Service health and status
2. Inter-service dependencies and startup order
3. Network connectivity between services
4. Volume mount issues
5. Port conflicts
6. Environment variable configuration
7. Resource constraints
8. Log patterns indicating errors
9. Common compose pitfalls

Provide specific, actionable recommendations to resolve the issues."""

            user_message = (
                f"Please analyze this Docker Compose project and help troubleshoot any issues:\n\n"
                f"{context}\n\n"
                "What could be wrong and how can I fix it?"
            )

            logger.debug(f"Generated troubleshoot prompt for compose project {project_name}")

            return PromptResult(
                description=f"Troubleshooting guidance for compose project {project_name}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate troubleshoot compose prompt: {e}")
            return PromptResult(
                description=f"Error troubleshooting compose project {project_name}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help troubleshooting compose project {project_name}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class OptimizeComposeConfigPrompt:
    """Prompt for optimizing Docker Compose configuration."""

    NAME = "optimize_compose_config"
    DESCRIPTION = "Suggest optimizations for Docker Compose configuration"

    def __init__(self, compose_client: ComposeClient) -> None:
        """Initialize the optimize compose prompt.

        Args:
            compose_client: Compose client wrapper

        """
        self.compose = compose_client

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
                    "name": "compose_file",
                    "description": "Path to docker-compose.yml file to optimize",
                    "required": True,
                }
            ],
        )

    async def generate(self, compose_file: str) -> PromptResult:
        """Generate optimization suggestions for a compose file.

        Args:
            compose_file: Path to compose file

        Returns:
            Prompt result with optimization suggestions

        """
        try:
            # Get compose config
            config_result = self.compose.get_config(
                compose_file=compose_file,
                format_json=True,
            )

            # Ensure we have a dict
            config: dict[str, Any] = config_result if isinstance(config_result, dict) else {}

            # Analyze configuration
            services = config.get("services", {})
            networks = config.get("networks", {})
            volumes = config.get("volumes", {})

            # Build analysis context
            services_summary = []
            for service_name, service_config in services.items():
                has_health_check = "healthcheck" in service_config
                has_resource_limits = (
                    "deploy" in service_config and "resources" in service_config["deploy"]
                )
                restart_policy = service_config.get("restart", "no")

                services_summary.append(
                    f"- {service_name}:\n"
                    f"  - Health check: {'Yes' if has_health_check else 'No'}\n"
                    f"  - Resource limits: {'Yes' if has_resource_limits else 'No'}\n"
                    f"  - Restart policy: {restart_policy}\n"
                    f"  - Ports: {len(service_config.get('ports', []))}\n"
                    f"  - Volumes: {len(service_config.get('volumes', []))}"
                )

            context = f"""Docker Compose Configuration Analysis

Services ({len(services)} total):
{chr(10).join(services_summary)}

Networks: {len(networks)} defined
Volumes: {len(volumes)} defined

Version: {config.get("version", "not specified")}
"""

            system_message = """You are a Docker Compose optimization expert. \
Analyze the compose configuration and suggest improvements for:
1. Service health checks
2. Resource limits and reservations
3. Restart policies for reliability
4. Network configuration and isolation
5. Volume management and data persistence
6. Environment variable management
7. Security best practices
8. Build optimization
9. Dependency management (depends_on)
10. Logging configuration

Provide specific, practical recommendations with YAML examples."""

            user_message = (
                f"Please analyze this Docker Compose configuration and suggest optimizations:\n\n"
                f"{context}\n\n"
                "How can I optimize this compose file for better performance, "
                "reliability, and security?"
            )

            logger.debug(f"Generated optimization prompt for compose file {compose_file}")

            return PromptResult(
                description=f"Optimization suggestions for compose file {compose_file}",
                messages=[
                    PromptMessage(role="system", content=system_message),
                    PromptMessage(role="user", content=user_message),
                ],
            )

        except Exception as e:
            logger.error(f"Failed to generate optimize compose prompt: {e}")
            return PromptResult(
                description=f"Error optimizing compose file {compose_file}",
                messages=[
                    PromptMessage(
                        role="user",
                        content=(
                            f"I need help optimizing compose file {compose_file}, "
                            f"but encountered an error: {e}"
                        ),
                    )
                ],
            )


class PromptProvider:
    """Main prompt provider that manages all Docker and Compose prompts."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        compose_client: ComposeClient | None = None,
    ) -> None:
        """Initialize the prompt provider.

        Args:
            docker_client: Docker client wrapper
            compose_client: Compose client wrapper (optional)

        """
        self.docker = docker_client
        self.troubleshoot_prompt = TroubleshootContainerPrompt(docker_client)
        self.optimize_prompt = OptimizeContainerPrompt(docker_client)
        self.generate_compose_prompt = GenerateComposePrompt(docker_client)

        # Initialize compose prompts
        self.compose = compose_client or ComposeClient()
        self.troubleshoot_compose_prompt = TroubleshootComposeStackPrompt(self.compose)
        self.optimize_compose_prompt = OptimizeComposeConfigPrompt(self.compose)

        self.prompts = {
            self.troubleshoot_prompt.NAME: self.troubleshoot_prompt,
            self.optimize_prompt.NAME: self.optimize_prompt,
            self.generate_compose_prompt.NAME: self.generate_compose_prompt,
            self.troubleshoot_compose_prompt.NAME: self.troubleshoot_compose_prompt,
            self.optimize_compose_prompt.NAME: self.optimize_compose_prompt,
        }

        logger.debug("Initialized PromptProvider")

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
                    TroubleshootContainerPrompt
                    | OptimizeContainerPrompt
                    | GenerateComposePrompt
                    | TroubleshootComposeStackPrompt
                    | OptimizeComposeConfigPrompt
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
        if name not in self.prompts:
            raise ValueError(f"Unknown prompt: {name}")

        # Call the appropriate generate method with arguments
        if name == TroubleshootContainerPrompt.NAME:
            container_id = arguments.get("container_id")
            if not container_id:
                raise ValueError("container_id is required for troubleshoot_container prompt")
            return await self.troubleshoot_prompt.generate(container_id)

        if name == OptimizeContainerPrompt.NAME:
            container_id = arguments.get("container_id")
            if not container_id:
                raise ValueError("container_id is required for optimize_container prompt")
            return await self.optimize_prompt.generate(container_id)

        if name == GenerateComposePrompt.NAME:
            container_id = arguments.get("container_id")
            service_description = arguments.get("service_description")
            return await self.generate_compose_prompt.generate(container_id, service_description)

        if name == TroubleshootComposeStackPrompt.NAME:
            project_name = arguments.get("project_name")
            if not project_name:
                raise ValueError("project_name is required for troubleshoot_compose_stack prompt")
            compose_file = arguments.get("compose_file")
            return await self.troubleshoot_compose_prompt.generate(project_name, compose_file)

        if name == OptimizeComposeConfigPrompt.NAME:
            compose_file = arguments.get("compose_file")
            if not compose_file:
                raise ValueError("compose_file is required for optimize_compose_config prompt")
            return await self.optimize_compose_prompt.generate(compose_file)

        raise ValueError(f"Unsupported prompt: {name}")
