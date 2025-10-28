"""MCP Prompt templates for Docker operations.

This module provides prompt templates that help users with common Docker tasks:
- troubleshoot_container: Diagnose container issues
- optimize_container: Suggest container optimizations
- generate_compose: Generate docker-compose.yml files
"""

from typing import Any

from pydantic import BaseModel, Field

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

        self.prompts = {
            self.troubleshoot_prompt.NAME: self.troubleshoot_prompt,
            self.optimize_prompt.NAME: self.optimize_prompt,
            self.generate_compose_prompt.NAME: self.generate_compose_prompt,
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
            if isinstance(  # noqa: UP038 - isinstance requires tuple, not union type
                prompt,
                (TroubleshootContainerPrompt, OptimizeContainerPrompt, GenerateComposePrompt),
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

        raise ValueError(f"Unsupported prompt: {name}")
