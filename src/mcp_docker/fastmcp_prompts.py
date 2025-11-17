"""FastMCP 2.0 prompt implementations.

This module provides Docker prompts using FastMCP's @mcp.prompt() decorator:
- troubleshoot_container: Diagnose container issues
- optimize_container: Suggest container optimizations
- generate_compose: Generate docker-compose.yml files
- debug_networking: Deep-dive network troubleshooting
- security_audit: Comprehensive security analysis
"""

import asyncio
from typing import Any

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.stats_formatter import calculate_memory_usage

logger = get_logger(__name__)


def create_troubleshoot_container_prompt(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, Any]:
    """Create troubleshoot container FastMCP prompt.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, async_function)
    """

    async def troubleshoot_container(container_id: str) -> str:
        """Diagnose and troubleshoot container issues.

        Args:
            container_id: Container ID or name to troubleshoot

        Returns:
            Troubleshooting prompt with container diagnostics
        """

        def _fetch_data() -> dict[str, Any]:
            container = docker_client.client.containers.get(container_id)
            attrs = container.attrs
            logs = container.logs(tail=50).decode("utf-8", errors="replace")
            return {"attrs": attrs, "logs": logs}

        data = await asyncio.to_thread(_fetch_data)

        state = data["attrs"].get("State", {})
        config = data["attrs"].get("Config", {})
        logs = data["logs"]

        prompt = f"""Please help me troubleshoot container '{container_id}'.

Container Status: {state.get("Status", "unknown")}
Exit Code: {state.get("ExitCode", "N/A")}
Error: {state.get("Error", "None")}

Image: {config.get("Image", "unknown")}
Command: {config.get("Cmd", [])}

Recent Logs (last 50 lines):
{logs}

Please analyze the container state and logs to:
1. Identify the root cause of any issues
2. Suggest specific fixes or debugging steps
3. Recommend best practices to prevent similar issues
"""

        logger.debug(f"Generated troubleshooting prompt for {container_id}")
        return prompt

    return (
        "troubleshoot_container",
        "Diagnose and troubleshoot container issues",
        troubleshoot_container,
    )


def create_optimize_container_prompt(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, Any]:
    """Create optimize container FastMCP prompt.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, async_function)
    """

    async def optimize_container(container_id: str) -> str:
        """Suggest optimizations for a container.

        Args:
            container_id: Container ID or name to optimize

        Returns:
            Optimization suggestions prompt
        """

        def _fetch_data() -> dict[str, Any]:
            container = docker_client.client.containers.get(container_id)
            attrs = container.attrs
            stats = container.stats(stream=False)  # type: ignore[no-untyped-call]
            return {"attrs": attrs, "stats": stats}

        data = await asyncio.to_thread(_fetch_data)

        config = data["attrs"].get("Config", {})
        host_config = data["attrs"].get("HostConfig", {})
        memory_info = calculate_memory_usage(data["stats"])

        prompt = f"""Please suggest optimizations for container '{container_id}'.

Current Configuration:
- Image: {config.get("Image", "unknown")}
- Memory Limit: {host_config.get("Memory", "unlimited")}
- CPU Shares: {host_config.get("CpuShares", "default")}
- Restart Policy: {host_config.get("RestartPolicy", {}).get("Name", "no")}

Current Resource Usage:
- Memory: {memory_info["usage_mb"]:.2f} MB / {memory_info["limit_mb"]:.2f} MB
  ({memory_info["percent"]:.1f}%)

Please provide:
1. Resource allocation recommendations (CPU, memory)
2. Dockerfile improvements if applicable
3. Performance tuning suggestions
4. Security hardening recommendations
"""

        logger.debug(f"Generated optimization prompt for {container_id}")
        return prompt

    return (
        "optimize_container",
        "Suggest container optimizations and best practices",
        optimize_container,
    )


def create_generate_compose_prompt(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, Any]:
    """Create generate compose FastMCP prompt.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, async_function)
    """

    async def generate_compose(container_id: str) -> str:
        """Generate a docker-compose.yml for a container.

        Args:
            container_id: Container ID or name to convert

        Returns:
            Prompt for generating docker-compose.yml
        """

        def _fetch_data() -> dict[str, Any]:
            container = docker_client.client.containers.get(container_id)
            return container.attrs

        attrs = await asyncio.to_thread(_fetch_data)

        config = attrs.get("Config", {})
        host_config = attrs.get("HostConfig", {})

        prompt = f"""Please generate a docker-compose.yml file for container '{container_id}'.

Container Configuration:
- Image: {config.get("Image", "unknown")}
- Environment Variables: {len(config.get("Env", []))} vars
- Exposed Ports: {list(config.get("ExposedPorts", {}).keys())}
- Volumes: {host_config.get("Binds", [])}
- Networks: {list(attrs.get("NetworkSettings", {}).get("Networks", {}).keys())}
- Restart Policy: {host_config.get("RestartPolicy", {}).get("Name", "no")}

Please create a docker-compose.yml that:
1. Captures all essential configuration
2. Uses best practices for compose files
3. Includes comments explaining each section
4. Is ready to use with 'docker-compose up'
"""

        logger.debug(f"Generated compose prompt for {container_id}")
        return prompt

    return (
        "generate_compose",
        "Generate a docker-compose.yml from a running container",
        generate_compose,
    )


def create_debug_networking_prompt(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, Any]:
    """Create debug networking FastMCP prompt.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, async_function)
    """

    async def debug_networking(container_id: str) -> str:
        """Deep-dive network troubleshooting for a container.

        Args:
            container_id: Container ID or name to debug

        Returns:
            Network debugging prompt
        """

        def _fetch_data() -> dict[str, Any]:
            container = docker_client.client.containers.get(container_id)
            attrs = container.attrs
            logs = container.logs(tail=100).decode("utf-8", errors="replace")
            return {"attrs": attrs, "logs": logs}

        data = await asyncio.to_thread(_fetch_data)

        network_settings = data["attrs"].get("NetworkSettings", {})
        networks = network_settings.get("Networks", {})

        prompt = f"""Please help me debug networking issues for container '{container_id}'.

Network Configuration:
"""

        for network_name, network_config in networks.items():
            prompt += f"""
Network: {network_name}
- IP Address: {network_config.get("IPAddress", "N/A")}
- Gateway: {network_config.get("Gateway", "N/A")}
- MAC Address: {network_config.get("MacAddress", "N/A")}
"""

        prompt += f"""
Port Bindings: {network_settings.get("Ports", {})}

Recent Logs (last 100 lines):
{data["logs"]}

Please analyze the network configuration and logs to:
1. Identify any network connectivity issues
2. Check for DNS resolution problems
3. Verify port bindings and accessibility
4. Suggest network troubleshooting steps
"""

        logger.debug(f"Generated network debug prompt for {container_id}")
        return prompt

    return (
        "debug_networking",
        "Deep-dive network troubleshooting for containers",
        debug_networking,
    )


def create_security_audit_prompt(
    docker_client: DockerClientWrapper,
) -> tuple[str, str, Any]:
    """Create security audit FastMCP prompt.

    Args:
        docker_client: Docker client wrapper

    Returns:
        Tuple of (name, description, async_function)
    """

    async def security_audit(container_id: str | None = None) -> str:
        """Perform a comprehensive security analysis.

        Args:
            container_id: Optional container ID to audit (if None, audits all)

        Returns:
            Security audit prompt
        """

        def _fetch_data() -> list[dict[str, Any]]:
            if container_id:
                container = docker_client.client.containers.get(container_id)
                return [container.attrs]
            containers = docker_client.client.containers.list(all=True)
            return [c.attrs for c in containers[:20]]  # Limit to 20 containers

        containers_data = await asyncio.to_thread(_fetch_data)

        if container_id:
            prompt = f"""Please perform a security audit on container '{container_id}'.

"""
        else:
            prompt = f"""Please perform a security audit on {len(containers_data)} containers.

"""

        for attrs in containers_data:
            config = attrs.get("Config", {})
            host_config = attrs.get("HostConfig", {})
            name = attrs.get("Name", "unknown").lstrip("/")

            prompt += f"""
Container: {name}
- Image: {config.get("Image", "unknown")}
- Privileged: {host_config.get("Privileged", False)}
- User: {config.get("User", "root")}
- Capabilities: {host_config.get("CapAdd", [])}
- Volume Mounts: {len(host_config.get("Binds", []))} mounts
- Network Mode: {host_config.get("NetworkMode", "default")}
"""

        prompt += """
Please analyze for security risks:
1. Privileged containers or dangerous capabilities
2. Root user execution
3. Sensitive volume mounts (e.g., /var/run/docker.sock)
4. Exposed ports and network security
5. Image vulnerabilities and outdated images
6. Recommend security hardening measures
"""

        logger.debug("Generated security audit prompt")
        return prompt

    return (
        "security_audit",
        "Comprehensive security analysis of containers",
        security_audit,
    )


def register_all_prompts(app: Any, docker_client: DockerClientWrapper) -> dict[str, list[str]]:
    """Register all Docker prompts with FastMCP.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper

    Returns:
        Dictionary mapping category names to lists of registered prompt names
    """
    logger.info("Registering FastMCP prompts...")

    registered: dict[str, list[str]] = {"docker": []}

    # Register all 5 prompts
    prompts = [
        create_troubleshoot_container_prompt(docker_client),
        create_optimize_container_prompt(docker_client),
        create_generate_compose_prompt(docker_client),
        create_debug_networking_prompt(docker_client),
        create_security_audit_prompt(docker_client),
    ]

    for name, description, func in prompts:
        app.prompt(description=description)(func)
        registered["docker"].append(name)
        logger.debug(f"Registered prompt: {name}")

    total_prompts = sum(len(prompts) for prompts in registered.values())
    logger.info(f"Successfully registered {total_prompts} FastMCP prompts")

    return registered
