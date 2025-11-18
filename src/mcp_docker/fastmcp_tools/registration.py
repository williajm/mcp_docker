"""Tool registration for FastMCP 2.0.

This module handles registration of all FastMCP tools with the application.
"""

from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.container_inspection import register_container_inspection_tools
from mcp_docker.fastmcp_tools.container_lifecycle import register_container_lifecycle_tools
from mcp_docker.fastmcp_tools.image import register_image_tools
from mcp_docker.fastmcp_tools.network import register_network_tools
from mcp_docker.fastmcp_tools.system import register_system_tools
from mcp_docker.fastmcp_tools.volume import register_volume_tools
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


def register_all_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> dict[str, list[str]]:
    """Register all FastMCP tools with the application.

    This function is the main entry point for registering all tools during
    the FastMCP migration. It will progressively register more tools as
    they are migrated from the legacy BaseTool implementation.

    Args:
        app: FastMCP application instance
        docker_client: Docker client wrapper
        safety_config: Safety configuration

    Returns:
        Dictionary mapping category to list of registered tool names

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_docker.config import Config
        from mcp_docker.docker_wrapper.client import DockerClientWrapper
        from mcp_docker.fastmcp_tools import register_all_tools

        config = Config()
        docker_client = DockerClientWrapper(config.docker)
        app = FastMCP("mcp-docker")

        registered = register_all_tools(app, docker_client, config.safety)
        print(f"Registered {sum(len(v) for v in registered.values())} tools")
        ```
    """
    logger.info("Registering FastMCP tools...")

    registered: dict[str, list[str]] = {}

    # Phase 3: SAFE (read-only) tools
    # Phase 4: MODERATE and DESTRUCTIVE tools
    # All tools are now registered together per category

    # Container tools (inspection + lifecycle)
    registered["container_inspection"] = register_container_inspection_tools(
        app, docker_client, safety_config
    )
    registered["container_lifecycle"] = register_container_lifecycle_tools(
        app, docker_client, safety_config
    )

    # Image tools (SAFE + MODERATE + DESTRUCTIVE)
    registered["image"] = register_image_tools(app, docker_client, safety_config)

    # Network tools (SAFE + MODERATE + DESTRUCTIVE)
    registered["network"] = register_network_tools(app, docker_client, safety_config)

    # Volume tools (SAFE + MODERATE + DESTRUCTIVE)
    registered["volume"] = register_volume_tools(app, docker_client, safety_config)

    # System tools (DESTRUCTIVE)
    registered["system"] = register_system_tools(app, docker_client, safety_config)

    total_tools = sum(len(tools) for tools in registered.values())
    logger.info(
        f"Successfully registered {total_tools} FastMCP tools across {len(registered)} categories"
    )

    return registered
