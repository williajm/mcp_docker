"""Centralized tool registry for FastMCP tools.

This module provides a declarative way to register all Docker tools,
eliminating boilerplate and making it easy to expose tool metadata.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.fastmcp_tools.filters import register_tools_with_filtering
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.safety import OperationSafety

logger = get_logger(__name__)


@dataclass
class ToolFactory:
    """Factory function for creating a Docker tool.

    Attributes:
        factory: Function that creates the tool (returns tuple with tool metadata)
        category: Tool category (e.g., "container", "image", "network")
        requires_safety_config: Whether the factory requires safety_config parameter
    """

    factory: Callable[..., tuple[str, str, OperationSafety, bool, bool, Any]]
    category: str
    requires_safety_config: bool = False


class ToolRegistry:
    """Central registry of all Docker tools.

    This registry provides:
    - Single source of truth for all tools
    - Easy metadata access (category, safety level)
    - Simplified registration logic
    - Automatic discovery for documentation/tests
    """

    def __init__(self) -> None:
        """Initialize empty tool registry."""
        self._tools: dict[str, ToolFactory] = {}

    def register(
        self,
        factory: Callable[..., tuple[str, str, OperationSafety, bool, bool, Any]],
        category: str,
        requires_safety_config: bool = False,
    ) -> None:
        """Register a tool factory.

        Args:
            factory: Tool factory function (e.g., create_list_containers_tool)
            category: Category name (e.g., "container_inspection", "network")
            requires_safety_config: Whether factory needs safety_config parameter

        Example:
            registry = ToolRegistry()
            registry.register(create_list_containers_tool, "container_inspection", True)
        """
        # Call factory with minimal args to get tool name
        if requires_safety_config:
            # For factories that need safety_config, we need to handle differently
            # We'll store the factory and defer getting the name until registration time
            tool_key = f"{category}:{factory.__name__}"
        else:
            tool_key = f"{category}:{factory.__name__}"

        self._tools[tool_key] = ToolFactory(
            factory=factory,
            category=category,
            requires_safety_config=requires_safety_config,
        )

    def get_by_category(self, category: str) -> list[ToolFactory]:
        """Get all tool factories for a specific category.

        Args:
            category: Category name to filter by

        Returns:
            List of ToolFactory instances for the category
        """
        return [tool for tool in self._tools.values() if tool.category == category]

    def get_all_categories(self) -> list[str]:
        """Get list of all registered categories.

        Returns:
            List of unique category names
        """
        return sorted({tool.category for tool in self._tools.values()})

    def get_all_tools(self) -> dict[str, ToolFactory]:
        """Get all registered tools.

        Returns:
            Dictionary mapping tool keys to ToolFactory instances
        """
        return self._tools.copy()

    def register_with_app(
        self,
        app: Any,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
    ) -> dict[str, list[str]]:
        """Register all tools with FastMCP application.

        Args:
            app: FastMCP application instance
            docker_client: Docker client wrapper
            safety_config: Safety configuration

        Returns:
            Dictionary mapping category to list of registered tool names
        """
        registered: dict[str, list[str]] = {}

        for category in self.get_all_categories():
            tools_list = []

            for tool_factory in self.get_by_category(category):
                # Call factory with appropriate arguments
                if tool_factory.requires_safety_config:
                    tool_tuple = tool_factory.factory(docker_client, safety_config)
                else:
                    tool_tuple = tool_factory.factory(docker_client)

                tools_list.append(tool_tuple)

            # Register all tools in this category
            registered[category] = register_tools_with_filtering(app, tools_list, safety_config)

        return registered


# Global registry instance
_global_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry instance.

    Returns:
        Global ToolRegistry instance (creates if doesn't exist)
    """
    global _global_registry  # noqa: PLW0603
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def register_tool(
    category: str,
    requires_safety_config: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to register a tool factory with the global registry.

    Args:
        category: Tool category name
        requires_safety_config: Whether factory requires safety_config parameter

    Returns:
        Decorator function

    Example:
        @register_tool("container_inspection", requires_safety_config=True)
        def create_list_containers_tool(...):
            ...
    """

    def decorator(factory: Callable[..., Any]) -> Callable[..., Any]:
        registry = get_tool_registry()
        registry.register(factory, category, requires_safety_config)
        return factory

    return decorator


def build_tools_from_factories(
    factories: list[tuple[Callable[..., Any], bool]],
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig | None = None,
) -> list[tuple[str, str, OperationSafety, bool, bool, Any]]:
    """Build tools list from factory functions.

    This helper reduces boilerplate in register_*_tools() functions.

    Args:
        factories: List of (factory_function, requires_safety_config) tuples
        docker_client: Docker client wrapper
        safety_config: Safety configuration (optional)

    Returns:
        List of tool tuples ready for register_tools_with_filtering()

    Example:
        TOOL_FACTORIES = [
            (create_list_containers_tool, True),
            (create_inspect_container_tool, False),
        ]

        def register_container_tools(app, docker_client, safety_config):
            tools = build_tools_from_factories(TOOL_FACTORIES, docker_client, safety_config)
            return register_tools_with_filtering(app, tools, safety_config)
    """
    tools = []
    for factory, requires_safety in factories:
        if requires_safety:
            if safety_config is None:
                # Skip tools that require safety_config if it's not provided
                logger.warning(
                    f"Skipping tool {factory.__name__} - requires safety_config but none provided"
                )
                continue
            tool = factory(docker_client, safety_config)
        else:
            tool = factory(docker_client)
        tools.append(tool)
    return tools


__all__ = [
    "ToolFactory",
    "ToolRegistry",
    "get_tool_registry",
    "register_tool",
    "build_tools_from_factories",
]
