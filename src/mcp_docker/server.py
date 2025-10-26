"""MCP Docker Server implementation.

This module provides the main MCP server that exposes Docker functionality
as tools, resources, and prompts through the Model Context Protocol.
"""

import asyncio
import inspect
from typing import Any

from mcp_docker.config import Config
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.prompts.templates import PromptProvider
from mcp_docker.resources.providers import ResourceProvider
from mcp_docker.tools import base as tools_base
from mcp_docker.tools import container_tools, image_tools, network_tools, system_tools, volume_tools
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)


class MCPDockerServer:
    """MCP server for Docker operations.

    This server exposes Docker functionality through the Model Context Protocol,
    allowing AI assistants to interact with Docker containers, images, networks,
    volumes, and system operations.
    """

    def __init__(self, config: Config) -> None:
        """Initialize the MCP Docker server.

        Args:
            config: Server configuration
        """
        self.config = config
        self.docker_client = DockerClientWrapper(config.docker)
        self.tools: dict[str, Any] = {}
        self.resource_provider = ResourceProvider(self.docker_client)
        self.prompt_provider = PromptProvider(self.docker_client)

        # Initialize semaphore for concurrency limiting
        self._operation_semaphore = asyncio.Semaphore(config.safety.max_concurrent_operations)

        logger.info("Initializing MCP Docker server")
        self._register_tools()
        logger.info(f"Registered {len(self.tools)} tools")
        logger.info(
            f"Initialized resource and prompt providers "
            f"(max concurrent operations: {config.safety.max_concurrent_operations})"
        )

    def _register_tools(self) -> None:
        """Auto-register all Docker tools from tool modules.

        This method discovers all BaseTool subclasses from the tool modules
        and automatically registers them. New tools added to any module will
        be automatically registered without code changes here.
        """
        tool_modules = [container_tools, image_tools, network_tools, volume_tools, system_tools]

        for module in tool_modules:
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's a BaseTool subclass (but not BaseTool itself)
                if (
                    issubclass(obj, tools_base.BaseTool)
                    and obj is not tools_base.BaseTool
                    and obj.__module__ == module.__name__  # Ensure it's defined in this module
                ):
                    try:
                        tool_instance = obj(self.docker_client, self.config.safety)
                        self._register_tool(tool_instance)
                        logger.debug(f"Auto-registered tool: {tool_instance.name}")
                    except Exception as e:
                        logger.error(
                            f"Failed to register tool {name} from {module.__name__}: {e}"
                        )

    def _register_tool(self, tool: Any) -> None:
        """Register a single tool.

        Args:
            tool: Tool instance to register
        """
        self.tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")

    def list_tools(self) -> list[dict[str, Any]]:
        """List all available tools.

        Returns:
            List of tool definitions for MCP protocol
        """
        tool_list = []
        for tool_name, tool in self.tools.items():
            tool_def = {
                "name": tool_name,
                "description": tool.description,
                "inputSchema": tool.input_schema.model_json_schema(),
            }
            tool_list.append(tool_def)

        logger.debug(f"Listed {len(tool_list)} tools")
        return tool_list

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a tool with the given arguments.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments

        Returns:
            Tool execution result

        Raises:
            ValueError: If tool not found
            PermissionError: If operation is not allowed by safety config
        """
        if tool_name not in self.tools:
            logger.error(f"Tool not found: {tool_name}")
            raise ValueError(f"Tool not found: {tool_name}")

        tool = self.tools[tool_name]
        logger.info(f"Calling tool: {tool_name}")

        # Use semaphore to limit concurrent operations
        async with self._operation_semaphore:
            try:
                # Additional safety checks beyond what BaseTool.check_safety() does
                # (BaseTool handles DESTRUCTIVE operations, we handle privileged containers here)
                self._check_privileged_operations(tool.name, arguments)

                # Use BaseTool.run() which handles validation and safety checks
                result = await tool.run(arguments)

                # Convert result to dict
                result_dict = result.model_dump() if hasattr(result, "model_dump") else result

                logger.info(f"Tool {tool_name} executed successfully")
                return {"success": True, "result": result_dict}

            except Exception as e:
                logger.error(f"Tool {tool_name} failed: {e}")
                return {"success": False, "error": str(e), "error_type": type(e).__name__}

    def _check_privileged_operations(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Check privileged operations beyond BaseTool's safety checks.

        BaseTool.check_safety() handles DESTRUCTIVE operations.
        This method handles privileged container checks.

        Args:
            tool_name: Name of the tool
            arguments: Tool arguments (to check privileged flag)

        Raises:
            PermissionError: If privileged operation is not allowed
        """
        # Check privileged containers (for exec commands)
        if tool_name == "docker_exec_command":
            privileged = arguments.get("privileged", False)
            if privileged and not self.config.safety.allow_privileged_containers:
                logger.warning("Privileged exec command blocked by safety config")
                raise PermissionError(
                    "Privileged containers are not allowed. "
                    "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
                )

        # Check privileged flag in container creation
        if tool_name == "docker_create_container":
            privileged = arguments.get("privileged", False)
            if privileged and not self.config.safety.allow_privileged_containers:
                logger.warning("Privileged container creation blocked by safety config")
                raise PermissionError(
                    "Privileged containers are not allowed. "
                    "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
                )

    async def start(self) -> None:
        """Start the MCP server."""
        logger.info("Starting MCP Docker server")

        # Check Docker daemon health
        try:
            health_status = self.docker_client.health_check()
            status = health_status.get("status", "unknown")
            if status == "healthy":
                logger.info("Docker daemon is healthy")
            else:
                logger.warning(f"Docker daemon health check failed: {status}")
        except Exception as e:
            logger.warning(f"Docker daemon health check failed: {e}")

    async def stop(self) -> None:
        """Stop the MCP server."""
        logger.info("Stopping MCP Docker server")
        self.docker_client.close()
        logger.info("MCP Docker server stopped")

    def list_resources(self) -> list[dict[str, Any]]:
        """List all available resources.

        Returns:
            List of resource definitions for MCP protocol

        """
        try:
            resources = self.resource_provider.list_resources()
            resource_list = [
                {
                    "uri": resource.uri,
                    "name": resource.name,
                    "description": resource.description,
                    "mimeType": resource.mime_type,
                }
                for resource in resources
            ]

            logger.debug(f"Listed {len(resource_list)} resources")
            return resource_list

        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            return []

    async def read_resource(self, uri: str) -> dict[str, Any]:
        """Read a resource by URI.

        Args:
            uri: Resource URI

        Returns:
            Resource content

        """
        try:
            content = await self.resource_provider.read_resource(uri)

            result = {
                "uri": content.uri,
                "mimeType": content.mime_type,
            }

            if content.text is not None:
                result["text"] = content.text
            if content.blob is not None:
                # Convert bytes to base64 string for JSON serialization if needed
                blob_value = (
                    content.blob.decode("utf-8")
                    if isinstance(content.blob, bytes)
                    else content.blob
                )
                result["blob"] = blob_value

            logger.info(f"Read resource: {uri}")
            return result

        except Exception as e:
            logger.error(f"Failed to read resource {uri}: {e}")
            raise

    def list_prompts(self) -> list[dict[str, Any]]:
        """List all available prompts.

        Returns:
            List of prompt definitions for MCP protocol

        """
        try:
            prompts = self.prompt_provider.list_prompts()
            prompt_list = [
                {
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments,
                }
                for prompt in prompts
            ]

            logger.debug(f"Listed {len(prompt_list)} prompts")
            return prompt_list

        except Exception as e:
            logger.error(f"Failed to list prompts: {e}")
            return []

    async def get_prompt(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Get a prompt by name with arguments.

        Args:
            name: Prompt name
            arguments: Prompt arguments

        Returns:
            Prompt messages

        """
        try:
            result = await self.prompt_provider.get_prompt(name, arguments)

            messages = [
                {"role": message.role, "content": message.content} for message in result.messages
            ]

            logger.info(f"Generated prompt: {name}")
            return {
                "description": result.description,
                "messages": messages,
            }

        except Exception as e:
            logger.error(f"Failed to get prompt {name}: {e}")
            raise

    def __repr__(self) -> str:
        """Return string representation."""
        return f"MCPDockerServer(tools={len(self.tools)}, resources=enabled, prompts=enabled)"
