"""MCP Docker Server implementation.

This module provides the main MCP server that exposes Docker functionality
as tools, resources, and prompts through the Model Context Protocol.
"""

from typing import Any

from mcp_docker.config import Config
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.prompts.templates import PromptProvider
from mcp_docker.resources.providers import ResourceProvider
from mcp_docker.tools.base import OperationSafety
from mcp_docker.tools.container_tools import (
    ContainerLogsTool,
    ContainerStatsTool,
    CreateContainerTool,
    ExecCommandTool,
    InspectContainerTool,
    ListContainersTool,
    RemoveContainerTool,
    RestartContainerTool,
    StartContainerTool,
    StopContainerTool,
)
from mcp_docker.tools.image_tools import (
    BuildImageTool,
    ImageHistoryTool,
    InspectImageTool,
    ListImagesTool,
    PruneImagesTool,
    PullImageTool,
    PushImageTool,
    RemoveImageTool,
    TagImageTool,
)
from mcp_docker.tools.network_tools import (
    ConnectContainerTool,
    CreateNetworkTool,
    DisconnectContainerTool,
    InspectNetworkTool,
    ListNetworksTool,
    RemoveNetworkTool,
)
from mcp_docker.tools.system_tools import (
    EventsTool,
    HealthCheckTool,
    SystemDfTool,
    SystemInfoTool,
    SystemPruneTool,
    VersionTool,
)
from mcp_docker.tools.volume_tools import (
    CreateVolumeTool,
    InspectVolumeTool,
    ListVolumesTool,
    PruneVolumesTool,
    RemoveVolumeTool,
)
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

        logger.info("Initializing MCP Docker server")
        self._register_tools()
        logger.info(f"Registered {len(self.tools)} tools")
        logger.info("Initialized resource and prompt providers")

    def _register_tools(self) -> None:
        """Register all Docker tools."""
        # Container tools (10 tools)
        self._register_tool(ListContainersTool(self.docker_client))
        self._register_tool(InspectContainerTool(self.docker_client))
        self._register_tool(CreateContainerTool(self.docker_client))
        self._register_tool(StartContainerTool(self.docker_client))
        self._register_tool(StopContainerTool(self.docker_client))
        self._register_tool(RestartContainerTool(self.docker_client))
        self._register_tool(RemoveContainerTool(self.docker_client))
        self._register_tool(ContainerLogsTool(self.docker_client))
        self._register_tool(ExecCommandTool(self.docker_client))
        self._register_tool(ContainerStatsTool(self.docker_client))

        # Image tools (9 tools)
        self._register_tool(ListImagesTool(self.docker_client))
        self._register_tool(InspectImageTool(self.docker_client))
        self._register_tool(PullImageTool(self.docker_client))
        self._register_tool(BuildImageTool(self.docker_client))
        self._register_tool(PushImageTool(self.docker_client))
        self._register_tool(TagImageTool(self.docker_client))
        self._register_tool(RemoveImageTool(self.docker_client))
        self._register_tool(PruneImagesTool(self.docker_client))
        self._register_tool(ImageHistoryTool(self.docker_client))

        # Network tools (6 tools)
        self._register_tool(ListNetworksTool(self.docker_client))
        self._register_tool(InspectNetworkTool(self.docker_client))
        self._register_tool(CreateNetworkTool(self.docker_client))
        self._register_tool(ConnectContainerTool(self.docker_client))
        self._register_tool(DisconnectContainerTool(self.docker_client))
        self._register_tool(RemoveNetworkTool(self.docker_client))

        # Volume tools (5 tools)
        self._register_tool(ListVolumesTool(self.docker_client))
        self._register_tool(InspectVolumeTool(self.docker_client))
        self._register_tool(CreateVolumeTool(self.docker_client))
        self._register_tool(RemoveVolumeTool(self.docker_client))
        self._register_tool(PruneVolumesTool(self.docker_client))

        # System tools (6 tools)
        self._register_tool(SystemInfoTool(self.docker_client))
        self._register_tool(SystemDfTool(self.docker_client))
        self._register_tool(SystemPruneTool(self.docker_client))
        self._register_tool(VersionTool(self.docker_client))
        self._register_tool(EventsTool(self.docker_client))
        self._register_tool(HealthCheckTool(self.docker_client))

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
                "inputSchema": tool.input_model.model_json_schema(),
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

        try:
            # Check safety before execution
            self._check_tool_safety(tool, arguments)

            # Validate input
            validated_input = tool.input_model(**arguments)

            # Execute tool
            result = await tool.execute(validated_input)

            # Convert result to dict
            result_dict = result.model_dump() if hasattr(result, "model_dump") else result

            logger.info(f"Tool {tool_name} executed successfully")
            return {"success": True, "result": result_dict}

        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return {"success": False, "error": str(e), "error_type": type(e).__name__}

    def _check_tool_safety(self, tool: Any, arguments: dict[str, Any]) -> None:
        """Check if a tool operation is allowed based on safety configuration.

        Args:
            tool: Tool instance to check
            arguments: Tool arguments (to check privileged flag)

        Raises:
            PermissionError: If operation is not allowed
        """
        # Get tool safety level
        safety_level = getattr(tool, "safety_level", OperationSafety.SAFE)

        # Check destructive operations
        if safety_level == OperationSafety.DESTRUCTIVE:
            if not self.config.safety.allow_destructive_operations:
                logger.warning(f"Destructive operation '{tool.name}' blocked by safety config")
                raise PermissionError(
                    f"Destructive operation '{tool.name}' is not allowed. "
                    "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
                )

            if self.config.safety.require_confirmation_for_destructive:
                logger.warning(
                    f"Destructive operation '{tool.name}' requires confirmation. "
                    "Proceeding without confirmation in MCP mode."
                )

        # Check privileged containers (for exec commands)
        if tool.name == "docker_exec_command":
            privileged = arguments.get("privileged", False)
            if privileged and not self.config.safety.allow_privileged_containers:
                logger.warning("Privileged exec command blocked by safety config")
                raise PermissionError(
                    "Privileged containers are not allowed. "
                    "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
                )

        # Check privileged flag in container creation
        if tool.name == "docker_create_container":
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
