"""MCP Docker Server implementation.

This module provides the main MCP server that exposes Docker functionality
as tools through the Model Context Protocol.
"""

from typing import Any

from mcp_docker.config import Config
from mcp_docker.docker.client import DockerClientWrapper
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

        logger.info("Initializing MCP Docker server")
        self._register_tools()
        logger.info(f"Registered {len(self.tools)} tools")

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
        """
        if tool_name not in self.tools:
            logger.error(f"Tool not found: {tool_name}")
            raise ValueError(f"Tool not found: {tool_name}")

        tool = self.tools[tool_name]
        logger.info(f"Calling tool: {tool_name}")

        try:
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

    def __repr__(self) -> str:
        """Return string representation."""
        return f"MCPDockerServer(tools={len(self.tools)})"
