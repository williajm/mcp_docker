"""MCP Docker tools."""

from mcp_docker.tools.base import BaseTool, ToolInput, ToolResult
from mcp_docker.tools.compose_tools import (
    ComposeBuildTool,
    ComposeConfigTool,
    ComposeDownTool,
    ComposeExecTool,
    ComposeLogsTool,
    ComposePsTool,
    ComposeRestartTool,
    ComposeScaleTool,
    ComposeStopTool,
    ComposeUpTool,
    ComposeValidateTool,
    ComposeWriteFileTool,
)
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

__all__ = [
    "BaseTool",
    "ToolInput",
    "ToolResult",
    # Compose tools
    "ComposeBuildTool",
    "ComposeConfigTool",
    "ComposeDownTool",
    "ComposeExecTool",
    "ComposeLogsTool",
    "ComposePsTool",
    "ComposeRestartTool",
    "ComposeScaleTool",
    "ComposeStopTool",
    "ComposeUpTool",
    "ComposeValidateTool",
    "ComposeWriteFileTool",
    # Container tools
    "ContainerLogsTool",
    "ContainerStatsTool",
    "CreateContainerTool",
    "ExecCommandTool",
    "InspectContainerTool",
    "ListContainersTool",
    "RemoveContainerTool",
    "RestartContainerTool",
    "StartContainerTool",
    "StopContainerTool",
    # Image tools
    "BuildImageTool",
    "ImageHistoryTool",
    "InspectImageTool",
    "ListImagesTool",
    "PruneImagesTool",
    "PullImageTool",
    "PushImageTool",
    "RemoveImageTool",
    "TagImageTool",
    # Network tools
    "ConnectContainerTool",
    "CreateNetworkTool",
    "DisconnectContainerTool",
    "InspectNetworkTool",
    "ListNetworksTool",
    "RemoveNetworkTool",
    # Volume tools
    "CreateVolumeTool",
    "InspectVolumeTool",
    "ListVolumesTool",
    "PruneVolumesTool",
    "RemoveVolumeTool",
    # System tools
    "EventsTool",
    "HealthCheckTool",
    "SystemDfTool",
    "SystemInfoTool",
    "SystemPruneTool",
    "VersionTool",
]
