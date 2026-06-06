"""FastMCP system tools."""

from typing import Any

from docker.errors import APIError
from pydantic import BaseModel, Field

from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import ToolSpec
from mcp_docker.tools.filters import register_tools_with_filtering
from mcp_docker.utils.errors import DockerOperationError
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)

# Input/Output Models


class VersionOutput(BaseModel):
    """Output for Docker version information."""

    version: str = Field(description="Docker version")
    api_version: str = Field(description="Docker API version")
    platform: dict[str, str] = Field(description="Platform information")
    components: list[dict[str, Any]] = Field(description="Docker components")


# FastMCP Tool Functions


def create_version_tool(
    docker_client: DockerClientWrapper,
) -> ToolSpec:
    """Create the docker_version tool."""

    def version() -> dict[str, Any]:
        """Get Docker version information."""
        try:
            logger.info("Getting Docker version information")

            version_info = docker_client.client.version()

            output = VersionOutput(
                version=version_info.get("Version", "unknown"),
                api_version=version_info.get("ApiVersion", "unknown"),
                platform={
                    "name": version_info.get("Platform", {}).get("Name", "unknown"),
                    "os": version_info.get("Os", "unknown"),
                    "arch": version_info.get("Arch", "unknown"),
                    "kernel": version_info.get("KernelVersion", "unknown"),
                },
                components=version_info.get("Components", []),
            )

            logger.info(f"Docker version: {output.version}, API: {output.api_version}")
            return output.model_dump()

        except APIError as e:
            logger.error(f"Failed to get Docker version: {e}")
            raise DockerOperationError(f"Failed to get Docker version: {e}") from e

    return ToolSpec(
        name="docker_version",
        description=(
            "Get Docker version information including API version, platform, and components"
        ),
        safety=OperationSafety.SAFE,
        func=version,
        idempotent=True,
    )


def register_system_tools(
    app: Any,
    docker_client: DockerClientWrapper,
    safety_config: Any = None,
) -> list[str]:
    """Register read-only system tools with FastMCP."""
    tools = [
        create_version_tool(docker_client),
    ]
    return register_tools_with_filtering(app, tools, safety_config)
