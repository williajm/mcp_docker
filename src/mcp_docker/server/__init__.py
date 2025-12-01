"""MCP server implementation.

This package contains the FastMCP server implementation:
- server: Main MCP server class (FastMCPDockerServer)
- prompts: AI prompt templates
- resources: MCP resource definitions
"""

from mcp_docker.server.server import FastMCPDockerServer

__all__ = ["FastMCPDockerServer"]
