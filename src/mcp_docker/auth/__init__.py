"""Authentication module for MCP Docker server."""

from mcp_docker.auth.middleware import AuthMiddleware
from mcp_docker.auth.models import ClientInfo

__all__ = ["ClientInfo", "AuthMiddleware"]
