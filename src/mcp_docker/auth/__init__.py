"""Authentication module for MCP Docker server."""

from mcp_docker.auth.middleware import AuthMiddleware
from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.oauth_auth import OAuthAuthenticationError, OAuthAuthenticator

__all__ = ["ClientInfo", "AuthMiddleware", "OAuthAuthenticator", "OAuthAuthenticationError"]
