"""Authentication module for MCP Docker server."""

from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.oauth_auth import OAuthAuthenticationError, OAuthAuthenticator
from mcp_docker.middleware.auth import AuthMiddleware

__all__ = ["ClientInfo", "AuthMiddleware", "OAuthAuthenticator", "OAuthAuthenticationError"]
