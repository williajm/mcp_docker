"""Authentication module for MCP Docker server."""

from mcp_docker.auth.models import ClientInfo
from mcp_docker.auth.oauth_auth import OAuthAuthenticationError, OAuthAuthenticator

# Note: AuthMiddleware is available from mcp_docker.middleware.auth
# Not re-exported here to avoid circular imports with fastmcp

__all__ = ["ClientInfo", "OAuthAuthenticator", "OAuthAuthenticationError"]
