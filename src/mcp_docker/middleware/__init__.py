"""FastMCP middleware for Docker operations.

This package provides FastMCP-compatible middleware for safety enforcement,
rate limiting, audit logging, debug logging, and authentication.
"""

from mcp_docker.middleware.audit import AuditMiddleware
from mcp_docker.middleware.auth import AuthMiddleware
from mcp_docker.middleware.debug_logging import DebugLoggingMiddleware
from mcp_docker.middleware.error_handler import ErrorHandlerMiddleware
from mcp_docker.middleware.rate_limit import PreAuthRateLimitMiddleware, RateLimitMiddleware
from mcp_docker.middleware.safety import SafetyMiddleware
from mcp_docker.middleware.utils import get_operation_name, get_operation_type

__all__ = [
    "AuthMiddleware",
    "SafetyMiddleware",
    "RateLimitMiddleware",
    "PreAuthRateLimitMiddleware",
    "AuditMiddleware",
    "DebugLoggingMiddleware",
    "ErrorHandlerMiddleware",
    "get_operation_type",
    "get_operation_name",
]
