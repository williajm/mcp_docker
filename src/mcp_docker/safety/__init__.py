"""Safety enforcement module for Docker operations.

This package provides centralized safety enforcement that works with
any MCP framework (legacy SDK or FastMCP).
"""

from mcp_docker.safety.core import SafetyEnforcer

__all__ = ["SafetyEnforcer"]
