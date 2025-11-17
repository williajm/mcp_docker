"""FastMCP 2.0 tool implementations.

This package contains FastMCP-based tool implementations that replace
the class-based BaseTool implementations during the migration.

Organization:
- container_inspection.py: SAFE tools for container inspection
- container_lifecycle.py: MODERATE tools for container lifecycle
- image.py: Image management tools
- network.py: Network management tools
- volume.py: Volume management tools
- system.py: System-level operations
"""

from mcp_docker.fastmcp_tools.registration import register_all_tools

__all__ = ["register_all_tools"]
