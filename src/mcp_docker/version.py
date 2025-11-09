"""Version information for MCP Docker server.

Increment the build number each time the code changes to help identify
which version is running in Claude Desktop.
"""

__version__ = "1.0.1"
__build__ = 2  # v1.0.1: Fix SSE server graceful shutdown


def get_full_version() -> str:
    """Get full version string with build number."""
    return f"{__version__}.{__build__}"
