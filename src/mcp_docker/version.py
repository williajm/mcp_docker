"""Version information for MCP Docker server.

Increment the build number each time the code changes to help identify
which version is running in Claude Desktop.
"""

__version__ = "0.4.1"
__build__ = 13  # v0.4.1: Fixed token permissions and signed releases


def get_full_version() -> str:
    """Get full version string with build number."""
    return f"{__version__}.{__build__}"
