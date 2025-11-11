"""Version information for MCP Docker server.

Increment the build number each time the code changes to help identify
which version is running in Claude Desktop.
"""

__version__ = "1.0.2"
__build__ = 1  # v1.0.2: Critical security fixes and authentication improvements


def get_full_version() -> str:
    """Get full version string with build number."""
    return f"{__version__}.{__build__}"
