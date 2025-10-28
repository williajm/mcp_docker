"""Version information for MCP Docker server.

Increment the build number each time the code changes to help identify
which version is running in Claude Desktop.
"""

__version__ = "0.2.0"
__build__ = 12  # v0.2.0: Removed Docker Compose support, added read-only mode


def get_full_version() -> str:
    """Get full version string with build number."""
    return f"{__version__}.{__build__}"
