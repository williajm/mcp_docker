"""Version information for MCP Docker server.

Version is defined in pyproject.toml and read at runtime via importlib.metadata.
Increment the build number each time the code changes to help identify
which version is running in Claude Desktop.
"""

from importlib.metadata import version

__build__ = 1  # v1.0.4: OAuth/OIDC authentication and security fixes


def get_version() -> str:
    """Get version string from package metadata."""
    try:
        return version("mcp-docker")
    except Exception:
        # Fallback for development installs
        return "0.0.0+dev"


def get_full_version() -> str:
    """Get full version string with build number."""
    return f"{get_version()}.{__build__}"


# Backwards compatibility
__version__ = get_version()
