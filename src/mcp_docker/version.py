"""Version information for MCP Docker server.

Version is defined in pyproject.toml and read at runtime via importlib.metadata.
"""

from importlib.metadata import version


def get_version() -> str:
    """Get version string from package metadata."""
    try:
        return version("mcp-docker")
    except Exception:
        # Fallback for development installs
        return "0.0.0+dev"


# Backwards compatibility
__version__ = get_version()
