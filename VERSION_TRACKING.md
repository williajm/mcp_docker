# Version Tracking

This document explains how version tracking works in the MCP Docker server.

## Version Number Format

The server uses a version format: `MAJOR.MINOR.PATCH.BUILD`

- **MAJOR.MINOR.PATCH**: Semantic version (currently `0.1.0`)
- **BUILD**: Incremental build number

Example: `0.1.0.1` means version 0.1.0, build 1

## How to Update the Version

When you make code changes, increment the build number in `src/mcp_docker/version.py`:

```python
__version__ = "0.1.0"
__build__ = 2  # <- Increment this number
```

## Why This Matters

The version is logged at server startup and helps identify which version of the code is running in Claude Desktop. This is critical for debugging issues like:

- Stale cached versions
- Mismatched schemas between client and server
- Confirming code changes are actually being used

## Version Display Locations

1. **Server Logs**: On startup, the full version is logged:
   ```
   MCP Docker Server v0.1.0.1 Initializing
   ```

2. **MCP Protocol**: The version is sent in the server info during initialization

3. **Log Files**: Check `mcp_docker.log` or `C:\Users\<user>\AppData\Roaming\Claude\logs\mcp-server-mcp_docker.log`

## Build Number History

| Build | Date | Changes |
|-------|------|---------|
| 1 | 2025-10-26 | Added version tracking system |
| 2 | 2025-10-26 | Fixed MCP protocol version reporting |
| 3 | 2025-10-26 | Added JSON string auto-parsing workaround (didn't work) |
| 4 | 2025-10-26 | Fixed JSON string auto-parsing for docker_create_container |
| 5 | 2025-10-26 | Fixed JSON string parsing for docker_exec_command and docker_build_image |
| 6 | 2025-10-26 | Fixed JSON string parsing for docker_create_network and docker_create_volume (COMPLETE) |
