# Configuration Reference

Complete reference for the local MCP Docker server configuration options.

All configuration is via environment variables or a local `.env` file.

```bash
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_MODERATE_OPERATIONS=true
MCP_LOG_LEVEL=INFO
```

## Docker Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_BASE_URL` | Auto-detected | Docker daemon socket URL. Linux, macOS, and WSL use `unix:///var/run/docker.sock`; Windows uses `npipe:////./pipe/docker_engine`. |
| `DOCKER_TIMEOUT` | `60` | Docker operation timeout in seconds. |

## Safety Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFETY_ALLOW_MODERATE_OPERATIONS` | `true` | Allow reversible lifecycle operations: start, stop, and restart. |
| `SAFETY_DEFAULT_TOOL_TIMEOUT` | `30` | Default tool timeout in seconds. Set `0` for no timeout. |
| `SAFETY_MAX_RESPONSE_BYTES` | `1048576` | Maximum tool response size in bytes. Set `0` for no response limit. |

The package does not expose destructive tools. Remove, prune, build, push, exec, create-network, create-volume, and create-container operations are not registered.

## Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVER_NAME` | `mcp-docker` | Server name in MCP protocol metadata. |
| `MCP_SERVER_VERSION` | Package version | Server version in MCP protocol metadata. |
| `MCP_LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `MCP_JSON_LOGGING` | `false` | Emit JSON-formatted logs. |
| `MCP_DEBUG_MODE` | `false` | Show unsanitized errors for local debugging. |

## Common Scenarios

**Default local mode:**

```bash
uv run mcp-docker
```

**Read-only mode:**

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false uv run mcp-docker
```

**Custom Docker socket:**

```bash
DOCKER_BASE_URL=unix:///var/run/docker.sock uv run mcp-docker
```

## Boolean Values

Pydantic settings accepts common boolean strings:

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_MODERATE_OPERATIONS=false
```

## See Also

- [README.md](README.md) - Getting started and exposed tools
- [SECURITY.md](SECURITY.md) - Security notes
- [src/mcp_docker/config.py](src/mcp_docker/config.py) - Configuration implementation
