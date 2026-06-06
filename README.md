# MCP Docker Server

| Category | Status |
| --- | --- |
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Bandit](https://github.com/williajm/mcp_docker/actions/workflows/bandit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/bandit.yml) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) |

A local [Model Context Protocol](https://modelcontextprotocol.io) server for Docker visibility and light lifecycle control.

**12 tools** | **stdio transport only** | **no destructive Docker operations**

## Quick Start

**Claude Code:**

```bash
claude mcp add --transport stdio docker uvx mcp-docker@latest
```

**Codex:**

```bash
codex mcp add docker -- uvx mcp-docker@latest
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"]
    }
  }
}
```

The Docker socket is auto-detected for your OS. This package intentionally runs over stdio only; it is not a network-exposed Docker administration service.

## Tools

### Container

| Tool | Description | Safety |
| ---- | ----------- | ------ |
| `docker_list_containers` | List containers with filters | Safe |
| `docker_inspect_container` | Detailed container info | Safe |
| `docker_container_logs` | Get container logs | Safe |
| `docker_container_stats` | Resource usage stats | Safe |
| `docker_start_container` | Start container | Moderate |
| `docker_stop_container` | Stop container gracefully | Moderate |
| `docker_restart_container` | Restart container | Moderate |

### Image

| Tool | Description | Safety |
| ---- | ----------- | ------ |
| `docker_list_images` | List images | Safe |
| `docker_inspect_image` | Image details | Safe |

### Network

| Tool | Description | Safety |
| ---- | ----------- | ------ |
| `docker_list_networks` | List networks | Safe |

### Volume

| Tool | Description | Safety |
| ---- | ----------- | ------ |
| `docker_list_volumes` | List volumes | Safe |

### System

| Tool | Description | Safety |
| ---- | ----------- | ------ |
| `docker_version` | Docker version info | Safe |

## Safety

Safe tools are read-only and always allowed. Moderate tools are reversible lifecycle operations and are allowed by default.

```bash
# Read-only mode: list, inspect, logs, stats, version only
SAFETY_ALLOW_MODERATE_OPERATIONS=false
```

The package does not expose destructive tools such as remove, prune, build, push, or exec.

## Configuration

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `DOCKER_BASE_URL` | Auto-detected | Docker daemon socket URL |
| `DOCKER_TIMEOUT` | `60` | Docker operation timeout in seconds |
| `SAFETY_ALLOW_MODERATE_OPERATIONS` | `true` | Allow reversible start/stop/restart tools |
| `SAFETY_DEFAULT_TOOL_TIMEOUT` | `30` | Tool timeout in seconds, `0` disables |
| `SAFETY_MAX_RESPONSE_BYTES` | `1048576` | Maximum tool response size, `0` disables |
| `MCP_LOG_LEVEL` | `INFO` | Logging level |
| `MCP_JSON_LOGGING` | `false` | Emit JSON logs |
| `MCP_DEBUG_MODE` | `false` | Show unsanitized errors for local debugging |

## Development

```bash
uv sync --group dev
uv run pytest tests/unit/ -v
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/mcp_docker/
```

## Requirements

- Python 3.11+
- Docker 20.10+
- Key dependencies: `fastmcp`, `docker`, `pydantic`, `pydantic-settings`, `loguru`

## License

MIT — see [LICENSE](LICENSE).
