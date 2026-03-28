# MCP Docker Server

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/)
[![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants. Manage containers, images, networks, and volumes through a type-safe API with configurable safety controls.

**33 tools** | **5 AI prompts** | **2 resource templates** | stdio and HTTP transports

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

No additional configuration needed for local use. The Docker socket is auto-detected for your OS.

> `uvx` caches packages. Use `uvx mcp-docker@latest` or `uv cache prune` to get updates.

### HTTP Transport

For network deployments:

```bash
mcp-docker --transport http --host 127.0.0.1 --port 8000
```

For production, deploy behind a reverse proxy (NGINX, Caddy) for TLS, authentication, and rate limiting.

## Tools

### Container (10 tools)

| Tool | Description | Safety |
|------|-------------|--------|
| `docker_list_containers` | List containers with filters | Safe |
| `docker_inspect_container` | Detailed container info | Safe |
| `docker_container_logs` | Get container logs | Safe |
| `docker_container_stats` | Resource usage stats | Safe |
| `docker_create_container` | Create new container | Moderate |
| `docker_start_container` | Start container | Moderate |
| `docker_stop_container` | Stop container gracefully | Moderate |
| `docker_restart_container` | Restart container | Moderate |
| `docker_exec_command` | Execute command in container | Moderate |
| `docker_remove_container` | Remove container | Destructive |

### Image (9 tools)

| Tool | Description | Safety |
|------|-------------|--------|
| `docker_list_images` | List images | Safe |
| `docker_inspect_image` | Image details | Safe |
| `docker_image_history` | View layer history | Safe |
| `docker_pull_image` | Pull from registry | Moderate |
| `docker_build_image` | Build from Dockerfile | Moderate |
| `docker_push_image` | Push to registry | Moderate |
| `docker_tag_image` | Tag image | Moderate |
| `docker_remove_image` | Remove image | Destructive |
| `docker_prune_images` | Clean unused images | Destructive |

### Network (6 tools)

| Tool | Description | Safety |
|------|-------------|--------|
| `docker_list_networks` | List networks | Safe |
| `docker_inspect_network` | Network details | Safe |
| `docker_create_network` | Create network | Moderate |
| `docker_connect_container` | Connect container to network | Moderate |
| `docker_disconnect_container` | Disconnect from network | Moderate |
| `docker_remove_network` | Remove network | Destructive |

### Volume (5 tools)

| Tool | Description | Safety |
|------|-------------|--------|
| `docker_list_volumes` | List volumes | Safe |
| `docker_inspect_volume` | Volume details | Safe |
| `docker_create_volume` | Create volume | Moderate |
| `docker_remove_volume` | Remove volume | Destructive |
| `docker_prune_volumes` | Clean unused volumes | Destructive |

### System (3 tools)

| Tool | Description | Safety |
|------|-------------|--------|
| `docker_version` | Docker version info | Safe |
| `docker_events` | Docker events with filters | Safe |
| `docker_prune_system` | Clean all unused resources | Destructive |

## Prompts

| Prompt | Purpose |
|--------|---------|
| `troubleshoot_container` | Diagnose container issues with logs and config analysis |
| `optimize_container` | Resource usage and security optimization suggestions |
| `generate_compose` | Generate docker-compose.yml from containers or descriptions |
| `debug_networking` | Systematic L3-L7 network troubleshooting |
| `security_audit` | CIS Docker Benchmark security analysis |

## Resource Templates

Discoverable via `resources/templates/list`:

- **`container://logs/{container_id}`** — Last 100 lines of container logs
- **`container://stats/{container_id}`** — Real-time resource usage (CPU, memory, network, I/O)

## Safety System

Three-tier classification controls what operations are permitted:

| Level | Description | Default | Examples |
|-------|-------------|---------|----------|
| **Safe** | Read-only operations | Always allowed | list, inspect, logs, stats |
| **Moderate** | Reversible state changes | Allowed | create, start, stop, pull |
| **Destructive** | Permanent changes | Blocked | remove, prune |

### Configuration

```bash
# Control operation levels
SAFETY_ALLOW_MODERATE_OPERATIONS=true      # default: true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # default: false

# Fine-grained tool filtering
SAFETY_ALLOWED_TOOLS="docker_list_containers,docker_inspect_container"  # whitelist (empty = all)
SAFETY_DENIED_TOOLS="docker_prune_system"                               # blacklist (takes precedence)
```

Deny list is checked before allow list. Both apply on top of the safety level gates.

### Preset Modes

**Read-only** — monitoring and observability only:
```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

**Balanced** (default) — development and operations:
```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

**Full access** — infrastructure management:
```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
```

## Security

Container logs may contain malicious prompts (RADE risk). See [SECURITY.md](SECURITY.md) for the full threat model.

Built-in security features: rate limiting, audit logging, IP filtering, OAuth support, error sanitization, and command injection validation.

For complete configuration reference, see [CONFIGURATION.md](CONFIGURATION.md).

## MCP Server vs Docker CLI

| Aspect | Docker CLI | MCP Server |
|--------|-----------|------------|
| Claude Desktop | No CLI access | Required (only option) |
| Claude Code | Works directly | Optional (adds safety) |
| Safety controls | None | Three-tier with filtering |
| Data format | Text (needs parsing) | Structured JSON |
| Audit logging | Manual | Built-in |
| Rate limiting | None | Configurable |
| Input validation | None | Pydantic schemas |
| Docker coverage | Full | 33 core operations |

**Use MCP Server** for Claude Desktop (required), production automation, compliance, or when you need safety controls.

**Use CLI directly** in Claude Code for simple tasks or features beyond the 33 tools.

## Development

### Setup

```bash
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync --group dev
```

### Testing

Four test levels: unit (no Docker, ~5s), integration (Docker, ~10s), E2E (Docker, ~60s), and fuzz (security).

```bash
uv run pytest --cov=mcp_docker --cov-report=html   # All tests with coverage
uv run pytest tests/unit/ -v                         # Unit only
uv run pytest tests/integration/ -v -m integration   # Integration
uv run pytest tests/e2e/ -v -m "e2e and not stress"  # E2E (no stress)
```

### Linting and Type Checking

```bash
uv run ruff check src/ tests/       # Lint
uv run ruff format --check src/ tests/  # Format check
uv run mypy src/mcp_docker/         # Type check (strict)
```

### Project Structure

```
src/mcp_docker/
├── __main__.py          # Entry point (transport selection)
├── config.py            # Pydantic settings (env vars)
├── server/              # MCP server, prompts, resources
├── tools/               # Tool implementations by category
├── docker/              # Docker SDK wrapper
├── services/            # Audit, rate limiting, safety
├── middleware/           # Auth, safety, rate limiting
└── utils/               # Validation, helpers, errors
```

## Requirements

- Python 3.11+
- Docker 20.10+
- Key dependencies: `mcp>=1.2.0`, `docker>=7.1.0`, `pydantic>=2.0.0`, `loguru`, `authlib`, `limits`

## License

MIT — see [LICENSE](LICENSE).

## Links

- [PyPI Stats](https://pypi.kopdog.com/package/?name=mcp-docker) | [Model Context Protocol](https://modelcontextprotocol.io) | [Docker SDK](https://docker-py.readthedocs.io/)
