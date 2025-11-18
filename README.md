# MCP Docker Server

| Category | Status |
| --- | --- |
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

**Quick Start:**

- **Claude Code (stdio)**: `claude mcp add --transport stdio docker uvx mcp-docker@latest`
- **Codex (stdio)**: `codex mcp add docker -- uvx mcp-docker@latest`

## Features

- **33 Docker Tools**: Individually optional via config. Complete container, image, network, volume, and system management
- **5 AI Prompts**: Intelligent troubleshooting, optimization, networking debug, and security analysis
- **2 Resources**: Real-time container logs and resource statistics
- **2 Transport Options**: stdio (local) and HTTP (network deployments)
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: Extensive test coverage with unit, integration, E2E, and fuzz tests
- **Continuous Fuzzing**: ClusterFuzzLite integration for security and robustness (OpenSSF Scorecard compliant)
- **Modern Python**: Built with Python 3.11+, uv package manager, and async-first design

## Install Instructions

### Prerequisites

- Python 3.11+ and Docker installed
- [uv](https://github.com/astral-sh/uv) package manager (automatically installed by `uvx`)

### Installation with Claude Code

Run this command in your terminal:

```bash
claude mcp add --transport stdio docker uvx mcp-docker@latest
```

That's it! The Docker socket is auto-detected for your OS (Windows, Linux, macOS, WSL).

### Installation with Claude Desktop

Add to your `claude_desktop_config.json`:

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

**Note:** No additional configuration needed for local use. The Docker socket is automatically detected based on your operating system.

**Getting Updates:** `uvx` caches packages and won't automatically update. To get the latest version:

```bash
# Run the latest version (recommended - no caching)
uvx mcp-docker@latest

# Or clear all cached tool environments
uv cache prune
```

### Advanced Usage

#### HTTP Transport

For network-accessible deployments, use HTTP transport:

```bash
# Run with HTTP transport
mcp-docker --transport http --host 127.0.0.1 --port 8000
```

**Production Deployment:**

For production use, deploy behind a reverse proxy (NGINX, Caddy) that provides:

- HTTPS/TLS termination
- OAuth/authentication
- Rate limiting
- IP filtering

Command-line options: `--transport` (stdio/http), `--host`, `--port`

## Security

The MCP Docker server provides enterprise-grade security for production deployments with OAuth authentication, TLS encryption, rate limiting, audit logging, and safety controls.

**⚠️ Important**: Container logs may contain malicious prompts (RADE risk). See [SECURITY.md](SECURITY.md) for threat model and mitigations.

**For production deployment**, see [SECURITY.md](SECURITY.md) for:

- Complete security feature guide (OAuth, TLS, IP filtering, rate limiting, audit logging)
- Production deployment checklist
- Threat model and mitigation strategies
- Security best practices

### Configuration

All environment variables (safety, server, transports, OAuth, rate limits, CORS) are documented in
[CONFIGURATION.md](CONFIGURATION.md). Production hardening steps, threat models, and deployment
checklists live in [SECURITY.md](SECURITY.md).

**Documentation:**

- [CONFIGURATION.md](CONFIGURATION.md) - Complete configuration reference (all options)
- [SECURITY.md](SECURITY.md) - Security features and production guidelines

## Tools Overview

The server provides 33 tools organized into 5 categories:

### Container Management (10 tools)

- `docker_list_containers` - List containers with filters
- `docker_inspect_container` - Get detailed container info
- `docker_create_container` - Create new container
- `docker_start_container` - Start container
- `docker_stop_container` - Stop container gracefully
- `docker_restart_container` - Restart container
- `docker_remove_container` - Remove container
- `docker_container_logs` - Get container logs
- `docker_exec_command` - Execute command in container
- `docker_container_stats` - Get resource usage stats

### Image Management (9 tools)

- `docker_list_images` - List images
- `docker_inspect_image` - Get image details
- `docker_pull_image` - Pull from registry
- `docker_build_image` - Build from Dockerfile
- `docker_push_image` - Push to registry
- `docker_tag_image` - Tag image
- `docker_remove_image` - Remove image
- `docker_prune_images` - Clean unused images
- `docker_image_history` - View layer history

### Network Management (6 tools)

- `docker_list_networks` - List networks
- `docker_inspect_network` - Get network details
- `docker_create_network` - Create network
- `docker_connect_container` - Connect container to network
- `docker_disconnect_container` - Disconnect from network
- `docker_remove_network` - Remove network

### Volume Management (5 tools)

- `docker_list_volumes` - List volumes
- `docker_inspect_volume` - Get volume details
- `docker_create_volume` - Create volume
- `docker_remove_volume` - Remove volume
- `docker_prune_volumes` - Clean unused volumes

### System Tools (3 tools)

- `docker_version` - Get Docker version info
- `docker_events` - Get Docker events with optional time range and filters
- `docker_prune_system` - Clean all unused resources

## Prompts

Five prompts help AI assistants work with Docker:

- **troubleshoot_container** - Diagnose container issues with logs and configuration analysis
- **optimize_container** - Get optimization suggestions for resource usage and security
- **generate_compose** - Generate docker-compose.yml from containers or descriptions
- **debug_networking** - Deep-dive analysis of container networking problems with systematic L3-L7 troubleshooting
- **security_audit** - Comprehensive security analysis following CIS Docker Benchmark with compliance mapping

## Resources

Two resources provide real-time access to container data:

- **container://logs/{container_id}** - Stream container logs
- **container://stats/{container_id}** - Get resource usage statistics

## Safety System

The server implements a three-tier safety system with configurable operation modes and fine-grained tool filtering:

### Operation Safety Levels

1. **SAFE** - Read-only operations (list, inspect, logs, stats)
   - No restrictions
   - Always allowed
   - Examples: `docker_list_containers`, `docker_inspect_image`, `docker_container_logs`

2. **MODERATE** - State-changing but reversible (start, stop, create)
   - Can modify system state
   - Controlled by `SAFETY_ALLOW_MODERATE_OPERATIONS` (default: `true`)
   - Examples: `docker_create_container`, `docker_start_container`, `docker_pull_image`

3. **DESTRUCTIVE** - Permanent changes (remove, prune)
   - Cannot be easily undone
   - Requires `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Can require confirmation
   - Examples: `docker_remove_container`, `docker_prune_images`, `docker_system_prune`

### Tool Filtering (Allow/Deny Lists)

In addition to safety levels, you can control exactly which tools are available using allow and deny lists:

**Deny List** - Block specific tools (takes precedence over allow list)

```bash
# Block destructive operations by tool name
SAFETY_DENIED_TOOLS="docker_remove_container,docker_prune_images,docker_system_prune"
```

**Allow List** - Only permit specific tools (empty = allow all based on safety level)

```bash
# Only allow read-only monitoring tools
SAFETY_ALLOWED_TOOLS="docker_list_containers,docker_inspect_container,docker_container_logs,docker_container_stats,docker_version"
```

**How it works:**

1. Safety level restrictions apply first (MODERATE/DESTRUCTIVE settings)
2. Deny list blocks specific tools regardless of safety level
3. Allow list (if non-empty) restricts to only listed tools
4. Tools are filtered in both `list_tools()` and at execution time

**Use cases:**

- Restrict AI agents to read-only operations for monitoring
- Block specific dangerous tools while allowing others at same safety level
- Create custom tool subsets for different user roles or environments
- Prevent accidental execution of critical operations

### Safety Modes

Configure the safety mode using environment variables:

**Read-Only Mode (Safest)** - Monitoring and observability only

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Optional: Explicitly allow only monitoring tools
SAFETY_ALLOWED_TOOLS="docker_list_containers,docker_list_images,docker_inspect_container,docker_inspect_image,docker_container_logs,docker_container_stats,docker_version,docker_system_info"
```

- ✅ List, inspect, logs, stats
- ❌ Create, start, stop, pull
- ❌ Remove, prune

**Default Mode (Balanced)** - Development and operations

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true  # or omit (default)
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false

# Optional: Deny only the most dangerous operations
SAFETY_DENIED_TOOLS="docker_system_prune,docker_prune_volumes"
```

- ✅ List, inspect, logs, stats
- ✅ Create, start, stop, pull
- ❌ Remove, prune

**Full Mode (Least Restrictive)** - Infrastructure management

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
```

- ✅ List, inspect, logs, stats
- ✅ Create, start, stop, pull
- ✅ Remove, prune

> **Note:** Read-only mode is ideal for monitoring, auditing, and observability use cases where no changes to Docker state should be allowed.

## MCP Server vs. Docker CLI

| Feature | Docker CLI Directly | MCP Docker Server |
| --------- | ------------------- | ------------------- |
| **Claude Desktop** | ❌ No CLI access | ✅ **Required** (only option) |
| **Claude Code** | ✅ Works immediately | ✅ Optional (adds safety) |
| **Setup** | None needed | Install & configure |
| **Safety Controls** | ❌ None | ✅ Read-only mode, operation blocking |
| **Data Format** | Text (requires parsing) | Structured JSON |
| **Audit Logging** | Manual setup | ✅ Built-in |
| **Rate Limiting** | ❌ None | ✅ Configurable |
| **Input Validation** | ❌ None | ✅ Pydantic schemas |
| **Docker Coverage** | 100% (all features) | 36 core operations |
| **Complexity** | Low (standard commands) | Medium (MCP protocol) |

**When to use MCP Server:**

- **Required:** Claude Desktop (no other option)
- **Recommended:** Production automation, compliance requirements, multi-user access, safety controls needed

**When to use CLI directly:**

- **Best for:** Claude Code with simple tasks, advanced Docker features, minimal setup

**Hybrid approach:** Use MCP for common operations + CLI for advanced features.

## Documentation

- [Security Guide](SECURITY.md) - Security features, TLS/HTTPS, authentication, production checklist

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker

# Install dependencies
uv sync --group dev

# Run tests
uv run pytest

# Run linting
uv run ruff check src tests
uv run ruff format src tests

# Run type checking
uv run mypy src tests
```

### Running Tests

The project includes four levels of testing: unit, integration, end-to-end (E2E), and fuzz tests.

#### Test Level Comparison

| Aspect | Unit Tests | Integration Tests | E2E Tests | Fuzz Tests |
| -------- | ----------- | ------------------- | ----------- | ------------ |
| **Docker Daemon** | ❌ Not required | ✅ Required | ✅ Required | ❌ Not required |
| **Docker Operations** | ❌ None | ✅ Real operations | ✅ Real operations | ❌ None |
| **Server Instance** | ❌ None / Mocked | ✅ Real MCPDockerServer | ✅ Real MCPDockerServer | ❌ Component-level |
| **MCP Client** | ❌ None | ❌ Direct server calls | ✅ Real ClientSession | ❌ None |
| **Transport Layer** | ❌ None | ❌ Bypassed | ✅ Real stdio/SSE | ❌ None |
| **Purpose** | Logic/validation | Component integration | Full workflows | Security/robustness |
| **Speed** | ⚡ Very fast (<5s) | ⚡ Fast (~10s) | 🐌 Slower (~30-60s) | ⚡ Continuous (CI) |

#### Running Different Test Levels

```bash
# Run all tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html

# Run unit tests only (fast, no Docker required)
uv run pytest tests/unit/ -v

# Run integration tests (requires Docker)
uv run pytest tests/integration/ -v -m integration

# Run E2E tests (requires Docker, comprehensive)
uv run pytest tests/e2e/ -v -m e2e

# Run E2E tests excluding slow tests
uv run pytest tests/e2e/ -v -m "e2e and not slow"

# Run fuzz tests locally (requires atheris)
python3 tests/fuzz/fuzz_validation.py -atheris_runs=10000
```

#### Fuzzing

The project uses [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) for continuous fuzzing to meet [OpenSSF Scorecard](https://github.com/ossf/scorecard) requirements. Fuzz tests run automatically in CI/CD to discover security vulnerabilities and edge cases.

### Project Structure

```text
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __main__.py          # Entry point
│       ├── server.py            # MCP server implementation
│       ├── config.py            # Configuration management
│       ├── docker/              # Docker SDK wrapper
│       ├── tools/               # MCP tool implementations
│       ├── resources/           # MCP resource providers
│       ├── prompts/             # MCP prompt templates
│       └── utils/               # Utilities (logging, validation, safety)
├── tests/                       # Test suite
├── docs/                        # Documentation
└── pyproject.toml              # Project configuration
```

## Requirements

- **Python**: 3.11 or higher
- **Docker**: Any recent version (tested with 20.10+)
- **Dependencies**:
  - `mcp>=1.2.0` - MCP SDK
  - `docker>=7.1.0` - Docker SDK for Python
  - `pydantic>=2.0.0` - Data validation
  - `loguru>=0.7.0` - Logging
  - `secure>=1.0.1` - Security headers
  - `authlib>=1.6.5` - OAuth/OIDC authentication (JWT validation)
  - `httpx>=0.28.1` - HTTP client for OAuth token introspection
  - `limits>=5.6.0` - Rate limiting
  - `cachetools>=6.2.1` - JWKS caching

### Code Standards

- Follow PEP 8 style guidelines
- Use type hints for all functions
- Write docstrings (Google style)
- Maintain high test coverage
- Pass all linting and type checking

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with the [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
- Uses the official [Docker SDK for Python](https://docker-py.readthedocs.io/)
- Powered by modern Python tooling: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)
