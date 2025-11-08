# MCP Docker Server

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml)
[![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml)
[![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml)
[![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml)
[![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)
[![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases)
[![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://williajm.github.io/mcp_docker/)
[![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy)
[![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr)
[![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de)
[![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it)
[![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt)
[![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es)
[![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl)
[![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk)
[![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja)
[![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

## Features

- **36 Docker Tools**: Complete container, image, network, volume, and system management
- **5 AI Prompts**: Intelligent troubleshooting, optimization, networking debug, and security analysis
- **2 Resources**: Real-time container logs and resource statistics
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: Extensive test coverage with unit, integration, E2E, and fuzz tests
- **Continuous Fuzzing**: ClusterFuzzLite integration for security and robustness (OpenSSF Scorecard compliant)
- **Modern Python**: Built with Python 3.11+, uv package manager, and async-first design

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Docker installed and running
- [uv](https://github.com/astral-sh/uv) package manager (recommended) or pip

### Installation

#### Option 1: Using uvx (Recommended)

```bash
# Run directly without installation
uvx mcp-docker
```

#### Option 2: Using uv

```bash
# Install from source
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Option 3: Using pip

```bash
# Install from source
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
mcp-docker
```

### Configuration

The server can be configured via environment variables or a `.env` file.

#### Platform-Specific Docker Configuration

**IMPORTANT**: The `DOCKER_BASE_URL` must be set correctly for your platform:

**Linux / macOS:**
```bash
export DOCKER_BASE_URL="unix:///var/run/docker.sock"
```

**Windows (Docker Desktop):**
```cmd
set DOCKER_BASE_URL=npipe:////./pipe/docker_engine
```

**PowerShell:**
```powershell
$env:DOCKER_BASE_URL="npipe:////./pipe/docker_engine"
```

#### All Configuration Options

```bash
# Docker Configuration
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Linux/macOS (default)
# export DOCKER_BASE_URL="npipe:////./pipe/docker_engine"  # Windows
export DOCKER_TIMEOUT=60  # API timeout in seconds (default: 60)
export DOCKER_TLS_VERIFY=false  # Enable TLS verification (default: false)
export DOCKER_TLS_CA_CERT="/path/to/ca.pem"  # Path to CA certificate (optional)
export DOCKER_TLS_CLIENT_CERT="/path/to/cert.pem"  # Path to client certificate (optional)
export DOCKER_TLS_CLIENT_KEY="/path/to/key.pem"  # Path to client key (optional)

# Safety Configuration
export SAFETY_ALLOW_MODERATE_OPERATIONS=true  # Allow state-changing ops like create, start, stop (default: true)
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Allow rm, prune operations (default: false)
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Allow privileged containers (default: false)
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Require confirmation (default: true)
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Max concurrent operations (default: 10)

# Server Configuration
export MCP_SERVER_NAME="mcp-docker"  # MCP server name (default: mcp-docker)
export MCP_SERVER_VERSION="0.1.0"  # MCP server version (default: 0.1.0)
export MCP_LOG_LEVEL="INFO"  # Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
export MCP_DOCKER_LOG_PATH="/path/to/mcp_docker.log"  # Log file path (optional, defaults to mcp_docker.log in working directory)
```

#### Using a .env File

Alternatively, create a `.env` file in your project directory:

```bash
# .env file example (Linux/macOS)
DOCKER_BASE_URL=unix:///var/run/docker.sock
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# .env file example (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
SAFETY_ALLOW_MODERATE_OPERATIONS=true
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

### Claude Desktop Setup

Add to your Claude Desktop configuration:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Basic configuration (stdio transport - recommended):**
```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "unix:///var/run/docker.sock"
      }
    }
  }
}
```

**Windows configuration:**
```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "DOCKER_BASE_URL": "npipe:////./pipe/docker_engine"
      }
    }
  }
}
```

### Advanced Usage

#### SSE Transport (HTTP)

The server supports SSE (Server-Sent Events) transport over HTTP in addition to the default stdio transport:

```bash
# Run with SSE transport
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

**Command-line options:**
- `--transport`: Transport type (`stdio` or `sse`, default: `stdio`)
- `--host`: Host to bind SSE server (default: `127.0.0.1`)
- `--port`: Port to bind SSE server (default: `8000`)

#### Custom Log Path

Set a custom log file location using the `MCP_DOCKER_LOG_PATH` environment variable:

```bash
export MCP_DOCKER_LOG_PATH="/var/log/mcp_docker.log"
mcp-docker
```

## Tools Overview

The server provides 36 tools organized into 5 categories:

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

### System Tools (6 tools)
- `docker_system_info` - Get Docker system information
- `docker_system_df` - Disk usage statistics
- `docker_system_prune` - Clean all unused resources
- `docker_version` - Get Docker version info
- `docker_events` - Stream Docker events
- `docker_healthcheck` - Check Docker daemon health

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

The server implements a three-tier safety system with configurable operation modes:

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

### Safety Modes

Configure the safety mode using environment variables:

**Read-Only Mode (Safest)** - Monitoring and observability only
```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```
- ✅ List, inspect, logs, stats
- ❌ Create, start, stop, pull
- ❌ Remove, prune

**Default Mode (Balanced)** - Development and operations
```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=true  # or omit (default)
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
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

## Documentation

- [API Reference](docs/API.md) - Complete tool documentation with examples
- [Setup Guide](docs/SETUP.md) - Installation and configuration details
- [Usage Examples](docs/EXAMPLES.md) - Practical usage scenarios
- [Architecture](docs/ARCHITECTURE.md) - Design principles and implementation

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
|--------|-----------|-------------------|-----------|------------|
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
python3 tests/fuzz/fuzz_ssh_auth.py -atheris_runs=10000
python3 tests/fuzz/fuzz_validation.py -atheris_runs=10000
```

#### Fuzzing

The project uses [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) for continuous fuzzing to meet [OpenSSF Scorecard](https://github.com/ossf/scorecard) requirements. Fuzz tests run automatically in CI/CD to discover security vulnerabilities and edge cases. See [docs/FUZZING.md](docs/FUZZING.md) for details.

### Project Structure

```
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

## Roadmap

- [ ] Docker Swarm operations
- [ ] Remote Docker host support
- [ ] Enhanced streaming (build/pull progress)
- [ ] WebSocket transport option
- [ ] Docker Scout integration
