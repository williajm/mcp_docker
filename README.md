# MCP Docker Server

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml)
[![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml)
[![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml)
[![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml)
[![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![Python 3.11-3.13](https://img.shields.io/badge/python-3.11--3.13-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://williajm.github.io/mcp_docker/)
[![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.fr.md)
[![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.de.md)
[![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.it.md)
[![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.es.md)
[![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.uk.md)
[![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.pt.md)
[![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.ja.md)
[![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://github.com/williajm/mcp_docker/blob/main/docs/README.zh.md)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

## Features

- **48 Docker Tools**: Complete container, image, network, volume, system, and **Docker Compose** management
- **5 AI Prompts**: Intelligent troubleshooting and optimization for containers and compose stacks
- **5 Resources**: Real-time container logs, stats, and compose project information
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: 88%+ test coverage with unit and integration tests
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
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

```bash
# .env file example (Windows)
DOCKER_BASE_URL=npipe:////./pipe/docker_engine
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

The server provides 48 tools organized into 6 categories:

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

### Docker Compose Management (12 tools)
- `docker_compose_up` - Start compose project services
- `docker_compose_down` - Stop and remove compose services
- `docker_compose_restart` - Restart compose services
- `docker_compose_stop` - Stop compose services
- `docker_compose_ps` - List compose project services
- `docker_compose_logs` - Get compose service logs
- `docker_compose_exec` - Execute command in compose service
- `docker_compose_build` - Build or rebuild compose services
- `docker_compose_write_file` - Create compose files in compose_files/ directory
- `docker_compose_scale` - Scale compose services
- `docker_compose_validate` - Validate compose file syntax
- `docker_compose_config` - Get resolved compose configuration

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

Five prompts help AI assistants work with Docker and Compose:

### Container Prompts
- **troubleshoot_container** - Diagnose container issues with logs and configuration analysis
- **optimize_container** - Get optimization suggestions for resource usage and security
- **generate_compose** - Generate docker-compose.yml from containers or descriptions

### Compose Prompts
- **troubleshoot_compose_stack** - Diagnose Docker Compose project issues and service dependencies
- **optimize_compose_config** - Optimize compose configuration for performance, reliability, and security

## Resources

Five resources provide real-time access to container and compose data:

### Container Resources
- **container://logs/{container_id}** - Stream container logs
- **container://stats/{container_id}** - Get resource usage statistics

### Compose Resources
- **compose://config/{project_name}** - Get resolved compose project configuration
- **compose://services/{project_name}** - List services in a compose project
- **compose://logs/{project_name}/{service_name}** - Get logs from a compose service

## Compose Files Directory

The `compose_files/` directory provides a secure sandbox for creating and testing Docker Compose configurations.

### Sample Files

Three ready-to-use sample files are included:
- `nginx-redis.yml` - Multi-service web stack (nginx + redis)
- `postgres-pgadmin.yml` - Database stack with admin UI
- `simple-webapp.yml` - Minimal single-service example

### Creating Custom Compose Files

Use the `docker_compose_write_file` tool to create custom compose files:

```python
# Claude can create compose files like this:
{
  "filename": "my-stack",  # Will be saved as user-my-stack.yml
  "content": {
    "version": "3.8",
    "services": {
      "web": {
        "image": "nginx:alpine",
        "ports": ["8080:80"]
      }
    }
  }
}
```

### Security Features

All compose files written via the tool are:
- ✅ Restricted to the `compose_files/` directory only
- ✅ Automatically prefixed with `user-` to distinguish from samples
- ✅ Validated for YAML syntax and structure
- ✅ Checked for dangerous volume mounts (/, /etc, /root, etc.)
- ✅ Validated for proper port ranges and network configurations
- ✅ Protected against path traversal attacks

### Testing Workflow

Recommended workflow for testing compose functionality:

1. **Create** a compose file using `docker_compose_write_file`
2. **Validate** with `docker_compose_validate`
3. **Start** services with `docker_compose_up`
4. **Check** status with `docker_compose_ps`
5. **View** logs with `docker_compose_logs`
6. **Clean up** with `docker_compose_down`

## Safety System

The server implements a three-tier safety system:

1. **SAFE** - Read-only operations (list, inspect, logs, stats)
   - No restrictions
   - Always allowed

2. **MODERATE** - State-changing but reversible (start, stop, create)
   - Can modify system state
   - Generally safe

3. **DESTRUCTIVE** - Permanent changes (remove, prune)
   - Requires `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true`
   - Can require confirmation
   - Cannot be easily undone

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

```bash
# Run all tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html

# Run unit tests only
uv run pytest tests/unit/ -v

# Run integration tests (requires Docker)
uv run pytest tests/integration/ -v -m integration
```

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
- Maintain 90%+ test coverage
- Pass all linting and type checking

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with the [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
- Uses the official [Docker SDK for Python](https://docker-py.readthedocs.io/)
- Powered by modern Python tooling: [uv](https://github.com/astral-sh/uv), [ruff](https://github.com/astral-sh/ruff), [mypy](https://mypy-lang.org/), [pytest](https://pytest.org/)

## Roadmap

- [x] Docker Compose full support (11 tools, 2 prompts, 3 resources)
- [ ] Docker Swarm operations
- [ ] Remote Docker host support
- [ ] Enhanced streaming (build/pull progress)
- [ ] WebSocket transport option
- [ ] Docker Scout integration
