# MCP Docker Server

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-Server-green.svg)](https://modelcontextprotocol.io)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

## Features

- **37 Docker Tools**: Complete container, image, network, volume, and system management
- **3 AI Prompts**: Intelligent troubleshooting, optimization suggestions, and compose file generation
- **2 Resources**: Real-time container logs and resource statistics
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: 90%+ test coverage with unit, integration, and performance tests
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

The server can be configured via environment variables:

```bash
# Docker Configuration
export DOCKER_BASE_URL="unix:///var/run/docker.sock"  # Default Docker socket
export DOCKER_TIMEOUT=30  # API timeout in seconds
export DOCKER_VERSION="auto"  # Docker API version

# Safety Configuration
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false  # Allow rm, prune operations
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false  # Allow privileged containers
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true  # Require confirmation
export SAFETY_MAX_CONCURRENT_OPERATIONS=10  # Max concurrent operations

# Server Configuration
export SERVER_NAME="mcp-docker"
export SERVER_VERSION="0.1.0"
```

### Claude Desktop Setup

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "docker": {
      "command": "uvx",
      "args": ["mcp-docker"],
      "env": {
        "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "false"
      }
    }
  }
}
```

## Tools Overview

The server provides 37 tools organized into 5 categories:

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

### System Tools (7 tools)
- `docker_system_info` - Get Docker system information
- `docker_system_df` - Disk usage statistics
- `docker_system_prune` - Clean all unused resources
- `docker_version` - Get Docker version info
- `docker_events` - Stream Docker events
- `docker_healthcheck` - Check Docker daemon health

## Prompts

Three prompts help AI assistants work with Docker:

- **troubleshoot_container** - Diagnose container issues with logs and configuration analysis
- **optimize_container** - Get optimization suggestions for resource usage and security
- **generate_compose** - Generate docker-compose.yml from containers or descriptions

## Resources

Two resources provide real-time access to container data:

- **container://logs/{container_id}** - Stream container logs
- **container://stats/{container_id}** - Get resource usage statistics

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

# Run performance tests
uv run pytest tests/performance/ -v
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

- [ ] Docker Compose full support
- [ ] Docker Swarm operations
- [ ] Remote Docker host support
- [ ] Enhanced streaming (build/pull progress)
- [ ] WebSocket transport option
- [ ] Docker Scout integration


