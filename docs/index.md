---
layout: default
title: MCP Docker Server
---

# MCP Docker Server Documentation

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
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

## Features

- **36 Docker Tools**: Complete container, image, network, volume, and system management
- **3 AI Prompts**: Intelligent troubleshooting and optimization for containers
- **2 Resources**: Real-time container logs and resource statistics
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: 88%+ test coverage with unit and integration tests
- **Modern Python**: Built with Python 3.11+, uv package manager, and async-first design

## Quick Links

### Getting Started
- [Setup Guide](SETUP.md) - Installation, configuration, and quick start
- [Examples](EXAMPLES.md) - Real-world usage examples and tutorials

### Reference
- [API Reference](API.md) - Complete API documentation for all 36 tools, prompts, and resources
- [Architecture](ARCHITECTURE.md) - Technical design, patterns, and implementation details

### Resources
- [GitHub Repository](https://github.com/williajm/mcp_docker)
- [Issues & Bug Reports](https://github.com/williajm/mcp_docker/issues)
- [Model Context Protocol](https://modelcontextprotocol.io)

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Docker installed and running
- [uv](https://github.com/astral-sh/uv) package manager (recommended) or pip

### Installation

#### Using uvx (Recommended)

```bash
# Run directly without installation
uvx mcp-docker
```

#### Using uv

```bash
# Install from source
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
uv sync
uv run mcp-docker
```

#### Using pip

```bash
# Install from PyPI (when published)
pip install mcp-docker

# Or install from source
git clone https://github.com/williajm/mcp_docker.git
cd mcp_docker
pip install -e .
```

### Configuration

Add to your MCP client configuration (e.g., Claude Desktop).

**IMPORTANT**: Use the correct `DOCKER_BASE_URL` for your platform:

#### Linux / macOS

Configuration file location: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux)

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

#### Windows

Configuration file location: `%APPDATA%\Claude\claude_desktop_config.json`

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

**Note**: Ensure Docker Desktop is running before starting the MCP server.

## Safety System

The MCP Docker server includes a three-tier safety classification system:

### Safety Levels

1. **SAFE** - Read-only operations with no risk
   - List containers, images, networks, volumes
   - Inspect resources
   - View logs and stats

2. **MODERATE** - Operations that create or modify but don't destroy
   - Create containers, networks, volumes
   - Start/stop/restart containers
   - Pull images
   - Connect/disconnect networks

3. **DESTRUCTIVE** - Operations that permanently delete data
   - Remove containers, images, networks, volumes
   - Prune operations
   - System cleanup

### Configuration

Control safety levels via environment variables:

```bash
# Allow all destructive operations
export SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true

# Allow privileged containers
export SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true

# Require confirmation for destructive operations
export SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true
```

## What's Available

### 36 Docker Tools

#### Container Management (10 tools)
- List, inspect, create, start, stop, restart containers
- View logs, execute commands, get stats
- Remove containers

#### Image Management (9 tools)
- List, inspect, pull, build, push images
- Tag, remove, prune images
- View image history

#### Network Management (6 tools)
- List, inspect, create, remove networks
- Connect/disconnect containers
- Manage network configurations

#### Volume Management (5 tools)
- List, inspect, create, remove volumes
- Prune unused volumes
- Manage volume drivers

#### System Operations (6 tools)
- System info, disk usage, version
- System-wide pruning
- Event monitoring
- Health checks

### 3 AI Prompts

1. **troubleshoot_container** - Diagnose container issues
2. **optimize_container** - Suggest performance improvements
3. **generate_compose** - Create docker-compose.yml files

### 2 Resources

1. **Container Logs** - Stream real-time logs from containers
2. **Container Stats** - Monitor resource usage metrics

## Example Usage

### List All Containers

```python
# Using the MCP tool
result = await client.call_tool("docker_list_containers", {
    "all": True,
    "filters": {"status": ["running"]}
})
```

### Troubleshoot a Container

```python
# Using the AI prompt
prompt = await client.get_prompt("troubleshoot_container", {
    "container_id": "my-container"
})
# Returns detailed diagnostics and recommendations
```

### Stream Container Logs

```python
# Using the resource
logs = await client.read_resource(
    "container_logs://my-container?tail=100&follow=true"
)
```

## Documentation Structure

- **[Setup Guide](SETUP.md)**: Installation, configuration, and environment setup
- **[API Reference](API.md)**: Complete tool, prompt, and resource documentation
- **[Examples](EXAMPLES.md)**: Real-world usage scenarios and code samples
- **[Architecture](ARCHITECTURE.md)**: Design patterns, testing strategy, and implementation

## Contributing

Contributions are welcome! Please see the [GitHub repository](https://github.com/williajm/mcp_docker) for:
- Filing issues and bug reports
- Submitting pull requests
- Reviewing code and documentation

## License

MIT License - see [LICENSE](https://github.com/williajm/mcp_docker/blob/main/LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/williajm/mcp_docker/issues)
- **Discussions**: [GitHub Discussions](https://github.com/williajm/mcp_docker/discussions)
- **MCP Documentation**: [modelcontextprotocol.io](https://modelcontextprotocol.io)

---

**Version**: 0.2.0
**Last Updated**: 2025-10-28
**Python**: 3.11+
**Docker**: API version 1.41+
