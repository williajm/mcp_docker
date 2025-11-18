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
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker)
[![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases)
[![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

## Features

- **33 Docker Tools**: Complete container, image, network, volume, and system management
- **5 AI Prompts**: Intelligent troubleshooting, optimization, networking debug, and security analysis
- **2 Resources**: Real-time container logs and resource statistics
- **Type Safety**: Full type hints with Pydantic validation and mypy strict mode
- **Safety Controls**: Three-tier safety system (safe/moderate/destructive) with configurable restrictions
- **Comprehensive Testing**: Extensive test coverage with unit and integration tests
- **Modern Python**: Built with Python 3.11+, uv package manager, and async-first design

## Canonical Docs

The project docs live in three Markdown sources. Each section in this site links directly to them:

- [README.md](https://github.com/williajm/mcp_docker/blob/main/README.md) — Overview, features, install flow, tools/prompts/resources
- [CONFIGURATION.md](https://github.com/williajm/mcp_docker/blob/main/CONFIGURATION.md) — All environment variables for Docker, transports, safety, and server settings
- [SECURITY.md](https://github.com/williajm/mcp_docker/blob/main/SECURITY.md) — Threat model, OAuth/TLS guidance, deployment checklist

## Quick Start

See [Installation Instructions](https://github.com/williajm/mcp_docker/blob/main/README.md#install-instructions) in the main README for a complete setup guide including:

- Prerequisites (Python 3.11+, Docker, uv/pip)
- Installation methods (uvx, uv, pip)
- Configuration for Claude Desktop (Linux/macOS/Windows)
- Platform-specific Docker socket URLs

## Safety System

Three-tier classification: **SAFE** (read-only) → **MODERATE** (create/modify) → **DESTRUCTIVE** (delete).

Control via environment variables: `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS`, `SAFETY_ALLOW_PRIVILEGED_CONTAINERS`, etc.

See [README.md](https://github.com/williajm/mcp_docker/blob/main/README.md#safety-system) for complete safety system documentation.

## What's Available

- **33 Docker Tools** - Container, image, network, volume, and system management
- **5 AI Prompts** - Troubleshooting, optimization, networking debug, security audit, compose generation
- **2 Resources** - Container logs and stats streaming

For complete list see [README.md](https://github.com/williajm/mcp_docker/blob/main/README.md#tools-overview).

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
logs = await client.read_resource("container://logs/my-container")
# Pass tail/follow arguments via your MCP client options
```

## Documentation Sources

- **README.md**: Overview, onboarding, tool/prompt/resource catalog
- **CONFIGURATION.md**: Canonical environment variable reference (Docker, transports, safety, TLS)
- **SECURITY.md**: OAuth/TLS configuration, IP filtering, audit trail, production hardening guide

For questions or issues, open a ticket in the [GitHub repository](https://github.com/williajm/mcp_docker).

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

**Version**: 1.2.0
**Last Updated**: 2025-11-18
**Python**: 3.11+
**Docker**: API version 1.41+
