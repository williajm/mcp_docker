---
layout: default
title: MCP Docker Server
---

# MCP Docker Server Documentation

[![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml)
[![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml)
[![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A local [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for Docker visibility and light lifecycle control.

## Features

- **12 Docker tools** for container inspection, reversible container lifecycle actions, image inspection, network listing, volume listing, and Docker version info
- **stdio transport only** for local MCP clients
- **No destructive Docker operations** exposed through MCP
- **Type safety** with Pydantic validation and mypy strict mode
- **Small configuration surface** focused on Docker connection, reversible-operation gating, and logging

## Canonical Docs

- [README.md](https://github.com/williajm/mcp_docker/blob/main/README.md) - Overview, install flow, and exposed tools
- [CONFIGURATION.md](https://github.com/williajm/mcp_docker/blob/main/CONFIGURATION.md) - Environment variable reference
- [SECURITY.md](https://github.com/williajm/mcp_docker/blob/main/SECURITY.md) - Security notes

## Quick Start

```bash
codex mcp add docker -- uvx mcp-docker@latest
```

```bash
claude mcp add --transport stdio docker uvx mcp-docker@latest
```

## Safety

Safe tools are read-only and always allowed. Moderate tools start, stop, or restart containers and are allowed by default.

```bash
SAFETY_ALLOW_MODERATE_OPERATIONS=false
```

This read-only mode leaves list, inspect, logs, stats, and version tools available while blocking start/stop/restart.

## What's Available

- Container: list, inspect, logs, stats, start, stop, restart
- Image: list, inspect
- Network: list
- Volume: list
- System: Docker version

For complete details, see [README.md](https://github.com/williajm/mcp_docker/blob/main/README.md#tools).

## Support

- **Issues**: [GitHub Issues](https://github.com/williajm/mcp_docker/issues)
- **MCP Documentation**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **PyPI Download Stats**: [pypi.kopdog.com](https://pypi.kopdog.com/package/?name=mcp-docker)

---

**Version**: 1.2.9.dev0
**Last Updated**: 2026-06-06
**Python**: 3.11+
**Docker**: API version 1.41+
