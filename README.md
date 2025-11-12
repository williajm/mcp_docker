# MCP Docker Server

| Category | Status |
|---|---|
| **Build & CI** | [![CI](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/ci.yml) [![CodeQL](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/codeql.yml) [![Pre-commit](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/pre-commit.yml) [![Dependency Review](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/dependency-review.yml) [![License Compliance](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/license-compliance.yml) [![Documentation](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/docs.yml) [![codecov](https://codecov.io/gh/williajm/mcp_docker/branch/main/graph/badge.svg)](https://codecov.io/gh/williajm/mcp_docker) |
| **SonarQube** | [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=williajm_mcp_docker&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=williajm_mcp_docker) |
| **Security** | [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/williajm/mcp_docker/badge)](https://scorecard.dev/viewer/?uri=github.com/williajm/mcp_docker) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-blue.svg?logo=dependabot)](https://github.com/williajm/mcp_docker/security/dependabot) [![Fuzzing](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml/badge.svg)](https://github.com/williajm/mcp_docker/actions/workflows/cflite.yml) |
| **Package** | [![GitHub release](https://img.shields.io/github/v/release/williajm/mcp_docker)](https://github.com/williajm/mcp_docker/releases) [![PyPI version](https://img.shields.io/pypi/v/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI status](https://img.shields.io/pypi/status/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) [![PyPI downloads](https://img.shields.io/pypi/dm/mcp-docker.svg)](https://pypi.org/project/mcp-docker/) |
| **Technology** | [![Python 3.11-3.14](https://img.shields.io/badge/python-3.11--3.14-blue.svg)](https://www.python.org/downloads/) [![Docker](https://img.shields.io/badge/Docker-Management-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![type-checked: mypy](https://img.shields.io/badge/type--checked-mypy-blue.svg)](https://mypy-lang.org/) [![MCP](https://img.shields.io/badge/MCP-1.2.0+-5865F2.svg)](https://modelcontextprotocol.io) |
| **Documentation** | [![Documentation](https://img.shields.io/badge/docs-English-blue)](https://williajm.github.io/mcp_docker/) [![Dogfennaeth Cymraeg](https://img.shields.io/badge/docs-Cymraeg-blue)](https://williajm.github.io/mcp_docker/README.cy) [![Documentation en Français](https://img.shields.io/badge/docs-Fran%C3%A7ais-blue)](https://williajm.github.io/mcp_docker/README.fr) [![Dokumentation auf Deutsch](https://img.shields.io/badge/docs-Deutsch-blue)](https://williajm.github.io/mcp_docker/README.de) [![Documentazione in Italiano](https://img.shields.io/badge/docs-Italiano-blue)](https://williajm.github.io/mcp_docker/README.it) [![Documentação em Português](https://img.shields.io/badge/docs-Portugu%C3%AAs-blue)](https://williajm.github.io/mcp_docker/README.pt) [![Documentación en Español](https://img.shields.io/badge/docs-Espa%C3%B1ol-blue)](https://williajm.github.io/mcp_docker/README.es) [![Dokumentacja po polsku](https://img.shields.io/badge/docs-Polski-blue)](https://williajm.github.io/mcp_docker/README.pl) [![Документація Українською](https://img.shields.io/badge/docs-%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-blue)](https://williajm.github.io/mcp_docker/README.uk) [![日本語ドキュメント](https://img.shields.io/badge/docs-%E6%97%A5%E6%9C%AC%E8%AA%9E-blue)](https://williajm.github.io/mcp_docker/README.ja) [![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-blue)](https://williajm.github.io/mcp_docker/README.zh) |

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Docker functionality to AI assistants like Claude. Manage containers, images, networks, and volumes through a type-safe, documented API with safety controls.

**Quick Start:** `claude mcp add --transport stdio docker uvx mcp-docker`

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

- Python 3.11+ and Docker installed
- [uv](https://github.com/astral-sh/uv) package manager (automatically installed by `uvx`)

### Installation with Claude Code

Run this command in your terminal:

```bash
claude mcp add --transport stdio docker uvx mcp-docker
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

**Note:** No additional configuration needed for local use. The Docker socket is automatically detected based on your operating system. See [docs/SETUP.md](docs/SETUP.md) for advanced configuration options.

### Manual Testing

Run directly with uvx (no installation needed):

```bash
uvx mcp-docker
```

**Getting Updates:** `uvx` caches packages and won't automatically update. To get the latest version:

```bash
# Force reinstall latest version
uvx --reinstall mcp-docker

# Or clear cache
uv cache clean mcp-docker
```

For detailed installation options (pip, from source, development setup), custom configuration, and troubleshooting, see [docs/SETUP.md](docs/SETUP.md).

### Advanced Usage

#### SSE Transport with TLS

For network-accessible deployments, use SSE transport with TLS/HTTPS:

```bash
# Production: Use the startup script with TLS
./start-mcp-docker-sse.sh

# Development: Run with SSE transport (no TLS)
mcp-docker --transport sse --host 127.0.0.1 --port 8000
```

Command-line options: `--transport` (stdio/sse), `--host`, `--port`

## Security

The MCP Docker server includes comprehensive security features for production deployments:

### Key Security Features

- **TLS/HTTPS**: Encrypted transport for SSE mode (required for production)
- **Authentication**: SSH key-based authentication for remote access
- **Rate Limiting**: Prevent abuse (60 req/min default, auth failures limited)
- **Audit Logging**: Track all operations with client IPs
- **IP Filtering**: Restrict access by network address
- **Error Sanitization**: Prevent information disclosure
- **Security Headers**: OWASP-recommended headers via `secure` library (HSTS, CSP, X-Frame-Options, etc.)

### ⚠️ Important Security Considerations

**Retrieval Agent Deception (RADE) Risk**: Container logs are returned unfiltered and may contain malicious prompts injected by untrusted containers. AI agents retrieving logs via `docker_container_logs` could be manipulated by these embedded instructions.

**Mitigation**:

- Treat container logs as untrusted user input
- Implement content filtering before presenting logs to AI agents
- Use read-only mode for untrusted containers
- Review audit logs for suspicious patterns

See [SECURITY.md](SECURITY.md) for the complete MCP threat model and mitigation strategies.

### Quick Production Setup

```bash
# Generate certificates
./scripts/generate-certs.sh

# Start with all security features enabled
./start-mcp-docker-sse.sh

# Test security configuration
./test-mcp-sse.sh
```

### Security Configuration

```bash
# TLS/HTTPS
MCP_TLS_ENABLED=true
MCP_TLS_CERT_FILE=~/.mcp-docker/certs/cert.pem
MCP_TLS_KEY_FILE=~/.mcp-docker/certs/key.pem

# Authentication
SECURITY_AUTH_ENABLED=true
SECURITY_SSH_AUTH_ENABLED=true
SECURITY_SSH_AUTHORIZED_KEYS_FILE=~/.mcp-docker/authorized_keys

# Rate Limiting
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_RPM=60
```

For complete security documentation, production deployment checklist, and best practices, see [SECURITY.md](SECURITY.md).

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

## MCP Server vs. Docker CLI: An Honest Comparison

**Should you use this MCP server or just let Claude run `docker` commands directly?** Here's an honest assessment:

### Using Docker CLI Directly

**Pros:**

- ✅ **Simpler setup** - No MCP server needed, works immediately
- ✅ **Full Docker access** - Every Docker feature available
- ✅ **No maintenance** - No additional service to run or update
- ✅ **Transparent** - See exactly what commands run
- ✅ **Familiar** - Standard Docker commands everyone knows

**Cons:**

- ❌ **No safety controls** - Can't restrict destructive operations programmatically
- ❌ **Text parsing** - Claude must parse unstructured CLI output
- ❌ **Less efficient** - Multiple commands needed for complex operations
- ❌ **No audit trail** - Unless you implement your own logging
- ❌ **No rate limiting** - Claude can run unlimited commands
- ❌ **Error handling** - Parsing error messages from text output
- ❌ **Command injection risk** - If Claude constructs commands incorrectly

**Example:**

```bash
# Claude needs multiple commands for a complex operation
docker ps --filter "status=running" --format json
docker inspect container_id
docker logs container_id --tail 100
# Parse JSON, extract data, reason about it...
```

### Using MCP Docker Server

**Pros:**

- ✅ **Enables Docker in Claude Desktop** - Claude Desktop has no CLI access, so MCP is the only way to use Docker
- ✅ **Safety controls** - Programmable restrictions (read-only mode, block destructive ops)
- ✅ **Structured data** - JSON input/output, easier for AI to process
- ✅ **Efficient** - One tool call can do what requires multiple CLI commands
- ✅ **Input validation** - Pydantic models prevent malformed requests
- ✅ **Audit logging** - Track all operations with timestamps and client info
- ✅ **Rate limiting** - Prevent runaway operations
- ✅ **Better errors** - Structured error responses with error types
- ✅ **Contextual** - AI prompts guide Claude on what tools do

**Cons:**

- ❌ **Setup required** - Install, configure, and maintain the server
- ❌ **Limited coverage** - Only 36 tools (doesn't expose every Docker feature)
- ❌ **Abstraction layer** - Another component in the stack
- ❌ **Learning curve** - Need to understand MCP protocol and tool schemas
- ❌ **Debugging** - Harder to see what's happening under the hood

**Example:**

```json
// One tool call with structured input/output
{
  "tool": "docker_list_containers",
  "arguments": {
    "all": true,
    "filters": {"status": ["running"]}
  }
}
// Returns clean JSON with exactly the data needed
```

### When to Use Each

**Use Docker CLI directly if:**

- You're using **Claude Code** (Claude Desktop has no CLI access)
- You need a Docker feature not exposed by the MCP server
- You want minimal setup and maximum simplicity
- You're comfortable with Claude having full Docker access
- You're doing one-off tasks where safety controls aren't important
- You trust the AI agent completely

**Use MCP Docker Server if:**

- You're using **Claude Desktop** (only way to access Docker)
- You want safety controls (read-only mode, block destructive operations)
- You need audit logging for compliance or debugging
- You want structured input/output for better AI reasoning
- You're building production automation with AI agents
- You need rate limiting to prevent runaway operations
- You want to restrict access to specific operations
- Multiple users/agents need different permission levels

### Hybrid Approach

You can use both:

- **MCP server** for common, safe operations (list, inspect, logs, stats)
- **Docker CLI** for advanced features not in the MCP server (BuildKit, plugins, swarm)
- **Safety**: Keep destructive operations disabled in MCP, require explicit CLI commands for those

### Bottom Line

**For Claude Desktop users:** MCP server is required (no CLI access available).

**For Claude Code users:**

- **Learning/exploration:** Docker CLI is simpler
- **Production automation:** MCP server provides safety, structure, and control
- **Maximum flexibility:** Use both as needed

The MCP server doesn't replace the Docker CLI - it provides a safer, more structured interface when you need it.

## Documentation

- [Security Guide](SECURITY.md) - Security features, TLS/HTTPS, authentication, production checklist
- [API Reference](docs/API.md) - Complete tool documentation with examples
- [Setup Guide](docs/SETUP.md) - Installation, configuration, and troubleshooting
- [Usage Examples](docs/EXAMPLES.md) - Practical usage scenarios
- [Testing Guide](docs/TESTING.md) - Testing strategy and running tests
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
  - `cryptography>=41.0.0` - SSH authentication
  - `limits>=5.6.0` - Rate limiting

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
