# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **local, stdio-only** MCP (Model Context Protocol) server that exposes read-only Docker visibility plus reversible container lifecycle control to AI assistants. It provides **12 Docker tools** for inspecting containers, images, networks, and volumes and for starting/stopping/restarting containers, with safety controls. It is intentionally *not* a network-exposed Docker administration service: there is no HTTP transport, no authentication stack, and no destructive or build operations.

**Key Technologies:**
- Python 3.11+ with strict type checking (mypy)
- FastMCP 3.x for MCP protocol implementation
- Docker SDK for Python (>=7.1.0)
- Pydantic for validation and settings
- uv for package management
- Single transport: stdio (local only)

## Development Commands

### Setup
```bash
# Install dependencies
uv sync --all-extras

# Install just dev dependencies
uv sync --group dev

# Update lockfile (use --exclude-newer for supply chain safety)
# The 3-day buffer gives the community time to detect malicious uploads
uv lock --exclude-newer "$(date -u -d '3 days ago' +%Y-%m-%dT00:00:00Z)"
```

### Testing

**Four test levels:** unit (fast, no Docker), integration (requires Docker), E2E (full workflows), fuzz (security)

```bash
# Run all tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html

# Unit tests only (fast, ~5s, no Docker required)
uv run pytest tests/unit/ -v

# Integration tests (requires Docker, ~10s)
uv run pytest tests/integration/ -v -m integration

# E2E tests (requires Docker, ~60s, excludes stress tests)
uv run pytest tests/e2e/ -v -m "e2e and not stress"

# E2E tests including stress tests (local only, ~90s)
uv run pytest tests/e2e/ -v -m e2e

# Stress/performance tests only (high resource usage, skip in CI)
uv run pytest tests/e2e/ -v -m stress

# Run a single test file
uv run pytest tests/unit/test_safety.py -v

# Run a specific test function
uv run pytest tests/unit/test_safety.py::test_function_name -v
```

### Linting and Type Checking

**IMPORTANT:** Always run Ruff before pushing to a PR (per user instructions).

```bash
# Run Ruff linting
uv run ruff check src/ tests/

# Auto-fix Ruff issues
uv run ruff check --fix src/ tests/

# Run Ruff formatting check
uv run ruff format --check src/ tests/

# Auto-format with Ruff
uv run ruff format src/ tests/

# Run mypy type checking (strict mode)
uv run mypy src/mcp_docker/

# Run all quality checks (what CI does)
uv run ruff check src/
uv run ruff format --check src/
uv run mypy src/mcp_docker/
```

### Running the Server

```bash
# Run server (stdio transport, the only transport)
uv run mcp-docker

# Show version and exit
uv run mcp-docker --version

# Run directly via Python module
uv run python -m mcp_docker
```

### Building and Publishing

```bash
# Build package
uv build

# Check package contents
tar -tzf dist/mcp-docker-*.tar.gz | head -20
```

### Versioning

This project follows [PEP 440](https://peps.python.org/pep-0440/) versioning with development versions between releases.

**Version Format:**
- **Release**: `1.0.5` (published to PyPI)
- **Development**: `1.0.6.dev0` (in-progress work toward next release)

**Workflow:**

1. **After releasing** (e.g., `1.0.5`):
   ```bash
   # Immediately bump to next dev version in pyproject.toml
   version = "1.0.6.dev0"
   ```

2. **During development**:
   - Keep version at `X.Y.Z.dev0` for all commits
   - The `.dev0` suffix indicates this is not a released version
   - Git builds and local installs will show the dev version

3. **Before release**:
   ```bash
   # Remove .dev0 suffix when ready to release
   version = "1.0.6"
   ```

**Why `.dev0`?**
- Makes it clear the code is a development version
- `pip` and `uv` treat `.dev` versions as pre-releases
- Prevents confusion between released `1.0.5` and in-progress `1.0.6`
- Follows standard Python packaging conventions

**Note:** We do not publish `.dev0` versions to PyPI. They are only for local development and git-based installs.

## Architecture

### Core Components

1. **FastMCPDockerServer** (`src/mcp_docker/server/server.py`)
   - Main MCP server implementation using FastMCP 3.x
   - Wraps the FastMCP app with two middleware (error handling, safety) plus the
     built-in response limiter, and with configuration
   - Coordinates tool registration and safety enforcement

2. **Tool System** (`src/mcp_docker/tools/`)
   - **FastMCP Decorator Pattern**: Tools registered via `app.tool(...)` from `ToolSpec`s
   - **registration.py**: Central registration of all tool categories
   - Six category modules: container_inspection, container_lifecycle, image, network, volume, system
   - The 12 exposed tools: list/inspect/logs/stats containers, start/stop/restart
     containers, list/inspect images, list networks, list volumes, version
   - Each tool has a safety level: SAFE (read-only) or MODERATE (reversible).
     DESTRUCTIVE is still defined in the enum for fail-closed defaults but no
     destructive tool is registered.
   - **Tool Timeouts**: Per-tool execution timeouts via FastMCP's `timeout` parameter. Default 30s (`SAFETY_DEFAULT_TOOL_TIMEOUT`), with 60s (`TIMEOUT_MEDIUM`) for container logs.
   - **MCP Annotations**: Tools expose standard MCP annotations to help clients make decisions:
     - `readOnly`: Tool only reads data without modification (auto-set for SAFE tools)
     - `idempotent`: Tool can be safely retried with same parameters (e.g., start/stop/restart containers)
     - `openWorldInteraction`: Tool communicates with external systems

3. **Safety System** (`src/mcp_docker/services/safety.py`, `services/safety_enforcer.py`, `config.py`)
   - **Classification**: SAFE / MODERATE / DESTRUCTIVE (`OperationSafety`)
   - **Operation gating**: `SafetyEnforcer.check_operation_safety` allows SAFE always,
     MODERATE when `SAFETY_ALLOW_MODERATE_OPERATIONS=true` (the default), and always
     rejects DESTRUCTIVE ("not available in this slim package")
   - `services/safety.py` retains reusable validation primitives
     (command/mount/port checks) used by tests and available for future tools
   - **Enforcement flow**: SAFE → allow; MODERATE → allow if enabled; DESTRUCTIVE → reject

4. **Error Handling** (`src/mcp_docker/middleware/error_handler.py`, `utils/error_sanitizer.py`)
   - **Error Sanitization**: Prevents information disclosure when `debug_mode=False`

5. **Configuration** (`src/mcp_docker/config.py`)
   - Pydantic Settings with environment variable support
   - Three config sections: DockerConfig, SafetyConfig, ServerConfig
   - SafetyConfig fields: `allow_moderate_operations`, `default_tool_timeout`, `max_response_bytes`
   - Auto-detects Docker socket based on OS (Windows npipe, Linux/macOS/WSL unix socket)
   - Env prefix: `DOCKER_*`, `SAFETY_*`, `MCP_*`

6. **Middleware System** (`src/mcp_docker/middleware/`)
   - **ErrorHandlerMiddleware**: Sanitizes errors before the client sees them (when `debug_mode=False`)
   - **SafetyMiddleware**: Validates operations against safety levels (fails closed to DESTRUCTIVE for unknown tools)
   - **ResponseLimitingMiddleware** (FastMCP built-in): Global safety net that truncates oversized tool responses (`SAFETY_MAX_RESPONSE_BYTES`)
   - Middleware executes in order: error_handler → safety → response_limiting

7. **Docker Wrapper** (`src/mcp_docker/docker/client.py`)
   - Wraps Docker SDK with error handling and timeout management
   - Provides async-friendly interfaces to synchronous Docker SDK
   - Handles connection lifecycle and cleanup

8. **Transport** (`src/mcp_docker/__main__.py`)
   - **stdio only**: Local process-to-process communication, no network. The CLI
     is argparse-based and takes only `--version`/`-v`.

### Adding New Tools

Tools are built as `ToolSpec`s and registered via `register_tools_with_filtering`.
To add a new tool:

1. Add a `create_*_tool` factory to the appropriate module in `src/mcp_docker/tools/`
2. Define Pydantic input/output models for type safety if needed
3. Return a `ToolSpec` with the right `safety` level (SAFE or MODERATE)
4. Add the spec to the category's `register_*_tools()` list
5. Category registration is called from `register_all_tools()` in `registration.py`

Tool functions are plain (synchronous) functions; FastMCP runs them. The Docker
SDK is synchronous and called directly inside them.

Example:
```python
# In src/mcp_docker/tools/container_lifecycle.py
from mcp_docker.services.safety import OperationSafety
from mcp_docker.tools.common import ToolSpec


def create_my_operation_tool(docker_client: DockerClientWrapper) -> ToolSpec:
    """Create the my_operation tool."""

    def my_operation(container_id: str) -> dict[str, Any]:
        """My tool description.

        Args:
            container_id: Container ID or name

        Returns:
            Operation result
        """
        container = docker_client.client.containers.get(container_id)
        return {"status": "success", "data": container.some_operation()}

    return ToolSpec(
        name="docker_my_operation",
        description="My tool description",
        safety=OperationSafety.MODERATE,
        func=my_operation,
    )
```

### Test Structure

- **tests/unit/**: Fast tests, mock Docker, no Docker daemon required
  - `test_safety.py`, `test_validation.py`: Safety and validation logic
  - `test_config.py`: Configuration validation tests
- **tests/integration/**: Real Docker operations, requires daemon, tests component integration
  - `test_fastmcp_server.py`: FastMCP server integration tests
- **tests/e2e/**: Full workflow tests with real MCP protocol
  - `test_protocol_validation_e2e.py`: stdio MCP protocol E2E tests
- **tests/fuzz/**: ClusterFuzzLite fuzz tests for security (validation, JSON parsing)
- **tests/conftest.py**: Shared pytest fixtures (mock Docker client, config, etc.)

When adding tests:
- Unit tests for business logic and validation
- Integration tests for Docker operations
- E2E tests for multi-step workflows
- Mark slow tests with `@pytest.mark.slow` (still run in CI, just slower)
- Mark stress/performance tests with `@pytest.mark.stress` (skipped in CI, run locally)

## Code Standards

- **Type hints required**: All functions must have type hints (enforced by mypy strict mode)
- **Docstrings required**: Google-style docstrings for all public functions/classes
- **Pydantic validation**: Use Pydantic models for tool input parameters (automatic validation)
- **Error handling**: Raise exceptions for errors; FastMCP handles conversion to MCP error responses
- **Logging**: Use `loguru` via `get_logger(__name__)`, never print statements
- **Tool functions are synchronous**: tools are plain functions wrapped in `ToolSpec`; the Docker SDK (sync) is called directly
- **Security first**: Validate all user input, sanitize errors, avoid information disclosure

## Common Patterns

### Tool Function Pattern
```python
def create_my_tool(docker_client: DockerClientWrapper) -> ToolSpec:
    """Create the my_tool tool."""

    def my_tool(container_id: str) -> dict[str, Any]:
        """Tool description.

        Args:
            container_id: Container ID or name

        Returns:
            Operation result
        """
        result = docker_client.client.containers.get(container_id)
        return {"status": "success", "data": result}

    return ToolSpec(
        name="docker_my_tool",
        description="Tool description",
        safety=OperationSafety.SAFE,
        func=my_tool,
        idempotent=True,
    )
```

### Input Validation Pattern
Tool functions take individual typed parameters; FastMCP derives the schema and
validates inputs from those annotations. Pydantic models in the tool modules are
used for output shaping and for parsing/validating complex fields:

```python
from pydantic import BaseModel, Field

class MyToolOutput(BaseModel):
    """Pydantic model for output shaping."""
    container_id: str = Field(description="Container ID")
    status: str = Field(description="Container status")

def my_tool(container_id: str, force: bool = False) -> dict[str, Any]:
    # `container_id` / `force` are validated by FastMCP from the annotations
    ...
    return MyToolOutput(container_id=container_id, status="ok").model_dump()
```

### Safety Levels
The safety level is set on the `ToolSpec`, not via a decorator. Annotations are
derived from it by `register_tools_with_filtering` (`get_mcp_annotations`):

```python
# SAFE tool (read-only)
ToolSpec(name="docker_list_containers", description="...",
         safety=OperationSafety.SAFE, func=list_containers, idempotent=True)

# MODERATE tool (reversible changes)
ToolSpec(name="docker_start_container", description="...",
         safety=OperationSafety.MODERATE, func=start_container, idempotent=True)

# NOTE: OperationSafety.DESTRUCTIVE exists in the enum (for the fail-closed
# default), but this package does not register any destructive tools.
```

## CI/CD

CI runs on: Python 3.11, 3.12, 3.13, 3.14

**Quality Gates:**
- Ruff linting (no errors)
- Ruff formatting check
- mypy type checking (strict mode)
- Unit test coverage >= 85%
- Integration tests pass
- E2E tests pass (excludes stress tests)
- CodeQL security analysis
- SonarCloud quality analysis
- ClusterFuzzLite fuzzing
- Pre-commit hooks

### GitHub Actions - Claude Workflows

Two Claude-powered workflows are available (requires `CLAUDE_CODE_OAUTH_TOKEN` secret):

1. **Automated Code Review** (`.github/workflows/claude-code-review.yml`)
   - Triggers: PR opened/synchronized (via `pull_request_target`)
   - Restricted tools: `gh pr/issue view, list, diff, comment`
   - Reviews code quality, security, performance, test coverage

2. **Interactive Assistant** (`.github/workflows/claude.yml`)
   - Triggers: `@claude` mentions in issues/PR comments (owner only)
   - Restricted tools: Read-only `gh` commands + comment ability
   - Security: Only repo owner (williajm) can trigger

**Important:** Workflows validate against main branch. Changes to workflow files in PRs won't run until merged to main (security feature to prevent workflow bypass).

## Security Considerations

- **Local-only by design**: stdio transport, no network listener, no auth stack. Run it as a local subprocess of the MCP client; do not expose it as a network service.
- **RADE Risk**: Container logs may contain malicious prompts (treat as untrusted input)
- **Docker Socket Access**: Equivalent to root access on host
- **No destructive operations**: remove/prune/build/push/exec and container creation are not exposed; the surface is read-only plus reversible start/stop/restart
- **Error Sanitization**: Prevents information disclosure (`ErrorHandlerMiddleware` when `debug_mode=False`)
- **Supply Chain**: CI uses `--locked` to enforce lockfile integrity with hashes. When updating dependencies, use `uv lock --exclude-newer` with a 3-day buffer to avoid pulling newly published (potentially malicious) packages

## Configuration

All configuration is via environment variables. For complete reference of all options, see [CONFIGURATION.md](CONFIGURATION.md).

**Quick examples:**

```bash
# Docker connection (auto-detected if unset)
DOCKER_BASE_URL=unix:///var/run/docker.sock

# Safety - gate reversible lifecycle tools (read-only mode when false)
SAFETY_ALLOW_MODERATE_OPERATIONS=true

# Logging
MCP_LOG_LEVEL=INFO
```

See [CONFIGURATION.md](CONFIGURATION.md) for all available options and common scenarios.

## Common Tasks

### Adding a new Docker operation
1. Choose appropriate category module in `src/mcp_docker/tools/`
   - `container_inspection.py`: SAFE (read-only) container tools
   - `container_lifecycle.py`: MODERATE container tools (start/stop/restart)
   - `image.py`: SAFE image tools (list/inspect)
   - `network.py`: SAFE network tools (list)
   - `volume.py`: SAFE volume tools (list)
   - `system.py`: SAFE system tools (version)
2. Build a `ToolSpec` and add it to the module's `register_*_tools()` list
3. Define Pydantic models for input validation if needed
4. Set the safety level on the `ToolSpec` (`OperationSafety.SAFE` or `MODERATE`;
   DESTRUCTIVE tools are not exposed by this package)
5. Add unit tests in `tests/unit/` (see `test_fastmcp_tool_execution.py` for the pattern)
6. Add integration tests in `tests/integration/` if Docker behavior needs coverage
7. Update tool count in README.md and the Project Overview above if it changed

### Debugging test failures
```bash
# Run with verbose output and stop on first failure
uv run pytest tests/unit/test_safety.py -vvs -x

# Run with pdb on failure
uv run pytest tests/unit/test_safety.py --pdb

# Show local variables on failure
uv run pytest tests/unit/test_safety.py -l
```

### Checking coverage
```bash
# Generate HTML coverage report
uv run pytest tests/unit/ --cov=mcp_docker --cov-report=html

# Open report (WSL)
explorer.exe htmlcov/index.html

# See missing lines
uv run pytest tests/unit/ --cov=mcp_docker --cov-report=term-missing
```

### Preparing a Release

**Files to update before releasing a new version:**

1. **`pyproject.toml`** - Remove `.dev0` suffix from version (e.g., `1.2.3.dev0` → `1.2.3`)

2. **`sonar-project.properties`** - Update `sonar.projectVersion` to match the release version

3. **`CHANGELOG.md`** - Add release section with:
   - New version header with date: `## [X.Y.Z] - YYYY-MM-DD`
   - Review git log since last release: `git log v{last_version}..HEAD --oneline`
   - Categorize changes: Added, Changed, Fixed, Security, Documentation, Deprecated, Removed

4. **`docs/index.md`** - Update footer:
   - `**Version**: X.Y.Z`
   - `**Last Updated**: YYYY-MM-DD`

5. **README.md** - Update if the tool count changed

**Release checklist:**
```bash
# 1. Check commits since last release
git log v1.2.2..HEAD --oneline

# 2. Update all files above

# 3. Run quality checks
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/mcp_docker/
uv run pytest tests/unit/ -v

# 4. Commit and create PR
git add -A
git commit -m "chore: Prepare vX.Y.Z release"

# 5. After merge, tag and create GitHub release
# Include a verification section in the release notes so users know
# how to verify artifact integrity (SHA256 checksums and SLSA provenance
# are uploaded automatically by the release workflow)
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z - Title" --notes "Release notes here"

# The release workflow automatically uploads SHA256SUMS.txt and SLSA
# attestation bundles. Include a verification section in release notes:
#
#   ## Verification
#   sha256sum --ignore-missing -c SHA256SUMS.txt
#   gh attestation verify <artifact> --owner williajm

# 6. Immediately bump to next dev version (via PR, not direct to main)
# Edit pyproject.toml: version = "X.Y.(Z+1).dev0"
```
