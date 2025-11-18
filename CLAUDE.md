# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that exposes Docker functionality to AI assistants. It provides 33 Docker tools, 5 AI prompts, and 2 resources for managing containers, images, networks, and volumes with comprehensive safety controls.

**Key Technologies:**
- Python 3.11+ with strict type checking (mypy)
- FastMCP 2.0 for MCP protocol implementation
- Docker SDK for Python (>=7.1.0)
- Pydantic for validation and settings
- uv for package management
- Supports two transports: stdio (local) and HTTP (network)

## Development Commands

### Setup
```bash
# Install dependencies
uv sync --all-extras

# Install just dev dependencies
uv sync --group dev
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
# Run server with stdio transport (local, default)
uv run mcp-docker

# Run server with HTTP transport (for network deployments)
uv run mcp-docker --transport http --host 127.0.0.1 --port 8000

# Run directly via Python module
uv run python -m mcp_docker

# Note: For production HTTP deployments, use a reverse proxy (NGINX, Caddy)
# for HTTPS/TLS termination, authentication, and rate limiting
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

1. **MCPDockerServer** (`src/mcp_docker/server.py`)
   - Main MCP server implementation
   - Auto-discovers and registers all tools via reflection
   - Manages security (auth, rate limiting, audit logging)
   - Handles concurrency with semaphores
   - Coordinates tools, resources, prompts, and safety enforcement

2. **Tool System** (`src/mcp_docker/tools/`)
   - **base.py**: `BaseTool` abstract class with safety enforcement
   - All tools inherit from `BaseTool` and implement: `name`, `description`, `input_schema`, `output_schema`, `safety_level`, `execute()`
   - Tools auto-register by being discovered in tool modules
   - Five categories: container_lifecycle, container_inspection, image, network, volume, system
   - Each tool has a safety level: SAFE (read-only), MODERATE (reversible), DESTRUCTIVE (permanent)
   - **MCP Annotations**: Tools expose four standard MCP annotations to help clients make decisions:
     - `readOnly`: Tool only reads data without modification (auto-set for SAFE tools)
     - `destructive`: Tool permanently deletes data (auto-set for DESTRUCTIVE tools)
     - `idempotent`: Tool can be safely retried with same parameters (e.g., start/stop/restart containers, pull images)
     - `openWorldInteraction`: Tool communicates with external systems (e.g., pull/push images from registries)

3. **Safety System** (`src/mcp_docker/utils/safety.py`, `config.py`)
   - **Three-tier classification**: SAFE/MODERATE/DESTRUCTIVE
   - **Tool filtering**: Allow/deny lists via `SAFETY_ALLOWED_TOOLS`/`SAFETY_DENIED_TOOLS`
   - **Operation gating**: `SAFETY_ALLOW_MODERATE_OPERATIONS`, `SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS`
   - **Command validation**: Detects dangerous commands (rm -rf /, dd if=/dev/zero, fork bombs)
   - **Concurrency limiting**: Max concurrent operations via semaphore
   - **Enforcement flow**: Safety level → Deny list → Allow list → Execute

4. **Security Features** (`src/mcp_docker/security/`, `src/mcp_docker/auth/`)
   - **IP Filtering** (`auth/middleware.py`): Network-level access control via IP allowlist
   - **Rate Limiting** (`security/rate_limiter.py`): Per-client request throttling
   - **Audit Logging** (`security/audit.py`): Operation tracking with client IPs
   - **Error Sanitization** (`utils/error_sanitizer.py`): Prevents information disclosure
   - **TLS/HTTPS**: Use reverse proxy (NGINX, Caddy) for production HTTP deployments

5. **Configuration** (`src/mcp_docker/config.py`)
   - Pydantic Settings with environment variable support
   - Four config sections: DockerConfig, SafetyConfig, SecurityConfig, ServerConfig
   - Auto-detects Docker socket based on OS (Windows npipe, Linux/macOS/WSL unix socket)
   - Validates Docker TLS certificates
   - Env prefix: `DOCKER_*`, `SAFETY_*`, `SECURITY_*`, `MCP_*`

6. **Docker Wrapper** (`src/mcp_docker/docker_wrapper/client.py`)
   - Wraps Docker SDK with error handling and timeout management
   - Provides async-friendly interfaces to synchronous Docker SDK
   - Handles connection lifecycle and cleanup

7. **Transport Implementations** (`src/mcp_docker/__main__.py`)
   - **stdio**: Local process-to-process communication (default, no network)
   - **HTTP**: FastMCP 2.0 native HTTP transport
     - Plain HTTP (use reverse proxy for HTTPS in production)
     - Single unified endpoint
     - Built-in session management

### Adding New Tools

Tools use FastMCP's decorator pattern. To add a new tool:

1. Add function to appropriate module in `fastmcp_tools/` directory
2. Define Pydantic input/output models for type safety
3. Return tuple of (name, description, function, safety_level, annotations) from factory function
4. Tool will be registered in `register_all_tools()` in `fastmcp_tools/__init__.py`

Example:
```python
def create_my_tool(
    docker_client: DockerClientWrapper,
    safety_config: SafetyConfig,
) -> tuple[str, str, Any, OperationSafety, dict[str, Any]]:
    """Create my new Docker tool."""

    async def my_tool(container_id: str) -> dict[str, Any]:
        """My tool description.

        Args:
            container_id: Container ID or name

        Returns:
            Operation result
        """
        # Use asyncio.to_thread for blocking Docker SDK calls
        def _do_operation():
            container = docker_client.client.containers.get(container_id)
            return container.some_operation()

        result = await asyncio.to_thread(_do_operation)
        return {"status": "success", "data": result}

    safety_level = OperationSafety.MODERATE
    annotations = get_mcp_annotations(safety_level)
    annotations["idempotent"] = True  # if operation is safe to retry

    return (
        "docker_my_operation",
        "Description of what this tool does",
        my_tool,
        safety_level,
        annotations,
    )
```

### Test Structure

- **tests/unit/**: Fast tests, mock Docker, no Docker daemon required
  - `test_safety.py`, `test_validation.py`: Safety and validation logic
  - `test_config.py`: Configuration validation tests
- **tests/integration/**: Real Docker operations, requires daemon, tests component integration
  - `test_fastmcp_server.py`: FastMCP server integration tests
- **tests/e2e/**: Full workflow tests with real MCP protocol
  - `test_stdio_transport_e2e.py`: stdio transport E2E tests
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
- **Pydantic validation**: Use Pydantic models for all input/output schemas
- **Error handling**: Return `ToolResult.error_result()` for expected errors, raise for unexpected
- **Logging**: Use `loguru` via `get_logger(__name__)`, never print statements
- **Async where needed**: MCP handlers are async, Docker SDK is sync (wrap if needed)
- **Security first**: Validate all user input, sanitize errors, avoid information disclosure

## Common Patterns

### Tool Result Pattern
```python
try:
    result = self.docker.some_operation()
    return ToolResult.success_result(data=result, operation="operation_name")
except DockerException as e:
    return ToolResult.error_result(error=str(e))
```

### Input Validation Pattern
```python
class MyToolInput(ToolInput):
    field: str = Field(..., min_length=1, max_length=255, pattern=r"^[a-zA-Z0-9_-]+$")
```

### Safety Enforcement Pattern
```python
@property
def safety_level(self) -> OperationSafety:
    return OperationSafety.DESTRUCTIVE

def execute(self, arguments: dict[str, Any]) -> ToolResult:
    # BaseTool.execute_with_safety() checks safety before calling this
    # No need to check safety level here
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

- **RADE Risk**: Container logs may contain malicious prompts (treat as untrusted input)
- **Docker Socket Access**: Equivalent to root access on host
- **HTTPS Required**: Use reverse proxy (NGINX, Caddy) for production HTTP deployments
- **Auth Required**: For network-accessible deployments
- **Rate Limiting**: Prevents abuse
- **Command Injection**: Validated via safety.py patterns
- **Error Sanitization**: Prevents information disclosure

## Configuration

All configuration is via environment variables. For complete reference of all options, see [CONFIGURATION.md](CONFIGURATION.md).

**Quick examples:**

```bash
# Safety - Control operations
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
SAFETY_ALLOWED_TOOLS=docker_list_containers,docker_inspect_container

# Security
SECURITY_OAUTH_ENABLED=true
SECURITY_RATE_LIMIT_RPM=60
SECURITY_ALLOWED_CLIENT_IPS='["127.0.0.1"]'
```

See [CONFIGURATION.md](CONFIGURATION.md) for all available options and common scenarios.

## Common Tasks

### Adding a new Docker operation
1. Add tool factory function to appropriate `fastmcp_tools/*.py` file
2. Define Pydantic models for input/output validation
3. Return (name, description, function, safety_level, annotations) tuple
4. Register in `register_all_tools()` in `fastmcp_tools/__init__.py`
5. Add unit tests in `tests/unit/`
6. Add integration tests in `tests/integration/`
7. Update tool count in README.md if needed

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
