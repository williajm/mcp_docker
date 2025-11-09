# Testing Guide

This guide explains the testing strategy for mcp-docker, including the three-tier test architecture and how to run and write tests.

## Table of Contents

- [Test Architecture](#test-architecture)
- [Test Level Comparison](#test-level-comparison)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [CI/CD Integration](#cicd-integration)
- [Best Practices](#best-practices)

---

## Test Architecture

The mcp-docker project uses a **three-tier testing strategy**:

1. **Unit Tests (~440 tests)** - Fast feedback on logic correctness
2. **Integration Tests (~107 tests)** - Verify components work together
3. **E2E Tests (~14 tests)** - Validate complete production workflows

Each level serves a specific purpose and catches different types of bugs.

---

## Test Level Comparison

| Component | Unit Tests | Integration Tests | E2E Tests |
|-----------|-----------|-------------------|-----------|
| **Docker Daemon** | Mocked | Real (required) | Real (required) |
| **Docker Client** | Mocked | Real | Real |
| **MCPDockerServer** | Mocked/None | Real instance | Real instance |
| **MCP Protocol** | None | Bypassed (direct calls) | Real (via ClientSession) |
| **Transport (stdio/SSE)** | None | None | Real |
| **Auth Middleware** | Isolated | Real | Real |
| **Rate Limiter** | Isolated | Real | Real |
| **Audit Logger** | Isolated | Real | Real |
| **SSH Key Operations** | Mocked filesystem | Real key files | Real key files |
| **Speed** | Very fast (<5s) | Fast (~15s) | Slower (~60s) |
| **Purpose** | Verify logic | Verify integration | Verify end-to-end |

### Detailed Breakdown

#### Unit Tests (`tests/unit/`)

**What they test:**

- Individual functions and classes in isolation
- Algorithm correctness (timestamp validation, signature verification)
- Edge cases and error handling
- Data model validation

**Example:**

```python
def test_validate_timestamp_expired(self):
    """Test validating expired timestamp."""
    protocol = SSHAuthProtocol(max_timestamp_age=300)
    old_timestamp = datetime.now(UTC).timestamp() - 600
    timestamp = datetime.fromtimestamp(old_timestamp, UTC).isoformat()

    assert protocol.validate_timestamp(timestamp) is False
```

**Characteristics:**

- No external dependencies (Docker, network)
- Heavy use of mocking and fixtures
- Tests single responsibility
- Very fast execution (<5s for all unit tests)

**When to use:**

- Testing business logic
- Testing error conditions
- Testing edge cases
- During active development (TDD)

---

#### Integration Tests (`tests/integration/`)

**What they test:**

- Multiple components working together
- Server-level tool execution
- Docker operations with real Docker daemon
- Component interaction and data flow

**Example:**

```python
@pytest.mark.asyncio
async def test_call_tool_with_ssh_auth(self, setup_server_with_ssh_auth):
    """Test calling tool through server with SSH auth."""
    server, private_key, client_id = setup_server_with_ssh_auth

    ssh_auth = self.create_ssh_auth_data(client_id, private_key)

    # Call server method directly (no MCP client)
    result = await server.call_tool(
        tool_name="docker_list_containers",
        arguments={"all": True},
        ssh_auth_data=ssh_auth,
    )

    assert result.get("success") is True
```

**Characteristics:**

- Requires Docker daemon
- Real Docker operations (create, start, stop containers)
- Direct server method calls (bypasses MCP protocol)
- Moderate execution time (~10s for all integration tests)

**When to use:**

- Testing component integration
- Verifying Docker operations work
- Testing middleware and authentication flow
- Smoke testing before E2E

---

#### E2E Tests (`tests/e2e/`)

**What they test:**

- Complete user workflows
- Real MCP client connections
- Full transport layer (stdio/SSE)
- Production scenarios and edge cases
- Performance and stress testing

**Example:**

```python
@pytest.mark.e2e
@pytest.mark.asyncio
async def test_complete_docker_workflow_with_ssh_auth(tmp_path):
    """E2E: Complete Docker workflow with SSH authentication."""

    # Setup server with SSH auth
    server, auth_keys_file = setup_mcp_server_with_ssh(tmp_path)
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)

    # Connect real MCP client
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Execute complete workflow with fresh auth for each call
            ssh_auth1 = create_ssh_auth_data("client1", private_key)
            pull_result = await session.call_tool(
                "pull_image",
                arguments={"_auth": {"ssh": ssh_auth1}, "image": "nginx:alpine"}
            )

            ssh_auth2 = create_ssh_auth_data("client1", private_key)
            create_result = await session.call_tool(
                "create_container",
                arguments={"_auth": {"ssh": ssh_auth2}, "image": "nginx:alpine"}
            )
            # ... more operations ...
```

**Characteristics:**

- Requires Docker daemon
- Real MCP client (ClientSession)
- Real transport protocols (stdio, SSE)
- Complete workflows (pull → create → start → stop → remove)
- Slower execution (~30-60s for all E2E tests)

**When to use:**

- Validating production scenarios
- Testing complete user workflows
- Performance and stress testing
- Pre-release validation
- Catching integration issues missed by unit/integration tests

---

## Running Tests

### Prerequisites

**For Unit Tests:**

- Python 3.11+
- uv package manager
- No Docker required ✅

**For Integration and E2E Tests:**

- Python 3.11+
- uv package manager
- Docker daemon running ✅

### Basic Commands

```bash
# Install dependencies
uv sync --all-extras

# Run all tests
uv run pytest

# Run with coverage report
uv run pytest --cov=mcp_docker --cov-report=html
```

### Running by Test Level

```bash
# Unit tests only (fast, no Docker)
uv run pytest tests/unit/ -v

# Integration tests only (requires Docker)
uv run pytest tests/integration/ -v -m integration

# E2E tests only (requires Docker)
uv run pytest tests/e2e/ -v -m e2e

# E2E excluding slow tests (faster feedback)
uv run pytest tests/e2e/ -v -m "e2e and not slow"
```

### Running Specific Tests

```bash
# Run specific test file
uv run pytest tests/unit/auth/test_ssh_auth.py -v

# Run specific test function
uv run pytest tests/e2e/test_ssh_auth_e2e.py::test_replay_attack_prevention -v

# Run tests matching pattern
uv run pytest -k "ssh_auth" -v

# Run tests for specific component
uv run pytest tests/unit/auth/ -v
```

### Using Pytest Markers

```bash
# Run only integration tests
pytest -m integration

# Run only E2E tests
pytest -m e2e

# Run only slow tests
pytest -m slow

# Run E2E tests excluding slow ones
pytest -m "e2e and not slow"

# Run all tests except slow ones
pytest -m "not slow"
```

### Coverage Analysis

```bash
# Generate HTML coverage report
uv run pytest --cov=mcp_docker --cov-report=html
open htmlcov/index.html

# Generate XML coverage report (for CI)
uv run pytest --cov=mcp_docker --cov-report=xml

# Show missing lines in terminal
uv run pytest --cov=mcp_docker --cov-report=term-missing

# Fail if coverage below threshold
uv run pytest --cov=mcp_docker --cov-fail-under=85
```

### Execution Time Examples

```bash
# Unit tests - Very fast
$ pytest tests/unit/ -v
====== 200+ tests in 4.2s ======

# Integration tests - Fast
$ pytest tests/integration/ -v -m integration
====== 50 tests in 12.5s ======

# E2E tests (quick) - Medium
$ pytest tests/e2e/ -v -m "e2e and not slow"
====== 14 tests in 22.8s ======

# E2E tests (full) - Slower
$ pytest tests/e2e/ -v -m e2e
====== 17 tests in 47.3s ======

# All tests - Comprehensive
$ pytest
====== 267+ tests in 65.7s ======
```

---

## Writing Tests

### General Guidelines

1. **Follow test pyramid** - More unit tests, fewer E2E tests
2. **Test one thing** - Each test should verify one behavior
3. **Descriptive names** - Test names should explain what they test
4. **AAA pattern** - Arrange, Act, Assert
5. **Clean up resources** - Use fixtures and `finally` blocks
6. **Mark appropriately** - Use `@pytest.mark.*` decorators

### Unit Test Example

```python
# tests/unit/auth/test_ssh_auth.py
import pytest
from mcp_docker.auth.ssh_auth import SSHAuthProtocol

class TestSSHAuthProtocol:
    """Unit tests for SSH authentication protocol."""

    def test_validate_timestamp_valid(self):
        """Test validating recent timestamp."""
        # Arrange
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        timestamp = datetime.now(UTC).isoformat()

        # Act
        result = protocol.validate_timestamp(timestamp)

        # Assert
        assert result is True

    def test_validate_timestamp_expired(self):
        """Test validating expired timestamp."""
        # Arrange
        protocol = SSHAuthProtocol(max_timestamp_age=300)
        old_time = datetime.now(UTC).timestamp() - 600  # 10 min ago
        timestamp = datetime.fromtimestamp(old_time, UTC).isoformat()

        # Act
        result = protocol.validate_timestamp(timestamp)

        # Assert
        assert result is False
```

### Integration Test Example

```python
# tests/integration/test_ssh_auth_integration.py
import pytest
from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer

class TestSSHAuthIntegration:
    """Integration tests for SSH authentication."""

    @pytest.fixture
    def setup_server_with_ssh_auth(self, tmp_path):
        """Setup MCP server with SSH authentication enabled."""
        # Generate SSH key pair
        private_key, public_key = generate_test_keys(tmp_path)

        # Create authorized_keys file
        auth_keys_file = tmp_path / "authorized_keys"
        auth_keys_file.write_text(f"{public_key}\n")

        # Configure server
        config = Config()
        config.security.ssh_auth_enabled = True
        config.security.ssh_authorized_keys_file = auth_keys_file

        server = MCPDockerServer(config)
        return server, private_key, "test-client"

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_call_tool_with_ssh_auth(self, setup_server_with_ssh_auth):
        """Test calling tool through server with SSH auth."""
        server, private_key, client_id = setup_server_with_ssh_auth

        # Create auth data
        ssh_auth = create_ssh_auth_data(client_id, private_key)

        # Call server method
        result = await server.call_tool(
            tool_name="docker_list_containers",
            arguments={"all": True},
            ssh_auth_data=ssh_auth,
        )

        # Verify
        assert result.get("success") is True
```

### E2E Test Example

```python
# tests/e2e/test_ssh_auth_e2e.py
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_complete_docker_workflow_with_ssh_auth(tmp_path):
    """
    E2E test: Complete Docker workflow authenticated with SSH keys.

    Validates:
    1. MCP client connection via stdio transport
    2. SSH authentication for each tool call
    3. Complete container lifecycle
    4. Audit log verification
    """
    # Setup
    server, auth_keys_file = setup_mcp_server_with_ssh(tmp_path)
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    auth_keys_file.write_text(f"{public_key_line}\n")

    server_params = StdioServerParameters(
        command="mcp-docker",
        args=["--transport", "stdio"],
    )

    try:
        # Connect real MCP client
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Pull image
                ssh_auth1 = create_ssh_auth_data("client1", private_key)
                pull_result = await session.call_tool(
                    "pull_image",
                    arguments={"_auth": {"ssh": ssh_auth1}, "image": "nginx:alpine"}
                )
                assert pull_result["success"]

                # Create container (fresh auth!)
                ssh_auth2 = create_ssh_auth_data("client1", private_key)
                create_result = await session.call_tool(
                    "create_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth2},
                        "image": "nginx:alpine",
                        "name": "test-nginx"
                    }
                )
                container_id = create_result["container_id"]

                # Start, stop, remove...
                # (Each with fresh SSH auth)

    finally:
        # Cleanup
        cleanup_containers(container_id)
```

---

## CI/CD Integration

### Current CI Configuration

The project uses GitHub Actions with three test jobs:

```yaml
# .github/workflows/ci.yml

test:
  name: Unit Tests
  runs-on: ubuntu-latest
  steps:
    - name: Run unit tests with coverage
      run: |
        uv run pytest tests/unit/ \
          --cov=mcp_docker \
          --cov-report=xml \
          --cov-fail-under=85

integration-test:
  name: Integration Tests
  runs-on: ubuntu-latest
  services:
    docker:
      image: docker:24-dind
  steps:
    - name: Run integration tests
      run: |
        uv run pytest tests/integration/ \
          -m "integration" \
          --maxfail=5
```

### Recommended CI Strategy

```yaml
# Fast feedback on every PR (runs in parallel)
unit-tests:
  pytest tests/unit/ --cov-fail-under=85

integration-tests:
  pytest tests/integration/ -m integration

# Quick E2E validation on PRs
e2e-tests-quick:
  pytest tests/e2e/ -m "e2e and not slow"

# Full E2E validation on main/release only
e2e-tests-full:
  if: github.ref == 'refs/heads/main'
  pytest tests/e2e/ -m e2e
```

This provides:

- **Fast PR feedback** (~20s) with unit + integration + quick E2E
- **Full validation** (~60s) on main branch before releases

---

## Best Practices

### Test Organization

```text
tests/
├── unit/                    # Unit tests (fast, isolated)
│   ├── auth/               # Auth component tests
│   │   ├── test_ssh_auth.py
│   │   └── test_ssh_keys.py
│   ├── tools/              # Tool tests
│   └── utils/              # Utility tests
├── integration/             # Integration tests (server-level)
│   ├── test_ssh_auth_integration.py
│   ├── test_mcp_server.py
│   └── test_container_lifecycle.py
├── e2e/                    # E2E tests (complete workflows)
│   └── test_ssh_auth_e2e.py
├── fixtures/               # Shared fixtures
└── conftest.py            # Pytest configuration
```

### Test Naming Conventions

```python
# Good test names
def test_validate_timestamp_expired()
def test_create_container_with_ssh_auth()
def test_replay_attack_prevention()

# Bad test names
def test_timestamp()        # Not specific
def test_feature()          # Too vague
def test_1()               # No description
```

### Fixture Usage

```python
# Reusable fixtures in conftest.py
@pytest.fixture
def tmp_ssh_keys(tmp_path):
    """Generate temporary SSH key pair."""
    private_key, public_key = generate_ed25519_key_pair(tmp_path)
    yield private_key, public_key
    # Cleanup handled by tmp_path

# Use fixtures in tests
def test_ssh_authentication(tmp_ssh_keys):
    private_key, public_key = tmp_ssh_keys
    # Test logic here
```

### Cleanup and Resource Management

```python
# Always cleanup in E2E tests
@pytest.fixture
async def test_container(mcp_server):
    """Create test container with automatic cleanup."""
    container_id = None

    try:
        result = await mcp_server.call_tool(
            "docker_create_container",
            {"image": "alpine:latest", "name": "test-container"}
        )
        container_id = result["container_id"]
        yield container_id
    finally:
        if container_id:
            await mcp_server.call_tool(
                "docker_remove_container",
                {"container_id": container_id, "force": True}
            )
```

### Test Markers

```python
# Use pytest markers for organization
@pytest.mark.unit           # Unit test
@pytest.mark.integration    # Integration test
@pytest.mark.e2e           # E2E test
@pytest.mark.slow          # Slow test (>5s)
@pytest.mark.asyncio       # Async test

# Example
@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.asyncio
async def test_concurrent_clients():
    """E2E: Test 10 concurrent clients."""
    # Test logic
```

### When to Write Each Test Level

**Write Unit Tests when:**

- ✅ Testing business logic
- ✅ Testing edge cases
- ✅ Testing error handling
- ✅ TDD development
- ✅ Need fast feedback

**Write Integration Tests when:**

- ✅ Testing component interaction
- ✅ Verifying Docker operations
- ✅ Testing middleware flow
- ✅ Smoke testing features

**Write E2E Tests when:**

- ✅ Testing user workflows
- ✅ Validating transport layers
- ✅ Testing security in realistic scenarios
- ✅ Performance/stress testing
- ✅ Pre-release validation

---

## Test Coverage Goals

| Test Level | Coverage Goal | Current Coverage |
|-----------|---------------|------------------|
| Unit | 90%+ | ~92% |
| Integration | 70%+ | ~75% |
| E2E | Key workflows | 17 scenarios |
| Overall | 85%+ | ~88% |

---

## Troubleshooting

### Docker Not Available

```bash
# Error: docker.errors.DockerException: Error while fetching server API version

# Solution 1: Start Docker daemon
sudo systemctl start docker

# Solution 2: Check Docker socket permissions
sudo chmod 666 /var/run/docker.sock

# Solution 3: Skip integration/E2E tests
pytest tests/unit/ -v
```

### Slow Test Execution

```bash
# Run only fast tests
pytest -m "not slow" -v

# Run tests in parallel (requires pytest-xdist)
pytest -n auto
```

### Test Failures in CI

```bash
# Run with same settings as CI
pytest tests/unit/ --cov=mcp_docker --cov-fail-under=85
pytest tests/integration/ -m integration --maxfail=5
```

---

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Test Coverage with pytest-cov](https://pytest-cov.readthedocs.io/)
- [E2E Test Report](../E2E_TEST_REPORT.md)
- [SSH Authentication Docs](./SSH_AUTHENTICATION.md)
- [Contributing Guide](../CONTRIBUTING.md)

---

## Summary

The mcp-docker testing strategy provides:

✅ **Fast feedback** with unit tests (<5s)
✅ **Component validation** with integration tests (~10s)
✅ **Production confidence** with E2E tests (~30-60s)
✅ **High coverage** across all modules
✅ **CI/CD ready** with automated testing

Choose the right test level for the job:

- **Unit** for logic and edge cases
- **Integration** for component interaction
- **E2E** for complete workflows

Happy testing! 🧪
