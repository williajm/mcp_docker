# Integration Testing Guide

This document provides guidance for running and debugging integration tests in the MCP Docker project.

## Prerequisites

### Required
- Docker daemon running and accessible
- Docker SDK for Python installed (`pip install docker`)
- Sufficient permissions to create/remove Docker resources

### Optional
- Docker Compose (for complex test scenarios)
- Access to Docker Hub or configured registry (for image pull tests)

## Running Integration Tests

### Run All Integration Tests
```bash
# Run all integration tests
uv run pytest tests/integration/ -v -m integration

# Run with coverage
uv run pytest tests/integration/ --cov=mcp_docker -m integration
```

### Run Specific Test Suites
```bash
# Safety features tests
uv run pytest tests/integration/test_safety_features.py -v

# Resource tests
uv run pytest tests/integration/test_resources.py -v

# End-to-end workflow tests
uv run pytest tests/e2e/ -v -m e2e
```

### Run Specific Test
```bash
uv run pytest tests/integration/test_safety_features.py::TestDestructiveOperationsSafety::test_remove_container_blocked_when_destructive_disabled -v
```

## Common Issues and Solutions

### Issue: Container Name Conflicts

**Symptom:**
```
409 Client Error: Conflict ("Conflict. The container name "/test-container" is already in use")
```

**Cause:** Test containers from previous runs weren't cleaned up properly.

**Solutions:**

1. **Automatic Cleanup (Recommended):** Tests use fixtures with cleanup. If tests are interrupted, run:
```bash
# Remove all test containers
docker rm -f $(docker ps -aq --filter "name=mcp-docker-*")

# Remove all test volumes
docker volume rm $(docker volume ls -q --filter "name=mcp-docker-*")

# Remove all test networks
docker network rm $(docker network ls -q --filter "name=mcp-docker-*")
```

2. **Manual Cleanup:** Before running tests:
```bash
docker rm -f mcp-docker-safety-test-container
docker volume rm mcp-docker-safety-test-volume
```

3. **Use Test Isolation:** Run tests in isolated Docker contexts or use unique test names.

### Issue: Docker Daemon Not Available

**Symptom:**
```
docker.errors.DockerException: Error while fetching server API version
```

**Solutions:**

1. **Check Docker is running:**
```bash
docker ps
```

2. **Verify Docker socket permissions:**
```bash
# Linux/macOS
ls -l /var/run/docker.sock
# Should be writable by your user or group

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Then log out and back in
```

3. **Windows:** Ensure Docker Desktop is running and configured for WSL2 if using WSL.

4. **Custom Docker Host:**
```bash
export DOCKER_HOST=tcp://localhost:2375
```

### Issue: Permission Denied Errors

**Symptom:**
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**

1. **Check Docker socket permissions:**
```bash
# Linux
sudo chmod 666 /var/run/docker.sock
# Or add user to docker group (preferred)
sudo usermod -aG docker $USER
```

2. **Verify SafetyConfig:** Some operations require explicit permission:
```python
# In test fixtures
config.safety = SafetyConfig(
    allow_moderate_operations=True,
    allow_destructive_operations=True,  # For remove/prune tests
    allow_privileged_containers=True,    # For privileged tests
)
```

### Issue: Tests Hang or Timeout

**Symptom:** Tests run indefinitely without completing.

**Causes & Solutions:**

1. **Container not stopping:**
```bash
# Kill stuck containers
docker kill $(docker ps -q --filter "name=mcp-docker-*")
```

2. **Event stream not closing:** Some tests use `docker events`. Ensure `until` parameter is set:
```python
await server.call_tool("docker_events", {"until": "1s"})
```

3. **Increase timeout:**
```bash
# Run with longer timeout
pytest tests/integration/ --timeout=300
```

### Issue: Image Pull Failures

**Symptom:**
```
docker.errors.ImageNotFound: 404 Client Error: Not Found
```

**Solutions:**

1. **Pre-pull test images:**
```bash
docker pull alpine:latest
docker pull nginx:latest
docker pull busybox:latest
```

2. **Configure registry authentication:**
```bash
docker login
# Or set DOCKER_REGISTRY_AUTH in environment
```

3. **Use local images:** Modify tests to use images already present:
```bash
docker images  # Check available images
```

## Test Isolation Best Practices

### 1. Use Unique Test Names

Tests use fixtures that provide unique names:
```python
@pytest.fixture
def test_container_name() -> Generator[str, None, None]:
    name = f"mcp-docker-test-{uuid.uuid4().hex[:8]}"
    # ... cleanup logic
    yield name
```

### 2. Cleanup Fixtures

Always use fixtures with cleanup (setup/teardown):
```python
@pytest.fixture
def test_container_name() -> Generator[str, None, None]:
    name = "test-container"

    # Cleanup before test (idempotent)
    try:
        client = docker.from_env()
        container = client.containers.get(name)
        container.remove(force=True)
    except docker.errors.NotFound:
        pass

    yield name

    # Cleanup after test
    try:
        client = docker.from_env()
        container = client.containers.get(name)
        container.remove(force=True)
    except docker.errors.NotFound:
        pass
```

### 3. Use autouse Fixtures for Global Cleanup

```python
@pytest.fixture(scope="session", autouse=True)
def cleanup_test_resources():
    """Clean up all test resources before and after test session."""
    yield
    # Cleanup logic runs after all tests
    os.system("docker rm -f $(docker ps -aq --filter 'name=mcp-docker-test-*')")
```

## Debugging Integration Tests

### Enable Verbose Logging

```bash
# Set log level in environment
export MCP_LOG_LEVEL=DEBUG

# Run tests with pytest verbose output
uv run pytest tests/integration/ -vv -s

# Capture Docker API calls
export DOCKER_DEBUG=1
```

### Inspect Docker State During Tests

1. **Pause test execution:**
```python
import pdb; pdb.set_trace()  # Add in test
```

2. **Check Docker resources:**
```bash
# In another terminal during paused test
docker ps -a
docker volume ls
docker network ls
docker inspect <container-name>
```

### Use pytest Debugging Features

```bash
# Drop into debugger on failure
uv run pytest tests/integration/ --pdb

# Show local variables on failure
uv run pytest tests/integration/ -l

# Only run tests that failed last time
uv run pytest tests/integration/ --lf

# Run tests in order they failed last time
uv run pytest tests/integration/ --ff
```

## Test Configuration

### Safety Configuration

Tests use different configurations for different scenarios:

```python
# Restrictive (read-only)
restrictive_config = SafetyConfig(
    allow_moderate_operations=False,
    allow_destructive_operations=False,
    allow_privileged_containers=False,
)

# Permissive (full access)
permissive_config = SafetyConfig(
    allow_moderate_operations=True,
    allow_destructive_operations=True,
    allow_privileged_containers=True,
)
```

### Docker Configuration

```python
# Standard configuration
docker_config = DockerConfig(
    base_url="unix:///var/run/docker.sock",  # or "npipe:////./pipe/docker_engine" on Windows
    timeout=60,
)

# With TLS
docker_config = DockerConfig(
    base_url="tcp://docker-host:2376",
    tls_verify=True,
    tls_ca_cert="/path/to/ca.pem",
    tls_client_cert="/path/to/cert.pem",
    tls_client_key="/path/to/key.pem",
)
```

## CI/CD Considerations

### GitHub Actions

```yaml
- name: Start Docker
  run: |
    sudo systemctl start docker
    sudo chmod 666 /var/run/docker.sock

- name: Run Integration Tests
  run: |
    uv run pytest tests/integration/ -v -m integration
```

### Docker-in-Docker (DinD)

```yaml
services:
  docker:
    image: docker:dind
    privileged: true

steps:
  - name: Wait for Docker
    run: |
      timeout 30 sh -c 'until docker ps; do sleep 1; done'
```

## Known Limitations

### 1. Privileged Container Creation

The `docker_create_container` tool does not currently support the `privileged` parameter. The related integration test is skipped.

**To enable:**
1. Add `privileged: bool = False` to `CreateContainerInput`
2. Implement `check_privileged_arguments()` in `CreateContainerTool`
3. Pass privileged flag to Docker API in `host_config`

### 2. Resource Quotas

Some operations may fail if Docker has resource limits:
- Memory limits
- CPU limits
- Storage limits

**Solution:** Configure Docker daemon with appropriate resources or skip resource-intensive tests.

### 3. Platform Differences

Tests may behave differently on:
- **Linux:** Native Docker, fastest performance
- **macOS:** Docker Desktop with VM overhead
- **Windows:** Docker Desktop with WSL2 or Hyper-V

**Recommendation:** Use Linux for CI/CD pipelines for consistent behavior.

## Additional Resources

- [Docker SDK for Python Documentation](https://docker-py.readthedocs.io/)
- [pytest Documentation](https://docs.pytest.org/)
- [Docker API Reference](https://docs.docker.com/engine/api/)
- [MCP Docker Testing Strategy](./TESTING.md)

## Getting Help

If you encounter issues not covered here:

1. Check test logs: `tests/integration/*.log`
2. Inspect Docker state: `docker ps -a`, `docker inspect`
3. Review audit logs: `mcp_audit.log`
4. Open an issue: https://github.com/anthropics/mcp-docker/issues
