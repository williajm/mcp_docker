# Security Testing Guide

This document explains how to test the security features of the MCP Docker server, both locally and in CI/CD pipelines.

## Test Suite Overview

The security test suite includes **60 comprehensive unit tests** covering:

- **API Key Authentication** (18 tests)
- **Authentication Middleware** (14 tests)
- **Audit Logging** (13 tests)
- **Rate Limiting** (15 tests)

### Test Coverage

```
src/mcp_docker/auth/api_key.py       96% coverage (68 statements, 3 missed)
src/mcp_docker/auth/middleware.py    95% coverage (43 statements, 2 missed)
src/mcp_docker/security/audit.py     93% coverage (61 statements, 4 missed)
src/mcp_docker/security/rate_limiter.py  99% coverage (71 statements, 1 missed)
```

**Overall security module coverage: ~95%**

## Running Tests Locally

### Prerequisites

Ensure you have the development environment set up:

```bash
# Install dependencies
uv sync --group dev

# Verify pytest is installed
uv run pytest --version
```

### Run All Security Tests

```bash
# Run all security tests with verbose output
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -v

# Expected output: 60 passed in ~2-3 seconds
```

### Run Specific Test Modules

```bash
# Test only API key authentication
uv run pytest tests/unit/test_auth/test_api_key.py -v

# Test only authentication middleware
uv run pytest tests/unit/test_auth/test_middleware.py -v

# Test only audit logging
uv run pytest tests/unit/test_security/test_audit.py -v

# Test only rate limiting
uv run pytest tests/unit/test_security/test_rate_limiter.py -v
```

### Run Specific Test Cases

```bash
# Run a single test class
uv run pytest tests/unit/test_auth/test_api_key.py::TestAPIKeyAuthenticator -v

# Run a single test function
uv run pytest tests/unit/test_auth/test_api_key.py::TestAPIKeyAuthenticator::test_authenticate_valid_key -v
```

### Run with Coverage

```bash
# Generate coverage report for security modules only
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ --cov=src/mcp_docker/auth --cov=src/mcp_docker/security --cov-report=term-missing

# Generate HTML coverage report
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ --cov=src/mcp_docker/auth --cov=src/mcp_docker/security --cov-report=html

# Open the HTML report
# Windows: start htmlcov/index.html
# Linux/Mac: open htmlcov/index.html
```

### Run with Different Verbosity Levels

```bash
# Quiet mode (only show summary)
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -q

# Verbose mode (show each test)
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -v

# Very verbose mode (show full test names)
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -vv
```

### Run Failed Tests Only

```bash
# Run tests that failed in the last run
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ --lf

# Run failed tests first, then others
uv run pytest tests/unit/test_auth/ tests/unit/test_security/ --ff
```

## Running Tests in CI/CD

### GitHub Actions

The security tests are automatically run as part of the CI pipeline. The existing `.github/workflows/ci.yml` includes:

```yaml
- name: Run unit tests
  run: uv run pytest tests/unit/ -v
```

This will run **all** unit tests, including the security tests.

### Running Security Tests Only in CI

If you want to run only security tests in a separate job, add this to your workflow:

```yaml
test-security:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    - name: Install uv
      run: pip install uv
    - name: Install dependencies
      run: uv sync --group dev
    - name: Run security tests
      run: |
        uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -v --cov=src/mcp_docker/auth --cov=src/mcp_docker/security --cov-report=term
```

### Coverage Requirements

The security tests achieve **95%+ coverage** of the security modules. The overall project coverage may be lower because:

1. The main server integration (`__main__.py`, `server.py`) isn't tested in unit tests
2. Docker tool implementations have their own test suite
3. Some edge cases (file I/O errors) are hard to test

**For security-critical code, we maintain 95%+ coverage.**

## Test Structure

### Test Organization

```
tests/
├── unit/
│   ├── test_auth/
│   │   ├── __init__.py
│   │   ├── test_api_key.py        # API key authentication tests
│   │   └── test_middleware.py     # Auth middleware tests
│   └── test_security/
│       ├── __init__.py
│       ├── test_audit.py          # Audit logging tests
│       └── test_rate_limiter.py   # Rate limiting tests
```

### Test Categories

#### 1. API Key Authentication Tests (`test_api_key.py`)

Tests the core authentication logic:

- ✅ API key generation (cryptographic randomness)
- ✅ Key loading from JSON file
- ✅ Key validation (format, length)
- ✅ Authentication (valid/invalid/disabled keys)
- ✅ Key reloading (hot-reload)
- ✅ Client listing (without exposing keys)
- ✅ Error handling (invalid JSON, missing file)

**Key test scenarios:**
- `test_authenticate_valid_key` - Successful authentication
- `test_authenticate_invalid_key` - Failed authentication
- `test_generate_api_key` - Secure key generation
- `test_reload_keys` - Hot-reloading keys

#### 2. Authentication Middleware Tests (`test_middleware.py`)

Tests the middleware integration:

- ✅ Auth enabled/disabled modes
- ✅ Request authentication flow
- ✅ IP allowlist filtering
- ✅ Error handling and reporting
- ✅ Key reloading

**Key test scenarios:**
- `test_authenticate_request_valid_key` - Valid API key
- `test_authenticate_request_invalid_key` - Invalid API key
- `test_authenticate_request_ip_allowlist_valid` - IP filtering
- `test_reload_keys` - Dynamic key updates

#### 3. Audit Logging Tests (`test_audit.py`)

Tests the audit trail functionality:

- ✅ Event creation and serialization (JSON)
- ✅ Tool call logging (success/failure)
- ✅ Authentication failure logging
- ✅ Rate limit violation logging
- ✅ Sensitive data redaction
- ✅ Multiple log entries
- ✅ Enabled/disabled modes

**Key test scenarios:**
- `test_log_tool_call_success` - Successful operation logging
- `test_log_tool_call_failure` - Failed operation logging
- `test_sanitize_arguments` - Sensitive data redaction
- `test_log_auth_failure` - Auth failure logging

#### 4. Rate Limiting Tests (`test_rate_limiter.py`)

Tests rate limiting logic:

- ✅ RPM (requests per minute) limiting
- ✅ Concurrent request limiting
- ✅ Per-client isolation
- ✅ Sliding window algorithm
- ✅ Slot acquisition/release
- ✅ Statistics tracking
- ✅ Data cleanup
- ✅ Enabled/disabled modes

**Key test scenarios:**
- `test_check_rate_limit_exceeded` - RPM limit enforcement
- `test_acquire_concurrent_slot_exceeded` - Concurrent limit
- `test_check_rate_limit_per_client` - Client isolation
- `test_release_concurrent_slot` - Proper cleanup

## Test Data and Fixtures

### Temporary Files

Tests use `pytest`'s `tmp_path` fixture to create temporary files:

```python
@pytest.fixture
def temp_keys_file(self, tmp_path: Path) -> Path:
    """Create a temporary API keys file."""
    keys_file = tmp_path / ".mcp_keys.json"
    # ... create test data
    return keys_file
```

**Benefits:**
- No file system pollution
- Automatic cleanup after tests
- Isolated test environments
- Works in CI/CD

### Test API Keys

Test API keys are hardcoded for reproducibility:

```python
"valid-key-123"      # Valid, enabled key
"disabled-key-456"   # Valid but disabled key
"invalid-key"        # Invalid key (not in file)
```

**Security note:** These are test-only keys and have no production value.

### Mock Clients

Test client configurations:

```python
ClientInfo(
    client_id="test-client",
    api_key_hash="abc123",
    description="Test client",
    ip_address="127.0.0.1",
)
```

## Debugging Tests

### Show Print Statements

```bash
# Show print() and log output during tests
uv run pytest tests/unit/test_auth/ -v -s
```

### Show Full Traceback

```bash
# Show full error traceback
uv run pytest tests/unit/test_auth/ -v --tb=long

# Show only first and last line of traceback
uv run pytest tests/unit/test_auth/ -v --tb=line
```

### Drop into Debugger on Failure

```bash
# Drop into pdb debugger on test failure
uv run pytest tests/unit/test_auth/ --pdb

# Drop into pdb on first failure
uv run pytest tests/unit/test_auth/ -x --pdb
```

### Run Tests with Profiling

```bash
# Show slowest 10 tests
uv run pytest tests/unit/test_auth/ --durations=10
```

## Common Issues and Solutions

### Issue: Tests Fail with "FileNotFoundError"

**Cause:** Test is not using `tmp_path` fixture

**Solution:** Ensure all file operations use pytest fixtures:

```python
def test_example(self, tmp_path: Path) -> None:
    test_file = tmp_path / "test.json"
    # ... use test_file
```

### Issue: Async Tests Don't Run

**Cause:** Missing `@pytest.mark.asyncio` decorator

**Solution:** Add decorator to async tests:

```python
@pytest.mark.asyncio
async def test_async_function(self) -> None:
    # ... async test code
```

### Issue: Rate Limiter Tests are Flaky

**Cause:** Timing-dependent tests can be flaky

**Solution:** Tests use short timeouts (0.1s) for speed. If flaky, increase timeout:

```python
await asyncio.wait_for(semaphore.acquire(), timeout=1.0)  # Longer timeout
```

### Issue: Coverage is Lower Than Expected

**Cause:** Some code paths are hard to test (file I/O errors)

**Solution:** This is expected. Security modules have 95%+ coverage, which is excellent for security-critical code.

## Manual Testing

### Test API Key Generation

```bash
# Generate a test API key
uv run python scripts/generate_api_key.py
```

### Test Authentication Flow

```python
# Create a test script
from pathlib import Path
from mcp_docker.auth.api_key import APIKeyAuthenticator

# Create test keys file
keys_file = Path(".mcp_keys_test.json")
keys_file.write_text('{"clients": [{"api_key": "test-key-123", "client_id": "test", "enabled": true}]}')

# Test authentication
auth = APIKeyAuthenticator(keys_file)
result = auth.authenticate("test-key-123", "127.0.0.1")
print(f"Auth result: {result}")

# Cleanup
keys_file.unlink()
```

### Test Rate Limiting

```python
import asyncio
from mcp_docker.security.rate_limiter import RateLimiter, RateLimitExceededError

async def test_rate_limit():
    limiter = RateLimiter(enabled=True, requests_per_minute=5)

    # Make 5 requests (should succeed)
    for i in range(5):
        await limiter.check_rate_limit("test-client")
        print(f"Request {i+1} succeeded")

    # 6th request should fail
    try:
        await limiter.check_rate_limit("test-client")
        print("Request 6 succeeded (unexpected!)")
    except RateLimitExceededError as e:
        print(f"Request 6 failed (expected): {e}")

asyncio.run(test_rate_limit())
```

### Test Audit Logging

```python
from pathlib import Path
from mcp_docker.auth.api_key import ClientInfo
from mcp_docker.security.audit import AuditLogger

# Create audit logger
log_file = Path("test_audit.log")
logger = AuditLogger(log_file, enabled=True)

# Log a test operation
client_info = ClientInfo(
    client_id="test-client",
    api_key_hash="abc123",
    ip_address="127.0.0.1",
)

logger.log_tool_call(
    client_info=client_info,
    tool_name="test_tool",
    arguments={"test": "arg"},
    result={"success": True},
)

# Check log file
print(log_file.read_text())

# Cleanup
log_file.unlink()
```

## Best Practices

### Writing New Security Tests

1. **Use pytest fixtures** for test data (tmp_path, etc.)
2. **Test both success and failure cases**
3. **Test edge cases** (empty input, None, invalid types)
4. **Use descriptive test names** (`test_authenticate_valid_key` not `test_auth`)
5. **Add docstrings** to explain what the test validates
6. **Keep tests isolated** (no shared state between tests)
7. **Use async tests** where appropriate (`@pytest.mark.asyncio`)

### Test Coverage Goals

- **Critical security code**: 95%+ coverage
- **Authentication**: 100% of security-critical paths
- **Rate limiting**: All enforcement logic
- **Audit logging**: All event types and sanitization

### CI/CD Integration

Tests should:
- ✅ Run quickly (< 5 seconds for security tests)
- ✅ Be deterministic (no flaky tests)
- ✅ Not require external services (Docker, databases, etc.)
- ✅ Clean up after themselves (no leftover files)
- ✅ Fail fast on security violations

## Continuous Improvement

### Adding New Tests

When adding new security features:

1. Write tests first (TDD approach)
2. Ensure 95%+ coverage of new code
3. Test both positive and negative cases
4. Add to this documentation

### Reviewing Test Results

Regular checks:

- Weekly: Run full test suite locally
- On every PR: CI runs all tests
- Monthly: Review coverage reports
- Quarterly: Update test documentation

## Support

For questions about security testing:

1. Check this documentation
2. Review existing test examples
3. Check pytest documentation: https://docs.pytest.org/
4. Open a GitHub issue with tag "testing"

## Summary

- **60 comprehensive unit tests** for security features
- **95%+ coverage** of security-critical code
- **Fast execution** (~2-3 seconds)
- **Works in CI/CD** (no external dependencies)
- **Easy to run locally** (`uv run pytest tests/unit/test_auth/ tests/unit/test_security/ -v`)
- **Well-documented** test cases with clear intent

The security test suite provides confidence that authentication, authorization, audit logging, and rate limiting work correctly and securely.
