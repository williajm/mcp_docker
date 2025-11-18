# E2E Test Strategy: Realistic Safety Enforcement Testing

## Why Previous E2E Tests Missed Critical Bugs

### The Problem
The existing E2E tests (`test_protocol_validation_e2e.py`) only tested:
- **Protocol fuzzing** (malformed JSON, null bytes)
- **Injection attacks** (XSS, SQL injection, command injection)
- **Server crash prevention**

**They did NOT test:**
- ❌ Actual MCP `tools/call` requests
- ❌ Middleware execution flow
- ❌ Safety enforcement through the full stack
- ❌ Real Docker operations

### Bugs That Slipped Through

#### Bug #1: Middleware Signature Mismatch
**Location:** `middleware/rate_limit.py`, `middleware/audit.py`

**The Bug:**
```python
# Wrong parameter order - FastMCP 2.0 protocol
async def __call__(self, call_next, context):  # ❌ Wrong order
    ...
```

**Should be:**
```python
async def __call__(self, context, call_next):  # ✓ Correct
    ...
```

**Why E2E didn't catch it:**
- Tests only sent malformed requests (empty payloads, invalid JSON)
- Never made actual `tools/call` requests through middleware stack
- Middleware was never executed, so signature mismatch was invisible

**How new E2E catches it:**
```python
# This immediately crashes if middleware signature is wrong
result = await mcp_client_session.call_tool(
    name="docker_list_containers",
    arguments={"all": True}
)
```

#### Bug #2: Safety Level Always SAFE
**Location:** `middleware/safety.py`

**The Bug:**
```python
safety_level = OperationSafety.SAFE  # ❌ Always defaulted to SAFE
# TODO: Get actual safety level from tool registry
```

**Result:** DESTRUCTIVE tools (`docker_remove_container`) bypassed safety checks entirely.

**Why E2E didn't catch it:**
- No tests called destructive tools with `allow_destructive_operations=false`
- No verification that safety policies were actually enforced
- Integration tests only checked components existed, not that they worked

**How new E2E catches it:**
```python
@pytest.mark.e2e
async def test_destructive_operation_blocked_when_disabled(
    mcp_client_session_safe_only: ClientSession,
):
    """CRITICAL: This catches the bug."""
    # Server has SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
    result = await mcp_client_session_safe_only.call_tool(
        name="docker_remove_container",  # DESTRUCTIVE tool
        arguments={"container_id": temp_id, "force": True}
    )

    # Should fail - but with Bug #2, it succeeded!
    assert result.isError or "not allowed" in result.content[0].text.lower()
```

## Realistic E2E Test Design

### What Makes These Tests "Realistic"

1. **Actual MCP SDK Client**
   - Uses `mcp` Python SDK (same library Claude Desktop uses)
   - Connects via stdio transport (production protocol)
   - Makes real JSON-RPC 2.0 requests

2. **Full Stack Execution**
   ```
   MCP Client (test)
        ↓ stdio
   MCP Server (__main__.py)
        ↓
   AuditMiddleware → logs request
        ↓
   AuthMiddleware → checks auth
        ↓
   SafetyMiddleware → enforces safety ← Bug #2 here
        ↓
   RateLimitMiddleware → checks limits ← Bug #1 here
        ↓
   Tool (docker_remove_container)
        ↓
   Docker SDK
        ↓
   Docker Daemon
   ```

3. **Real Docker Operations**
   - Creates actual Docker containers
   - Performs real operations (start, stop, inspect, remove)
   - Verifies side effects (container deleted, logs retrieved)
   - Cleans up after tests

4. **Configuration-Driven Testing**
   - Tests different safety configurations
   - Verifies allow/deny lists work
   - Tests both enabled and disabled states

### Test Coverage Matrix

| Test | Safety Level | Config | Expected Result | Catches Bug |
|------|-------------|--------|----------------|-------------|
| `test_safe_operation_list_containers_allowed` | SAFE | All enabled | ✓ Success | #1, #2 |
| `test_moderate_operation_blocked_when_disabled` | MODERATE | Moderate disabled | ✗ Blocked | #2 |
| `test_destructive_operation_blocked_when_disabled` | DESTRUCTIVE | Destructive disabled | ✗ Blocked | **#2** |
| `test_destructive_operation_remove_container_allowed_when_enabled` | DESTRUCTIVE | All enabled | ✓ Success + Verify deletion | #1, #2 |
| `test_middleware_executes_in_correct_order` | Any | Any | ✓ No crash | **#1** |
| `test_full_stack_with_real_docker_operation` | All levels | All enabled | ✓ Full workflow | #1, #2 |

### Key Differences from Old E2E Tests

| Aspect | Old E2E Tests | New E2E Tests |
|--------|--------------|---------------|
| **Client** | Raw subprocess stdin | MCP SDK client |
| **Protocol** | Malformed JSON strings | Actual `tools/call` requests |
| **Focus** | Server crash prevention | Safety enforcement |
| **Docker** | Not used | Real containers created/deleted |
| **Middleware** | Not exercised | Full stack execution |
| **Assertions** | "Didn't crash" | "Correct behavior" |

## Running the E2E Tests

### Run All E2E Tests
```bash
uv run pytest tests/e2e/test_safety_enforcement_e2e.py -v
```

### Run Specific Test Category
```bash
# Test SAFE operations
uv run pytest tests/e2e/test_safety_enforcement_e2e.py -k "safe_operation" -v

# Test DESTRUCTIVE operations
uv run pytest tests/e2e/test_safety_enforcement_e2e.py -k "destructive" -v

# Test tool allow/deny lists
uv run pytest tests/e2e/test_safety_enforcement_e2e.py -k "tool_" -v
```

### Run with Docker Cleanup Verification
```bash
# Verbose mode shows Docker operations
uv run pytest tests/e2e/test_safety_enforcement_e2e.py::test_full_stack_with_real_docker_operation -v -s
```

## Requirements

- Docker daemon running
- `mcp` Python SDK installed (`uv sync`)
- Alpine Docker image pulled (`docker pull alpine:latest`)

## Test Fixtures

### `mcp_client_session`
- Creates MCP client with all operations enabled
- Connects to server via stdio
- Used for positive tests (operations should succeed)

### `mcp_client_session_safe_only`
- Creates MCP client with MODERATE/DESTRUCTIVE disabled
- Used for negative tests (operations should be blocked)
- **This fixture catches Bug #2**

### `test_container_id`
- Creates a real Docker container for testing
- Automatically cleans up after test
- Used for inspect/start/stop operations

## Future Enhancements

1. **Rate Limiting Tests**
   - Test that rate limits actually trigger
   - Verify concurrent request limits work

2. **Audit Logging Tests**
   - Verify audit logs are written
   - Check log format and contents

3. **Network Transport Tests**
   - Test HTTP transport (when implemented)
   - Verify OAuth authentication

4. **Performance Tests**
   - Measure tool execution latency
   - Test under load

## Best Practices

1. **Always use real MCP SDK client** - Don't manually craft JSON-RPC
2. **Test both positive and negative cases** - Success AND failure paths
3. **Verify side effects** - Don't just check return values, verify Docker state
4. **Clean up resources** - Use fixtures with cleanup to avoid Docker pollution
5. **Test realistic workflows** - Multi-step operations (create → start → logs → remove)

## Conclusion

These realistic E2E tests would have caught both bugs because they:
1. **Exercise the full middleware stack** (catches signature mismatches)
2. **Verify safety enforcement** (catches incorrect safety levels)
3. **Use real Docker operations** (catches functional bugs)
4. **Test configuration variations** (catches policy bypasses)

The key insight: **E2E tests must test real behavior, not just crash prevention.**
