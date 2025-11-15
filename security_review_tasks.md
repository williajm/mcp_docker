# Security Review Remediation Tasks

**Project**: MCP Docker Server v1.1.1.dev0
**Review Date**: 2025-11-14
**Reviewers**: Claude, Gemini, GPT-5
**Status**: In Progress

---

## Task Status Legend

- 🔴 **Not Started** - Issue identified, no work begun
- 🟡 **In Progress** - Currently being investigated or fixed
- 🟢 **Completed** - Fixed and verified
- ⚫ **Rejected** - Decision made not to fix (with justification)
- 🔵 **Needs Investigation** - Requires further analysis before decision

---

## CRITICAL PRIORITY (Fix Before Any Production Use)

### C1. Volume Mount Validation Not Enforced 🟢
**Severity**: Critical (CVSS 9.1)
**Found by**: Claude, Gemini, GPT-5 (ALL THREE)
**Status**: Completed

**Issue**:
- `validate_mount_path()` exists in `src/mcp_docker/utils/safety.py` (lines 364-396)
- Function is NEVER called in `CreateContainerTool._validate_inputs()`
- Attackers can mount dangerous paths: `/`, `/etc/shadow`, `/root/.ssh`, `/var/run/docker.sock`
- Leads to container escape and host compromise

**Location**: `src/mcp_docker/tools/container_lifecycle_tools.py:166-215`

**Implementation Completed**:
- ✅ Enhanced `validate_mount_path()` with comprehensive dangerous path blocking
- ✅ Added `yolo_mode` parameter to bypass validation (for advanced users)
- ✅ Integrated validation into `CreateContainerTool._validate_inputs()`
- ✅ Added YOLO mode config option (`SAFETY_YOLO_MODE`)
- ✅ Added startup warning when YOLO mode enabled
- ✅ Created 22 comprehensive unit tests (19 for validation, 3 for CreateContainerTool)
- ✅ All tests pass (821 total unit tests)
- ✅ Code quality verified (Ruff, mypy)

**Blocks the following dangerous paths**:
- Root filesystem: `/`
- Docker socket: `/var/run/docker.sock`, `/run/docker.sock`
- System directories: `/etc`, `/sys`, `/proc`, `/boot`, `/dev`, `/root`, `/run`
- Docker data: `/var/lib/docker`, `/var/lib/containerd`
- SSH keys: Any path containing `/.ssh/`
- Sensitive files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.
- Windows paths: `C:/Windows`, `C:/Program Files`
- Path traversal attacks: Normalizes paths to prevent `../../etc/shadow`

**YOLO Mode**: Users who need dangerous mounts can set `SAFETY_YOLO_MODE=true` (at their own risk)

**Test Requirements**:
- ✅ Unit test: Reject mounts to `/`, `/etc`, `/var/run/docker.sock`
- ✅ Unit test: Accept safe paths (`/home/user/data`, `/tmp`, `/opt`)
- ✅ Unit test: YOLO mode bypasses all validation
- ⚠️  Integration test: Still needed
- ⚠️  E2E tests: Still needed

**References**:
- Claude Critical #1
- Gemini Critical #1 (partial)
- GPT-5 High #1

**Note**: YOLO mode currently only bypasses volume mount validation. See task L7 for making it bypass all safety checks.

---

### C2. Privileged Container Creation Not Restricted 🔴
**Severity**: Critical (CVSS 8.8)
**Found by**: Claude, Gemini
**Status**: Not Started

**Issue**:
- `CreateContainerTool` does NOT implement `check_privileged_arguments()`
- Docker SDK accepts `privileged=True` without validation
- `SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false` config is ignored
- Privileged containers can escape to host (load kernel modules, access /dev/mem)

**Location**: `src/mcp_docker/tools/container_lifecycle_tools.py`

**Remediation**:
```python
# Add to CreateContainerTool class:
def check_privileged_arguments(self, arguments: dict[str, Any]) -> None:
    """Check if privileged container creation is allowed."""
    privileged = arguments.get("privileged", False)
    if privileged and not self.safety.allow_privileged_containers:
        raise UnsafeOperationError(
            "Privileged containers are not allowed. "
            "Set SAFETY_ALLOW_PRIVILEGED_CONTAINERS=true to enable."
        )

    # Also check for:
    # - cap_add with dangerous capabilities
    # - security_opt disabling AppArmor/SELinux
    # - pid_mode="host" or network_mode="host"
```

**Test Requirements**:
- Unit test: Reject `privileged=True` when config disallows
- Unit test: Accept `privileged=True` when config allows
- Unit test: Check dangerous capabilities (CAP_SYS_ADMIN, etc.)
- Integration test: Verify Docker rejects the creation

**References**:
- Claude Critical #2
- Gemini Critical #1

---

### C3. Start Scripts Disable OAuth Despite "Security" Claims 🔴
**Severity**: Critical (Deployment Risk)
**Found by**: GPT-5
**Status**: Not Started

**Issue**:
- `./start-mcp-docker-httpstream.sh` and `./start-mcp-docker-sse.sh` force `SECURITY_OAUTH_ENABLED=false`
- Documentation says these scripts run "with security features"
- Results in unauthenticated HTTPS endpoint with root-level Docker access
- False sense of security for production deployments

**Location**:
- `start-mcp-docker-httpstream.sh:1-90`
- `start-mcp-docker-sse.sh:40-74`

**Remediation Options**:
1. Enable OAuth by default in scripts (require users to provide JWKS URL)
2. Enable IP allowlist by default (require users to configure allowed IPs)
3. Update SECURITY.md to clearly state scripts are for TESTING only
4. Create separate production-ready script templates

**Test Requirements**:
- Manual test: Verify scripts cannot be run without security config
- Documentation review: Ensure no misleading claims

**References**:
- GPT-5 Medium #3

---

## HIGH PRIORITY (Fix Within 1 Week)

### H1. Command Injection via Environment Variables 🔴
**Severity**: High (CVSS 8.1)
**Found by**: Claude
**Status**: Not Started

**Issue**:
- `ExecCommandTool` accepts arbitrary environment variables
- No validation for command injection characters in env var values
- Attack: `{"environment": {"MALICIOUS": "$(cat /etc/passwd)"}}`
- Combined with `command: ["sh", "-c", "$MALICIOUS"]` enables arbitrary execution

**Location**: `src/mcp_docker/tools/container_inspection_tools.py` (ExecCommandTool)

**Remediation**:
```python
# In utils/safety.py, enhance validate_environment_variable:
def validate_environment_variable(key: str, value: Any) -> tuple[str, str]:
    # ... existing code ...

    value_str = str(value)
    dangerous_in_env = [';', '&', '|', '$(', '`', '\n', '\r']
    if any(char in value_str for char in dangerous_in_env):
        raise ValidationError(
            f"Environment variable value contains potentially dangerous characters"
        )

    return key, value_str
```

**Test Requirements**:
- Unit test: Reject env vars with `$(`, backticks, pipes, etc.
- Unit test: Accept normal env vars
- Integration test: Verify Docker exec fails with dangerous env

**References**:
- Claude Critical #3

---

### H2. Secrets Leaked in generate_compose Prompt 🔴
**Severity**: High (Credential Disclosure)
**Found by**: GPT-5
**Status**: Not Started

**Issue**:
- `generate_compose` prompt dumps container environment variables into LLM context
- Environment variables often contain secrets (DB passwords, API tokens)
- Invoking this prompt with remote model leaks credentials
- No warning to users about this risk

**Location**: `src/mcp_docker/prompts/templates.py:432-476`

**Remediation Options**:
1. Redact env var values (show only keys: `DATABASE_URL=<REDACTED>`)
2. Add confirmation gate warning about secret disclosure
3. Add config flag to enable/disable env var inclusion
4. Document the risk prominently in prompt description

**Test Requirements**:
- Unit test: Verify env vars are redacted in prompt output
- Documentation: Add security warning to README and prompt docs

**References**:
- GPT-5 Medium #2

---

### H3. sanitize_command Function is Misleading 🔴
**Severity**: High (Developer Confusion)
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- Function name implies security sanitization
- Actually just converts strings to lists
- Developer might use it thinking it provides security
- Could introduce command injection vulnerabilities

**Location**: `src/mcp_docker/utils/validation.py`

**Remediation Options**:
1. **Recommended**: Remove function, implement inline where needed
2. Rename to `ensure_command_is_list` with clear docstring warning
3. Add actual sanitization logic to match the name

**Test Requirements**:
- Code search: Verify all call sites still work after change
- Update any related documentation

**References**:
- Gemini High #2

---

### H4. Insecure Default Docker Connection 🔴
**Severity**: High (Design Issue)
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- Defaults to Docker socket (`/var/run/docker.sock`)
- Socket access = root privileges on host
- No permission checks on socket file
- Documentation doesn't explain risks adequately

**Location**: `src/mcp_docker/config.py:59-72`

**Remediation**:
1. Add prominent security warning in README about socket risks
2. Add permission check on socket file at startup
3. Consider requiring explicit socket path (no default)
4. Document TLS-secured TCP socket as recommended approach

**Test Requirements**:
- Documentation review: Ensure risks are clear
- Add startup warning if running with socket access

**References**:
- Gemini High #3

---

### H5. Rate Limiter Memory Exhaustion 🔴
**Severity**: High (DoS)
**Found by**: Claude, Gemini
**Status**: Not Started

**Issue**:
- Creates new semaphore for every unique `client_id`
- Dictionaries grow unbounded
- Attacker can exhaust memory with many client IDs
- No cleanup of old entries

**Location**: `src/mcp_docker/security/rate_limiter.py:66-69`

**Remediation**:
```python
# Add LRU cache or periodic cleanup:
from collections import OrderedDict

class RateLimiter:
    def __init__(self, ...):
        self._max_clients = 10000  # Config
        self._semaphores = OrderedDict()  # LRU

    def acquire_concurrent_slot(self, client_id: str):
        # Evict oldest if over limit
        if len(self._semaphores) >= self._max_clients:
            self._semaphores.popitem(last=False)
```

**Test Requirements**:
- Unit test: Verify LRU eviction works
- Unit test: Verify max clients limit enforced
- Performance test: High client count doesn't exhaust memory

**References**:
- Claude Medium #6
- Gemini Low #6

---

## MEDIUM PRIORITY (Fix Within 1 Month)

### M1. Port Binding to 0.0.0.0 Not Restricted 🔴
**Severity**: Medium (CVSS 5.3)
**Found by**: Claude
**Status**: Not Started

**Issue**:
- No validation preventing binding to `0.0.0.0`
- Exposes containers on all network interfaces
- Increases attack surface for vulnerable containers

**Location**: `src/mcp_docker/utils/safety.py:398-417`

**Remediation**:
```python
# In validate_port_mapping:
if isinstance(host_config, tuple) and host_config[0] == "0.0.0.0":
    if not self.allow_public_port_binding:  # New config
        raise ValidationError(
            "Binding to 0.0.0.0 exposes container publicly. "
            "Use 127.0.0.1 for localhost only."
        )
```

**Test Requirements**:
- Unit test: Reject 0.0.0.0 when config disallows
- Unit test: Accept 127.0.0.1, specific IPs

**References**:
- Claude Medium #4

---

### M2. Container Log RADE Risk 🔴
**Severity**: Medium (CVSS 5.9)
**Found by**: Claude
**Status**: Not Started

**Issue**:
- Container logs may contain malicious prompts (RADE attack)
- No sanitization before returning to AI
- AI could be manipulated by log content
- Documentation mentions risk but no mitigation

**Location**: `src/mcp_docker/tools/container_inspection_tools.py:308-447`

**Remediation**:
1. Add warning metadata when returning logs
2. Implement prompt injection pattern detection
3. Add config to truncate/filter dangerous patterns
4. Document risk in tool description

**Test Requirements**:
- Unit test: Detect common prompt injection patterns
- Documentation: Add security warning

**References**:
- Claude Medium #7

---

### M3. JWT Clock Skew Too Permissive 🔴
**Severity**: Medium (CVSS 5.3)
**Found by**: Claude
**Status**: Not Started

**Issue**:
- Default clock skew is 60 seconds
- Allows tokens valid for extra minute after expiration
- Max allowed is 300 seconds (5 minutes!)

**Location**: `src/mcp_docker/config.py:370-375`

**Remediation**:
```python
oauth_clock_skew_seconds: int = Field(
    default=30,  # Reduced from 60
    description="Allowed clock skew in seconds for JWT exp/nbf validation",
    ge=0,
    le=60,  # Reduced from 300
)
```

**Test Requirements**:
- Unit test: Verify new defaults
- Integration test: Expired tokens rejected within skew

**References**:
- Claude Medium #8

---

### M4. No Fine-Grained Access Control on Docker API 🔴
**Severity**: Medium (Design Issue)
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- `DockerClientWrapper` provides full API access
- Violates principle of least privilege
- No way to restrict operations per component

**Location**: `src/mcp_docker/docker_wrapper/client.py`

**Remediation**:
- Design capability-based access control layer
- May require significant refactoring
- Consider for future major version

**Test Requirements**:
- Design review needed first

**References**:
- Gemini Medium #4

---

### M5. List-Based Commands Not Validated 🔴
**Severity**: Medium
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- `validate_command` checks string commands for dangerous patterns
- List-based commands bypass all checks
- Arguments in lists not validated

**Location**: `src/mcp_docker/utils/validation.py`

**Remediation**:
```python
def validate_command(command: str | list[str]) -> None:
    if isinstance(command, list):
        # Check each argument for dangerous patterns
        for arg in command:
            if any(pattern in str(arg) for pattern in DANGEROUS_PATTERNS):
                raise ValidationError(f"Dangerous pattern in command: {arg}")
```

**Test Requirements**:
- Unit test: Detect dangerous patterns in list commands
- Unit test: Allow safe list commands

**References**:
- Gemini Medium #5

---

## LOW PRIORITY (Future Enhancements)

### L1. Insecure Transport Warning Should Be Error 🔴
**Severity**: Low
**Found by**: Claude
**Status**: Not Started

**Issue**:
- SSE over HTTP (non-localhost) only warns
- Production could accidentally run insecure

**Location**: `src/mcp_docker/__main__.py:329-370`

**Remediation**: Make hard error or require `--allow-insecure` flag

**References**: Claude Low #9

---

### L2. Audit Log File Permissions Too Permissive 🔴
**Severity**: Low
**Found by**: Claude
**Status**: Not Started

**Issue**:
- Audit log directory created with 0o755 (world-readable)
- Logs may contain sensitive operation details

**Location**: `src/mcp_docker/config.py:397-408`

**Remediation**: Set 0o700 on directory and files

**References**: Claude Low #10

---

### L3. Secrets Detection Pattern Not Implemented 🔴
**Severity**: Low
**Found by**: Claude
**Status**: Not Started

**Issue**:
- Code detects sensitive variable names but doesn't warn
- Pattern matching exists but is no-op

**Location**: `src/mcp_docker/utils/safety.py:440-450`

**Remediation**: Implement entropy-based secret detection

**References**: Claude Low #11

---

### L4. CORS Preflight Cache Too Long 🔴
**Severity**: Low
**Found by**: Claude
**Status**: Not Started

**Issue**:
- Default max-age is 3600 seconds (1 hour)
- CORS policy changes take an hour to propagate

**Location**: `src/mcp_docker/config.py:625-629`

**Remediation**: Reduce to 600 seconds (10 minutes)

**References**: Claude Low #12

---

### L5. No Global Rate Limit 🔴
**Severity**: Low
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- Only per-client rate limiting
- Many clients could still overwhelm server

**Remediation**: Add global rate limit config

**References**: Gemini Low #7

---

### L6. OAuth Client Secret in Memory 🔴
**Severity**: Low
**Found by**: Gemini
**Status**: Not Started

**Issue**:
- Client secret stored in plaintext in memory
- Could be dumped from process memory

**Remediation**: For high-security environments, use secret management service

**References**: Gemini Low #8

---

### L7. YOLO Mode Only Bypasses Volume Mounts (Not All Safety Checks) 🔴
**Severity**: Low (Inconsistency)
**Found by**: Implementation Review
**Status**: Not Started

**Issue**:
- YOLO mode config and startup warning claim to disable ALL safety checks
- Currently YOLO mode only bypasses `validate_mount_path()` for volume mounts
- Other safety checks don't check `yolo_mode` flag yet:
  - Privileged container checks (`check_privileged_arguments()`)
  - Command injection validation (in `validate_command()` and env vars)
  - Destructive operation checks (safety level enforcement)
  - Command validation patterns (dangerous commands)

**Current State**:
- Config description: "Disable ALL safety checks and validation"
- Startup warning: Lists all bypassed checks
- Reality: Only volume mount validation bypassed

**Location**:
- Config: `src/mcp_docker/config.py:190-199`
- Startup warning: `src/mcp_docker/server.py:90-102`
- Volume mount bypass: `src/mcp_docker/utils/safety.py:382-384`

**Remediation**:
Make YOLO mode actually bypass all safety checks as advertised:

```python
# In src/mcp_docker/tools/base.py - BaseTool.check_safety():
def check_safety(self) -> None:
    # YOLO mode bypasses all safety checks
    if self.safety.yolo_mode:
        return
    # ... existing safety checks ...

# In src/mcp_docker/utils/validation.py - validate_command():
def validate_command(command: str | list[str], yolo_mode: bool = False) -> None:
    # YOLO mode bypasses command validation
    if yolo_mode:
        return
    # ... existing validation ...

# In src/mcp_docker/tools/container_inspection_tools.py - ExecCommandTool:
def check_privileged_arguments(self, arguments: dict[str, Any]) -> None:
    # YOLO mode bypasses privileged checks
    if self.safety.yolo_mode:
        return
    # ... existing checks ...

# Anywhere else that has safety checks
```

**Alternative**: Scale back the config/warning text to match current implementation (only volume mounts)

**Test Requirements**:
- Unit test: YOLO mode bypasses privileged container checks
- Unit test: YOLO mode bypasses command injection validation
- Unit test: YOLO mode bypasses destructive operation checks
- Unit test: YOLO mode bypasses dangerous command patterns
- Integration test: YOLO mode allows all dangerous operations

**References**: Implementation gap discovered during C1 implementation

---

## Summary Statistics

**Total Issues**: 22
- Critical: 3
- High: 5
- Medium: 5
- Low: 7

**By Status**:
- 🔴 Not Started: 20
- 🟡 In Progress: 0
- 🟢 Completed: 1 (C1 - Volume mount validation)
- ⚫ Rejected: 0
- 🔵 Needs Investigation: 0

**By Reviewer Agreement**:
- Found by all 3: 1 (C1 - Volume mounts)
- Found by 2: 3 (C2, H5, H4 partial)
- Found by 1: 17

---

## Next Steps

1. ✅ ~~Review and validate all Critical issues (C1-C3)~~ - C1 completed
2. Implement fixes for remaining Critical issues (C2-C3)
3. Create test coverage for each fix
4. Update documentation with security warnings
5. Consider security advisory for existing users
6. Move to High priority items after Critical complete
7. Future: Implement full YOLO mode bypass (L7)

---

## Notes

- This document should be updated as tasks progress
- Mark rejected items with justification
- Add links to PRs/commits when completed
- Consider creating GitHub issues for tracking
