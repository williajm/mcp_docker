# Volume Mount Validation - Solution Proposal

**Issue**: C1 from security review - Volume mount validation not enforced
**Severity**: Critical (CVSS 9.1)
**Status**: Proposal - Not Implemented

---

## Problem Statement

The `validate_mount_path()` function exists in `src/mcp_docker/utils/safety.py:364-396` with protections against sensitive paths, but it is **NEVER CALLED** in `CreateContainerTool._validate_inputs()`.

This allows attackers to:
- Mount entire host filesystem (`/` → `/host_root`)
- Mount Docker socket (`/var/run/docker.sock` → `/docker.sock`)
- Mount sensitive files (`/etc/shadow`, `/root/.ssh/id_rsa`)
- Escape container and gain root on host

---

## Current State Analysis

### Existing Function (`src/mcp_docker/utils/safety.py:364-396`)

**Current dangerous paths blocked**:
```python
dangerous_paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh",
    "/home/.ssh",
    "/.ssh",
]
```

**Critical gaps in current implementation**:
1. ❌ Docker socket not blocked (`/var/run/docker.sock`)
2. ❌ Root filesystem not blocked (`/`)
3. ❌ System directories not blocked (`/etc`, `/sys`, `/proc`, `/boot`)
4. ❌ Other sensitive paths not blocked (`/var/lib/docker`, `/home/*/.ssh`)
5. ❌ Windows paths not considered (`C:\`, `\\.\pipe\docker_engine`)
6. ❌ Path traversal not prevented (`../../../etc/shadow`)
7. ❌ Symlink resolution not performed

### CreateContainerTool Current Behavior (`src/mcp_docker/tools/container_lifecycle_tools.py:166-187`)

```python
def _validate_inputs(self, input_data: CreateContainerInput) -> None:
    if input_data.name:
        validate_container_name(input_data.name)
    if input_data.command:
        validate_command(input_data.command)
    if input_data.mem_limit:
        validate_memory(input_data.mem_limit)
    if input_data.ports:
        # Port validation exists
        ...
    # ❌ NO VOLUME VALIDATION - CRITICAL GAP!
```

---

## Proposed Solution (Simplified - No New Config Options)

### Approach: Just Fix the Bug

1. Enhance `validate_mount_path()` with comprehensive dangerous paths
2. Call it in `CreateContainerTool._validate_inputs()`
3. **No new config options** (we have enough already)
4. Block dangerous mounts, period

If users really need to mount something we block, they can file an issue and we'll evaluate if it's safe to allow.

### Phase 1: Enhanced Dangerous Path List

Expand the dangerous paths in `validate_mount_path()` to cover all container escape vectors:

```python
def validate_mount_path(
    path: str,
    allowed_paths: list[str] | None = None,
    yolo_mode: bool = False,
) -> None:
    """Validate that a mount path is safe.

    Args:
        path: Path to validate (host-side path)
        allowed_paths: List of allowed path prefixes (None = block dangerous only)
        yolo_mode: If True, skip all validation (DANGEROUS!)

    Raises:
        UnsafeOperationError: If path is not allowed
    """
    # YOLO mode bypasses all validation
    if yolo_mode:
        return

    # Normalize path (resolve .., remove trailing slashes, etc.)
    import os
    try:
        normalized_path = os.path.normpath(path)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid path format: {path}")

    # Block root filesystem mount (most dangerous)
    if normalized_path == "/" or normalized_path == "C:\\" or normalized_path == "C:/":
        raise UnsafeOperationError(
            "Mounting the entire root filesystem is not allowed. "
            "This would grant full host access from the container."
        )

    # Block Docker socket (equivalent to root access)
    docker_sockets = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "//./pipe/docker_engine",  # Windows
        "\\\\.\\pipe\\docker_engine",  # Windows
    ]
    for socket_path in docker_sockets:
        if normalized_path == socket_path or normalized_path.startswith(socket_path + "/"):
            raise UnsafeOperationError(
                f"Mounting Docker socket '{socket_path}' is not allowed. "
                "This grants root-equivalent access to the host."
            )

    # Block entire system directories
    dangerous_prefixes = [
        "/etc",           # System configuration
        "/sys",           # Kernel/system information
        "/proc",          # Process information
        "/boot",          # Boot files and kernel
        "/dev",           # Device files
        "/var/lib/docker",  # Docker's internal data
        "/var/lib/containerd",  # Containerd data
        "/root",          # Root user home
        "/run",           # Runtime data (includes docker.sock)
        "C:/Windows",     # Windows system
        "C:/Program Files",  # Windows programs
    ]

    for dangerous_prefix in dangerous_prefixes:
        if normalized_path.startswith(dangerous_prefix + "/") or normalized_path == dangerous_prefix:
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                f"Mounting system directory '{dangerous_prefix}' is blocked for security."
            )

    # Block specific sensitive files
    dangerous_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
    ]

    for dangerous_file in dangerous_files:
        if normalized_path == dangerous_file:
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                f"Mounting sensitive file '{dangerous_file}' is blocked."
            )

    # Block user SSH directories (with wildcard expansion concern)
    # Note: /home/.ssh already blocks, but this is more explicit
    ssh_patterns = ["/.ssh/", "/.ssh"]
    for pattern in ssh_patterns:
        if pattern in normalized_path:
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                "Mounting SSH directories is blocked to prevent key theft."
            )

    # Note: We don't use an allowlist - we just block dangerous paths
    # If a legitimate use case is blocked, users can file an issue
```

### Phase 2: Call Validation in CreateContainerTool

Add volume validation to `_validate_inputs()` in `src/mcp_docker/tools/container_lifecycle_tools.py`:

```python
def _validate_inputs(self, input_data: CreateContainerInput) -> None:
    """Validate all input parameters.

    Args:
        input_data: Input parameters to validate

    Raises:
        ValidationError: If validation fails
    """
    if input_data.name:
        validate_container_name(input_data.name)
    if input_data.command:
        validate_command(input_data.command)
    if input_data.mem_limit:
        validate_memory(input_data.mem_limit)
    if input_data.ports:
        # After field validation, ports is always a dict or None (never str)
        assert isinstance(input_data.ports, dict)
        for container_port, host_port in input_data.ports.items():
            if isinstance(host_port, int):
                validate_port_mapping(container_port, host_port)

    # NEW: Validate volume mounts
    if input_data.volumes:
        # After field validation, volumes is always a dict or None (never str)
        assert isinstance(input_data.volumes, dict)

        # Validate each host path
        for host_path, bind_config in input_data.volumes.items():
            # Validate the host-side path for dangerous mounts
            # Pass yolo_mode to bypass validation if enabled
            validate_mount_path(host_path, yolo_mode=self.safety.yolo_mode)

            # Also validate the bind config structure (skip if YOLO)
            if not self.safety.yolo_mode:
                if not isinstance(bind_config, dict):
                    raise ValidationError(
                        f"Volume bind config must be a dict, got {type(bind_config)}"
                    )

                if 'bind' not in bind_config:
                    raise ValidationError(
                        f"Volume bind config must contain 'bind' key: {bind_config}"
                    )
```

### Phase 3: Add YOLO Mode (One Config Option)

**Decision**: Add one simple config option for users who need to bypass safety checks.

**YOLO Mode**: "You Only Live Once" - disables ALL safety validation

```python
class SafetyConfig(BaseSettings):
    """Safety and operation control configuration."""

    # ... existing fields ...

    yolo_mode: bool = Field(
        default=False,
        description=(
            "YOLO MODE: Disable ALL safety checks and validation. "
            "⚠️  WARNING: This is EXTREMELY DANGEROUS and should only be used "
            "if you fully understand the security implications. "
            "Enables: dangerous volume mounts, privileged containers, destructive operations, "
            "command injection, etc. USE AT YOUR OWN RISK."
        ),
    )
```

**Environment variable**: `SAFETY_YOLO_MODE=true`

When YOLO mode is enabled:
- Volume mount validation is skipped
- Privileged container checks are skipped
- All dangerous path blocks are bypassed
- Command injection validation is skipped
- All safety checks are effectively disabled

**Warning on startup**: When YOLO mode is enabled, log a loud warning:
```
⚠️  ⚠️  ⚠️  YOLO MODE ENABLED ⚠️  ⚠️  ⚠️
ALL SAFETY CHECKS ARE DISABLED
THIS IS EXTREMELY DANGEROUS
PROCEED AT YOUR OWN RISK
⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️
```

---

## Behavior After Fix

### Default Behavior (Block Dangerous Paths)

No configuration needed. The validation will:
- ✅ Allow safe paths: `/home/user/data`, `/tmp/mydata`, `/opt/myapp`, etc.
- ❌ Block dangerous paths: `/`, `/etc`, `/var/run/docker.sock`, `/root/.ssh`, etc.

### YOLO Mode (Bypass All Safety Checks)

If a user absolutely needs to mount dangerous paths (e.g., for testing, development, or specific use cases):

```bash
export SAFETY_YOLO_MODE=true
```

**What YOLO mode does**:
- ✅ Allows ALL volume mounts (including `/`, Docker socket, `/etc`, etc.)
- ✅ Allows privileged containers
- ✅ Bypasses command injection validation
- ✅ Bypasses ALL safety checks across the entire server
- ⚠️  **EXTREMELY DANGEROUS** - only use if you fully understand the risks

**Warning**: On startup with YOLO mode:
```
⚠️  ⚠️  ⚠️  YOLO MODE ENABLED ⚠️  ⚠️  ⚠️
ALL SAFETY CHECKS ARE DISABLED
THIS IS EXTREMELY DANGEROUS
PROCEED AT YOUR OWN RISK
⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️  ⚠️
```

### Alternative: File an Issue

If you think a path we block should be allowed:

**Option 1**: File an issue explaining your use case
- We evaluate if it's safe to allow
- If safe, we update the validation logic
- If unsafe, we recommend YOLO mode (at your own risk)

---

## Test Coverage Requirements

### Unit Tests (`tests/unit/test_container_lifecycle_tools.py`)

```python
class TestCreateContainerToolVolumeValidation:
    """Test volume mount validation in CreateContainerTool."""

    def test_create_container_rejects_root_mount(self, mock_docker_client):
        """Test container creation rejects root filesystem mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="root filesystem"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/": {"bind": "/host_root", "mode": "rw"}
                }
            })

    def test_create_container_rejects_docker_socket(self, mock_docker_client):
        """Test container creation rejects Docker socket mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="Docker socket"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/var/run/docker.sock": {"bind": "/docker.sock", "mode": "rw"}
                }
            })

    def test_create_container_rejects_etc_directory(self, mock_docker_client):
        """Test container creation rejects /etc mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="/etc"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/etc": {"bind": "/host_etc", "mode": "ro"}
                }
            })

    def test_create_container_rejects_shadow_file(self, mock_docker_client):
        """Test container creation rejects /etc/shadow mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="shadow"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/etc/shadow": {"bind": "/shadow", "mode": "ro"}
                }
            })

    def test_create_container_rejects_ssh_keys(self, mock_docker_client):
        """Test container creation rejects SSH key directory mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="SSH"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/root/.ssh": {"bind": "/keys", "mode": "ro"}
                }
            })

    def test_create_container_accepts_safe_mount(self, mock_docker_client):
        """Test container creation accepts safe directory mount."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        # Mock successful creation
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.name = "test-container"
        mock_docker_client.containers.create.return_value = mock_container

        result = tool.execute({
            "image": "ubuntu",
            "volumes": {
                "/home/user/data": {"bind": "/data", "mode": "ro"}
            }
        })

        assert result.success
        assert result.data["container_id"] == "abc123"

    def test_create_container_path_traversal(self, mock_docker_client):
        """Test container creation blocks path traversal attempts."""
        tool = CreateContainerTool(mock_docker_client, SafetyConfig())

        with pytest.raises(UnsafeOperationError, match="shadow"):
            tool.execute({
                "image": "ubuntu",
                "volumes": {
                    "/home/user/../../etc/shadow": {"bind": "/data", "mode": "ro"}
                }
            })

    def test_create_container_yolo_mode_allows_dangerous_mount(self, mock_docker_client):
        """Test YOLO mode allows dangerous mounts."""
        config = SafetyConfig(yolo_mode=True)
        tool = CreateContainerTool(mock_docker_client, config)

        # Mock successful creation
        mock_container = MagicMock()
        mock_container.id = "yolo123"
        mock_container.name = "yolo-container"
        mock_docker_client.containers.create.return_value = mock_container

        # Should allow Docker socket mount in YOLO mode
        result = tool.execute({
            "image": "ubuntu",
            "volumes": {
                "/var/run/docker.sock": {"bind": "/docker.sock", "mode": "rw"}
            }
        })

        assert result.success
        assert result.data["container_id"] == "yolo123"

    def test_create_container_yolo_mode_allows_root_mount(self, mock_docker_client):
        """Test YOLO mode allows root filesystem mount."""
        config = SafetyConfig(yolo_mode=True)
        tool = CreateContainerTool(mock_docker_client, config)

        # Mock successful creation
        mock_container = MagicMock()
        mock_container.id = "yolo456"
        mock_docker_client.containers.create.return_value = mock_container

        # Should allow root mount in YOLO mode
        result = tool.execute({
            "image": "ubuntu",
            "volumes": {
                "/": {"bind": "/host_root", "mode": "rw"}
            }
        })

        assert result.success
```

### Integration Tests (`tests/integration/test_volume_mount_security.py`)

```python
@pytest.mark.integration
class TestVolumeMountSecurityIntegration:
    """Integration tests for volume mount security with real Docker."""

    @pytest.fixture
    def real_docker_client(self):
        """Create real Docker client for integration tests."""
        import docker
        return docker.from_env()

    def test_real_docker_rejects_dangerous_mount(self, real_docker_client):
        """Test that validation prevents dangerous mounts from reaching Docker."""
        tool = CreateContainerTool(real_docker_client, SafetyConfig())

        # Attempt to mount Docker socket
        result = tool.execute({
            "image": "alpine:latest",
            "volumes": {
                "/var/run/docker.sock": {"bind": "/docker.sock", "mode": "rw"}
            }
        })

        # Should fail at validation, not reach Docker
        assert not result.success
        assert "Docker socket" in result.error

    def test_real_docker_accepts_safe_mount(self, real_docker_client, tmp_path):
        """Test that safe mounts work end-to-end with real Docker."""
        tool = CreateContainerTool(real_docker_client, SafetyConfig())

        # Create a safe temporary directory
        safe_dir = tmp_path / "safe_mount"
        safe_dir.mkdir()
        (safe_dir / "test.txt").write_text("test data")

        # Should succeed
        result = tool.execute({
            "image": "alpine:latest",
            "name": f"test-safe-mount-{uuid.uuid4().hex[:8]}",
            "volumes": {
                str(safe_dir): {"bind": "/data", "mode": "ro"}
            },
            "command": ["cat", "/data/test.txt"]
        })

        assert result.success

        # Cleanup
        try:
            container = real_docker_client.containers.get(result.data["container_id"])
            container.remove(force=True)
        except:
            pass
```

### E2E Tests (Add to existing E2E test files)

```python
def test_e2e_volume_mount_security():
    """Test volume mount security in full MCP protocol flow."""
    # Use stdio transport for E2E test
    # Attempt to create container with dangerous mount via MCP protocol
    # Verify proper error response
```

---

## Documentation Updates Required

### 1. README.md

Add security warning in Features section:

```markdown
### Security Features

- **Volume Mount Validation**: Blocks dangerous host path mounts
  - Prevents mounting root filesystem, Docker socket, /etc, /sys, SSH keys
  - Optional allowlist for permitted paths only
  - Can disable all volume mounts for maximum security
```

### 2. SECURITY.md

Add new section:

```markdown
## Volume Mount Security

Container volume mounts can provide container escape vectors. The server automatically
blocks dangerous paths:

1. **Dangerous Path Blocking**: System paths (/etc, /sys, /proc, /boot, /dev) are blocked
2. **Docker Socket Protection**: /var/run/docker.sock cannot be mounted
3. **SSH Key Protection**: .ssh directories and key files are blocked
4. **Root Filesystem Protection**: / cannot be mounted
5. **Path Traversal Prevention**: Paths are normalized to prevent ../.. attacks

Safe paths like `/home/user/data`, `/tmp/mydata`, `/opt/myapp` are allowed.

### YOLO Mode

If you need to mount dangerous paths (e.g., for testing or development), you can enable YOLO mode:

```bash
export SAFETY_YOLO_MODE=true
```

⚠️  **WARNING**: YOLO mode disables ALL safety checks across the entire server. This is extremely
dangerous and should only be used if you fully understand the security implications. When enabled,
the server will print a prominent warning on startup.

### Filing an Issue

If you think a path we block should be allowed by default, please file an issue explaining your use case.
```

### 3. CONFIGURATION.md

Add YOLO mode documentation:

```markdown
### SAFETY_YOLO_MODE

**Type**: Boolean
**Default**: `false`
**Environment Variable**: `SAFETY_YOLO_MODE`

⚠️  **EXTREMELY DANGEROUS** - Disables ALL safety checks and validation.

When enabled:
- Volume mount validation is bypassed (allows mounting /, /etc, Docker socket, etc.)
- Privileged container checks are bypassed
- Command injection validation is bypassed
- All safety controls are effectively disabled

**Use cases**:
- Testing and development environments where you need full access
- Debugging container issues that require mounting system paths
- Advanced users who fully understand the security implications

**Warning**: The server will print a prominent warning on startup when YOLO mode is enabled.

**Example**:
```bash
export SAFETY_YOLO_MODE=true
```

**Recommendation**: Never use YOLO mode in production or when the server is accessible over a network.
```

### 4. CHANGELOG.md

```markdown
## [1.1.2] - YYYY-MM-DD

### Security
- **CRITICAL**: Fixed volume mount validation bypass (CVE-TBD)
  - `validate_mount_path()` is now called in `CreateContainerTool`
  - Enhanced dangerous path list to include Docker socket, system directories
  - Added path normalization to prevent traversal attacks
  - Blocks: root filesystem, /etc, /sys, /proc, /boot, /dev, /var/run/docker.sock, SSH keys
  - Added `SAFETY_YOLO_MODE` config to bypass all safety checks (use with extreme caution)
```

---

## Edge Cases to Consider

### 1. Symbolic Links
**Issue**: Attacker creates symlink to dangerous path, then mounts the symlink
**Solution**: Consider resolving symlinks with `os.path.realpath()` before validation
**Trade-off**: May break legitimate use cases with symlinks

### 2. Windows Path Formats
**Issue**: Windows paths like `C:\`, `\\?\`, `\\.\pipe\`
**Solution**: Add Windows-specific dangerous paths to the list
**Status**: Partially implemented in proposal

### 3. Case Sensitivity
**Issue**: macOS/Windows are case-insensitive (`/ETC` vs `/etc`)
**Solution**: Normalize paths to lowercase on case-insensitive systems
**Implementation**: Use `str.lower()` on macOS/Windows

### 4. Empty/Null Paths
**Issue**: Empty string or null might bypass checks
**Solution**: Early validation that path is non-empty string
**Implementation**: Add at start of `validate_mount_path()`

### 5. Relative Paths
**Issue**: Docker might resolve relative paths, bypassing validation
**Solution**: Convert to absolute paths before validation
**Implementation**: Use `os.path.abspath()` in normalization

### 6. Unicode/Encoding Issues
**Issue**: Unicode normalization attacks (`/etc` vs `/ⅇtc`)
**Solution**: Normalize unicode before comparison
**Implementation**: Use `unicodedata.normalize('NFC', path)`

### 7. Network Paths (SMB/NFS)
**Issue**: `//network/share` or NFS mounts
**Solution**: Decide policy - block or allow?
**Recommendation**: Block by default, add to allowlist if needed

---

## Implementation Checklist

- [ ] Add YOLO mode config option to `SafetyConfig`
  - [ ] Add `yolo_mode` field with scary warning in description
  - [ ] Add startup warning when YOLO mode is enabled
- [ ] Enhance `validate_mount_path()` in `src/mcp_docker/utils/safety.py`
  - [ ] Add `yolo_mode` parameter
  - [ ] Return early if YOLO mode enabled
  - [ ] Add Docker socket paths
  - [ ] Add system directories (/etc, /sys, /proc, /boot, /dev)
  - [ ] Add /var/lib/docker
  - [ ] Add Windows paths
  - [ ] Add path normalization (resolve .., trailing slashes)
  - [ ] Add symlink resolution (optional, assess trade-offs)
  - [ ] Add unicode normalization
- [ ] Call validation in `CreateContainerTool._validate_inputs()`
  - [ ] Import validate_mount_path
  - [ ] Add volume validation block
  - [ ] Pass `yolo_mode` to validate_mount_path
  - [ ] Validate bind config structure (skip if YOLO)
- [ ] Add YOLO mode tests
  - [ ] Test YOLO mode allows dangerous mounts
  - [ ] Test YOLO mode allows root filesystem
  - [ ] Test startup warning is logged
- [ ] Update tests
  - [ ] Unit tests for enhanced `validate_mount_path()`
  - [ ] Unit tests for `CreateContainerTool` validation
  - [ ] Integration tests with real Docker
  - [ ] E2E tests via MCP protocol
  - [ ] Fuzz tests for path traversal
- [ ] Update documentation
  - [ ] README.md security features
  - [ ] SECURITY.md volume mount section
  - [ ] CONFIGURATION.md new config options
  - [ ] CHANGELOG.md security fix entry
- [ ] Security advisory
  - [ ] Draft CVE if needed
  - [ ] GitHub Security Advisory
  - [ ] Notify existing users

---

## Rollout Strategy

### Phase 1: Implement & Test (Week 1)
1. Implement enhanced `validate_mount_path()`
2. Add call in `CreateContainerTool`
3. Add configuration options
4. Write comprehensive tests
5. Test with existing code to ensure no breaks

### Phase 2: Documentation & Review (Week 1)
1. Update all documentation
2. Internal security review
3. Update CHANGELOG
4. Consider CVE assignment

### Phase 3: Release (Week 2)
1. Release as patch version (1.1.2)
2. Publish security advisory
3. Notify users via GitHub release notes
4. Update PyPI package

### Phase 4: Monitoring (Ongoing)
1. Monitor for user issues
2. Address edge cases discovered
3. Consider additional hardening

---

## Alternative Approaches Considered

### Alternative 1: Add Multiple Config Options for Allowlists/Disable Mounts
**Approach**: Add `SAFETY_ALLOWED_MOUNT_PATHS`, `SAFETY_ALLOW_VOLUME_MOUNTS`, `SAFETY_REQUIRE_READONLY_MOUNTS`
**Pros**: Granular control, users can customize specific behaviors
**Cons**: Too many config options, complexity, configuration burden, users have to understand multiple knobs
**Decision**: **Rejected** - We have enough config options already. Use YOLO mode instead.

### Alternative 2: Warn Instead of Block
**Approach**: Log warning but allow dangerous mounts
**Pros**: Non-breaking, user choice
**Cons**: Defeats security purpose, users ignore warnings
**Decision**: Rejected - insufficient protection

### Alternative 3: Read-Only by Default
**Approach**: Force all mounts to be read-only unless explicitly set
**Pros**: Defense in depth, prevents container writing to host
**Cons**: Breaking change, may break legitimate use cases, needs config option
**Decision**: Rejected - would need config option we don't want

### Alternative 4: Selected Approach - Block Dangerous Paths + YOLO Mode
**Approach**: Enhance validation, block dangerous paths, add single YOLO mode escape hatch
**Pros**: Simple, secure by default, one obvious escape hatch for advanced users
**Cons**: May block legitimate edge cases (but users can use YOLO mode)
**Decision**: **ACCEPTED** - This is what we're implementing

YOLO mode is better than multiple config options because:
- One simple toggle instead of multiple knobs
- Clear name that signals danger ("YOLO" = risky behavior)
- All-or-nothing approach - no confusion about which safety check applies
- Easier to document and support

---

## Questions for Stakeholder (Answered)

1. **Config Options**: Should we add new config options for volume mount control?
   - **Answer**: No multiple config options - just add YOLO mode as a single escape hatch

2. **Breaking Changes**: Is it acceptable to block previously-allowed dangerous mounts?
   - **Answer**: Yes - this is a critical security fix

3. **Symlink Resolution**: Should we resolve symlinks before validation?
   - **Trade-off**: Security vs. legitimate symlink use cases
   - **Recommendation**: Yes - resolve symlinks (assess in implementation)

4. **CVE Assignment**: Should we request a CVE for this vulnerability?
   - **Recommendation**: Yes - it's a critical security bypass

5. **User Communication**: How aggressively should we notify existing users?
   - **Recommendation**: GitHub security advisory + release notes

---

## Success Criteria

- [ ] No dangerous paths can be mounted by default (root, /etc, /sys, Docker socket, SSH keys)
- [ ] Safe paths still work (e.g., /tmp/safe, /home/user/data)
- [ ] YOLO mode allows all dangerous paths when enabled
- [ ] Prominent warning printed on startup when YOLO mode enabled
- [ ] All tests pass (unit, integration, E2E)
- [ ] No false positives on legitimate use cases
- [ ] Performance impact is negligible (<1ms per mount validation)
- [ ] Documentation is clear and comprehensive
- [ ] Security advisory published

---

## Risk Assessment

**Implementation Risk**: LOW
- Small, focused change
- Existing function already tested
- Clear validation logic

**Compatibility Risk**: MEDIUM
- May break existing dangerous mounts (intentional)
- Users may have relied on dangerous behavior
- Mitigation: Clear documentation, config options

**Security Risk if NOT Fixed**: CRITICAL
- Complete host compromise via container escape
- Root access via Docker socket
- Credential theft via SSH key mounts

**Recommendation**: Proceed with implementation immediately. The security risk of NOT fixing far outweighs compatibility concerns.
