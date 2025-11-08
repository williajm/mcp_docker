# Fuzzing with ClusterFuzzLite

This document describes the fuzzing setup for MCP Docker using Google's ClusterFuzzLite.

## Overview

MCP Docker uses [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) for continuous fuzzing to improve security and robustness. Fuzzing automatically tests critical components with random inputs to discover:

- Security vulnerabilities (buffer overflows, injection attacks, etc.)
- Crashes and edge cases
- Input validation issues
- Parsing errors

This setup meets the [OpenSSF Scorecard fuzzing requirements](https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing).

## Fuzz Test Targets

We currently have **4 fuzz test harnesses** targeting critical security-sensitive components:

### 1. SSH Authentication (`fuzz_ssh_auth.py`)

Tests SSH signature verification and authentication parsing:
- SSH wire format parsing (`SSHWireMessage`)
- Ed25519/RSA/ECDSA signature verification
- Base64 decoding of signatures
- Authentication request construction

**Why critical**: SSH auth is the primary authentication mechanism and handles untrusted input from clients.

### 2. Input Validation (`fuzz_validation.py`)

Tests Docker name and parameter validation:
- Container name validation
- Image name validation
- Port number validation
- Memory string parsing
- Label key/value validation
- Special character handling

**Why critical**: Input validation is the first line of defense against injection attacks and malformed requests.

### 3. Command Sanitization (`fuzz_safety.py`)

Tests safety checks and dangerous command detection:
- Command sanitization (string and list formats)
- Dangerous pattern detection (rm -rf, fork bombs, etc.)
- Mount path validation (prevents sensitive file access)
- Port binding validation
- Privileged container checks
- Path traversal detection

**Why critical**: Command sanitization prevents arbitrary code execution and protects the host system.

### 4. JSON Parsing (`fuzz_json_parsing.py`)

Tests JSON parsing utilities:
- Generic JSON parsing
- Docker stats JSON parsing
- Deeply nested structures
- Special JSON values (null, large numbers, Unicode)
- Unicode handling

**Why critical**: JSON parsing is used throughout the codebase for Docker API responses and configuration.

## Running Fuzz Tests Locally

### Prerequisites

Install Atheris (Google's Python fuzzing engine):

```bash
uv sync --all-extras  # Includes atheris in dev dependencies
```

### Running Individual Fuzzers

```bash
# Run SSH auth fuzzer for 10,000 iterations
python3 tests/fuzz/fuzz_ssh_auth.py -atheris_runs=10000

# Run validation fuzzer for 1 hour
python3 tests/fuzz/fuzz_validation.py -atheris_runs=3600

# Run safety fuzzer with coverage
python3 tests/fuzz/fuzz_safety.py -atheris_runs=10000

# Run JSON parsing fuzzer
python3 tests/fuzz/fuzz_json_parsing.py -atheris_runs=10000
```

### Atheris Command-Line Options

```bash
# Run for specific number of iterations
-atheris_runs=N

# Run for specific time (seconds)
-max_total_time=N

# Use specific seed for reproducibility
-seed=N

# Show more verbose output
-verbosity=2

# Save failing inputs to a directory
-artifact_prefix=./crashes/
```

## CI/CD Integration

ClusterFuzzLite runs automatically in GitHub Actions with three modes:

### 1. PR Fuzzing (Pull Requests)

- Runs for **5 minutes** on every PR
- Uses **code-change mode** to focus on modified code
- Reports findings as GitHub Security alerts (SARIF)
- Sanitizers: address

### 2. Batch Fuzzing (Main Branch & Scheduled)

- Runs for **1 hour** weekly (Mondays at 2 AM UTC) and on main branch pushes
- Uses **batch mode** for comprehensive testing
- Sanitizers: address, undefined
- Builds corpus of test cases over time

### 3. Coverage Tracking (Main Branch & Scheduled)

- Runs for **10 minutes** weekly to measure code coverage
- Helps identify untested code paths
- Uses **coverage sanitizer**

## Workflow Configuration

The fuzzing workflow is defined in `.github/workflows/cflite.yml`:

```yaml
# Trigger on PRs, main branch, and daily schedule
on:
  pull_request:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Mondays at 2 AM UTC
```

## Configuration Files

### `.clusterfuzzlite/Dockerfile`

Defines the build environment:
- Based on `gcr.io/oss-fuzz-base/base-builder-python`
- Installs project dependencies
- Includes Atheris for fuzzing

### `.clusterfuzzlite/build.sh`

Build script that compiles fuzz targets:
- Installs the project in development mode
- Compiles each `fuzz_*.py` file as a standalone fuzzer
- Uses PyInstaller for better compatibility

### `.clusterfuzzlite/project.yaml`

Project metadata for ClusterFuzzLite:
- Language: Python
- Sanitizers: address, undefined
- Fuzzing engine: libfuzzer

## Writing New Fuzz Tests

To add a new fuzz test:

1. **Create a new file** in `tests/fuzz/` named `fuzz_<component>.py`

2. **Import Atheris** and your component:
```python
import sys
import atheris

with atheris.instrument_imports():
    from mcp_docker.your_module import your_function
```

3. **Write test functions** that exercise your component:
```python
def fuzz_your_component(data: bytes) -> None:
    """Fuzz test for your component."""
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)
    test_input = fdp.ConsumeUnicodeNoSurrogates(100)

    try:
        result = your_function(test_input)
        # Verify result if needed
        assert isinstance(result, expected_type)
    except (ValueError, YourExpectedException):
        # Expected errors are OK
        pass
```

4. **Add main entry point**:
```python
def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point."""
    fuzz_your_component(data)

def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

5. **Test locally**:
```bash
python3 tests/fuzz/fuzz_your_component.py -atheris_runs=1000
```

6. The fuzzer will be **automatically discovered** by ClusterFuzzLite's build script.

## Best Practices

### Do:
- ✅ Test components that handle external input
- ✅ Focus on security-critical code paths
- ✅ Catch and ignore expected exceptions
- ✅ Use `FuzzedDataProvider` for structured input generation
- ✅ Add early returns for insufficient input (`if len(data) < N: return`)
- ✅ Assert invariants to catch unexpected behavior

### Don't:
- ❌ Test pure business logic (use unit tests instead)
- ❌ Allow uncaught exceptions (indicates potential bugs)
- ❌ Perform slow operations (fuzzing should be fast)
- ❌ Use real Docker operations (use mocks in fuzz tests)
- ❌ Ignore sanitizer warnings

## Interpreting Results

### Clean Run
```
#1000    pulse  cov: 234 ft: 456 corp: 12/234Kb exec/s: 100
```
- `cov`: Code coverage (higher is better)
- `ft`: Features covered
- `corp`: Corpus size (test cases)
- `exec/s`: Executions per second

### Finding a Bug
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
```

ClusterFuzzLite will:
1. Create a GitHub Security alert (SARIF)
2. Save the failing input as an artifact
3. Report the issue on the PR or main branch

## Debugging Crashes

If a fuzzer finds a crash:

1. **Download the failing input** from GitHub Actions artifacts

2. **Reproduce locally**:
```bash
python3 tests/fuzz/fuzz_component.py failing_input_file
```

3. **Debug with GDB** (if needed):
```bash
gdb --args python3 tests/fuzz/fuzz_component.py failing_input_file
```

4. **Fix the bug** and verify:
```bash
# Run with the same input - should not crash
python3 tests/fuzz/fuzz_component.py failing_input_file

# Run extended fuzzing to ensure fix
python3 tests/fuzz/fuzz_component.py -atheris_runs=100000
```

## Monitoring and Metrics

### GitHub Actions

View fuzzing results in:
- **Actions tab** → ClusterFuzzLite workflow
- **Security tab** → Code scanning alerts

### Coverage Reports

Coverage reports are generated for each run and available as artifacts.

## Resources

- [ClusterFuzzLite Documentation](https://google.github.io/clusterfuzzlite/)
- [Atheris Documentation](https://github.com/google/atheris)
- [OpenSSF Scorecard Fuzzing Check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing)
- [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)

## Frequently Asked Questions

### Q: Why use ClusterFuzzLite instead of OSS-Fuzz?

**A:** ClusterFuzzLite is designed for continuous fuzzing in CI/CD without requiring acceptance into OSS-Fuzz. It provides:
- Faster integration (no application process)
- Full control over configuration
- Integration with GitHub Security alerts
- Suitable for private repositories

### Q: How long does fuzzing take?

**A:**
- PR fuzzing: 5 minutes per PR
- Batch fuzzing: 1 hour weekly (Mondays)
- Coverage: 10 minutes weekly (Mondays)
- Total CI time impact: ~5 minutes per PR

### Q: What if fuzzing finds a security vulnerability?

**A:**
1. GitHub will create a Security Alert
2. The PR will show a failing check
3. Fix the vulnerability before merging
4. Add a regression test

### Q: Can I run fuzzing locally?

**A:** Yes! Install Atheris and run any fuzzer:
```bash
uv sync --all-extras
python3 tests/fuzz/fuzz_ssh_auth.py -atheris_runs=10000
```

### Q: How do I exclude false positives?

**A:** Update the fuzzer to catch and ignore the exception:
```python
try:
    result = your_function(input)
except KnownFalsePositiveError:
    pass  # Expected error, not a bug
```

---

**Last Updated:** 2025-01-08
**Maintained By:** MCP Docker Project
**License:** MIT
