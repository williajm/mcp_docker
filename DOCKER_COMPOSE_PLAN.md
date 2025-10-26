# Docker Compose Support Implementation Plan

## Overview
Add Docker Compose functionality to MCP Docker Server, enabling multi-container application management through the MCP protocol.

## Technical Context
**Important**: The official Docker SDK for Python (docker-py) does NOT support Docker Compose v2. Compose v2 is written in Go, while v1 (deprecated) was Python. We have two implementation approaches:

### Option A: Subprocess Approach (Recommended)
- Use subprocess to call `docker compose` CLI commands
- Most reliable, uses official Docker Compose v2
- No additional dependencies
- Consistent with how many production systems handle compose

### Option B: Python-on-whales Library
- Third-party library that wraps docker compose CLI
- Provides Pythonic interface
- Additional dependency to maintain
- May lag behind official compose features

## Python Version Support
Following Python's official support timeline:
- **Minimum**: Python 3.11 (current requirement, supported until Oct 2027)
- **Recommended**: Also test with Python 3.12 (supported until Oct 2028)
- **Future**: Consider Python 3.13 compatibility (supported until Oct 2029)

## Phase 1: Core Infrastructure

### 1.1 Compose Client Wrapper
- [ ] Create `src/mcp_docker/compose_wrapper/client.py`
  - Wrapper around subprocess calls to `docker compose` CLI
  - Verify `docker compose version` works (v2 detection)
  - Command execution with timeout and error handling
  - Output parsing (JSON format where available)
  - Lazy initialization pattern (match existing Docker client)
  - Proper shell escaping and command sanitization

### 1.2 Base Compose Tool
- [ ] Create `src/mcp_docker/tools/compose_base.py`
  - Abstract base class for Compose operations
  - Inherit from existing `BaseTool`
  - Add compose-specific validation

## Phase 2: Essential Compose Tools

### 2.1 Project Management Tools
- [ ] `ComposeUpTool` - Start services defined in compose file
- [ ] `ComposeDownTool` - Stop and remove services
- [ ] `ComposeRestartTool` - Restart services
- [ ] `ComposeStopTool` - Stop services without removing

### 2.2 Service Management Tools
- [ ] `ComposeScaleTool` - Scale services to N instances
- [ ] `ComposePsTool` - List services and their status
- [ ] `ComposeLogsTool` - Get logs from compose services
- [ ] `ComposeExecTool` - Execute commands in service containers

### 2.3 Configuration Tools
- [ ] `ComposeValidateTool` - Validate compose file syntax
- [ ] `ComposeConfigTool` - View resolved configuration
- [ ] `ComposeBuildTool` - Build or rebuild services

## Phase 3: Safety & Validation

### 3.1 Compose-Specific Safety
- [ ] Add compose operations to `src/mcp_docker/utils/safety.py`
  - Classify operations (SAFE/MODERATE/DESTRUCTIVE)
  - Validate compose file paths (prevent directory traversal)
  - Network isolation checks

### 3.2 Input Validation
- [ ] Create `src/mcp_docker/utils/compose_validation.py`
  - Validate compose file format
  - Service name validation
  - Environment variable sanitization
  - Volume mount safety checks

## Phase 4: Testing

### 4.1 Unit Tests
- [ ] `tests/unit/test_compose_wrapper.py` - Client wrapper tests
- [ ] `tests/unit/test_compose_tools.py` - Individual tool tests
- [ ] `tests/unit/test_compose_validation.py` - Validation logic tests
- [ ] Mock all docker-compose SDK calls
- [ ] Achieve 95%+ coverage for new code

### 4.2 Integration Tests
- [ ] `tests/integration/test_compose_operations.py`
  - Test with sample compose files in `tests/fixtures/compose/`
  - Multi-container orchestration tests
  - Network connectivity tests
  - Volume sharing tests
  - Clean up all test resources

### 4.3 Test Fixtures
- [ ] Create sample compose files:
  - Simple web + db stack
  - Complex microservices setup
  - Invalid/malformed files for error testing

## Phase 5: Documentation & Resources

### 5.1 MCP Resources
- [ ] Add compose project resources to `src/mcp_docker/resources/providers.py`
  - `docker://compose/projects/{name}/config` - Project configuration
  - `docker://compose/projects/{name}/services` - Service list
  - `docker://compose/projects/{name}/logs` - Aggregated logs

### 5.2 Prompts
- [ ] Add compose prompts to `src/mcp_docker/prompts/templates.py`
  - `debug_compose_stack` - Troubleshoot compose issues
  - `optimize_compose_config` - Suggest improvements
  - `convert_to_compose` - Convert running containers to compose

### 5.3 Documentation
- [ ] Update `docs/API.md` with compose tools
- [ ] Add compose examples to `docs/EXAMPLES.md`
- [ ] Update README with compose capabilities

## Claude Code Integration Opportunities

### Development Assistance
- **Tool Generation**: Use Claude to generate boilerplate for each compose tool class
- **Test Creation**: Leverage Claude for comprehensive test case generation
- **Documentation**: Auto-generate docstrings and API documentation
- **Error Handling**: Analyze compose error outputs and suggest fixes
- **Code Review**: Review implementation for safety and best practices

### Implementation Patterns
- **Template Generation**: Create consistent tool class templates
- **Validation Logic**: Generate input validation functions
- **Mock Creation**: Generate test mocks for subprocess calls
- **Example Scripts**: Create usage examples for documentation

## Implementation Guidelines

### Code Quality Standards
- **Type hints**: All functions must have complete type annotations
- **Docstrings**: Google-style for all public methods
- **Error handling**: Consistent with existing patterns (ToolResult)
- **Async/await**: Prepare for future async docker-compose SDK

### Testing Requirements
- **Unit tests**: Mock all external dependencies
- **Integration tests**: Real Docker daemon required
- **Coverage**: Maintain 95%+ for new code
- **CI/CD**: All tests must pass in GitHub Actions

### Linting & Formatting
- **Ruff**: No violations (configured in pyproject.toml)
- **MyPy**: Strict mode, no implicit Any
- **Pre-commit**: All hooks must pass

### Safety Considerations
- Compose operations can affect multiple containers
- Network creation/deletion impacts isolation
- Volume operations may expose host filesystem
- Environment variables may contain secrets
- **Subprocess Security**: Sanitize all inputs to prevent command injection
- **File Path Validation**: Ensure compose files are within allowed directories
- **YAML Parsing**: Validate compose file content before execution

## Rollout Strategy

1. **MVP Release (Phases 1-2)**
   - Basic compose functionality
   - Essential operations only
   - Mark as experimental in v2.0.0

2. **Stable Release (Phases 3-5)**
   - Full safety validations
   - Complete test coverage
   - Production-ready in v2.1.0

3. **Future Enhancements**
   - Stack deployment (Docker Swarm)
   - Kubernetes compose support
   - Compose file generation from running containers

## Success Metrics
- [ ] All compose tools inherit from BaseTool
- [ ] 95%+ test coverage for new code
- [ ] Zero linting violations
- [ ] All safety checks enforced
- [ ] Documentation complete
- [ ] Integration tests pass on CI/CD

---

*This plan prioritizes clean, maintainable code with comprehensive testing and safety controls, following the existing patterns in the MCP Docker codebase.*