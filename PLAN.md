# MCP Docker Server Development Plan

## Overview
Build a Model Context Protocol (MCP) server in Python that exposes Docker functionality as tools, resources, and prompts, enabling AI assistants to interact with Docker containers, images, networks, and volumes locally.

## Architecture & Technology Stack

### Core Technologies
- **Runtime**: Python 3.11+
- **Package Manager**: `uv` (fast, modern Python package manager)
- **MCP SDK**: `mcp` (official Python SDK from Anthropic)
- **Docker Integration**: `docker` (official Docker SDK for Python)
- **Testing**: `pytest` + `pytest-asyncio` + `pytest-docker` + `pytest-cov`
- **Code Quality**: `ruff` (linting + formatting), `mypy` (type checking)
- **Validation**: `pydantic` v2 (schema validation)
- **Logging**: `loguru` (structured logging)

### Project Structure
```
mcp_docker/
├── src/
│   └── mcp_docker/
│       ├── __init__.py
│       ├── __main__.py              # Entry point
│       ├── server.py                # MCP server setup
│       ├── config.py                # Configuration management
│       ├── docker/
│       │   ├── __init__.py
│       │   ├── client.py            # Docker client wrapper
│       │   ├── containers.py        # Container operations
│       │   ├── images.py            # Image operations
│       │   ├── networks.py          # Network operations
│       │   ├── volumes.py           # Volume operations
│       │   └── types.py             # Type definitions
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── base.py              # Base tool class
│       │   ├── container_tools.py   # Container management
│       │   ├── image_tools.py       # Image management
│       │   ├── network_tools.py     # Network management
│       │   ├── volume_tools.py      # Volume management
│       │   └── system_tools.py      # System operations
│       ├── resources/
│       │   ├── __init__.py
│       │   └── providers.py         # Resource providers
│       ├── prompts/
│       │   ├── __init__.py
│       │   └── templates.py         # Prompt templates
│       └── utils/
│           ├── __init__.py
│           ├── validation.py        # Input validation (Pydantic)
│           ├── errors.py            # Custom exceptions
│           └── logger.py            # Structured logging
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_containers.py
│   │   ├── test_images.py
│   │   ├── test_networks.py
│   │   ├── test_volumes.py
│   │   └── test_validation.py
│   ├── integration/
│   │   ├── __init__.py
│   │   ├── test_container_lifecycle.py
│   │   ├── test_image_operations.py
│   │   ├── test_network_operations.py
│   │   └── test_mcp_server.py
│   ├── fixtures/
│   │   ├── __init__.py
│   │   └── docker_fixtures.py
│   └── conftest.py                  # Pytest configuration
├── docs/
│   ├── API.md                       # Tool/resource reference
│   ├── SETUP.md                     # Installation guide
│   ├── EXAMPLES.md                  # Usage examples
│   └── ARCHITECTURE.md              # Design decisions
├── .github/
│   └── workflows/
│       ├── ci.yml                   # CI/CD pipeline
│       └── release.yml              # Automated releases
├── pyproject.toml                   # uv/ruff/pytest config
├── uv.lock                          # Lock file
├── Dockerfile                       # Multi-stage build
├── docker-compose.yml               # Dev environment
├── .dockerignore
├── .gitignore
├── .python-version                  # 3.11
├── README.md
└── LICENSE
```

## Phase 1: Foundation & Project Setup

### Goals
- Initialize project with uv
- Configure development tools (ruff, mypy, pytest)
- Set up Docker client wrapper
- Establish base architecture

### Tasks

#### 1.1 Initialize Project with uv
```bash
# Initialize uv project
uv init

# Set Python version
echo "3.11" > .python-version

# Create project structure
mkdir -p src/mcp_docker/{docker,tools,resources,prompts,utils}
mkdir -p tests/{unit,integration,fixtures}
mkdir -p docs
```

#### 1.2 Configure `pyproject.toml`
Complete configuration for uv, ruff, mypy, and pytest with all dependencies and development tools.

#### 1.3 Install Dependencies
```bash
# Install all dependencies
uv sync
```

#### 1.4 Create Docker Client Wrapper
Implement `src/mcp_docker/docker/client.py` with:
- Lazy initialization
- Health checking
- Connection management
- Error handling

#### 1.5 Create Base Tool Architecture
Implement `src/mcp_docker/tools/base.py` with:
- `BaseTool` abstract class
- `ToolInput` base model
- `ToolOutput` base model
- MCP tool conversion

#### 1.6 Create Custom Errors
Implement `src/mcp_docker/utils/errors.py` with exception hierarchy:
- `MCPDockerError` (base)
- `DockerDaemonUnavailable`
- `ContainerNotFound`
- `ImageNotFound`
- `NetworkNotFound`
- `VolumeNotFound`
- `OperationTimeout`
- `ValidationError`
- `UnsafeOperation`

#### 1.7 Configure Logging
Implement `src/mcp_docker/utils/logger.py` with loguru configuration for structured logging.

#### 1.8 Create `.gitignore`
Python, uv, IDE, and testing artifacts.

#### 1.9 Create `.dockerignore`
Exclude development files from Docker builds.

### Deliverables
- ✓ Project initialized with uv
- ✓ Development tools configured (ruff, mypy, pytest)
- ✓ Docker client wrapper implemented
- ✓ Base tool architecture established
- ✓ Custom error classes defined
- ✓ Logging configured
- ✓ Project structure created

---

## Phase 2: Core Container Tools

### Goals
- Implement all container management tools
- Add comprehensive input validation
- Create unit tests for container tools

### Tool List (10 tools)
1. `docker_list_containers` - List containers with filters
2. `docker_inspect_container` - Get detailed container info
3. `docker_create_container` - Create new container
4. `docker_start_container` - Start container
5. `docker_stop_container` - Stop container (graceful + timeout)
6. `docker_restart_container` - Restart container
7. `docker_remove_container` - Remove container
8. `docker_container_logs` - Get container logs
9. `docker_exec_command` - Execute command in container
10. `docker_container_stats` - Get resource usage stats

### Implementation
Create `src/mcp_docker/tools/container_tools.py` with all 10 tools implementing:
- Pydantic input schemas
- Docker API integration
- Error handling
- Structured output

### Unit Tests
Create `tests/unit/test_containers.py` with:
- Mock-based unit tests
- Input validation tests
- Error condition tests
- 90%+ coverage target

### Deliverables
- ✓ 10 container tools implemented
- ✓ Input validation with Pydantic
- ✓ Comprehensive error handling
- ✓ Unit tests with 90%+ coverage
- ✓ Documentation strings

---

## Phase 3: Image, Network, and Volume Tools

### Goals
- Implement image management tools (9 tools)
- Implement network management tools (6 tools)
- Implement volume management tools (5 tools)
- Add unit tests for all tools

### Image Tools (9 tools)
1. `docker_list_images` - List images
2. `docker_inspect_image` - Get image details
3. `docker_pull_image` - Pull from registry
4. `docker_build_image` - Build from Dockerfile
5. `docker_push_image` - Push to registry
6. `docker_tag_image` - Tag image
7. `docker_remove_image` - Remove image
8. `docker_prune_images` - Clean unused images
9. `docker_image_history` - View layer history

### Network Tools (6 tools)
10. `docker_list_networks` - List networks
11. `docker_inspect_network` - Get network details
12. `docker_create_network` - Create network
13. `docker_connect_container` - Connect container to network
14. `docker_disconnect_container` - Disconnect from network
15. `docker_remove_network` - Remove network

### Volume Tools (5 tools)
16. `docker_list_volumes` - List volumes
17. `docker_inspect_volume` - Get volume details
18. `docker_create_volume` - Create volume
19. `docker_remove_volume` - Remove volume
20. `docker_prune_volumes` - Clean unused volumes

### Implementation Structure
Create:
- `src/mcp_docker/tools/image_tools.py`
- `src/mcp_docker/tools/network_tools.py`
- `src/mcp_docker/tools/volume_tools.py`

With corresponding test files:
- `tests/unit/test_images.py`
- `tests/unit/test_networks.py`
- `tests/unit/test_volumes.py`

### Deliverables
- ✓ 20 additional tools implemented
- ✓ Input validation for all tools
- ✓ Unit tests for all tools
- ✓ Error handling

---

## Phase 4: System Tools & MCP Server

### Goals
- Implement system-level Docker tools
- Create MCP server with tool registration
- Implement server lifecycle management
- Add configuration management

### System Tools (7 tools)
1. `docker_system_info` - Get Docker system information
2. `docker_system_df` - Disk usage statistics
3. `docker_system_prune` - Clean all unused resources
4. `docker_version` - Get Docker version info
5. `docker_events` - Stream Docker events
6. `docker_healthcheck` - Check Docker daemon health
7. `docker_compose_operations` - Basic compose operations

### MCP Server Implementation
Create `src/mcp_docker/server.py`:
- `MCPDockerServer` class
- Tool registration system
- MCP protocol handlers (list_tools, call_tool)
- Server lifecycle management
- Stdio transport integration

### Configuration Management
Create `src/mcp_docker/config.py`:
- Pydantic Settings for configuration
- Environment variable support
- Default values
- Validation

### Entry Point
Create `src/mcp_docker/__main__.py`:
- Main entry point
- Settings initialization
- Logging setup
- Server execution
- Graceful shutdown

### Deliverables
- ✓ 7 system tools implemented
- ✓ MCP server with tool registration
- ✓ Configuration management
- ✓ Server lifecycle management
- ✓ Entry point

---

## Phase 5: Resources, Prompts, and Safety

### Goals
- Implement MCP resources (logs, stats)
- Create prompt templates
- Add safety controls and validation
- Implement command sanitization

### Resources Implementation
Create `src/mcp_docker/resources/providers.py`:
- Container logs as resources
- Container stats as resources
- Resource listing
- Resource reading
- URI-based access

### Prompts Implementation
Create `src/mcp_docker/prompts/templates.py`:
- `troubleshoot_container` - Diagnose container issues
- `optimize_container` - Suggest optimizations
- `generate_compose` - Generate docker-compose.yml
- Prompt registration
- Argument handling

### Safety Controls
Create `src/mcp_docker/utils/safety.py`:
- Operation level classification (safe/moderate/destructive)
- Destructive operations set
- Operation validation
- Privileged mode controls
- Command sanitization
- Dangerous pattern detection

### Enhanced Validation
Create `src/mcp_docker/utils/validation.py`:
- `ContainerNameValidator`
- `ImageNameValidator`
- `PortValidator`
- `MemoryValidator`
- Input sanitization

### Deliverables
- ✓ Resource providers (logs, stats)
- ✓ Prompt templates (3 prompts)
- ✓ Safety controls
- ✓ Enhanced validation
- ✓ Command sanitization

---

## Phase 6: Comprehensive Testing

### Goals
- Achieve 90%+ test coverage
- Integration tests with real Docker
- E2E tests for MCP protocol
- Performance benchmarks

### Test Configuration
Create `tests/conftest.py`:
- Docker client fixture
- Test container fixture
- Test image fixture
- Test network fixture
- Test volume fixture
- Mock fixtures
- Settings fixture

### Unit Tests
Comprehensive unit tests for all components:
- `tests/unit/test_container_tools.py`
- `tests/unit/test_image_tools.py`
- `tests/unit/test_network_tools.py`
- `tests/unit/test_volume_tools.py`
- `tests/unit/test_system_tools.py`
- `tests/unit/test_validation.py`
- `tests/unit/test_safety.py`

### Integration Tests
Real Docker integration tests:
- `tests/integration/test_container_lifecycle.py`
- `tests/integration/test_image_operations.py`
- `tests/integration/test_network_operations.py`
- `tests/integration/test_volume_operations.py`
- `tests/integration/test_mcp_server.py`

### Performance Tests
Create `tests/performance/test_benchmarks.py`:
- Tool execution benchmarks
- Response time validation
- Resource usage monitoring

### Coverage Target
```bash
# Run tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html --cov-report=term

# Coverage should be 90%+
```

### Deliverables
- ✓ Unit tests (90%+ coverage)
- ✓ Integration tests (Docker operations)
- ✓ E2E tests (MCP server)
- ✓ Performance benchmarks
- ✓ Test fixtures and utilities

---

## Phase 7: Documentation

### Goals
- Comprehensive README
- API reference documentation
- Setup and configuration guide
- Usage examples
- Architecture documentation

### Documentation Files

#### README.md
Main project documentation:
- Project overview
- Features list
- Quick start guide
- Installation instructions
- Configuration examples
- Tool categories
- Development setup
- Requirements
- License and contributing

#### docs/API.md
Complete API reference:
- All 37 tools documented
- Input schemas with examples
- Output schemas with examples
- Error codes and meanings
- Usage notes

#### docs/SETUP.md
Installation and setup guide:
- Prerequisites
- Installation options (uvx, uv, pip, source)
- Claude Desktop configuration
- Environment variables
- Troubleshooting common issues
- Platform-specific notes

#### docs/EXAMPLES.md
Practical usage examples:
- Container health checks
- Application deployment
- Resource cleanup
- Troubleshooting workflows
- Multi-container applications
- Docker Compose generation

#### docs/ARCHITECTURE.md
Design and architecture:
- Component overview
- Design principles
- Type safety approach
- Error handling strategy
- Testing philosophy
- Security considerations
- Future enhancements

### Deliverables
- ✓ Comprehensive README
- ✓ API reference (37 tools)
- ✓ Setup guide
- ✓ Usage examples
- ✓ Architecture documentation

---

## Phase 8: CI/CD, Docker, and Release

### Goals
- GitHub Actions CI/CD pipeline
- Dockerfile for containerized deployment
- PyPI package preparation
- Release automation

### GitHub Actions Workflows

#### `.github/workflows/ci.yml`
Continuous Integration:
- Python version matrix (3.11, 3.12)
- Dependency installation with uv
- Ruff linting and formatting
- mypy type checking
- Unit tests with coverage
- Integration tests
- Coverage upload to Codecov
- Package building
- Docker image building

#### `.github/workflows/release.yml`
Release automation:
- Triggered on version tags
- Package building
- PyPI publishing
- GitHub release creation
- Artifact uploads

### Docker Configuration

#### Dockerfile
Multi-stage build:
- Builder stage with uv
- Production stage with minimal image
- Non-root user (mcpuser)
- Health check
- Optimized layers

#### docker-compose.yml
Development environment:
- Docker socket mounting
- Source code mounting
- Environment configuration
- Interactive mode

### Package Distribution

#### PyPI Metadata
Additional metadata in `pyproject.toml`:
- Homepage URL
- Documentation URL
- Repository URL
- Issues URL
- Changelog URL

#### Release Checklist
Create `RELEASE_CHECKLIST.md`:
- Pre-release checks
- Release process
- Post-release tasks

### Deliverables
- ✓ CI/CD pipeline (GitHub Actions)
- ✓ Dockerfile (multi-stage)
- ✓ docker-compose.yml
- ✓ Release automation
- ✓ PyPI publishing
- ✓ Package distribution

---

## Tool Summary

### All 37 Tools by Category

#### Container Management (10 tools)
1. `docker_list_containers`
2. `docker_inspect_container`
3. `docker_create_container`
4. `docker_start_container`
5. `docker_stop_container`
6. `docker_restart_container`
7. `docker_remove_container`
8. `docker_container_logs`
9. `docker_exec_command`
10. `docker_container_stats`

#### Image Management (9 tools)
11. `docker_list_images`
12. `docker_inspect_image`
13. `docker_pull_image`
14. `docker_build_image`
15. `docker_push_image`
16. `docker_tag_image`
17. `docker_remove_image`
18. `docker_prune_images`
19. `docker_image_history`

#### Network Management (6 tools)
20. `docker_list_networks`
21. `docker_inspect_network`
22. `docker_create_network`
23. `docker_connect_container`
24. `docker_disconnect_container`
25. `docker_remove_network`

#### Volume Management (5 tools)
26. `docker_list_volumes`
27. `docker_inspect_volume`
28. `docker_create_volume`
29. `docker_remove_volume`
30. `docker_prune_volumes`

#### System Tools (7 tools)
31. `docker_system_info`
32. `docker_system_df`
33. `docker_system_prune`
34. `docker_version`
35. `docker_events`
36. `docker_healthcheck`
37. `docker_compose_operations`

---

## Key Design Principles

### 1. Type Safety
- Python 3.11+ with full type hints
- Pydantic for runtime validation
- mypy strict mode for static type checking
- No `Any` types in public APIs

### 2. Error Handling
- Custom exception hierarchy
- Structured error responses with codes
- Actionable error messages
- Graceful degradation

### 3. Testing
- 90%+ code coverage target
- Unit tests with mocks
- Integration tests with real Docker
- E2E tests for MCP protocol
- Performance benchmarks

### 4. Safety
- Input validation with Pydantic
- Command sanitization
- Operation classification (safe/moderate/destructive)
- Privileged mode controls
- Confirmation for destructive operations

### 5. Performance
- Lazy initialization
- Streaming for large outputs
- Connection reuse
- Async-first design
- Target: <2s response time for most operations

### 6. Code Quality
- Ruff for linting and formatting
- Pre-commit hooks
- Consistent code style
- Comprehensive documentation
- Clean architecture

### 7. Developer Experience
- Clear error messages
- Extensive documentation
- Usage examples
- Simple installation (uvx)
- Easy configuration

---

## Success Criteria

### Functionality
- ✓ All 37 Docker operations working as MCP tools
- ✓ Resources for logs and stats
- ✓ 3 useful prompt templates
- ✓ Successfully integrates with Claude Desktop

### Code Quality
- ✓ 90%+ test coverage with pytest
- ✓ Type checking passes with mypy --strict
- ✓ Linting passes with ruff
- ✓ No security vulnerabilities

### Documentation
- ✓ Comprehensive README
- ✓ Complete API reference
- ✓ Setup guide with troubleshooting
- ✓ Practical usage examples
- ✓ Architecture documentation

### Production Readiness
- ✓ CI/CD pipeline functional
- ✓ Automated testing in CI
- ✓ Docker image available
- ✓ Published to PyPI
- ✓ Release automation working

### Performance
- ✓ <2s response time for most operations
- ✓ Handles concurrent requests
- ✓ Efficient resource usage
- ✓ No memory leaks

### Security
- ✓ Input validation comprehensive
- ✓ Command injection prevention
- ✓ Safe default configuration
- ✓ Privileged mode controls
- ✓ Security review passed

---

## Technology Justification

### Why Python?
- **Docker SDK**: Mature `docker` library with excellent documentation
- **MCP SDK**: Official Python SDK with FastMCP support
- **Type Safety**: Pydantic for runtime validation + mypy for static checking
- **Testing**: Pytest ecosystem is exceptional for async testing
- **Async**: Native async/await, perfect for I/O-bound Docker operations
- **Community**: Large Docker + Python community for support

### Why uv?
- **Speed**: 10-100x faster than pip
- **Modern**: Built with Rust, designed for 2025+
- **Simple**: Single tool for dependencies and scripts
- **Reliable**: Lock files ensure reproducible builds
- **Compatible**: Works with existing Python ecosystem

### Why ruff?
- **Speed**: 10-100x faster than traditional linters
- **Comprehensive**: Replaces flake8, isort, black, and more
- **Modern**: Built with Rust, actively maintained
- **Configurable**: Extensive rule selection
- **Integrated**: Linting + formatting in one tool

### Why pytest?
- **Standard**: De facto standard for Python testing
- **Powerful**: Fixtures, parametrization, markers
- **Async Support**: pytest-asyncio for async tests
- **Plugins**: Rich ecosystem (pytest-cov, pytest-docker, etc.)
- **Clear**: Excellent error reporting

### Why Pydantic?
- **Validation**: Runtime data validation with type hints
- **Serialization**: JSON schema generation
- **Performance**: Fast validation with Rust core
- **Integration**: Works seamlessly with type checkers
- **Documentation**: Self-documenting schemas

---

## Implementation Timeline

### Estimated Effort by Phase

**Phase 1: Foundation** (1-2 days)
- Project setup
- Base architecture
- Development tools

**Phase 2: Container Tools** (2-3 days)
- 10 container tools
- Unit tests
- Documentation

**Phase 3: Extended Tools** (3-4 days)
- 20 image/network/volume tools
- Unit tests
- Documentation

**Phase 4: System & Server** (2-3 days)
- 7 system tools
- MCP server implementation
- Configuration

**Phase 5: Safety & Features** (2-3 days)
- Resources and prompts
- Safety controls
- Validation

**Phase 6: Testing** (2-3 days)
- Integration tests
- E2E tests
- Performance tests
- Coverage improvement

**Phase 7: Documentation** (1-2 days)
- README
- API reference
- Setup guide
- Examples

**Phase 8: Production** (1-2 days)
- CI/CD pipeline
- Docker configuration
- Release preparation

**Total: 14-22 days** (2-4 weeks for full implementation)

---

## Next Steps

1. **Initialize Project**: Start with Phase 1 to set up the foundation
2. **Iterative Development**: Complete each phase sequentially
3. **Continuous Testing**: Write tests alongside implementation
4. **Documentation**: Document as you build
5. **Review**: Code review after each phase
6. **Release**: Deploy v1.0.0 after Phase 8

---

## Maintenance Plan

### Post-Release
- Monitor GitHub issues
- Respond to bug reports
- Update dependencies monthly
- Security patches as needed

### Future Enhancements
- Docker Compose full support
- Docker Swarm operations
- Remote Docker host support
- Enhanced streaming (build/pull progress)
- WebSocket transport option
- Metrics and monitoring
- Docker Scout integration
- Kubernetes support (future consideration)

---

## Contributing Guidelines

### Code Standards
- Follow PEP 8
- Use type hints everywhere
- Write docstrings (Google style)
- Keep functions small and focused
- Test coverage must not decrease

### PR Process
1. Fork repository
2. Create feature branch
3. Write tests first (TDD)
4. Implement feature
5. Run full test suite
6. Update documentation
7. Submit PR with clear description

### Code Review Criteria
- All tests passing
- Coverage maintained
- Type checking passes
- Linting passes
- Documentation updated
- No breaking changes (without major version bump)

---

## License

MIT License - See LICENSE file for details

## Contact

- **Repository**: https://github.com/williajm/mcp_docker
- **Issues**: https://github.com/williajm/mcp_docker/issues
- **Author**: James Williams
