# Docker Compose Full Support Implementation Plan

## Executive Summary

This document outlines a comprehensive plan to add full Docker Compose support to the MCP Docker Server. Currently, the server only provides AI-assisted compose file generation through a prompt template. This plan details the implementation of direct Docker Compose operational tools, enabling complete compose stack management through the MCP protocol.

## Current State Assessment

### What Exists Today
- **1 Prompt**: `generate_compose` - AI-assisted docker-compose.yml generation
- **0 Operational Tools**: No direct docker-compose command execution
- **Infrastructure Ready**: Modular architecture, safety system, and Docker SDK support

### Gap Analysis
The MCP Docker Server lacks tools for:
- Starting/stopping compose stacks (`docker compose up/down`)
- Managing compose services (`ps`, `restart`, `logs`)
- Building and rebuilding services
- Executing commands in compose services
- Managing compose projects and environments

## Implementation Strategy

### Core Principles
1. **Consistency**: Follow existing tool patterns and conventions
2. **Safety First**: Apply appropriate safety levels to compose operations
3. **Type Safety**: Full Pydantic validation and mypy strict mode
4. **Comprehensive Testing**: Unit, integration, and performance tests
5. **Progressive Enhancement**: Build on existing infrastructure

## Technical Specification

### New Docker Compose Tools

#### 1. Stack Management Tools

##### ComposeUpTool
```python
class ComposeUpTool:
    name = "docker_compose_up"
    description = "Start services defined in a docker-compose file"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None  # Specific services to start
        detach: bool = True
        build: bool = False
        force_recreate: bool = False
        no_deps: bool = False
        remove_orphans: bool = False
        scale: dict[str, int] | None = None  # Service scaling
        timeout: int = 60
        wait: bool = False  # Wait for services to be healthy
```

##### ComposeDownTool
```python
class ComposeDownTool:
    name = "docker_compose_down"
    description = "Stop and remove services defined in a docker-compose file"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        remove_images: str | None = None  # "local", "all", or None
        volumes: bool = False
        remove_orphans: bool = True
        timeout: int = 10
```

#### 2. Service Management Tools

##### ComposePsTool
```python
class ComposePsTool:
    name = "docker_compose_ps"
    description = "List services in a compose project"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        all: bool = False  # Include stopped services
        format: str | None = None  # Output format
```

##### ComposeRestartTool
```python
class ComposeRestartTool:
    name = "docker_compose_restart"
    description = "Restart services in a compose project"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        timeout: int = 10
```

##### ComposeStopTool
```python
class ComposeStopTool:
    name = "docker_compose_stop"
    description = "Stop services without removing them"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        timeout: int = 10
```

##### ComposeStartTool
```python
class ComposeStartTool:
    name = "docker_compose_start"
    description = "Start existing services"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
```

#### 3. Build and Development Tools

##### ComposeBuildTool
```python
class ComposeBuildTool:
    name = "docker_compose_build"
    description = "Build or rebuild services"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        no_cache: bool = False
        pull: bool = False
        build_args: dict[str, str] | None = None
        progress: str = "auto"  # "auto", "plain", "tty"
```

##### ComposePullTool
```python
class ComposePullTool:
    name = "docker_compose_pull"
    description = "Pull service images"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        ignore_pull_failures: bool = False
        include_deps: bool = True
```

##### ComposePushTool
```python
class ComposePushTool:
    name = "docker_compose_push"
    description = "Push service images"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        ignore_push_failures: bool = False
```

#### 4. Monitoring and Debugging Tools

##### ComposeLogsTool
```python
class ComposeLogsTool:
    name = "docker_compose_logs"
    description = "View output from services"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        follow: bool = False
        tail: int | str = "all"
        timestamps: bool = False
        since: str | None = None
        until: str | None = None
```

##### ComposeExecTool
```python
class ComposeExecTool:
    name = "docker_compose_exec"
    description = "Execute a command in a running service"
    safety_level = OperationSafety.MODERATE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        service: str  # Required - service name
        command: str | list[str]
        detach: bool = False
        privileged: bool = False
        user: str | None = None
        index: int = 1  # Container index for scaled services
        env: dict[str, str] | None = None
        workdir: str | None = None
```

##### ComposeTopTool
```python
class ComposeTopTool:
    name = "docker_compose_top"
    description = "Display running processes in services"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
```

#### 5. Configuration Management Tools

##### ComposeConfigTool
```python
class ComposeConfigTool:
    name = "docker_compose_config"
    description = "Validate and view the compose configuration"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        resolve_image_digests: bool = False
        services: bool = False  # List services only
        volumes: bool = False  # List volumes only
        profiles: list[str] | None = None
        format: str = "yaml"  # "yaml" or "json"
```

##### ComposeConvertTool
```python
class ComposeConvertTool:
    name = "docker_compose_convert"
    description = "Convert compose file between formats"
    safety_level = OperationSafety.SAFE

    class Input:
        compose_file: str
        output_format: str = "yaml"  # "yaml" or "json"
        output_file: str | None = None
```

#### 6. Project Management Tools

##### ComposeListTool
```python
class ComposeListTool:
    name = "docker_compose_list"
    description = "List compose projects"
    safety_level = OperationSafety.SAFE

    class Input:
        all: bool = False  # Include stopped projects
        format: str | None = None
```

##### ComposeKillTool
```python
class ComposeKillTool:
    name = "docker_compose_kill"
    description = "Force stop service containers"
    safety_level = OperationSafety.DESTRUCTIVE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        signal: str = "SIGKILL"
```

##### ComposeRemoveTool
```python
class ComposeRemoveTool:
    name = "docker_compose_rm"
    description = "Remove stopped service containers"
    safety_level = OperationSafety.DESTRUCTIVE

    class Input:
        compose_file: str | None = "docker-compose.yml"
        project_name: str | None = None
        services: list[str] | None = None
        stop: bool = False
        volumes: bool = False
        force: bool = False
```

### New Resources

#### ComposeProjectLogs Resource
```python
class ComposeProjectLogsResource:
    uri_pattern = "compose://logs/{project_name}"
    description = "Real-time logs from all services in a compose project"

    async def read(self, project_name: str) -> ResourceContent:
        # Stream logs from all services in the project
        pass
```

#### ComposeProjectStatus Resource
```python
class ComposeProjectStatusResource:
    uri_pattern = "compose://status/{project_name}"
    description = "Live status of services in a compose project"

    async def read(self, project_name: str) -> ResourceContent:
        # Return service states, health, and resource usage
        pass
```

### Enhanced Prompts

#### EnhancedComposeGeneratorPrompt
```python
class EnhancedComposeGeneratorPrompt:
    name = "generate_compose_advanced"
    description = "Generate production-ready docker-compose.yml with best practices"

    async def generate(
        self,
        services: list[str],
        environment: str = "development",  # dev, staging, production
        include_monitoring: bool = False,
        include_networking: bool = True,
        include_volumes: bool = True,
        include_healthchecks: bool = True,
        secrets_management: str | None = None,  # "env_file", "docker_secrets"
    ) -> PromptResult:
        pass
```

#### ComposeMigrationPrompt
```python
class ComposeMigrationPrompt:
    name = "migrate_to_compose"
    description = "Migrate existing containers to docker-compose configuration"

    async def generate(
        self,
        container_ids: list[str],
        preserve_networks: bool = True,
        preserve_volumes: bool = True,
        group_by: str = "network",  # "network", "label", "none"
    ) -> PromptResult:
        pass
```

## Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Update Docker SDK dependencies to ensure compose support
- [ ] Create `compose_tools.py` module structure
- [ ] Implement base classes for compose operations
- [ ] Add compose-specific error handling
- [ ] Update configuration for compose-specific settings

### Phase 2: Core Tools (Week 2-4)
- [ ] Implement ComposeUpTool
- [ ] Implement ComposeDownTool
- [ ] Implement ComposePsTool
- [ ] Implement ComposeLogsTool
- [ ] Implement ComposeExecTool
- [ ] Add comprehensive unit tests for core tools

### Phase 3: Service Management (Week 4-5)
- [ ] Implement ComposeRestartTool
- [ ] Implement ComposeStopTool
- [ ] Implement ComposeStartTool
- [ ] Implement ComposeBuildTool
- [ ] Implement ComposePullTool
- [ ] Add integration tests for service lifecycle

### Phase 4: Advanced Features (Week 5-6)
- [ ] Implement ComposeConfigTool
- [ ] Implement ComposeTopTool
- [ ] Implement ComposeListTool
- [ ] Implement ComposeKillTool
- [ ] Implement ComposeRemoveTool
- [ ] Add compose resources (logs, status)

### Phase 5: Enhanced Prompts (Week 6-7)
- [ ] Implement EnhancedComposeGeneratorPrompt
- [ ] Implement ComposeMigrationPrompt
- [ ] Add prompt integration tests
- [ ] Create example workflows

### Phase 6: Testing & Documentation (Week 7-8)
- [ ] Performance testing with multi-service stacks
- [ ] Edge case testing (missing files, invalid configs)
- [ ] Security audit for compose operations
- [ ] Update README with compose examples
- [ ] Create compose-specific documentation
- [ ] Add compose tutorials and best practices

## Testing Strategy

### Unit Tests
```python
# tests/unit/test_compose_tools.py
class TestComposeUpTool:
    async def test_up_with_defaults(self):
        # Test basic docker-compose up
        pass

    async def test_up_with_specific_services(self):
        # Test starting specific services
        pass

    async def test_up_with_build(self):
        # Test building before starting
        pass

    async def test_up_with_scaling(self):
        # Test service scaling
        pass
```

### Integration Tests
```python
# tests/integration/test_compose_integration.py
class TestComposeWorkflow:
    async def test_complete_lifecycle(self):
        # Up -> Ps -> Logs -> Exec -> Down
        pass

    async def test_multi_service_coordination(self):
        # Test inter-service dependencies
        pass

    async def test_compose_with_volumes(self):
        # Test volume persistence across restarts
        pass
```

### Performance Tests
```python
# tests/performance/test_compose_performance.py
class TestComposePerformance:
    async def test_large_stack_startup(self):
        # Test with 10+ services
        pass

    async def test_concurrent_operations(self):
        # Test parallel compose commands
        pass
```

## Safety Considerations

### Operation Safety Levels
| Tool | Safety Level | Rationale |
|------|-------------|-----------|
| ComposeUp | MODERATE | Creates containers but reversible |
| ComposeDown | MODERATE | Stops/removes but preserves volumes by default |
| ComposePs | SAFE | Read-only operation |
| ComposeLogs | SAFE | Read-only operation |
| ComposeExec | MODERATE | Can modify container state |
| ComposeBuild | MODERATE | Uses resources but reversible |
| ComposeKill | DESTRUCTIVE | Force stops without cleanup |
| ComposeRm | DESTRUCTIVE | Permanent container removal |

### Safety Features
1. **File Validation**: Check compose file exists and is valid YAML
2. **Project Isolation**: Ensure operations only affect specified project
3. **Dependency Protection**: Warn when removing services with dependents
4. **Volume Protection**: Default to preserving volumes, require explicit removal
5. **Network Isolation**: Respect network boundaries and security groups

## Configuration Updates

### New Environment Variables
```bash
# Compose-specific settings
MCP_DOCKER_COMPOSE_FILE_DEFAULT="docker-compose.yml"
MCP_DOCKER_COMPOSE_PROJECT_PREFIX="mcp"
MCP_DOCKER_COMPOSE_PARALLEL_LIMIT=4
MCP_DOCKER_COMPOSE_BUILD_PARALLEL=true
MCP_DOCKER_COMPOSE_COMPATIBILITY_MODE=false
```

### Config Schema Updates
```python
# config.py additions
class ComposeConfig(BaseModel):
    default_file: str = "docker-compose.yml"
    project_prefix: str = "mcp"
    parallel_limit: int = 4
    build_parallel: bool = True
    compatibility_mode: bool = False
    env_file: str | None = None

class ServerConfig(BaseModel):
    # ... existing fields ...
    compose: ComposeConfig = ComposeConfig()
```

## API Integration

### Docker SDK Compose Support
```python
# Docker SDK 7.1.0+ provides compose support
from docker.models.compose import Project

# Example usage in ComposeUpTool
async def execute(self, input_data: ComposeUpInput) -> ComposeUpOutput:
    project = self.docker_client.compose.get_project(
        name=input_data.project_name,
        config_files=[input_data.compose_file]
    )

    containers = await project.up(
        detached=input_data.detach,
        build=input_data.build,
        services=input_data.services
    )

    return ComposeUpOutput(
        project_name=project.name,
        services_started=len(containers)
    )
```

### Fallback Strategy
For Docker installations without native compose support:
```python
# Fallback to subprocess execution
import subprocess

async def execute_compose_command(args: list[str]) -> str:
    result = subprocess.run(
        ["docker", "compose"] + args,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout
```

## Documentation Plan

### User Documentation
1. **Getting Started with Compose**
   - Basic compose file creation
   - Starting your first stack
   - Managing services

2. **Advanced Compose Workflows**
   - Multi-environment deployments
   - Service scaling strategies
   - Health check configuration

3. **Compose Best Practices**
   - File organization
   - Secret management
   - Network design
   - Volume strategies

### Developer Documentation
1. **Compose Tool Architecture**
   - Tool implementation patterns
   - Error handling strategies
   - Testing approaches

2. **Extending Compose Support**
   - Adding new compose tools
   - Custom resource providers
   - Prompt template creation

## Success Metrics

### Functional Metrics
- [ ] All 18 compose tools implemented and tested
- [ ] 95%+ test coverage for compose module
- [ ] Zero critical security vulnerabilities
- [ ] Full mypy type coverage

### Performance Metrics
- [ ] Compose operations complete within 2x native docker-compose time
- [ ] Support stacks with 20+ services
- [ ] Concurrent operation support (4+ parallel commands)

### User Experience Metrics
- [ ] Complete compose workflow without leaving MCP
- [ ] Intuitive tool naming and parameters
- [ ] Comprehensive error messages
- [ ] Rich documentation and examples

## Migration Path

### For Existing Users
1. **Backward Compatibility**: Existing tools remain unchanged
2. **Progressive Enhancement**: New compose tools are additive
3. **Prompt Evolution**: Existing `generate_compose` enhanced, not replaced
4. **Documentation**: Clear migration guides for compose adoption

### Version Strategy
```
v1.0.0 - Current release (no compose tools)
v1.1.0 - Phase 1-2: Core compose tools
v1.2.0 - Phase 3-4: Complete compose toolkit
v1.3.0 - Phase 5-6: Enhanced prompts and polish
v2.0.0 - Full compose integration with potential breaking changes
```

## Risk Analysis

### Technical Risks
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Docker SDK compose limitations | Medium | High | Implement subprocess fallback |
| Complex dependency resolution | High | Medium | Leverage docker-compose native resolver |
| Performance with large stacks | Medium | Medium | Implement pagination and filtering |
| File system access restrictions | Low | High | Clear permission documentation |

### Operational Risks
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Accidental service deletion | Low | High | Safety levels and confirmations |
| Resource exhaustion | Medium | Medium | Resource limits and monitoring |
| Network conflicts | Low | Medium | Network validation before operations |

## Conclusion

Implementing full Docker Compose support in the MCP Docker Server is a natural evolution that leverages the existing robust architecture. The modular design, established patterns, and comprehensive safety system provide a solid foundation for adding these 18+ new tools.

This implementation will transform the MCP Docker Server from a container management tool to a complete Docker orchestration platform, enabling users to manage complex multi-service applications through the MCP protocol.

### Key Benefits
1. **Complete Lifecycle Management**: From development to production
2. **Multi-Service Orchestration**: Manage complex applications
3. **Enhanced Developer Experience**: Unified interface for all Docker operations
4. **AI-Powered Workflows**: Combine compose tools with AI assistance
5. **Enterprise Ready**: Safety, security, and scalability built-in

### Next Steps
1. Review and approve implementation plan
2. Prioritize tool implementation order
3. Assign development resources
4. Begin Phase 1 implementation
5. Establish testing infrastructure

---

*Document Version: 1.0.0*
*Last Updated: 2025-01-25*
*Status: DRAFT - Pending Review*