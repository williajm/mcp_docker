"""Integration tests for container lifecycle operations.

These tests require Docker to be running and will create/remove test containers.
"""

import pytest

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.container_tools import (
    ContainerLogsTool,
    ContainerStatsTool,
    CreateContainerTool,
    ExecCommandTool,
    InspectContainerTool,
    ListContainersTool,
    RemoveContainerTool,
    RestartContainerTool,
    StartContainerTool,
    StopContainerTool,
)


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_destructive_operations = True
    cfg.safety.allow_privileged_operations = False
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
def docker_wrapper(integration_config: Config) -> DockerClientWrapper:
    """Create Docker client wrapper."""
    wrapper = DockerClientWrapper(integration_config.docker)
    yield wrapper
    wrapper.close()


@pytest.fixture
def test_container_name() -> str:
    """Generate unique test container name."""
    return "mcp-docker-test-container"


@pytest.fixture
def cleanup_test_container(docker_wrapper: DockerClientWrapper, test_container_name: str):
    """Cleanup fixture to remove test container after tests."""
    yield
    # Cleanup after test
    try:
        container = docker_wrapper.client.containers.get(test_container_name)
        container.stop(timeout=1)
        container.remove(force=True)
    except Exception:
        pass  # Container doesn't exist or already removed


@pytest.mark.integration
class TestContainerLifecycle:
    """Integration tests for complete container lifecycle."""

    @pytest.mark.asyncio
    async def test_create_start_stop_remove_container(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test complete container lifecycle: create, start, stop, remove."""
        # Create tools
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        stop_tool = StopContainerTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveContainerTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectContainerTool(docker_wrapper, integration_config.safety)

        # Create container
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            }
        )
        assert create_result.success is True
        assert create_result.data is not None
        container_id = create_result.data["id"]

        # Inspect container (should be created but not running)
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        assert inspect_result.success is True
        assert inspect_result.data["state"] == "created"

        # Start container
        start_result = await start_tool.execute({"container_id": container_id})
        assert start_result.success is True

        # Inspect container (should be running)
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        assert inspect_result.success is True
        assert inspect_result.data["state"] == "running"

        # Stop container
        stop_result = await stop_tool.execute({"container_id": container_id, "timeout": 5})
        assert stop_result.success is True

        # Inspect container (should be stopped)
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        assert inspect_result.success is True
        assert inspect_result.data["state"] in ["exited", "stopped"]

        # Remove container
        remove_result = await remove_tool.execute({"container_id": container_id, "force": True})
        assert remove_result.success is True

    @pytest.mark.asyncio
    async def test_container_restart(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test container restart operation."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        restart_tool = RestartContainerTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectContainerTool(docker_wrapper, integration_config.safety)

        # Create and start container
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            }
        )
        container_id = create_result.data["id"]
        await start_tool.execute({"container_id": container_id})

        # Get initial start time
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        initial_start_time = inspect_result.data.get("started_at")

        # Restart container
        restart_result = await restart_tool.execute({"container_id": container_id, "timeout": 5})
        assert restart_result.success is True

        # Verify container is running and start time changed
        inspect_result = await inspect_tool.execute({"container_id": container_id})
        assert inspect_result.data["state"] == "running"
        new_start_time = inspect_result.data.get("started_at")
        assert new_start_time != initial_start_time

    @pytest.mark.asyncio
    async def test_container_logs(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test retrieving container logs."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        logs_tool = ContainerLogsTool(docker_wrapper, integration_config.safety)

        # Create container that produces output
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sh", "-c", "echo 'Hello from container' && sleep 10"],
            }
        )
        container_id = create_result.data["id"]
        await start_tool.execute({"container_id": container_id})

        # Wait a moment for output
        import asyncio

        await asyncio.sleep(1)

        # Get logs
        logs_result = await logs_tool.execute({"container_id": container_id, "tail": 100})
        assert logs_result.success is True
        assert "Hello from container" in logs_result.data["logs"]

    @pytest.mark.asyncio
    async def test_container_stats(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test retrieving container statistics."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        stats_tool = ContainerStatsTool(docker_wrapper, integration_config.safety)

        # Create and start container
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            }
        )
        container_id = create_result.data["id"]
        await start_tool.execute({"container_id": container_id})

        # Get stats
        stats_result = await stats_tool.execute({"container_id": container_id})
        assert stats_result.success is True
        assert "cpu_usage" in stats_result.data
        assert "memory_usage" in stats_result.data

    @pytest.mark.asyncio
    async def test_container_exec(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test executing commands in container."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        exec_tool = ExecCommandTool(docker_wrapper, integration_config.safety)

        # Create and start container
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            }
        )
        container_id = create_result.data["id"]
        await start_tool.execute({"container_id": container_id})

        # Execute command
        exec_result = await exec_tool.execute(
            {"container_id": container_id, "command": ["echo", "test"]}
        )
        assert exec_result.success is True
        assert "test" in exec_result.data["output"]

    @pytest.mark.asyncio
    async def test_list_containers(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test listing containers."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        list_tool = ListContainersTool(docker_wrapper, integration_config.safety)

        # Create container
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
            }
        )
        container_id = create_result.data["id"]

        # List all containers
        list_result = await list_tool.execute({"all": True})
        assert list_result.success is True
        assert len(list_result.data["containers"]) > 0

        # Find our container
        found = False
        for container in list_result.data["containers"]:
            if container["id"] == container_id:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_container_with_environment_variables(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_container_name: str,
        cleanup_test_container,
    ) -> None:
        """Test creating container with environment variables."""
        create_tool = CreateContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)
        exec_tool = ExecCommandTool(docker_wrapper, integration_config.safety)

        # Create container with environment variables
        create_result = await create_tool.execute(
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "300"],
                "environment": {"TEST_VAR": "test_value", "ANOTHER_VAR": "another_value"},
            }
        )
        container_id = create_result.data["id"]
        await start_tool.execute({"container_id": container_id})

        # Verify environment variable
        exec_result = await exec_tool.execute(
            {"container_id": container_id, "command": ["sh", "-c", "echo $TEST_VAR"]}
        )
        assert exec_result.success is True
        assert "test_value" in exec_result.data["output"]

    @pytest.mark.asyncio
    async def test_container_error_handling(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid operations."""
        inspect_tool = InspectContainerTool(docker_wrapper, integration_config.safety)
        start_tool = StartContainerTool(docker_wrapper, integration_config.safety)

        # Try to inspect non-existent container
        inspect_result = await inspect_tool.execute({"container_id": "nonexistent-container"})
        assert inspect_result.success is False
        assert "not found" in inspect_result.error.lower()

        # Try to start non-existent container
        start_result = await start_tool.execute({"container_id": "nonexistent-container"})
        assert start_result.success is False
