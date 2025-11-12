"""Integration tests for safety features.

These tests verify that safety controls work correctly in real Docker operations.
Tests require Docker to be running and will create/remove test resources.
"""

import asyncio
from collections.abc import Generator

import pytest

from mcp_docker.config import Config, SafetyConfig
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def restrictive_config() -> Config:
    """Create configuration with all safety features enabled (restrictive)."""
    cfg = Config()
    cfg.safety = SafetyConfig(
        allow_moderate_operations=True,
        allow_destructive_operations=False,
        allow_privileged_containers=False,
        require_confirmation_for_destructive=True,
        max_concurrent_operations=2,
    )
    return cfg


@pytest.fixture
def permissive_config() -> Config:
    """Create configuration with all safety features disabled (permissive)."""
    cfg = Config()
    cfg.safety = SafetyConfig(
        allow_moderate_operations=True,
        allow_destructive_operations=True,
        allow_privileged_containers=True,
        require_confirmation_for_destructive=False,
        max_concurrent_operations=10,
    )
    return cfg


@pytest.fixture
def test_container_name() -> Generator[str, None, None]:
    """Generate unique test container name with cleanup."""
    import docker

    name = "mcp-docker-safety-test-container"

    # Cleanup before test
    try:
        client = docker.from_env()
        try:
            container = client.containers.get(name)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        finally:
            client.close()
    except Exception:
        pass  # Docker not available, tests will skip anyway

    yield name

    # Cleanup after test
    try:
        client = docker.from_env()
        try:
            container = client.containers.get(name)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        finally:
            client.close()
    except Exception:
        pass


@pytest.fixture
def test_volume_name() -> Generator[str, None, None]:
    """Generate unique test volume name with cleanup."""
    import docker

    name = "mcp-docker-safety-test-volume"

    # Cleanup before test
    try:
        client = docker.from_env()
        try:
            volume = client.volumes.get(name)
            volume.remove(force=True)
        except docker.errors.NotFound:
            pass
        finally:
            client.close()
    except Exception:
        pass  # Docker not available, tests will skip anyway

    yield name

    # Cleanup after test
    try:
        client = docker.from_env()
        try:
            volume = client.volumes.get(name)
            volume.remove(force=True)
        except docker.errors.NotFound:
            pass
        finally:
            client.close()
    except Exception:
        pass


@pytest.mark.integration
class TestDestructiveOperationsSafety:
    """Test destructive operations safety controls."""

    @pytest.mark.asyncio
    async def test_remove_container_blocked_when_destructive_disabled(
        self, restrictive_config: Config, test_container_name: str
    ) -> None:
        """Test that removing containers is blocked when destructive ops disabled."""
        # Create server with restrictive config
        server = MCPDockerServer(restrictive_config)

        # First create a container using permissive server
        permissive_server = MCPDockerServer(Config())
        permissive_server.config.safety.allow_moderate_operations = True
        permissive_server.config.safety.allow_destructive_operations = True

        create_result = await permissive_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
            },
        )
        assert create_result["success"] is True

        try:
            # Try to remove with restrictive server - should fail
            remove_result = await server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

            # Should have failed
            assert remove_result["success"] is False
            assert "not allowed" in remove_result["error"].lower()

        finally:
            # Cleanup with permissive server
            await permissive_server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

    @pytest.mark.asyncio
    async def test_remove_container_allowed_when_destructive_enabled(
        self, permissive_config: Config, test_container_name: str
    ) -> None:
        """Test that removing containers works when destructive ops enabled."""
        server = MCPDockerServer(permissive_config)

        # Create container
        create_result = await server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
            },
        )
        assert create_result["success"] is True

        # Remove container - should succeed
        remove_result = await server.call_tool(
            "docker_remove_container",
            {"container_id": test_container_name, "force": True},
        )

        assert remove_result["success"] is True

    @pytest.mark.asyncio
    async def test_prune_volumes_blocked_when_destructive_disabled(
        self, restrictive_config: Config, test_volume_name: str
    ) -> None:
        """Test that pruning volumes is blocked when destructive ops disabled."""
        # Create server with restrictive config
        server = MCPDockerServer(restrictive_config)

        # Create a volume using permissive server
        permissive_server = MCPDockerServer(Config())
        permissive_server.config.safety.allow_moderate_operations = True
        permissive_server.config.safety.allow_destructive_operations = True

        create_result = await permissive_server.call_tool(
            "docker_create_volume",
            {"name": test_volume_name, "labels": {"test": "safety"}},
        )
        assert create_result["success"] is True

        try:
            # Try to prune volumes with restrictive server - should fail
            prune_result = await server.call_tool(
                "docker_prune_volumes",
                {"filters": {"label": ["test=safety"]}},
            )

            # Should have failed
            assert prune_result["success"] is False
            assert "not allowed" in prune_result["error"].lower()

        finally:
            # Cleanup with permissive server
            await permissive_server.call_tool(
                "docker_remove_volume", {"volume_name": test_volume_name}
            )


@pytest.mark.integration
class TestPrivilegedContainersSafety:
    """Test privileged containers safety controls."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="CreateContainerTool does not yet support privileged parameter")
    async def test_privileged_container_blocked_when_disabled(
        self, restrictive_config: Config, test_container_name: str
    ) -> None:
        """Test that privileged containers are blocked when not allowed.

        NOTE: This test is skipped because docker_create_container does not yet
        support the privileged parameter. To enable this test:
        1. Add 'privileged: bool = False' to CreateContainerInput
        2. Implement check_privileged_arguments() in CreateContainerTool
        3. Pass privileged flag to Docker API in host_config
        """
        server = MCPDockerServer(restrictive_config)

        # Try to create privileged container - should fail
        create_result = await server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
                "privileged": True,
            },
        )

        # Should have failed
        assert create_result["success"] is False
        assert "privileged" in create_result["error"].lower()

    @pytest.mark.asyncio
    async def test_privileged_exec_allowed_when_enabled(
        self, permissive_config: Config, test_container_name: str
    ) -> None:
        """Test that privileged exec works when allowed."""
        server = MCPDockerServer(permissive_config)

        # Create and start a container first
        create_result = await server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "60"],
            },
        )
        assert create_result["success"] is True

        start_result = await server.call_tool(
            "docker_start_container", {"container_id": test_container_name}
        )
        assert start_result["success"] is True

        try:
            # Privileged exec - should succeed with permissive config
            exec_result = await server.call_tool(
                "docker_exec_command",
                {
                    "container_id": test_container_name,
                    "command": ["echo", "test"],
                    "privileged": True,
                },
            )

            # Should succeed
            assert exec_result["success"] is True

        finally:
            # Cleanup
            await server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

    @pytest.mark.asyncio
    async def test_privileged_exec_blocked_when_disabled(
        self, restrictive_config: Config, test_container_name: str
    ) -> None:
        """Test that privileged exec is blocked when not allowed."""
        # Create a running container first with permissive server
        permissive_server = MCPDockerServer(Config())
        permissive_server.config.safety.allow_moderate_operations = True
        permissive_server.config.safety.allow_destructive_operations = True

        create_result = await permissive_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "60"],
            },
        )
        assert create_result["success"] is True

        start_result = await permissive_server.call_tool(
            "docker_start_container", {"container_id": test_container_name}
        )
        assert start_result["success"] is True

        try:
            # Try privileged exec with restrictive server - should fail
            server = MCPDockerServer(restrictive_config)
            exec_result = await server.call_tool(
                "docker_exec_command",
                {
                    "container_id": test_container_name,
                    "command": ["echo", "test"],
                    "privileged": True,
                },
            )

            # Should have failed
            assert exec_result["success"] is False
            assert "privileged" in exec_result["error"].lower()

        finally:
            # Cleanup
            await permissive_server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )


@pytest.mark.integration
class TestConcurrencyLimiting:
    """Test max concurrent operations limiting."""

    @pytest.mark.asyncio
    async def test_concurrent_operations_are_limited(self, test_container_name: str) -> None:
        """Test that concurrent operations respect the semaphore limit.

        Note: This test verifies that the semaphore exists and operations complete,
        but true concurrency limiting is better tested in unit tests where we can
        control timing more precisely.
        """
        # Create config with max 2 concurrent operations
        cfg = Config()
        cfg.safety.max_concurrent_operations = 2
        cfg.safety.allow_destructive_operations = True

        server = MCPDockerServer(cfg)

        # Verify the semaphore is initialized with correct limit
        assert server._operation_semaphore._value == 2

        # Launch multiple operations concurrently
        tasks = [server.call_tool("docker_list_containers", {"all": True}) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r["success"] for r in results)

        # Semaphore should be back to original value (all released)
        assert server._operation_semaphore._value == 2

    @pytest.mark.asyncio
    async def test_high_concurrency_limit_allows_more_operations(
        self, test_container_name: str
    ) -> None:
        """Test that higher concurrency limit is properly configured."""
        # Create config with max 10 concurrent operations
        cfg = Config()
        cfg.safety.max_concurrent_operations = 10
        cfg.security.rate_limit_concurrent = 10  # Also update rate limiter per-client limit

        server = MCPDockerServer(cfg)

        # Verify the semaphore is initialized with correct higher limit
        assert server._operation_semaphore._value == 10

        # Launch many operations concurrently
        tasks = [server.call_tool("docker_list_containers", {"all": True}) for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r["success"] for r in results)

        # Semaphore should be back to original value
        assert server._operation_semaphore._value == 10


@pytest.mark.integration
class TestSafeOperationsAlwaysAllowed:
    """Test that safe operations are always allowed regardless of config."""

    @pytest.mark.asyncio
    async def test_list_containers_always_allowed(self, restrictive_config: Config) -> None:
        """Test that listing containers works even with restrictive config."""
        server = MCPDockerServer(restrictive_config)

        result = await server.call_tool("docker_list_containers", {"all": True})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_inspect_container_always_allowed(
        self, restrictive_config: Config, test_container_name: str
    ) -> None:
        """Test that inspecting containers works even with restrictive config."""
        # Create a container first
        permissive_server = MCPDockerServer(Config())
        permissive_server.config.safety.allow_moderate_operations = True
        permissive_server.config.safety.allow_destructive_operations = True

        create_result = await permissive_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
            },
        )
        assert create_result["success"] is True

        try:
            # Inspect with restrictive server - should work
            server = MCPDockerServer(restrictive_config)
            inspect_result = await server.call_tool(
                "docker_inspect_container", {"container_id": test_container_name}
            )

            assert inspect_result["success"] is True

        finally:
            # Cleanup
            await permissive_server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

    @pytest.mark.asyncio
    async def test_docker_version_always_allowed(self, restrictive_config: Config) -> None:
        """Test that getting Docker version works even with restrictive config."""
        server = MCPDockerServer(restrictive_config)

        result = await server.call_tool("docker_version", {})

        assert result["success"] is True
        assert "Version" in result["result"]["version"]


@pytest.mark.integration
class TestReadOnlyModeSafety:
    """Test read-only mode (allow_moderate_operations=False) safety controls."""

    @pytest.mark.asyncio
    async def test_create_container_blocked_in_readonly_mode(
        self, test_container_name: str
    ) -> None:
        """Test that creating containers is blocked in read-only mode."""
        # Create config with read-only mode (moderate operations disabled)
        cfg = Config()
        cfg.safety.allow_moderate_operations = False
        cfg.safety.allow_destructive_operations = False
        cfg.safety.allow_privileged_containers = False

        server = MCPDockerServer(cfg)

        # Try to create container - should fail
        create_result = await server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
            },
        )

        # Should have failed
        assert create_result["success"] is False
        assert "read-only mode" in create_result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_blocked_in_readonly_mode(self, test_container_name: str) -> None:
        """Test that starting containers is blocked in read-only mode."""
        # Create a container first with permissive server
        permissive_server = MCPDockerServer(Config())
        permissive_server.config.safety.allow_moderate_operations = True
        permissive_server.config.safety.allow_destructive_operations = True

        create_result = await permissive_server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "60"],
            },
        )
        assert create_result["success"] is True

        try:
            # Create read-only mode server
            cfg = Config()
            cfg.safety.allow_moderate_operations = False
            cfg.safety.allow_destructive_operations = False

            server = MCPDockerServer(cfg)

            # Try to start container - should fail
            start_result = await server.call_tool(
                "docker_start_container", {"container_id": test_container_name}
            )

            # Should have failed
            assert start_result["success"] is False
            assert "read-only mode" in start_result["error"].lower()

        finally:
            # Cleanup
            await permissive_server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

    @pytest.mark.asyncio
    async def test_pull_image_blocked_in_readonly_mode(self) -> None:
        """Test that pulling images is blocked in read-only mode."""
        # Create config with read-only mode
        cfg = Config()
        cfg.safety.allow_moderate_operations = False
        cfg.safety.allow_destructive_operations = False

        server = MCPDockerServer(cfg)

        # Try to pull image - should fail
        pull_result = await server.call_tool("docker_pull_image", {"image": "alpine:latest"})

        # Should have failed
        assert pull_result["success"] is False
        assert "read-only mode" in pull_result["error"].lower()

    @pytest.mark.asyncio
    async def test_safe_operations_work_in_readonly_mode(self) -> None:
        """Test that safe operations still work in read-only mode."""
        # Create config with read-only mode
        cfg = Config()
        cfg.safety.allow_moderate_operations = False
        cfg.safety.allow_destructive_operations = False

        server = MCPDockerServer(cfg)

        # List containers - should work
        list_result = await server.call_tool("docker_list_containers", {"all": True})
        assert list_result["success"] is True

        # List images - should work
        images_result = await server.call_tool("docker_list_images", {})
        assert images_result["success"] is True

        # Get version - should work
        version_result = await server.call_tool("docker_version", {})
        assert version_result["success"] is True


@pytest.mark.integration
class TestToolFilteringBySafetyConfig:
    """Test that tools are filtered from list_tools() based on safety configuration."""

    @pytest.mark.asyncio
    async def test_all_tools_listed_when_all_operations_allowed(self) -> None:
        """Test that all 36 tools are listed when all operations are allowed."""
        cfg = Config()
        cfg.safety.allow_moderate_operations = True
        cfg.safety.allow_destructive_operations = True

        server = MCPDockerServer(cfg)
        tools = server.list_tools()

        # Should get all 36 tools
        assert len(tools) == 36

    @pytest.mark.asyncio
    async def test_destructive_tools_filtered_by_default(self) -> None:
        """Test that destructive tools are filtered with default config."""
        cfg = Config()
        # Default config: allow_moderate=True, allow_destructive=False

        server = MCPDockerServer(cfg)
        tools = server.list_tools()
        tool_names = [t["name"] for t in tools]

        # Should have SAFE + MODERATE tools but not DESTRUCTIVE
        assert "docker_list_containers" in tool_names
        assert "docker_create_container" in tool_names
        assert "docker_remove_container" not in tool_names
        assert "docker_prune_volumes" not in tool_names
        assert "docker_system_prune" not in tool_names

    @pytest.mark.asyncio
    async def test_only_safe_tools_listed_in_readonly_mode(self) -> None:
        """Test that only SAFE tools are listed in read-only mode."""
        cfg = Config()
        cfg.safety.allow_moderate_operations = False
        cfg.safety.allow_destructive_operations = False

        server = MCPDockerServer(cfg)
        tools = server.list_tools()
        tool_names = [t["name"] for t in tools]

        # Should only have SAFE tools
        assert "docker_list_containers" in tool_names
        assert "docker_inspect_container" in tool_names
        assert "docker_container_logs" in tool_names
        assert "docker_list_images" in tool_names
        assert "docker_version" in tool_names

        # Should NOT have MODERATE tools
        assert "docker_create_container" not in tool_names
        assert "docker_start_container" not in tool_names
        assert "docker_pull_image" not in tool_names

        # Should NOT have DESTRUCTIVE tools
        assert "docker_remove_container" not in tool_names
        assert "docker_prune_images" not in tool_names

    @pytest.mark.asyncio
    async def test_filtered_tools_cannot_be_called(self, test_container_name: str) -> None:
        """Test that calling a filtered destructive tool still fails at execution time.

        This is a defense-in-depth test: even though the tool won't be in list_tools(),
        if a client somehow tries to call it directly, the execution-time safety check
        should still block it.
        """
        cfg = Config()
        cfg.safety.allow_moderate_operations = True
        cfg.safety.allow_destructive_operations = False

        server = MCPDockerServer(cfg)

        # First create a container to test with
        create_result = await server.call_tool(
            "docker_create_container",
            {
                "image": "alpine:latest",
                "name": test_container_name,
                "command": ["sleep", "10"],
            },
        )
        assert create_result["success"] is True

        try:
            # Verify docker_remove_container is NOT in the filtered list
            tools = server.list_tools()
            tool_names = [t["name"] for t in tools]
            assert "docker_remove_container" not in tool_names

            # But if we try to call it directly, it should still fail at execution time
            remove_result = await server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

            assert remove_result["success"] is False
            assert "not allowed" in remove_result["error"].lower()

        finally:
            # Cleanup with permissive config
            cleanup_cfg = Config()
            cleanup_cfg.safety.allow_destructive_operations = True
            cleanup_server = MCPDockerServer(cleanup_cfg)
            await cleanup_server.call_tool(
                "docker_remove_container",
                {"container_id": test_container_name, "force": True},
            )

    @pytest.mark.asyncio
    async def test_context_window_reduction_in_readonly_mode(self) -> None:
        """Test that read-only mode significantly reduces the number of exposed tools.

        This verifies the core benefit: reduced context window usage.
        """
        # Full mode
        full_cfg = Config()
        full_cfg.safety.allow_moderate_operations = True
        full_cfg.safety.allow_destructive_operations = True
        full_server = MCPDockerServer(full_cfg)
        full_tools = full_server.list_tools()

        # Read-only mode
        readonly_cfg = Config()
        readonly_cfg.safety.allow_moderate_operations = False
        readonly_cfg.safety.allow_destructive_operations = False
        readonly_server = MCPDockerServer(readonly_cfg)
        readonly_tools = readonly_server.list_tools()

        # Read-only should have significantly fewer tools
        assert len(readonly_tools) < len(full_tools)
        # Should be less than half the tools
        assert len(readonly_tools) < len(full_tools) / 2

        # Verify the reduction is meaningful (at least 19 tools filtered)
        # 19 = 12 MODERATE tools + 7 DESTRUCTIVE tools
        filtered_count = len(full_tools) - len(readonly_tools)
        assert filtered_count >= 19
