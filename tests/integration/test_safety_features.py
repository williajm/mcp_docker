"""Integration tests for safety features.

These tests verify that safety controls work correctly in real Docker operations.
Tests require Docker to be running and will create/remove test resources.
"""

import asyncio

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
def test_container_name() -> str:
    """Generate unique test container name."""
    return "mcp-docker-safety-test-container"


@pytest.fixture
def test_volume_name() -> str:
    """Generate unique test volume name."""
    return "mcp-docker-safety-test-volume"


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
    async def test_privileged_container_blocked_when_disabled(
        self, restrictive_config: Config, test_container_name: str
    ) -> None:
        """Test that privileged containers are blocked when not allowed."""
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
