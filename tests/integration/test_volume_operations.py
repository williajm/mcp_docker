"""Integration tests for volume operations.

These tests require Docker to be running and will create/remove test volumes.
"""

import pytest

from mcp_docker.config import Config, DockerConfig, SafetyConfig, ServerConfig
from mcp_docker.docker.client import DockerClientWrapper
from mcp_docker.tools.volume_tools import (
    CreateVolumeTool,
    InspectVolumeTool,
    ListVolumesTool,
    PruneVolumesTool,
    RemoveVolumeTool,
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
def test_volume_name() -> str:
    """Test volume name."""
    return "mcp-docker-test-volume"


@pytest.fixture
def cleanup_test_volume(docker_wrapper: DockerClientWrapper, test_volume_name: str):
    """Cleanup fixture to remove test volume after tests."""
    yield
    try:
        volume = docker_wrapper.client.volumes.get(test_volume_name)
        volume.remove(force=True)
    except Exception:
        pass


@pytest.mark.integration
class TestVolumeOperations:
    """Integration tests for volume operations."""

    @pytest.mark.asyncio
    async def test_create_and_remove_volume(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume,
    ) -> None:
        """Test creating and removing a volume."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveVolumeTool(docker_wrapper, integration_config.safety)

        # Create volume
        create_result = await create_tool.execute({"name": test_volume_name})
        assert create_result.success is True
        assert create_result.data["name"] == test_volume_name

        # Remove volume
        remove_result = await remove_tool.execute({"volume_name": test_volume_name})
        assert remove_result.success is True

    @pytest.mark.asyncio
    async def test_list_volumes(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume,
    ) -> None:
        """Test listing volumes."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        list_tool = ListVolumesTool(docker_wrapper, integration_config.safety)

        # Create a test volume
        await create_tool.execute({"name": test_volume_name})

        # List volumes
        list_result = await list_tool.execute({})
        assert list_result.success is True
        assert len(list_result.data["volumes"]) > 0

        # Find our volume
        found = False
        for volume in list_result.data["volumes"]:
            if volume["name"] == test_volume_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_inspect_volume(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume,
    ) -> None:
        """Test inspecting a volume."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectVolumeTool(docker_wrapper, integration_config.safety)

        # Create volume
        await create_tool.execute({"name": test_volume_name})

        # Inspect volume
        inspect_result = await inspect_tool.execute({"volume_name": test_volume_name})
        assert inspect_result.success is True
        assert inspect_result.data["name"] == test_volume_name
        assert "driver" in inspect_result.data
        assert "mountpoint" in inspect_result.data

    @pytest.mark.asyncio
    async def test_create_volume_with_driver(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        cleanup_test_volume,
    ) -> None:
        """Test creating volume with specific driver."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectVolumeTool(docker_wrapper, integration_config.safety)

        volume_name = "mcp-docker-test-volume-custom"

        try:
            # Create volume with local driver
            create_result = await create_tool.execute(
                {"name": volume_name, "driver": "local"}
            )
            assert create_result.success is True

            # Inspect to verify driver
            inspect_result = await inspect_tool.execute({"volume_name": volume_name})
            assert inspect_result.success is True
            assert inspect_result.data["driver"] == "local"

        finally:
            # Cleanup
            try:
                volume = docker_wrapper.client.volumes.get(volume_name)
                volume.remove(force=True)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_create_volume_with_labels(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        cleanup_test_volume,
    ) -> None:
        """Test creating volume with labels."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        inspect_tool = InspectVolumeTool(docker_wrapper, integration_config.safety)

        volume_name = "mcp-docker-test-volume-labels"

        try:
            # Create volume with labels
            create_result = await create_tool.execute(
                {
                    "name": volume_name,
                    "labels": {"test": "integration", "project": "mcp-docker"},
                }
            )
            assert create_result.success is True

            # Inspect to verify labels
            inspect_result = await inspect_tool.execute({"volume_name": volume_name})
            assert inspect_result.success is True
            labels = inspect_result.data.get("labels", {})
            assert labels.get("test") == "integration"
            assert labels.get("project") == "mcp-docker"

        finally:
            # Cleanup
            try:
                volume = docker_wrapper.client.volumes.get(volume_name)
                volume.remove(force=True)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_remove_volume_with_force(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_volume_name: str,
    ) -> None:
        """Test removing volume with force option."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveVolumeTool(docker_wrapper, integration_config.safety)

        # Create volume
        await create_tool.execute({"name": test_volume_name})

        # Remove with force
        remove_result = await remove_tool.execute(
            {"volume_name": test_volume_name, "force": True}
        )
        assert remove_result.success is True

        # Verify removal
        inspect_tool = InspectVolumeTool(docker_wrapper, integration_config.safety)
        inspect_result = await inspect_tool.execute({"volume_name": test_volume_name})
        assert inspect_result.success is False

    @pytest.mark.asyncio
    async def test_prune_volumes(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test pruning unused volumes."""
        prune_tool = PruneVolumesTool(docker_wrapper, integration_config.safety)

        # Prune volumes (might not remove anything, but should succeed)
        prune_result = await prune_tool.execute({})
        assert prune_result.success is True
        assert "space_reclaimed" in prune_result.data
        assert "volumes_deleted" in prune_result.data

    @pytest.mark.asyncio
    async def test_volume_error_handling(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test error handling for invalid volume operations."""
        inspect_tool = InspectVolumeTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveVolumeTool(docker_wrapper, integration_config.safety)

        # Try to inspect non-existent volume
        inspect_result = await inspect_tool.execute({"volume_name": "nonexistent-volume"})
        assert inspect_result.success is False
        assert "not found" in inspect_result.error.lower()

        # Try to remove non-existent volume
        remove_result = await remove_tool.execute(
            {"volume_name": "nonexistent-volume", "force": False}
        )
        assert remove_result.success is False

    @pytest.mark.asyncio
    async def test_list_volumes_with_filters(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
        test_volume_name: str,
        cleanup_test_volume,
    ) -> None:
        """Test listing volumes with filters."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        list_tool = ListVolumesTool(docker_wrapper, integration_config.safety)

        # Create volume with label
        await create_tool.execute(
            {"name": test_volume_name, "labels": {"environment": "test"}}
        )

        # List with label filter
        list_result = await list_tool.execute({"filters": {"label": ["environment=test"]}})
        assert list_result.success is True

        # Find our volume
        found = False
        for volume in list_result.data["volumes"]:
            if volume["name"] == test_volume_name:
                found = True
                break
        assert found is True

    @pytest.mark.asyncio
    async def test_create_auto_named_volume(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test creating volume with auto-generated name."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        remove_tool = RemoveVolumeTool(docker_wrapper, integration_config.safety)

        # Create volume without specifying name
        create_result = await create_tool.execute({})
        assert create_result.success is True
        volume_name = create_result.data["name"]
        assert len(volume_name) > 0

        # Cleanup
        await remove_tool.execute({"volume_name": volume_name, "force": True})

    @pytest.mark.asyncio
    async def test_prune_volumes_with_filters(
        self,
        docker_wrapper: DockerClientWrapper,
        integration_config: Config,
    ) -> None:
        """Test pruning volumes with filters."""
        create_tool = CreateVolumeTool(docker_wrapper, integration_config.safety)
        prune_tool = PruneVolumesTool(docker_wrapper, integration_config.safety)

        # Create a volume with label for pruning test
        temp_volume_name = "mcp-docker-temp-volume"
        await create_tool.execute(
            {"name": temp_volume_name, "labels": {"temporary": "true"}}
        )

        try:
            # Prune with label filter
            prune_result = await prune_tool.execute({"filters": {"label": ["temporary=true"]}})
            assert prune_result.success is True

        finally:
            # Ensure cleanup
            try:
                volume = docker_wrapper.client.volumes.get(temp_volume_name)
                volume.remove(force=True)
            except Exception:
                pass
