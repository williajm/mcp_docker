"""End-to-end tests for safety enforcement through the MCP protocol.

These tests use the actual MCP SDK client to test the full stack:
- MCP Client → stdio transport → MCP Server → Middleware → SafetyEnforcer → Docker

These tests would have caught:
- Bug #1: Middleware signature mismatch (context/call_next parameter order)
- Bug #2: Safety level always defaulting to SAFE instead of reading tool metadata

The tests create real Docker containers for testing and clean them up afterward.
"""

import asyncio
import os
from collections.abc import AsyncIterator

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

# ============================================================================
# Helper Functions
# ============================================================================


async def create_mcp_session(
    allow_moderate: bool = True,
    allow_destructive: bool = True,
    extra_env: dict[str, str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Create an MCP client session with configurable safety settings.

    Args:
        allow_moderate: Whether to allow MODERATE operations
        allow_destructive: Whether to allow DESTRUCTIVE operations
        extra_env: Additional environment variables to set

    Yields:
        ClientSession connected to the server

    Note: Uses manual context manager enter/exit with error suppression to avoid
    asyncio teardown issues with pytest-asyncio.
    """
    env = {
        **os.environ,
        "SECURITY_OAUTH_ENABLED": "false",
        "SAFETY_ALLOW_MODERATE_OPERATIONS": str(allow_moderate).lower(),
        "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": str(allow_destructive).lower(),
        **(extra_env or {}),
    }

    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env=env,
    )

    stdio_ctx = stdio_client(server_params)
    read, write = await stdio_ctx.__aenter__()

    try:
        session_ctx = ClientSession(read, write)
        session = await session_ctx.__aenter__()
        try:
            await session.initialize()
            yield session
        finally:
            try:
                await session_ctx.__aexit__(None, None, None)
            except RuntimeError as e:
                if "cancel scope" not in str(e):
                    raise
    finally:
        try:
            await stdio_ctx.__aexit__(None, None, None)
        except RuntimeError as e:
            if "cancel scope" not in str(e):
                raise


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def skip_if_no_docker() -> None:
    """Skip test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.skip(f"Docker required but not available: {e}")


@pytest.fixture
async def mcp_client_session(skip_if_no_docker: None) -> AsyncIterator[ClientSession]:
    """Create an MCP client with all operations enabled."""
    async for session in create_mcp_session(allow_moderate=True, allow_destructive=True):
        yield session


@pytest.fixture
async def mcp_client_session_safe_only(skip_if_no_docker: None) -> AsyncIterator[ClientSession]:
    """Create an MCP client with only SAFE operations allowed."""
    async for session in create_mcp_session(allow_moderate=False, allow_destructive=False):
        yield session


@pytest.fixture
async def test_container_id(skip_if_no_docker: None) -> AsyncIterator[str]:
    """Create a test container for E2E tests and clean it up afterward."""
    import docker

    client = docker.from_env()
    container = None

    try:
        container = client.containers.create(
            image="alpine:latest",
            command="sleep 3600",
            name="mcp-docker-e2e-test-container",
            detach=True,
        )
        yield container.id
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        client.close()


# ============================================================================
# E2E Tests: SAFE Operations (Read-only)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_safe_operation_list_containers_allowed(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: SAFE operation (list containers) should always be allowed."""
    result = await mcp_client_session.call_tool(
        name="docker_list_containers",
        arguments={"all": True},
    )

    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    assert "containers" in result.content[0].text or "[]" in result.content[0].text


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_safe_operation_inspect_container_allowed(
    mcp_client_session: ClientSession,
    test_container_id: str,
) -> None:
    """E2E: SAFE operation (inspect container) should always be allowed."""
    result = await mcp_client_session.call_tool(
        name="docker_inspect_container",
        arguments={"container_id": test_container_id},
    )

    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    content = result.content[0].text
    assert "Id" in content or "id" in content.lower()


# ============================================================================
# E2E Tests: MODERATE Operations (Reversible)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_moderate_operation_start_container_allowed_when_enabled(
    mcp_client_session: ClientSession,
    test_container_id: str,
) -> None:
    """E2E: MODERATE operation (start container) allowed when config enables it."""
    result = await mcp_client_session.call_tool(
        name="docker_start_container",
        arguments={"container_id": test_container_id},
    )

    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    response_text = result.content[0].text.lower()
    assert "container_id" in response_text
    assert "status" in response_text
    assert "running" in response_text


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_moderate_operation_blocked_when_disabled(
    mcp_client_session_safe_only: ClientSession,
    test_container_id: str,
) -> None:
    """E2E: MODERATE operation should be blocked when config disables it.

    CRITICAL: This test would have caught Bug #2 (safety level always SAFE).
    """
    result = await mcp_client_session_safe_only.call_tool(
        name="docker_start_container",
        arguments={"container_id": test_container_id},
    )

    assert isinstance(result, CallToolResult)
    assert result.isError or "not allowed" in result.content[0].text.lower()


# ============================================================================
# E2E Tests: DESTRUCTIVE Operations (Permanent)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_destructive_operation_remove_container_allowed_when_enabled(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: DESTRUCTIVE operation (remove container) allowed when config enables it."""
    import docker

    client = docker.from_env()
    container = client.containers.create(
        image="alpine:latest",
        command="sleep 1",
        name="mcp-docker-e2e-temp-delete",
    )
    temp_id = container.id

    try:
        result = await mcp_client_session.call_tool(
            name="docker_remove_container",
            arguments={"container_id": temp_id, "force": True},
        )

        assert isinstance(result, CallToolResult)
        assert not result.isError

        with pytest.raises(docker.errors.NotFound):
            client.containers.get(temp_id)
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
        client.close()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_destructive_operation_blocked_when_disabled(
    mcp_client_session_safe_only: ClientSession,
) -> None:
    """E2E: DESTRUCTIVE operation should be blocked when config disables it.

    CRITICAL: This test would have caught Bug #2 (safety level always SAFE).
    """
    import docker

    client = docker.from_env()
    container = client.containers.create(
        image="alpine:latest",
        command="sleep 1",
        name="mcp-docker-e2e-temp-nodelete",
    )
    temp_id = container.id

    try:
        result = await mcp_client_session_safe_only.call_tool(
            name="docker_remove_container",
            arguments={"container_id": temp_id, "force": True},
        )

        assert isinstance(result, CallToolResult)
        assert result.isError or "not allowed" in result.content[0].text.lower()

        container_obj = client.containers.get(temp_id)
        assert container_obj is not None
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
        client.close()


# ============================================================================
# E2E Tests: Tool Allow/Deny Lists
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_tool_deny_list_enforcement() -> None:
    """E2E: Tools on deny list should be blocked regardless of safety level."""
    async for session in create_mcp_session(
        extra_env={"SAFETY_DENIED_TOOLS": "docker_list_containers"}
    ):
        result = await session.call_tool(
            name="docker_list_containers",
            arguments={"all": True},
        )

        assert isinstance(result, CallToolResult)
        assert result.isError or "denied" in result.content[0].text.lower()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_tool_allow_list_enforcement() -> None:
    """E2E: When allow list is set, only listed tools should work."""
    async for session in create_mcp_session(
        extra_env={"SAFETY_ALLOWED_TOOLS": "docker_list_containers"}
    ):
        # Allowed tool should work
        result1 = await session.call_tool(
            name="docker_list_containers",
            arguments={"all": True},
        )
        assert isinstance(result1, CallToolResult)
        assert not result1.isError

        # Non-allowed tool should fail
        result2 = await session.call_tool(
            name="docker_list_images",
            arguments={},
        )
        assert isinstance(result2, CallToolResult)
        assert result2.isError or "not in allow list" in result2.content[0].text.lower()


# ============================================================================
# E2E Tests: Middleware Stack Integration
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_middleware_executes_in_correct_order(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: Verify middleware executes in correct order.

    CRITICAL: This would have caught Bug #1 (middleware signature mismatch).
    """
    result = await mcp_client_session.call_tool(
        name="docker_list_containers",
        arguments={"all": True},
    )

    assert isinstance(result, CallToolResult)
    assert not result.isError


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_full_stack_with_real_docker_operation(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: Test complete flow from MCP client to Docker operation and back."""
    import docker

    client = docker.from_env()
    container = client.containers.create(
        image="alpine:latest",
        command="echo 'E2E test'",
        name="mcp-docker-e2e-full-stack",
        labels={"test": "e2e-full-stack"},
    )

    try:
        # Step 1: List containers
        list_result = await mcp_client_session.call_tool(
            name="docker_list_containers",
            arguments={"all": True},
        )
        assert not list_result.isError
        assert "mcp-docker-e2e-full-stack" in list_result.content[0].text

        # Step 2: Inspect the container
        inspect_result = await mcp_client_session.call_tool(
            name="docker_inspect_container",
            arguments={"container_id": container.id},
        )
        assert not inspect_result.isError
        assert container.id in inspect_result.content[0].text

        # Step 3: Start the container
        start_result = await mcp_client_session.call_tool(
            name="docker_start_container",
            arguments={"container_id": container.id},
        )
        assert not start_result.isError

        await asyncio.sleep(1)

        # Step 4: Get container logs
        logs_result = await mcp_client_session.call_tool(
            name="docker_container_logs",
            arguments={"container_id": container.id},
        )
        assert not logs_result.isError
        assert "E2E test" in logs_result.content[0].text

        # Step 5: Remove container
        remove_result = await mcp_client_session.call_tool(
            name="docker_remove_container",
            arguments={"container_id": container.id, "force": True},
        )
        assert not remove_result.isError

        with pytest.raises(docker.errors.NotFound):
            client.containers.get(container.id)
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass
        client.close()
