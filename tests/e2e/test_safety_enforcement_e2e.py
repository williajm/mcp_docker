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
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

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
async def mcp_client_session(skip_if_no_docker: None) -> Any:
    """Create an MCP client connected to the server via stdio.

    This simulates a real MCP client (like Claude Desktop) connecting to the server.

    Note: Uses manual context manager enter/exit with error suppression to avoid
    asyncio teardown issues with pytest-asyncio.
    """
    # Server parameters - connect to our MCP server via stdio
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={
            **os.environ,
            # Disable OAuth for local stdio testing
            "SECURITY_OAUTH_ENABLED": "false",
            # Enable all operations for positive tests (we'll test blocking too)
            "SAFETY_ALLOW_MODERATE_OPERATIONS": "true",
            "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "true",
        },
    )

    # Manually manage context managers to handle teardown errors
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
                # Suppress "cancel scope in different task" errors
    finally:
        try:
            await stdio_ctx.__aexit__(None, None, None)
        except RuntimeError as e:
            if "cancel scope" not in str(e):
                raise
            # Suppress "cancel scope in different task" errors


@pytest.fixture
async def mcp_client_session_safe_only(skip_if_no_docker: None) -> Any:
    """Create an MCP client with MODERATE and DESTRUCTIVE operations disabled.

    This tests the safety enforcement - only SAFE (read-only) tools should work.

    Note: Uses manual context manager enter/exit with error suppression to avoid
    asyncio teardown issues with pytest-asyncio.
    """
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={
            **os.environ,
            "SECURITY_OAUTH_ENABLED": "false",
            # CRITICAL: Disable moderate and destructive operations
            "SAFETY_ALLOW_MODERATE_OPERATIONS": "false",
            "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "false",
        },
    )

    # Manually manage context managers to handle teardown errors
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
                # Suppress "cancel scope in different task" errors
    finally:
        try:
            await stdio_ctx.__aexit__(None, None, None)
        except RuntimeError as e:
            if "cancel scope" not in str(e):
                raise
            # Suppress "cancel scope in different task" errors


@pytest.fixture
async def test_container_id(skip_if_no_docker: None) -> Any:
    """Create a test container for E2E tests and clean it up afterward."""
    import docker

    client = docker.from_env()
    container = None

    try:
        # Create a simple test container
        container = client.containers.create(
            image="alpine:latest",
            command="sleep 3600",
            name="mcp-docker-e2e-test-container",
            detach=True,
        )
        yield container.id

    finally:
        # Cleanup
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
    """E2E: SAFE operation (list containers) should always be allowed.

    This tests the full stack:
    - MCP client sends tools/call request
    - Server receives request through stdio
    - Middleware processes request
    - SafetyEnforcer checks tool is SAFE
    - Tool executes
    - Result returns to client
    """
    # Call the docker_list_containers tool (SAFE - read only)
    result = await mcp_client_session.call_tool(
        name="docker_list_containers",
        arguments={"all": True},
    )

    # Should succeed
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    # Result should be valid JSON with container list
    assert "containers" in result.content[0].text or "[]" in result.content[0].text


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_safe_operation_inspect_container_allowed(
    mcp_client_session: ClientSession,
    test_container_id: str,
) -> None:
    """E2E: SAFE operation (inspect container) should always be allowed."""
    # Call docker_inspect_container (SAFE - read only)
    result = await mcp_client_session.call_tool(
        name="docker_inspect_container",
        arguments={"container_id": test_container_id},
    )

    # Should succeed
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    # Should return container details
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
    """E2E: MODERATE operation (start container) allowed when config enables it.

    This would have caught Bug #2 if start_container was blocked despite being enabled.
    """
    # Call docker_start_container (MODERATE - reversible)
    result = await mcp_client_session.call_tool(
        name="docker_start_container",
        arguments={"container_id": test_container_id},
    )

    # Should succeed because SAFETY_ALLOW_MODERATE_OPERATIONS=true
    assert isinstance(result, CallToolResult)
    assert len(result.content) > 0
    # Tool returns JSON with container_id and status fields
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
    If the middleware was reading tool metadata correctly, this should raise an error.
    """
    # Call docker_start_container (MODERATE) when moderate operations are disabled
    result = await mcp_client_session_safe_only.call_tool(
        name="docker_start_container",
        arguments={"container_id": test_container_id},
    )

    # Should fail - check that error is returned
    assert isinstance(result, CallToolResult)
    # MCP SDK wraps errors in CallToolResult with isError=True
    assert result.isError or "not allowed" in result.content[0].text.lower()


# ============================================================================
# E2E Tests: DESTRUCTIVE Operations (Permanent)
# ============================================================================


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_destructive_operation_remove_container_allowed_when_enabled(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: DESTRUCTIVE operation (remove container) allowed when config enables it.

    This creates and removes a container to test the full flow.
    """
    import docker

    client = docker.from_env()

    # Create a temporary container to remove
    container = client.containers.create(
        image="alpine:latest",
        command="sleep 1",
        name="mcp-docker-e2e-temp-delete",
    )
    temp_id = container.id

    try:
        # Call docker_remove_container (DESTRUCTIVE - permanent deletion)
        result = await mcp_client_session.call_tool(
            name="docker_remove_container",
            arguments={"container_id": temp_id, "force": True},
        )

        # Should succeed because SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true
        assert isinstance(result, CallToolResult)
        assert not result.isError

        # Verify container was actually deleted
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(temp_id)

    finally:
        # Cleanup if removal failed
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
    The middleware was defaulting all tools to SAFE, so docker_remove_container
    (which is DESTRUCTIVE) was being allowed when it should have been blocked.
    """
    import docker

    client = docker.from_env()

    # Create a temporary container (that we won't actually delete)
    container = client.containers.create(
        image="alpine:latest",
        command="sleep 1",
        name="mcp-docker-e2e-temp-nodelete",
    )
    temp_id = container.id

    try:
        # Call docker_remove_container (DESTRUCTIVE) when destructive ops are disabled
        result = await mcp_client_session_safe_only.call_tool(
            name="docker_remove_container",
            arguments={"container_id": temp_id, "force": True},
        )

        # Should fail with error
        assert isinstance(result, CallToolResult)
        assert result.isError or "not allowed" in result.content[0].text.lower()

        # Verify container still exists (was not deleted)
        container_obj = client.containers.get(temp_id)
        assert container_obj is not None

    finally:
        # Cleanup
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
    """E2E: Tools on deny list should be blocked regardless of safety level.

    This tests that the SafetyEnforcer deny list works through the full stack.
    """
    # Create client with docker_list_containers on deny list
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={
            **os.environ,
            "SECURITY_OAUTH_ENABLED": "false",
            # Deny a normally-safe operation
            "SAFETY_DENIED_TOOLS": "docker_list_containers",
        },
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Try to call the denied tool
            result = await session.call_tool(
                name="docker_list_containers",
                arguments={"all": True},
            )

            # Should fail even though it's SAFE
            assert isinstance(result, CallToolResult)
            assert result.isError or "denied" in result.content[0].text.lower()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_tool_allow_list_enforcement() -> None:
    """E2E: When allow list is set, only listed tools should work.

    This tests that the SafetyEnforcer allow list works through the full stack.
    """
    # Create client with only docker_list_containers allowed
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={
            **os.environ,
            "SECURITY_OAUTH_ENABLED": "false",
            # Only allow one tool
            "SAFETY_ALLOWED_TOOLS": "docker_list_containers",
        },
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

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
    If the middleware signature was wrong (context, call_next vs call_next, context),
    this test would fail immediately when making the first tool call.
    """
    # Make a simple tool call - if middleware signature is wrong, this will crash
    result = await mcp_client_session.call_tool(
        name="docker_list_containers",
        arguments={"all": True},
    )

    # If we get here without crashing, middleware stack executed correctly
    assert isinstance(result, CallToolResult)
    assert not result.isError


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_full_stack_with_real_docker_operation(
    mcp_client_session: ClientSession,
) -> None:
    """E2E: Test complete flow from MCP client to Docker operation and back.

    This is the most realistic test - it exercises the entire stack:
    1. MCP client sends request
    2. Server receives via stdio
    3. AuditMiddleware logs request
    4. AuthMiddleware checks auth (stdio bypass)
    5. SafetyMiddleware enforces safety (checks tool metadata)
    6. RateLimitMiddleware checks limits
    7. Tool executes Docker operation
    8. Result flows back through stack to client
    """
    import docker

    client = docker.from_env()

    # Create a test container
    container = client.containers.create(
        image="alpine:latest",
        command="echo 'E2E test'",
        name="mcp-docker-e2e-full-stack",
        labels={"test": "e2e-full-stack"},
    )

    try:
        # Step 1: List containers (should see our test container)
        list_result = await mcp_client_session.call_tool(
            name="docker_list_containers",
            arguments={"all": True},
        )
        assert not list_result.isError
        assert "mcp-docker-e2e-full-stack" in list_result.content[0].text

        # Step 2: Inspect the container (read metadata)
        inspect_result = await mcp_client_session.call_tool(
            name="docker_inspect_container",
            arguments={"container_id": container.id},
        )
        assert not inspect_result.isError
        assert container.id in inspect_result.content[0].text

        # Step 3: Start the container (moderate operation)
        start_result = await mcp_client_session.call_tool(
            name="docker_start_container",
            arguments={"container_id": container.id},
        )
        assert not start_result.isError

        # Wait for container to finish
        await asyncio.sleep(1)

        # Step 4: Get container logs
        logs_result = await mcp_client_session.call_tool(
            name="docker_container_logs",
            arguments={"container_id": container.id},
        )
        assert not logs_result.isError
        assert "E2E test" in logs_result.content[0].text

        # Step 5: Remove container (destructive operation)
        remove_result = await mcp_client_session.call_tool(
            name="docker_remove_container",
            arguments={"container_id": container.id, "force": True},
        )
        assert not remove_result.isError

        # Verify container was deleted
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(container.id)

    finally:
        # Cleanup
        try:
            container.remove(force=True)
        except Exception:
            pass
        client.close()
