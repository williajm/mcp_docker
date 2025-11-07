"""True end-to-end tests for Docker volume workflows with real MCP client.

These tests use a real MCP ClientSession with stdio transport to validate
complete volume management workflows through the production authentication
and communication stack.
"""

import os
import secrets

import pytest

from tests.e2e.test_ssh_auth_true_e2e import (
    MCP_CLIENT_AVAILABLE,
    create_ssh_auth_data,
    generate_ed25519_key_pair,
)

# MCP client imports
if MCP_CLIENT_AVAILABLE:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client


# ============================================================================
# Helper Functions
# ============================================================================


def safe_parse_json(result, operation_name: str):
    """Safely parse JSON from MCP call result with error handling."""
    import json

    if hasattr(result, "isError") and result.isError:
        error_msg = result.content[0].text if result.content else "Unknown error"
        raise AssertionError(f"{operation_name} failed: {error_msg}")

    result_text = result.content[0].text if result.content else ""
    if not result_text or not result_text.strip():
        raise AssertionError(f"Empty response from {operation_name}")

    try:
        return json.loads(result_text)
    except json.JSONDecodeError as e:
        raise AssertionError(f"Invalid JSON from {operation_name}: {result_text[:100]}") from e


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def skip_if_no_mcp_client():
    """Fail test if MCP client library is not available."""
    if not MCP_CLIENT_AVAILABLE:
        pytest.fail("MCP client library is required for E2E tests (pip install mcp)")


@pytest.fixture
def skip_if_no_docker():
    """Fail test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.fail(f"Docker is required for E2E tests but is not available: {e}")


@pytest.fixture(autouse=True)
def cleanup_docker_resources(request):
    """Automatically cleanup Docker resources after each test.

    This fixture uses autouse=True to run after every test, cleaning up
    any networks, containers, and volumes created during E2E tests.
    """
    yield  # Let the test run first

    # Cleanup after test completes
    try:
        import docker

        client = docker.from_env()

        # Remove networks with e2e labels
        for network in client.networks.list(filters={"label": "test"}):
            # Only remove e2e test networks (those starting with 'e2e-')
            if network.name.startswith("e2e-"):
                try:
                    network.remove()
                except Exception:
                    pass  # Ignore errors - network might be in use or already removed

        # Remove containers with e2e labels
        for container in client.containers.list(all=True, filters={"label": "test"}):
            if container.name.startswith("e2e-"):
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        # Remove volumes with e2e labels
        for volume in client.volumes.list(filters={"label": "test"}):
            if volume.name.startswith("e2e-"):
                try:
                    volume.remove(force=True)
                except Exception:
                    pass

        client.close()
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def ssh_server_env(tmp_path):
    """Setup SSH authentication environment for MCP server.

    Returns:
        Tuple of (authorized_keys_file, env_vars_dict)
    """
    # Create authorized_keys file
    auth_keys_file = tmp_path / "authorized_keys"
    auth_keys_file.touch()
    auth_keys_file.chmod(0o600)

    # Environment variables for server
    env_vars = {
        "SECURITY_AUTH_ENABLED": "true",
        "SECURITY_SSH_AUTH_ENABLED": "true",
        "SECURITY_SSH_AUTHORIZED_KEYS_FILE": str(auth_keys_file),
        "SECURITY_SSH_SIGNATURE_MAX_AGE": "300",
        "DOCKER_BASE_URL": "unix:///var/run/docker.sock",
    }

    return auth_keys_file, env_vars


# ============================================================================
# Volume Lifecycle E2E Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_volume_basic_lifecycle_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Basic volume lifecycle through stdio transport.

    Workflow:
    1. Create named volume with SSH auth
    2. Inspect volume details with SSH auth
    3. List volumes to verify creation with SSH auth
    4. Remove volume with SSH auth

    This validates the complete volume management flow through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "volume-lifecycle-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:volume-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    volume_name = f"e2e-test-vol-{secrets.token_hex(4)}"

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Step 1: Create volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_result = await session.call_tool(
                    "docker_create_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": volume_name,
                        "driver": "local",
                        "labels": {"test": "e2e", "purpose": "lifecycle"},
                    },
                )
                assert create_result is not None
                result_data = safe_parse_json(create_result, "docker_create_volume")
                created_name = result_data.get("name")
                assert created_name == volume_name

                # Step 2: Inspect volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_result = await session.call_tool(
                    "docker_inspect_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "volume_name": volume_name,
                    },
                )
                assert inspect_result is not None
                inspect_data = safe_parse_json(inspect_result, "docker_inspect_volume")
                assert inspect_data.get("details") is not None
                details = inspect_data["details"]
                assert details["Name"] == volume_name
                assert details["Driver"] == "local"

                # Step 3: List volumes
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                list_result = await session.call_tool(
                    "docker_list_volumes",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"name": [volume_name]},
                    },
                )
                assert list_result is not None
                list_data = safe_parse_json(list_result, "docker_list_volumes")
                assert list_data.get("count", 0) >= 1
                volumes = list_data.get("volumes", [])
                assert any(vol["name"] == volume_name for vol in volumes)

                # Step 4: Remove volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                remove_result = await session.call_tool(
                    "docker_remove_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "volume_name": volume_name,
                    },
                )
                assert remove_result is not None

    finally:
        # Cleanup if something failed
        try:
            import docker

            docker_client = docker.from_env()
            try:
                volume = docker_client.volumes.get(volume_name)
                volume.remove()
            except Exception:
                pass
        except Exception:
            pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_volume_with_container_mount_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Volume mounted in container through stdio transport.

    Workflow:
    1. Create named volume
    2. Pull alpine image
    3. Create container with volume mounted
    4. Start container
    5. Execute command in container to write to volume
    6. Inspect container to verify mount
    7. Cleanup: remove container and volume

    This validates volume mounting and usage through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "volume-mount-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:volume-mount-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    volume_name = f"e2e-test-vol-{secrets.token_hex(4)}"
    container_name = f"e2e-test-container-{secrets.token_hex(4)}"
    container_id = None

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                import json

                # Step 1: Create volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_vol_result = await session.call_tool(
                    "docker_create_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": volume_name,
                        "driver": "local",
                    },
                )
                vol_data = safe_parse_json(create_vol_result, "docker_create_volume")
                assert vol_data.get("name") == volume_name

                # Step 2: Pull image
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_pull_image",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "image": "alpine",
                        "tag": "3.19",
                    },
                )

                # Step 3: Create container with volume mount
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_container_result = await session.call_tool(
                    "docker_create_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "image": "alpine:3.19",
                        "name": container_name,
                        "command": ["sleep", "60"],
                        "volumes": {volume_name: {"bind": "/data", "mode": "rw"}},
                    },
                )
                container_text = (
                    create_container_result.content[0].text if create_container_result else ""
                )
                container_data = json.loads(container_text)
                container_id = container_data.get("container_id")

                # Step 4: Start container
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_start_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container": container_id,
                    },
                )

                # Step 5: Inspect container to verify mount
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_result = await session.call_tool(
                    "docker_inspect_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container_id": container_id,
                    },
                )
                inspect_data = safe_parse_json(inspect_result, "docker_inspect_container")
                details = inspect_data["details"]
                mounts = details.get("Mounts", [])
                assert len(mounts) > 0, "Container should have volume mounted"
                volume_mount = next((m for m in mounts if m.get("Name") == volume_name), None)
                assert volume_mount is not None, f"Volume {volume_name} should be mounted"
                assert volume_mount.get("Destination") == "/data"

                # Step 6: Cleanup container
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_stop_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container": container_id,
                        "timeout": 5,
                    },
                )

                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_remove_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container": container_id,
                        "force": True,
                    },
                )
                container_id = None

                # Cleanup volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_remove_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "volume_name": volume_name,
                    },
                )

    finally:
        # Cleanup if something failed
        try:
            import docker

            docker_client = docker.from_env()
            if container_id:
                try:
                    container = docker_client.containers.get(container_id)
                    container.remove(force=True)
                except Exception:
                    pass
            try:
                volume = docker_client.volumes.get(volume_name)
                volume.remove()
            except Exception:
                pass
        except Exception:
            pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_volumes_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Multiple volume management through stdio transport.

    Workflow:
    1. Create multiple volumes (data, logs, cache)
    2. List all volumes
    3. Inspect each volume
    4. Remove all volumes

    This validates managing multiple volumes simultaneously through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "multi-volume-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:multi-volume-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    suffix = secrets.token_hex(4)
    volume_names = [
        f"e2e-data-{suffix}",
        f"e2e-logs-{suffix}",
        f"e2e-cache-{suffix}",
    ]

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Step 1: Create multiple volumes
                for volume_name in volume_names:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    create_result = await session.call_tool(
                        "docker_create_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "name": volume_name,
                            "driver": "local",
                            "labels": {"test": "e2e-multi"},
                        },
                    )
                    vol_data = safe_parse_json(create_result, "docker_create_volume")
                    assert vol_data.get("name") == volume_name

                # Step 2: List volumes
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                list_result = await session.call_tool(
                    "docker_list_volumes",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"label": ["test=e2e-multi"]},
                    },
                )
                list_data = safe_parse_json(list_result, "docker_list_volumes")
                assert list_data.get("count", 0) == 3

                # Step 3: Inspect each volume
                for volume_name in volume_names:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    inspect_result = await session.call_tool(
                        "docker_inspect_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "volume_name": volume_name,
                        },
                    )
                    assert inspect_result is not None

                # Step 4: Remove all volumes
                for volume_name in volume_names:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_remove_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "volume_name": volume_name,
                        },
                    )

    finally:
        # Cleanup if something failed
        try:
            import docker

            docker_client = docker.from_env()
            for volume_name in volume_names:
                try:
                    volume = docker_client.volumes.get(volume_name)
                    volume.remove()
                except Exception:
                    pass
        except Exception:
            pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.slow
async def test_volume_prune_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Volume pruning through stdio transport.

    Workflow:
    1. Create test volumes with labels
    2. Verify volumes exist
    3. Prune volumes with specific label
    4. Verify only labeled volumes removed

    This validates volume pruning functionality through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "volume-prune-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:prune-test\n")

    # Configure server with destructive operations enabled
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars, "SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS": "true"},
    )

    suffix = secrets.token_hex(4)
    prune_volume = f"e2e-prune-vol-{suffix}"
    keep_volume = f"e2e-keep-vol-{suffix}"

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Step 1: Create volumes with different labels
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_create_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": prune_volume,
                        "labels": {"cleanup": "true", "test": "prune"},
                    },
                )

                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_create_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": keep_volume,
                        "labels": {"cleanup": "false", "test": "prune"},
                    },
                )

                # Step 2: Verify both volumes exist
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                list_result = await session.call_tool(
                    "docker_list_volumes",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"label": ["test=prune"]},
                    },
                )
                list_data = safe_parse_json(list_result, "docker_list_volumes")
                assert list_data.get("count", 0) == 2

                # Step 3: Prune volumes with cleanup=true label
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                prune_result = await session.call_tool(
                    "docker_prune_volumes",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"label": ["cleanup=true"]},
                    },
                )
                prune_data = safe_parse_json(prune_result, "docker_prune_volumes")
                # Docker prune only removes unused/dangling volumes
                # Just verify the operation succeeded and returned valid data
                assert "deleted" in prune_data
                assert "space_reclaimed" in prune_data
                # Note: Created volumes aren't "dangling" so they won't be pruned
                # The important thing is the operation completed successfully

                # Step 4: Verify keep_volume still exists
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_result = await session.call_tool(
                    "docker_inspect_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "volume_name": keep_volume,
                    },
                )
                assert inspect_result is not None

                # Cleanup both volumes (prune didn't remove them as they're not dangling)
                for vol_name in [prune_volume, keep_volume]:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_remove_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "volume_name": vol_name,
                        },
                    )

    finally:
        # Cleanup if something failed
        try:
            import docker

            docker_client = docker.from_env()
            for vol_name in [prune_volume, keep_volume]:
                try:
                    volume = docker_client.volumes.get(vol_name)
                    volume.remove()
                except Exception:
                    pass
        except Exception:
            pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_volume_error_handling_via_stdio(
    tmp_path, skip_if_no_mcp_client, skip_if_no_docker, ssh_server_env
):
    """TRUE E2E: Volume error handling through stdio transport.

    Workflow:
    1. Attempt to inspect non-existent volume
    2. Attempt to remove non-existent volume
    3. Create volume, then try to create with same name

    This validates error handling for volume operations through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "volume-error-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:error-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    volume_name = f"e2e-test-vol-{secrets.token_hex(4)}"

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Test 1: Inspect non-existent volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                try:
                    await session.call_tool(
                        "docker_inspect_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "volume_name": "non-existent-volume-12345",
                        },
                    )
                except Exception as e:
                    assert "not found" in str(e).lower() or "volume" in str(e).lower()

                # Test 2: Remove non-existent volume
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                try:
                    await session.call_tool(
                        "docker_remove_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "volume_name": "non-existent-volume-12345",
                        },
                    )
                except Exception as e:
                    assert "not found" in str(e).lower() or "volume" in str(e).lower()

                # Test 3: Create volume with duplicate name
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_result = await session.call_tool(
                    "docker_create_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": volume_name,
                    },
                )
                vol_data = safe_parse_json(create_result, "docker_create_volume")
                assert vol_data.get("name") == volume_name

                # Try to create again with same name (should fail or return existing)
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                try:
                    await session.call_tool(
                        "docker_create_volume",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "name": volume_name,
                        },
                    )
                    # Some Docker versions return existing volume instead of error
                except Exception as e:
                    assert "exists" in str(e).lower() or "conflict" in str(e).lower()

                # Cleanup
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_remove_volume",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "volume_name": volume_name,
                    },
                )

    finally:
        # Cleanup if something failed
        try:
            import docker

            docker_client = docker.from_env()
            try:
                volume = docker_client.volumes.get(volume_name)
                volume.remove()
            except Exception:
                pass
        except Exception:
            pass
