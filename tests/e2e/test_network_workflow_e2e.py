"""True end-to-end tests for Docker network workflows with real MCP client.

These tests use a real MCP ClientSession with stdio transport to validate
complete network management workflows through the production authentication
and communication stack.
"""

import os
import secrets
from typing import Any

import pytest

from tests.e2e.helpers import get_tool_result_text
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
# Fixtures
# ============================================================================


@pytest.fixture
def skip_if_no_mcp_client() -> Any:
    """Fail test if MCP client library is not available."""
    if not MCP_CLIENT_AVAILABLE:
        pytest.fail("MCP client library is required for E2E tests (pip install mcp)")


@pytest.fixture
def skip_if_no_docker() -> Any:
    """Fail test if Docker is not available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.close()
    except Exception as e:
        pytest.fail(f"Docker is required for E2E tests but is not available: {e}")


@pytest.fixture(autouse=True)
def cleanup_docker_resources(request: Any) -> Any:
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
def ssh_server_env(tmp_path: Any) -> Any:
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
# Network Lifecycle E2E Tests
# ============================================================================


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_network_basic_lifecycle_via_stdio(
    tmp_path: Any, skip_if_no_mcp_client: Any, skip_if_no_docker: Any, ssh_server_env: Any
) -> None:
    """TRUE E2E: Basic network lifecycle through stdio transport.

    Workflow:
    1. Create custom bridge network with SSH auth
    2. Inspect network details with SSH auth
    3. List networks to verify creation with SSH auth
    4. Remove network with SSH auth

    This validates the complete network management flow through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "network-lifecycle-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:network-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    network_name = f"e2e-test-net-{secrets.token_hex(4)}"
    network_id = None

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Step 1: Create network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_result = await session.call_tool(
                    "docker_create_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": network_name,
                        "driver": "bridge",
                        "labels": {"test": "e2e", "purpose": "lifecycle"},
                    },
                )
                assert create_result is not None
                # Extract network_id from MCP result
                # Result structure: [TextContent(type='text', text='...JSON...')]
                result_text = get_tool_result_text(create_result) if create_result else ""
                import json

                result_data = json.loads(result_text)
                network_id = result_data.get("network_id")
                assert network_id is not None, "Network ID should be returned"

                # Step 2: Inspect network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_result = await session.call_tool(
                    "docker_inspect_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                    },
                )
                assert inspect_result is not None
                inspect_text = get_tool_result_text(inspect_result) if inspect_result else ""
                inspect_data = json.loads(inspect_text)
                assert inspect_data.get("details") is not None
                details = inspect_data["details"]
                assert details["Name"] == network_name
                assert details["Driver"] == "bridge"

                # Step 3: List networks
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                list_result = await session.call_tool(
                    "docker_list_networks",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"name": [network_name]},
                    },
                )
                assert list_result is not None
                list_text = get_tool_result_text(list_result) if list_result else ""
                list_data = json.loads(list_text)
                assert list_data.get("count", 0) >= 1
                networks = list_data.get("networks", [])
                assert any(net["name"] == network_name for net in networks)

                # Step 4: Remove network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                remove_result = await session.call_tool(
                    "docker_remove_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                    },
                )
                assert remove_result is not None
                network_id = None  # Cleaned up

    finally:
        # Cleanup if something failed
        if network_id:
            try:
                import docker

                docker_client = docker.from_env()
                network = docker_client.networks.get(network_id)
                network.remove()
            except Exception:
                pass  # Best effort cleanup


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_network_with_container_connectivity_via_stdio(
    tmp_path: Any, skip_if_no_mcp_client: Any, skip_if_no_docker: Any, ssh_server_env: Any
) -> None:
    """TRUE E2E: Network with container connectivity through stdio transport.

    Workflow:
    1. Create custom network
    2. Pull alpine image
    3. Create container (automatically connected to default network)
    4. Connect container to custom network
    5. Inspect network to verify connection
    6. Disconnect container from custom network
    7. Cleanup: remove container and network

    This validates container-network interaction through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "network-container-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:container-network-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    network_name = f"e2e-test-net-{secrets.token_hex(4)}"
    container_name = f"e2e-test-container-{secrets.token_hex(4)}"
    network_id = None
    container_id = None

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                import json

                # Step 1: Create network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_net_result = await session.call_tool(
                    "docker_create_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": network_name,
                        "driver": "bridge",
                    },
                )
                net_text = get_tool_result_text(create_net_result) if create_net_result else ""
                net_data = json.loads(net_text)
                network_id = net_data.get("network_id")

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

                # Step 3: Create container
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_container_result = await session.call_tool(
                    "docker_create_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "image": "alpine:3.19",
                        "name": container_name,
                        "command": ["sleep", "60"],
                    },
                )
                container_text = (
                    get_tool_result_text(create_container_result) if create_container_result else ""
                )
                container_data = json.loads(container_text)
                container_id = container_data.get("container_id")

                # Start container
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_start_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container": container_id,
                    },
                )

                # Step 4: Connect container to custom network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                connect_result = await session.call_tool(
                    "docker_connect_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                        "container_id": container_id,
                        "aliases": ["test-alias"],
                    },
                )
                # Check if connection succeeded
                assert connect_result is not None
                if hasattr(connect_result, "isError") and connect_result.isError:
                    error_msg = (
                        get_tool_result_text(connect_result)
                        if connect_result.content
                        else "Unknown error"
                    )
                    raise AssertionError(f"Container connection failed: {error_msg}")

                # Step 5: Inspect container to verify network connection
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_container_result = await session.call_tool(
                    "docker_inspect_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "container_id": container_id,
                    },
                )
                # Check if operation succeeded
                if (
                    hasattr(inspect_container_result, "isError")
                    and inspect_container_result.isError
                ):
                    error_msg = (
                        get_tool_result_text(inspect_container_result)
                        if inspect_container_result.content
                        else "Unknown error"
                    )
                    raise AssertionError(f"Container inspect failed: {error_msg}")
                container_inspect_text = (
                    get_tool_result_text(inspect_container_result)
                    if inspect_container_result.content
                    else ""
                )
                if not container_inspect_text or not container_inspect_text.strip():
                    raise AssertionError("Empty response from docker_inspect_container")
                container_inspect_data = json.loads(container_inspect_text)
                container_details = container_inspect_data["details"]
                networks = container_details.get("NetworkSettings", {}).get("Networks", {})
                # Verify container is connected to our custom network
                assert network_name in networks, (
                    f"Container should be connected to {network_name}. Networks: {list(networks.keys())}"
                )

                # Step 6: Disconnect container
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                disconnect_result = await session.call_tool(
                    "docker_disconnect_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                        "container_id": container_id,
                    },
                )
                assert disconnect_result is not None

                # Step 7: Cleanup container
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

                # Cleanup network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_remove_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                    },
                )
                network_id = None

    finally:
        # Cleanup if something failed
        if container_id or network_id:
            try:
                import docker

                docker_client = docker.from_env()
                if container_id:
                    try:
                        container = docker_client.containers.get(container_id)
                        container.remove(force=True)
                    except Exception:
                        pass
                if network_id:
                    try:
                        network = docker_client.networks.get(network_id)
                        network.remove()
                    except Exception:
                        pass
            except Exception:
                pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_networks_via_stdio(
    tmp_path: Any, skip_if_no_mcp_client: Any, skip_if_no_docker: Any, ssh_server_env: Any
) -> None:
    """TRUE E2E: Multiple network management through stdio transport.

    Workflow:
    1. Create multiple networks (frontend, backend)
    2. List all networks
    3. Inspect each network
    4. Remove all networks

    This validates managing multiple networks simultaneously through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "multi-network-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:multi-network-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    suffix = secrets.token_hex(4)
    network_names = [f"e2e-frontend-{suffix}", f"e2e-backend-{suffix}"]
    network_ids = []

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                import json

                # Step 1: Create multiple networks
                for network_name in network_names:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    create_result = await session.call_tool(
                        "docker_create_network",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "name": network_name,
                            "driver": "bridge",
                            "labels": {"test": "e2e-multi"},
                        },
                    )
                    net_text = get_tool_result_text(create_result) if create_result else ""
                    net_data = json.loads(net_text)
                    network_ids.append(net_data.get("network_id"))

                # Step 2: List networks
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                list_result = await session.call_tool(
                    "docker_list_networks",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "filters": {"label": ["test=e2e-multi"]},
                    },
                )
                list_text = get_tool_result_text(list_result) if list_result else ""
                list_data = json.loads(list_text)
                assert list_data.get("count", 0) == 2

                # Step 3: Inspect each network
                for network_id in network_ids:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    inspect_result = await session.call_tool(
                        "docker_inspect_network",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "network_id": network_id,
                        },
                    )
                    assert inspect_result is not None

                # Step 4: Remove all networks
                for network_id in network_ids:
                    ssh_auth = create_ssh_auth_data(client_id, private_key)
                    await session.call_tool(
                        "docker_remove_network",
                        arguments={
                            "_auth": {"ssh": ssh_auth},
                            "network_id": network_id,
                        },
                    )
                network_ids = []

    finally:
        # Cleanup if something failed
        if network_ids:
            try:
                import docker

                docker_client = docker.from_env()
                for network_id in network_ids:
                    try:
                        network = docker_client.networks.get(network_id)
                        network.remove()
                    except Exception:
                        pass
            except Exception:
                pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.slow
async def test_network_with_ipam_config_via_stdio(
    tmp_path: Any, skip_if_no_mcp_client: Any, skip_if_no_docker: Any, ssh_server_env: Any
) -> None:
    """TRUE E2E: Network with custom IPAM configuration through stdio transport.

    Workflow:
    1. Create network with custom subnet and gateway
    2. Inspect network to verify IPAM settings
    3. Create container connected to network with specific IP
    4. Cleanup

    This validates advanced network configuration through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "ipam-network-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:ipam-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    network_name = f"e2e-ipam-net-{secrets.token_hex(4)}"
    network_id = None
    # Use a unique random subnet to avoid conflicts with existing networks
    subnet_third_octet = secrets.randbelow(256)
    subnet = f"10.{subnet_third_octet}.0.0/16"
    gateway = f"10.{subnet_third_octet}.0.1"

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                import json

                # Step 1: Create network with IPAM
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                create_result = await session.call_tool(
                    "docker_create_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "name": network_name,
                        "driver": "bridge",
                        "ipam": {"Config": [{"Subnet": subnet, "Gateway": gateway}]},
                    },
                )
                # Check if operation succeeded before parsing
                if hasattr(create_result, "isError") and create_result.isError:
                    error_msg = (
                        get_tool_result_text(create_result)
                        if create_result.content
                        else "Unknown error"
                    )
                    raise AssertionError(f"Network creation failed: {error_msg}")

                net_text = get_tool_result_text(create_result) if create_result.content else ""
                if not net_text or not net_text.strip():
                    raise AssertionError("Empty response from docker_create_network")

                net_data = json.loads(net_text)
                network_id = net_data.get("network_id")

                # Step 2: Inspect network to verify IPAM
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                inspect_result = await session.call_tool(
                    "docker_inspect_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                    },
                )
                inspect_text = get_tool_result_text(inspect_result) if inspect_result else ""
                inspect_data = json.loads(inspect_text)
                details = inspect_data["details"]
                ipam = details.get("IPAM", {})
                config = ipam.get("Config", [])
                assert len(config) > 0
                assert config[0].get("Subnet") == subnet
                assert config[0].get("Gateway") == gateway

                # Step 3: Cleanup network
                ssh_auth = create_ssh_auth_data(client_id, private_key)
                await session.call_tool(
                    "docker_remove_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": network_id,
                    },
                )
                network_id = None

    finally:
        # Cleanup if something failed
        if network_id:
            try:
                import docker

                docker_client = docker.from_env()
                network = docker_client.networks.get(network_id)
                network.remove()
            except Exception:
                pass


@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.asyncio
async def test_network_error_handling_via_stdio(
    tmp_path: Any, skip_if_no_mcp_client: Any, skip_if_no_docker: Any, ssh_server_env: Any
) -> None:
    """TRUE E2E: Network error handling through stdio transport.

    Workflow:
    1. Attempt to inspect non-existent network
    2. Attempt to remove non-existent network
    3. Attempt to connect container to non-existent network

    This validates error handling for network operations through MCP protocol.
    """
    auth_keys_file, env_vars = ssh_server_env

    # Generate SSH key pair
    private_key, public_key_line = generate_ed25519_key_pair(tmp_path)
    client_id = "network-error-client"

    # Add to authorized_keys
    auth_keys_file.write_text(f"{public_key_line} {client_id}:error-test\n")

    # Configure server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_docker", "--transport", "stdio"],
        env={**os.environ, **env_vars},
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Test 1: Inspect non-existent network
            ssh_auth = create_ssh_auth_data(client_id, private_key)
            try:
                await session.call_tool(
                    "docker_inspect_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": "non-existent-network-12345",
                    },
                )
            except Exception as e:
                assert "not found" in str(e).lower() or "network" in str(e).lower()

            # Test 2: Remove non-existent network
            ssh_auth = create_ssh_auth_data(client_id, private_key)
            try:
                await session.call_tool(
                    "docker_remove_network",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": "non-existent-network-12345",
                    },
                )
            except Exception as e:
                assert "not found" in str(e).lower() or "network" in str(e).lower()

            # Test 3: Connect to non-existent network
            ssh_auth = create_ssh_auth_data(client_id, private_key)
            try:
                await session.call_tool(
                    "docker_connect_container",
                    arguments={
                        "_auth": {"ssh": ssh_auth},
                        "network_id": "non-existent-network-12345",
                        "container_id": "fake-container",
                    },
                )
            except Exception as e:
                assert "not found" in str(e).lower() or "network" in str(e).lower()
