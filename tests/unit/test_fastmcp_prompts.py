"""Unit tests for FastMCP prompts."""

from unittest.mock import Mock

import pytest

from mcp_docker.fastmcp_prompts import (
    create_debug_networking_prompt,
    create_generate_compose_prompt,
    create_optimize_container_prompt,
    create_security_audit_prompt,
    create_troubleshoot_container_prompt,
    register_all_prompts,
)


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = Mock()
    client.client = Mock()
    return client


@pytest.fixture
def mock_container():
    """Create a mock Docker container."""
    container = Mock()
    container.attrs = {
        "State": {
            "Status": "running",
            "ExitCode": 0,
            "Error": "",
        },
        "Config": {
            "Image": "nginx:latest",
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Env": ["PATH=/usr/local/bin"],
            "ExposedPorts": {"80/tcp": {}},
        },
        "HostConfig": {
            "Memory": 536870912,
            "CpuShares": 1024,
            "RestartPolicy": {"Name": "always"},
            "Binds": ["/data:/app/data"],
        },
        "NetworkSettings": {
            "Networks": {
                "bridge": {
                    "IPAddress": "172.17.0.2",
                    "Gateway": "172.17.0.1",
                    "MacAddress": "02:42:ac:11:00:02",
                }
            },
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
        "Name": "/test-container",
    }
    container.logs = Mock(return_value=b"Log line 1\nLog line 2\n")
    container.stats = Mock(
        return_value={
            "memory_stats": {"usage": 134217728, "limit": 536870912},
            "cpu_stats": {"cpu_usage": {"total_usage": 1000000}},
        }
    )
    return container


class TestCreateTroubleshootContainerPrompt:
    """Test create_troubleshoot_container_prompt."""

    def test_creates_prompt_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        name, description, func = create_troubleshoot_container_prompt(mock_docker_client)

        assert name == "troubleshoot_container"
        assert "troubleshoot" in description.lower()
        assert callable(func)

    @pytest.mark.asyncio
    async def test_prompt_generation(self, mock_docker_client, mock_container):
        """Test prompt generation with container data."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, _, prompt_func = create_troubleshoot_container_prompt(mock_docker_client)

        result = await prompt_func("test-container")

        assert isinstance(result, str)
        assert "test-container" in result
        assert "running" in result.lower()
        assert "Log line 1" in result or "Log line 2" in result


class TestCreateOptimizeContainerPrompt:
    """Test create_optimize_container_prompt."""

    def test_creates_prompt_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        name, description, func = create_optimize_container_prompt(mock_docker_client)

        assert name == "optimize_container"
        assert "optimi" in description.lower()
        assert callable(func)

    @pytest.mark.asyncio
    async def test_prompt_generation(self, mock_docker_client, mock_container):
        """Test prompt generation with optimization suggestions."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, _, prompt_func = create_optimize_container_prompt(mock_docker_client)

        result = await prompt_func("test-container")

        assert isinstance(result, str)
        assert "test-container" in result
        assert "optimization" in result.lower() or "optimi" in result.lower()


class TestCreateGenerateComposePrompt:
    """Test create_generate_compose_prompt."""

    def test_creates_prompt_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        name, description, func = create_generate_compose_prompt(mock_docker_client)

        assert name == "generate_compose"
        assert "compose" in description.lower()
        assert callable(func)

    @pytest.mark.asyncio
    async def test_prompt_generation(self, mock_docker_client, mock_container):
        """Test prompt generation for docker-compose."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, _, prompt_func = create_generate_compose_prompt(mock_docker_client)

        result = await prompt_func("test-container")

        assert isinstance(result, str)
        assert "test-container" in result
        assert "docker-compose" in result.lower()
        assert "nginx" in result


class TestCreateDebugNetworkingPrompt:
    """Test create_debug_networking_prompt."""

    def test_creates_prompt_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        name, description, func = create_debug_networking_prompt(mock_docker_client)

        assert name == "debug_networking"
        assert "network" in description.lower()
        assert callable(func)

    @pytest.mark.asyncio
    async def test_prompt_generation(self, mock_docker_client, mock_container):
        """Test prompt generation for network debugging."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, _, prompt_func = create_debug_networking_prompt(mock_docker_client)

        result = await prompt_func("test-container")

        assert isinstance(result, str)
        assert "test-container" in result
        assert "network" in result.lower()
        assert "172.17.0.2" in result  # IP address


class TestCreateSecurityAuditPrompt:
    """Test create_security_audit_prompt."""

    def test_creates_prompt_tuple(self, mock_docker_client):
        """Test that function returns correct tuple."""
        name, description, func = create_security_audit_prompt(mock_docker_client)

        assert name == "security_audit"
        assert "security" in description.lower()
        assert callable(func)

    @pytest.mark.asyncio
    async def test_prompt_generation_single_container(self, mock_docker_client, mock_container):
        """Test prompt generation for single container audit."""
        mock_docker_client.client.containers.get = Mock(return_value=mock_container)

        _, _, prompt_func = create_security_audit_prompt(mock_docker_client)

        result = await prompt_func("test-container")

        assert isinstance(result, str)
        assert "test-container" in result
        assert "security" in result.lower()

    @pytest.mark.asyncio
    async def test_prompt_generation_all_containers(self, mock_docker_client, mock_container):
        """Test prompt generation for all containers audit."""
        mock_docker_client.client.containers.list = Mock(return_value=[mock_container] * 3)

        _, _, prompt_func = create_security_audit_prompt(mock_docker_client)

        result = await prompt_func(None)  # None = audit all

        assert isinstance(result, str)
        assert "3 containers" in result
        assert "security" in result.lower()


class TestRegisterAllPrompts:
    """Test register_all_prompts."""

    def test_registers_all_prompts(self, mock_docker_client):
        """Test that all prompts are registered."""
        app = Mock()
        app.prompt = Mock(return_value=lambda f: f)  # Mock decorator

        registered = register_all_prompts(app, mock_docker_client)

        assert "docker" in registered
        assert len(registered["docker"]) == 5
        assert "troubleshoot_container" in registered["docker"]
        assert "optimize_container" in registered["docker"]
        assert "generate_compose" in registered["docker"]
        assert "debug_networking" in registered["docker"]
        assert "security_audit" in registered["docker"]

        # Verify app.prompt was called 5 times
        assert app.prompt.call_count == 5
