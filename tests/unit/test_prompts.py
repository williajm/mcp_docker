"""Unit tests for prompt templates."""

from unittest.mock import MagicMock, Mock

import pytest

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.prompts.templates import (
    DebugNetworkingOptions,
    DebugNetworkingPrompt,
    GenerateComposeOptions,
    GenerateComposePrompt,
    OptimizeContainerPrompt,
    OptimizeOptions,
    PromptProvider,
    SecurityAuditOptions,
    SecurityAuditPrompt,
    TroubleshootContainerPrompt,
    TroubleshootOptions,
)


@pytest.fixture
def mock_docker_client() -> DockerClientWrapper:
    """Create a mock Docker client."""
    client = Mock(spec=DockerClientWrapper)
    client.client = MagicMock()
    return client


@pytest.fixture
def troubleshoot_prompt(
    mock_docker_client: DockerClientWrapper,
) -> TroubleshootContainerPrompt:
    """Create a troubleshoot prompt."""
    return TroubleshootContainerPrompt(mock_docker_client)


@pytest.fixture
def optimize_prompt(mock_docker_client: DockerClientWrapper) -> OptimizeContainerPrompt:
    """Create an optimize prompt."""
    return OptimizeContainerPrompt(mock_docker_client)


@pytest.fixture
def generate_compose_prompt(
    mock_docker_client: DockerClientWrapper,
) -> GenerateComposePrompt:
    """Create a generate compose prompt."""
    return GenerateComposePrompt(mock_docker_client)


@pytest.fixture
def debug_networking_prompt(
    mock_docker_client: DockerClientWrapper,
) -> DebugNetworkingPrompt:
    """Create a debug networking prompt."""
    return DebugNetworkingPrompt(mock_docker_client)


@pytest.fixture
def security_audit_prompt(mock_docker_client: DockerClientWrapper) -> SecurityAuditPrompt:
    """Create a security audit prompt."""
    return SecurityAuditPrompt(mock_docker_client)


@pytest.fixture
def prompt_provider(mock_docker_client: DockerClientWrapper) -> PromptProvider:
    """Create a prompt provider."""
    return PromptProvider(mock_docker_client)


class TestTroubleshootContainerPrompt:
    """Test troubleshoot container prompt."""

    def test_get_metadata(self, troubleshoot_prompt: TroubleshootContainerPrompt) -> None:
        """Test getting prompt metadata."""
        metadata = troubleshoot_prompt.get_metadata()
        assert metadata.name == "troubleshoot_container"
        assert "troubleshoot" in metadata.description.lower()
        assert len(metadata.arguments) == 1
        assert metadata.arguments[0]["name"] == "container_id"
        assert metadata.arguments[0]["required"] is True

    @pytest.mark.asyncio
    async def test_generate_success(
        self,
        troubleshoot_prompt: TroubleshootContainerPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating troubleshoot prompt successfully."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.status = "exited"
        mock_container.logs.return_value = b"Error: Something went wrong\n"
        mock_container.attrs = {
            "State": {
                "Running": False,
                "ExitCode": 1,
                "Error": "Process exited with code 1",
            },
            "Config": {
                "Image": "nginx:latest",
                "Cmd": ["nginx", "-g", "daemon off;"],
                "Entrypoint": None,
                "Env": ["PATH=/usr/local/bin"],
            },
            "HostConfig": {"RestartPolicy": {"Name": "always"}},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt
        result = await troubleshoot_prompt.generate(TroubleshootOptions(container_id="abc123"))

        assert result.description is not None
        assert "abc123" in result.description
        assert len(result.messages) == 2

        # Check system message
        assert result.messages[0].role == "system"
        assert "troubleshoot" in result.messages[0].content.lower()

        # Check user message
        assert result.messages[1].role == "user"
        assert "abc123" in result.messages[1].content
        assert "exited" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_error(
        self,
        troubleshoot_prompt: TroubleshootContainerPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating troubleshoot prompt with error."""
        mock_docker_client.client.containers.get.side_effect = Exception("Container not found")

        # Should return fallback prompt
        result = await troubleshoot_prompt.generate(TroubleshootOptions(container_id="nonexistent"))

        assert result.description is not None
        assert "error" in result.description.lower()
        assert len(result.messages) == 1


class TestOptimizeContainerPrompt:
    """Test optimize container prompt."""

    def test_get_metadata(self, optimize_prompt: OptimizeContainerPrompt) -> None:
        """Test getting prompt metadata."""
        metadata = optimize_prompt.get_metadata()
        assert metadata.name == "optimize_container"
        assert "optim" in metadata.description.lower()
        assert len(metadata.arguments) == 1
        assert metadata.arguments[0]["name"] == "container_id"

    @pytest.mark.asyncio
    async def test_generate_running_container(
        self,
        optimize_prompt: OptimizeContainerPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating optimize prompt for running container."""
        # Mock running container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.status = "running"
        mock_container.attrs = {
            "Config": {
                "Image": "nginx:latest",
                "Env": ["PATH=/usr/local/bin"],
            },
            "HostConfig": {
                "RestartPolicy": {"Name": "no"},
                "Memory": 536870912,  # 512 MB
                "CpuShares": 1024,
                "Privileged": False,
                "NetworkMode": "bridge",
                "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
                "Binds": ["/data:/data"],
            },
        }
        mock_container.stats.return_value = {
            "memory_stats": {
                "usage": 104857600,  # 100 MB
                "limit": 536870912,  # 512 MB
            },
            "cpu_stats": {"online_cpus": 4},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt
        result = await optimize_prompt.generate(OptimizeOptions(container_id="abc123"))

        assert result.description is not None
        assert "abc123" in result.description
        assert len(result.messages) == 2

        # Check messages
        assert result.messages[0].role == "system"
        assert "optim" in result.messages[0].content.lower()
        assert result.messages[1].role == "user"
        assert "Memory:" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_stopped_container(
        self,
        optimize_prompt: OptimizeContainerPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating optimize prompt for stopped container."""
        # Mock stopped container
        mock_container = MagicMock()
        mock_container.short_id = "def456"
        mock_container.name = "stopped-container"
        mock_container.status = "exited"
        mock_container.attrs = {
            "Config": {"Image": "alpine:latest", "Env": []},
            "HostConfig": {
                "RestartPolicy": {"Name": "no"},
                "Memory": "unlimited",
                "CpuShares": "default",
                "Privileged": False,
                "NetworkMode": "default",
                "PortBindings": {},
                "Binds": [],
            },
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt
        result = await optimize_prompt.generate(OptimizeOptions(container_id="def456"))

        assert result.description is not None
        assert len(result.messages) == 2
        assert "not running" in result.messages[1].content


class TestGenerateComposePrompt:
    """Test generate compose prompt."""

    def test_get_metadata(self, generate_compose_prompt: GenerateComposePrompt) -> None:
        """Test getting prompt metadata."""
        metadata = generate_compose_prompt.get_metadata()
        assert metadata.name == "generate_compose"
        assert "docker-compose" in metadata.description.lower()
        assert len(metadata.arguments) == 2
        assert metadata.arguments[0]["name"] == "container_id"
        assert metadata.arguments[0]["required"] is False
        assert metadata.arguments[1]["name"] == "service_description"

    @pytest.mark.asyncio
    async def test_generate_from_container(
        self,
        generate_compose_prompt: GenerateComposePrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating compose from existing container."""
        # Mock container
        mock_container = MagicMock()
        mock_container.name = "web-app"
        mock_container.attrs = {
            "Config": {
                "Image": "nginx:latest",
                "Env": ["NGINX_PORT=80", "APP_ENV=production"],
            },
            "HostConfig": {
                "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
                "Binds": ["/data:/usr/share/nginx/html"],
                "RestartPolicy": {"Name": "always"},
                "NetworkMode": "bridge",
            },
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt
        result = await generate_compose_prompt.generate(
            GenerateComposeOptions(container_id="abc123")
        )

        assert result.description is not None
        assert len(result.messages) == 2
        assert result.messages[0].role == "system"
        assert "docker-compose" in result.messages[0].content.lower()
        assert result.messages[1].role == "user"
        assert "nginx:latest" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_from_description(
        self,
        generate_compose_prompt: GenerateComposePrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating compose from service description."""
        # Generate prompt with description only
        result = await generate_compose_prompt.generate(
            GenerateComposeOptions(service_description="A web app with nginx and postgres")
        )

        assert result.description is not None
        assert len(result.messages) == 2
        assert "web app with nginx and postgres" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_empty(
        self,
        generate_compose_prompt: GenerateComposePrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating compose with no parameters."""
        # Generate prompt with no parameters
        result = await generate_compose_prompt.generate(GenerateComposeOptions())

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_generate_container_error(
        self,
        generate_compose_prompt: GenerateComposePrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating compose when container fetch fails."""
        mock_docker_client.client.containers.get.side_effect = Exception("Container not found")

        # Should still generate a prompt with error note
        result = await generate_compose_prompt.generate(
            GenerateComposeOptions(container_id="nonexistent")
        )

        assert result.description is not None
        assert len(result.messages) == 2
        assert "Could not retrieve" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_with_null_fields(
        self,
        generate_compose_prompt: GenerateComposePrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating compose from container with null Env, PortBindings, and Binds."""
        # Mock container with None values (as Docker API often returns)
        mock_container = MagicMock()
        mock_container.name = "minimal-container"
        mock_container.attrs = {
            "Config": {
                "Image": "alpine:latest",
                "Env": None,  # Docker API returns None when no env vars
            },
            "HostConfig": {
                "PortBindings": None,  # Docker API returns None when no port bindings
                "Binds": None,  # Docker API returns None when no bind mounts
                "RestartPolicy": {"Name": "no"},
                "NetworkMode": "bridge",
            },
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Should not crash - this is the critical test
        result = await generate_compose_prompt.generate(
            GenerateComposeOptions(container_id="abc123")
        )

        assert result.description is not None
        assert len(result.messages) == 2
        assert "alpine:latest" in result.messages[1].content
        # Verify it handles null values gracefully
        assert "0 variables" in result.messages[1].content
        assert "0 ports" in result.messages[1].content
        assert "0 mounts" in result.messages[1].content


class TestDebugNetworkingPrompt:
    """Test debug networking prompt."""

    def test_get_metadata(self, debug_networking_prompt: DebugNetworkingPrompt) -> None:
        """Test getting prompt metadata."""
        metadata = debug_networking_prompt.get_metadata()
        assert metadata.name == "debug_networking"
        assert "network" in metadata.description.lower()
        assert len(metadata.arguments) == 2
        assert metadata.arguments[0]["name"] == "container_id"
        assert metadata.arguments[0]["required"] is True
        assert metadata.arguments[1]["name"] == "target_host"
        assert metadata.arguments[1]["required"] is False

    @pytest.mark.asyncio
    async def test_generate_success(
        self,
        debug_networking_prompt: DebugNetworkingPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating network debug prompt successfully."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.status = "running"
        mock_container.logs.return_value = b"Connection refused\nTimeout error\n"
        mock_container.attrs = {
            "Config": {"Hostname": "test-host"},
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
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt
        result = await debug_networking_prompt.generate(
            DebugNetworkingOptions(container_id="abc123")
        )

        assert result.description is not None
        assert "abc123" in result.description
        assert len(result.messages) == 2

        # Check system message
        assert result.messages[0].role == "system"
        assert "network" in result.messages[0].content.lower()

        # Check user message
        assert result.messages[1].role == "user"
        assert "172.17.0.2" in result.messages[1].content
        assert "8080" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_with_target_host(
        self,
        debug_networking_prompt: DebugNetworkingPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating network debug prompt with target host."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.status = "running"
        mock_container.logs.return_value = b"Connection logs"
        mock_container.attrs = {
            "Config": {"Hostname": "test-host"},
            "NetworkSettings": {"Networks": {}, "Ports": {}},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt with target host
        result = await debug_networking_prompt.generate(
            DebugNetworkingOptions(container_id="abc123", target_host="example.com")
        )

        assert result.description is not None
        assert len(result.messages) == 2
        assert "example.com" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_error(
        self,
        debug_networking_prompt: DebugNetworkingPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating network debug prompt with error."""
        mock_docker_client.client.containers.get.side_effect = Exception("Container not found")

        # Should return fallback prompt
        result = await debug_networking_prompt.generate(
            DebugNetworkingOptions(container_id="nonexistent")
        )

        assert result.description is not None
        assert "error" in result.description.lower()
        assert len(result.messages) == 1


class TestSecurityAuditPrompt:
    """Test security audit prompt."""

    def test_get_metadata(self, security_audit_prompt: SecurityAuditPrompt) -> None:
        """Test getting prompt metadata."""
        metadata = security_audit_prompt.get_metadata()
        assert metadata.name == "security_audit"
        assert "security" in metadata.description.lower()
        assert len(metadata.arguments) == 1
        assert metadata.arguments[0]["name"] == "container_id"
        assert metadata.arguments[0]["required"] is False

    @pytest.mark.asyncio
    async def test_generate_single_container(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating security audit for single container."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.attrs = {
            "Config": {
                "Image": "nginx:latest",
                "User": "root",
                "Env": ["PASSWORD=secret123", "API_KEY=xyz"],
            },
            "HostConfig": {
                "Privileged": True,
                "CapAdd": ["SYS_ADMIN"],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
            },
            "NetworkSettings": {"Ports": {"22/tcp": [{"HostIp": "0.0.0.0", "HostPort": "22"}]}},
            "Mounts": [
                {
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "Type": "bind",
                    "RW": True,
                }
            ],
        }
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": ["apparmor", "seccomp"],
        }

        # Generate prompt
        result = await security_audit_prompt.generate(SecurityAuditOptions(container_id="abc123"))

        assert result.description is not None
        assert "1 container" in result.description
        assert len(result.messages) == 2

        # Check system message
        assert result.messages[0].role == "system"
        assert "security" in result.messages[0].content.lower()

        # Check user message
        assert result.messages[1].role == "user"
        assert "Privileged Mode" in result.messages[1].content
        assert "root" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_all_containers(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating security audit for all containers."""
        # Mock multiple containers
        mock_container1 = MagicMock()
        mock_container1.short_id = "abc123"
        mock_container1.name = "container1"
        mock_container1.attrs = {
            "Config": {"Image": "nginx:latest", "User": "", "Env": []},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "ReadonlyRootfs": True,
            },
            "NetworkSettings": {"Ports": {}},
            "Mounts": [],
        }

        mock_container2 = MagicMock()
        mock_container2.short_id = "def456"
        mock_container2.name = "container2"
        mock_container2.attrs = {
            "Config": {"Image": "redis:latest", "User": "redis", "Env": []},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
            },
            "NetworkSettings": {"Ports": {}},
            "Mounts": [],
        }

        mock_docker_client.client.containers.list.return_value = [
            mock_container1,
            mock_container2,
        ]
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        # Generate prompt without container_id (audit all)
        result = await security_audit_prompt.generate(SecurityAuditOptions())

        # Verify all=True was passed to list all containers
        mock_docker_client.client.containers.list.assert_called_once_with(all=True)

        assert result.description is not None
        assert "2 container" in result.description
        assert len(result.messages) == 2
        assert "container1" in result.messages[1].content
        assert "container2" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_generate_no_containers(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating security audit with no containers."""
        mock_docker_client.client.containers.list.return_value = []

        # Generate prompt
        result = await security_audit_prompt.generate(SecurityAuditOptions())

        assert result.description is not None
        assert "no containers" in result.description.lower()
        assert len(result.messages) == 1
        assert "No containers found" in result.messages[0].content

    @pytest.mark.asyncio
    async def test_generate_error(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test generating security audit with error."""
        mock_docker_client.client.containers.get.side_effect = Exception("Container not found")

        # Should return fallback prompt
        result = await security_audit_prompt.generate(
            SecurityAuditOptions(container_id="nonexistent")
        )

        assert result.description is not None
        assert "error" in result.description.lower()
        assert len(result.messages) == 1

    @pytest.mark.asyncio
    async def test_generate_detects_ssh_mounts(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test that SSH directory mounts are properly detected as sensitive."""
        # Mock container with various SSH mounts
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-ssh-mounts"
        mock_container.attrs = {
            "Config": {"Image": "test:latest", "User": "", "Env": []},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
            },
            "NetworkSettings": {"Ports": {}},
            "Mounts": [
                {
                    "Source": "/root/.ssh",
                    "Destination": "/root/.ssh",
                    "Type": "bind",
                    "RW": True,
                },
                {
                    "Source": "/home/user/.ssh",
                    "Destination": "/home/user/.ssh",
                    "Type": "bind",
                    "RW": True,
                },
                {
                    "Source": "/home/dev/.ssh/id_rsa",
                    "Destination": "/keys/id_rsa",
                    "Type": "bind",
                    "RW": False,
                },
            ],
        }
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        # Generate prompt
        result = await security_audit_prompt.generate(SecurityAuditOptions(container_id="abc123"))

        # Verify SSH mounts are detected
        content = result.messages[1].content
        assert "/root/.ssh" in content
        assert "/home/user/.ssh" in content
        assert "/home/dev/.ssh/id_rsa" in content

    @pytest.mark.asyncio
    async def test_generate_handles_null_ports_and_env(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test that security audit handles null Ports and Env gracefully."""
        # Mock container with null Ports and Env (like scratch images)
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "scratch-container"
        mock_container.attrs = {
            "Config": {
                "Image": "scratch",
                "User": "",
                "Env": None,  # null Env (common in minimal images)
            },
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
                "Memory": 0,
                "CpuShares": 0,
                "RestartPolicy": {"Name": "no"},
                "NetworkMode": "bridge",
            },
            "NetworkSettings": {
                "Ports": None,  # null Ports (common when no ports exposed)
            },
            "Mounts": [],
        }
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        # Generate prompt - should not crash
        result = await security_audit_prompt.generate(SecurityAuditOptions(container_id="abc123"))

        # Verify it completed successfully
        assert result.description is not None
        assert len(result.messages) == 2
        assert "scratch" in result.messages[1].content

    @pytest.mark.asyncio
    async def test_network_isolation_default_is_bridge(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test that 'default' network mode is correctly identified as bridge (not isolated)."""
        # Mock container with "default" network mode
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "default-network"
        mock_container.attrs = {
            "Config": {"Image": "test:latest", "User": "", "Env": []},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
                "Memory": 0,
                "CpuShares": 0,
                "RestartPolicy": {"Name": "no"},
                "NetworkMode": "default",  # default = bridge
            },
            "NetworkSettings": {"Ports": None},
            "Mounts": [],
        }
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        # Generate prompt
        result = await security_audit_prompt.generate(SecurityAuditOptions(container_id="abc123"))

        # Verify "default" is treated as bridge (warning, not isolated)
        content = result.messages[1].content
        assert "⚠️ BRIDGE mode" in content
        assert "✓ Isolated" not in content

    @pytest.mark.asyncio
    async def test_container_cap_limits_audit(
        self,
        security_audit_prompt: SecurityAuditPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test that auditing all containers caps at 20 to avoid token limits."""
        # Mock 25 containers
        mock_containers = []
        for i in range(25):
            mock_container = MagicMock()
            mock_container.short_id = f"abc{i:03d}"
            mock_container.name = f"container{i}"
            mock_container.attrs = {
                "Config": {"Image": "test:latest", "User": "", "Env": []},
                "HostConfig": {
                    "Privileged": False,
                    "CapAdd": [],
                    "CapDrop": [],
                    "SecurityOpt": [],
                    "ReadonlyRootfs": False,
                    "Memory": 0,
                    "CpuShares": 0,
                    "RestartPolicy": {"Name": "no"},
                    "NetworkMode": "bridge",
                },
                "NetworkSettings": {"Ports": None},
                "Mounts": [],
            }
            mock_containers.append(mock_container)

        mock_docker_client.client.containers.list.return_value = mock_containers
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        # Generate prompt without container_id (audit all)
        result = await security_audit_prompt.generate(SecurityAuditOptions())

        # Verify only 20 containers are included and truncation warning is present
        content = result.messages[1].content
        assert "Only showing first 20 of 25 containers" in content
        # Verify the last container (container19) is included but container20 is not
        assert "container19" in content
        assert "container20" not in content


class TestDebugNetworkingNullHandling:
    """Test debug networking prompt null handling."""

    @pytest.mark.asyncio
    async def test_handles_null_ports(
        self,
        debug_networking_prompt: DebugNetworkingPrompt,
        mock_docker_client: DockerClientWrapper,
    ) -> None:
        """Test that debug networking handles null Ports gracefully."""
        # Mock container with null Ports
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test-container"
        mock_container.status = "running"
        mock_container.logs.return_value = b"Connection logs"
        mock_container.attrs = {
            "Config": {"Hostname": "test-host"},
            "NetworkSettings": {
                "Networks": {},
                "Ports": None,  # null Ports
            },
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        # Generate prompt - should not crash
        result = await debug_networking_prompt.generate(
            DebugNetworkingOptions(container_id="abc123")
        )

        # Verify it completed successfully
        assert result.description is not None
        assert len(result.messages) == 2


class TestPromptProvider:
    """Test prompt provider."""

    def test_initialization(self, prompt_provider: PromptProvider) -> None:
        """Test prompt provider initialization."""
        assert prompt_provider.troubleshoot_prompt is not None
        assert prompt_provider.optimize_prompt is not None
        assert prompt_provider.generate_compose_prompt is not None
        assert prompt_provider.debug_networking_prompt is not None
        assert prompt_provider.security_audit_prompt is not None
        assert len(prompt_provider.prompts) == 5

    def test_list_prompts(self, prompt_provider: PromptProvider) -> None:
        """Test listing prompts."""
        prompts = prompt_provider.list_prompts()
        assert len(prompts) == 5

        prompt_names = [p.name for p in prompts]
        assert "troubleshoot_container" in prompt_names
        assert "optimize_container" in prompt_names
        assert "generate_compose" in prompt_names
        assert "debug_networking" in prompt_names
        assert "security_audit" in prompt_names

    @pytest.mark.asyncio
    async def test_get_prompt_troubleshoot(
        self, prompt_provider: PromptProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test getting troubleshoot prompt."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test"
        mock_container.status = "running"
        mock_container.logs.return_value = b"logs"
        mock_container.attrs = {
            "State": {"Running": True},
            "Config": {"Image": "test:latest"},
            "HostConfig": {},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        result = await prompt_provider.get_prompt(
            "troubleshoot_container", {"container_id": "abc123"}
        )

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_get_prompt_optimize(
        self, prompt_provider: PromptProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test getting optimize prompt."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test"
        mock_container.status = "running"
        mock_container.stats.return_value = {
            "memory_stats": {"usage": 1000, "limit": 10000},
            "cpu_stats": {"online_cpus": 2},
        }
        mock_container.attrs = {
            "Config": {"Image": "test:latest"},
            "HostConfig": {},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        result = await prompt_provider.get_prompt("optimize_container", {"container_id": "abc123"})

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_get_prompt_generate_compose(
        self, prompt_provider: PromptProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test getting generate compose prompt."""
        result = await prompt_provider.get_prompt(
            "generate_compose", {"service_description": "web app"}
        )

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_get_prompt_unknown(self, prompt_provider: PromptProvider) -> None:
        """Test getting unknown prompt."""
        with pytest.raises(ValueError, match="Unknown prompt"):
            await prompt_provider.get_prompt("unknown_prompt", {})

    @pytest.mark.asyncio
    async def test_get_prompt_debug_networking(
        self, prompt_provider: PromptProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test getting debug networking prompt."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test"
        mock_container.status = "running"
        mock_container.logs.return_value = b"logs"
        mock_container.attrs = {
            "Config": {"Hostname": "test"},
            "NetworkSettings": {"Networks": {}, "Ports": {}},
        }
        mock_docker_client.client.containers.get.return_value = mock_container

        result = await prompt_provider.get_prompt("debug_networking", {"container_id": "abc123"})

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_get_prompt_security_audit(
        self, prompt_provider: PromptProvider, mock_docker_client: DockerClientWrapper
    ) -> None:
        """Test getting security audit prompt."""
        # Mock container
        mock_container = MagicMock()
        mock_container.short_id = "abc123"
        mock_container.name = "test"
        mock_container.attrs = {
            "Config": {"Image": "test:latest", "User": "", "Env": []},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": [],
                "CapDrop": [],
                "SecurityOpt": [],
                "ReadonlyRootfs": False,
            },
            "NetworkSettings": {"Ports": {}},
            "Mounts": [],
        }
        mock_docker_client.client.containers.get.return_value = mock_container
        mock_docker_client.client.info.return_value = {
            "ServerVersion": "24.0.0",
            "SecurityOptions": [],
        }

        result = await prompt_provider.get_prompt("security_audit", {"container_id": "abc123"})

        assert result.description is not None
        assert len(result.messages) == 2

    @pytest.mark.asyncio
    async def test_get_prompt_missing_required_arg(self, prompt_provider: PromptProvider) -> None:
        """Test getting prompt with missing required argument."""
        with pytest.raises(ValueError, match="container_id is required"):
            await prompt_provider.get_prompt("troubleshoot_container", {})

        with pytest.raises(ValueError, match="container_id is required"):
            await prompt_provider.get_prompt("optimize_container", {})

        with pytest.raises(ValueError, match="container_id is required"):
            await prompt_provider.get_prompt("debug_networking", {})
