"""Unit tests for prompt templates."""

from unittest.mock import MagicMock, Mock

import pytest

from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.prompts.templates import (
    GenerateComposePrompt,
    OptimizeContainerPrompt,
    PromptProvider,
    TroubleshootContainerPrompt,
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
        result = await troubleshoot_prompt.generate("abc123")

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
        result = await troubleshoot_prompt.generate("nonexistent")

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
        result = await optimize_prompt.generate("abc123")

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
        result = await optimize_prompt.generate("def456")

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
        result = await generate_compose_prompt.generate(container_id="abc123")

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
            service_description="A web app with nginx and postgres"
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
        result = await generate_compose_prompt.generate()

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
        result = await generate_compose_prompt.generate(container_id="nonexistent")

        assert result.description is not None
        assert len(result.messages) == 2
        assert "Could not retrieve" in result.messages[1].content


class TestPromptProvider:
    """Test prompt provider."""

    def test_initialization(self, prompt_provider: PromptProvider) -> None:
        """Test prompt provider initialization."""
        assert prompt_provider.troubleshoot_prompt is not None
        assert prompt_provider.optimize_prompt is not None
        assert prompt_provider.generate_compose_prompt is not None
        assert prompt_provider.troubleshoot_compose_prompt is not None
        assert prompt_provider.optimize_compose_prompt is not None
        assert len(prompt_provider.prompts) == 5

    def test_list_prompts(self, prompt_provider: PromptProvider) -> None:
        """Test listing prompts."""
        prompts = prompt_provider.list_prompts()
        assert len(prompts) == 5

        prompt_names = [p.name for p in prompts]
        assert "troubleshoot_container" in prompt_names
        assert "optimize_container" in prompt_names
        assert "generate_compose" in prompt_names
        assert "troubleshoot_compose_stack" in prompt_names
        assert "optimize_compose_config" in prompt_names

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
    async def test_get_prompt_missing_required_arg(self, prompt_provider: PromptProvider) -> None:
        """Test getting prompt with missing required argument."""
        with pytest.raises(ValueError, match="container_id is required"):
            await prompt_provider.get_prompt("troubleshoot_container", {})

        with pytest.raises(ValueError, match="container_id is required"):
            await prompt_provider.get_prompt("optimize_container", {})
