"""Unit tests for Docker Compose tools."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.config import SafetyConfig
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.tools.compose_tools import (
    ComposeBuildInput,
    ComposeBuildTool,
    ComposeConfigInput,
    ComposeConfigTool,
    ComposeDownInput,
    ComposeDownTool,
    ComposeExecInput,
    ComposeExecTool,
    ComposeLogsInput,
    ComposeLogsTool,
    ComposePsInput,
    ComposePsTool,
    ComposeRestartInput,
    ComposeRestartTool,
    ComposeScaleInput,
    ComposeScaleTool,
    ComposeStopInput,
    ComposeStopTool,
    ComposeUpInput,
    ComposeUpTool,
    ComposeValidateInput,
    ComposeValidateTool,
)
from mcp_docker.utils.errors import DockerOperationError, ValidationError
from mcp_docker.utils.safety import OperationSafety


@pytest.fixture
def docker_client() -> MagicMock:
    """Create a mock Docker client."""
    return MagicMock(spec=DockerClientWrapper)


@pytest.fixture
def safety_config() -> SafetyConfig:
    """Create a safety configuration."""
    return SafetyConfig(allow_destructive_operations=True)


@pytest.fixture
def compose_client() -> MagicMock:
    """Create a mock Compose client."""
    return MagicMock(spec=ComposeClient)


@pytest.fixture
def compose_file(tmp_path: Path) -> Path:
    """Create a temporary compose file."""
    file_path = tmp_path / "docker-compose.yml"
    file_path.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")
    return file_path


class TestComposeUpTool:
    """Test Compose up tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeUpTool:
        """Create a ComposeUpTool instance."""
        return ComposeUpTool(docker_client, safety_config, compose_client)

    def test_name(self, tool: ComposeUpTool) -> None:
        """Test tool name."""
        assert tool.name == "docker_compose_up"

    def test_safety_level(self, tool: ComposeUpTool) -> None:
        """Test tool safety level."""
        assert tool.safety_level == OperationSafety.MODERATE

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeUpTool, compose_file: Path) -> None:
        """Test successful compose up execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Services started",
            "stderr": "",
        }

        input_data = ComposeUpInput(
            compose_file=str(compose_file),
            services=["web"],
            detach=True,
        )

        result = await tool.execute(input_data)

        assert result.success is True
        assert "started successfully" in result.message
        tool.compose.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_failure(self, tool: ComposeUpTool, compose_file: Path) -> None:
        """Test compose up execution failure."""
        tool.compose.execute.return_value = {
            "success": False,
            "stdout": "",
            "stderr": "Failed to start",
        }

        input_data = ComposeUpInput(compose_file=str(compose_file))

        with pytest.raises(DockerOperationError, match="Failed to start"):
            await tool.execute(input_data)

    @pytest.mark.asyncio
    async def test_execute_with_build(self, tool: ComposeUpTool, compose_file: Path) -> None:
        """Test compose up with build option."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Building and starting",
            "stderr": "",
        }

        input_data = ComposeUpInput(
            compose_file=str(compose_file),
            build=True,
        )

        result = await tool.execute(input_data)

        assert result.success is True
        # Verify --build was passed
        call_args = tool.compose.execute.call_args
        assert "--build" in call_args[1]["args"]


class TestComposeDownTool:
    """Test Compose down tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeDownTool:
        """Create a ComposeDownTool instance."""
        return ComposeDownTool(docker_client, safety_config, compose_client)

    def test_safety_level(self, tool: ComposeDownTool) -> None:
        """Test tool safety level is destructive."""
        assert tool.safety_level == OperationSafety.DESTRUCTIVE

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeDownTool, compose_file: Path) -> None:
        """Test successful compose down execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Services stopped",
            "stderr": "",
        }

        input_data = ComposeDownInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert result.success is True
        assert "stopped and removed" in result.message

    @pytest.mark.asyncio
    async def test_execute_with_volumes(self, tool: ComposeDownTool, compose_file: Path) -> None:
        """Test compose down with volume removal."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Stopped",
            "stderr": "",
        }

        input_data = ComposeDownInput(
            compose_file=str(compose_file),
            remove_volumes=True,
        )

        result = await tool.execute(input_data)

        assert result.success is True
        # Verify --volumes was passed
        call_args = tool.compose.execute.call_args
        assert "--volumes" in call_args[1]["args"]


class TestComposeRestartTool:
    """Test Compose restart tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeRestartTool:
        """Create a ComposeRestartTool instance."""
        return ComposeRestartTool(docker_client, safety_config, compose_client)

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeRestartTool, compose_file: Path) -> None:
        """Test successful compose restart execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Services restarted",
            "stderr": "",
        }

        input_data = ComposeRestartInput(
            compose_file=str(compose_file),
            services=["web", "db"],
        )

        result = await tool.execute(input_data)

        assert result.success is True
        assert "restarted successfully" in result.message


class TestComposeStopTool:
    """Test Compose stop tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeStopTool:
        """Create a ComposeStopTool instance."""
        return ComposeStopTool(docker_client, safety_config, compose_client)

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeStopTool, compose_file: Path) -> None:
        """Test successful compose stop execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Services stopped",
            "stderr": "",
        }

        input_data = ComposeStopInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert result.success is True
        assert "stopped successfully" in result.message


class TestComposeScaleTool:
    """Test Compose scale tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeScaleTool:
        """Create a ComposeScaleTool instance."""
        return ComposeScaleTool(docker_client, safety_config, compose_client)

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeScaleTool, compose_file: Path) -> None:
        """Test successful compose scale execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Services scaled",
            "stderr": "",
        }

        input_data = ComposeScaleInput(
            compose_file=str(compose_file),
            service_replicas={"web": 3, "api": 2},
        )

        result = await tool.execute(input_data)

        assert result.success is True
        assert result.scaled_services == {"web": 3, "api": 2}

    @pytest.mark.asyncio
    async def test_execute_invalid_replica_count(
        self, tool: ComposeScaleTool, compose_file: Path
    ) -> None:
        """Test scale with invalid replica count."""
        input_data = ComposeScaleInput(
            compose_file=str(compose_file),
            service_replicas={"web": -1},
        )

        with pytest.raises(ValidationError, match="Replica count must be >= 0"):
            await tool.execute(input_data)


class TestComposePsTool:
    """Test Compose ps tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposePsTool:
        """Create a ComposePsTool instance."""
        return ComposePsTool(docker_client, safety_config, compose_client)

    def test_safety_level(self, tool: ComposePsTool) -> None:
        """Test tool safety level is safe."""
        assert tool.safety_level == OperationSafety.SAFE

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposePsTool, compose_file: Path) -> None:
        """Test successful compose ps execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "[]",
            "stderr": "",
            "data": [
                {"Name": "web", "State": "running"},
                {"Name": "db", "State": "running"},
            ],
        }

        input_data = ComposePsInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert result.count == 2
        assert len(result.services) == 2


class TestComposeLogsTool:
    """Test Compose logs tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeLogsTool:
        """Create a ComposeLogsTool instance."""
        return ComposeLogsTool(docker_client, safety_config, compose_client)

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeLogsTool, compose_file: Path) -> None:
        """Test successful compose logs execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "web | Starting nginx\ndb | Starting postgres",
            "stderr": "",
        }

        input_data = ComposeLogsInput(
            compose_file=str(compose_file),
            tail=100,
        )

        result = await tool.execute(input_data)

        assert "nginx" in result.logs
        assert "postgres" in result.logs

    @pytest.mark.asyncio
    async def test_execute_follow_not_supported(
        self, tool: ComposeLogsTool, compose_file: Path
    ) -> None:
        """Test that follow mode raises error."""
        input_data = ComposeLogsInput(
            compose_file=str(compose_file),
            follow=True,
        )

        with pytest.raises(ValidationError, match="Follow mode is not supported"):
            await tool.execute(input_data)


class TestComposeExecTool:
    """Test Compose exec tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeExecTool:
        """Create a ComposeExecTool instance."""
        return ComposeExecTool(docker_client, safety_config, compose_client)

    def test_safety_level(self, tool: ComposeExecTool) -> None:
        """Test tool safety level is moderate."""
        assert tool.safety_level == OperationSafety.MODERATE

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeExecTool, compose_file: Path) -> None:
        """Test successful compose exec execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "command output",
            "stderr": "",
        }

        input_data = ComposeExecInput(
            compose_file=str(compose_file),
            service="web",
            command=["ls", "-la"],
        )

        result = await tool.execute(input_data)

        assert result.exit_code == 0
        assert "command output" in result.output
        assert result.service == "web"

    @pytest.mark.asyncio
    async def test_execute_with_environment(
        self, tool: ComposeExecTool, compose_file: Path
    ) -> None:
        """Test compose exec with environment variables."""
        tool.compose.execute.return_value = {
            "success": True,
            "exit_code": 0,
            "stdout": "output",
            "stderr": "",
        }

        input_data = ComposeExecInput(
            compose_file=str(compose_file),
            service="web",
            command="env",
            environment={"DEBUG": "true"},
        )

        result = await tool.execute(input_data)

        assert result.exit_code == 0
        # Verify --env was passed
        call_args = tool.compose.execute.call_args
        assert "--env" in call_args[1]["args"]


class TestComposeValidateTool:
    """Test Compose validate tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeValidateTool:
        """Create a ComposeValidateTool instance."""
        return ComposeValidateTool(docker_client, safety_config, compose_client)

    def test_safety_level(self, tool: ComposeValidateTool) -> None:
        """Test tool safety level is safe."""
        assert tool.safety_level == OperationSafety.SAFE

    @pytest.mark.asyncio
    async def test_execute_valid_file(self, tool: ComposeValidateTool, compose_file: Path) -> None:
        """Test validation of valid compose file."""
        tool.compose.validate_compose_file.return_value = {
            "valid": True,
            "file": str(compose_file),
        }

        input_data = ComposeValidateInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert result.valid is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_execute_invalid_file(
        self, tool: ComposeValidateTool, compose_file: Path
    ) -> None:
        """Test validation of invalid compose file."""
        tool.compose.validate_compose_file.return_value = {
            "valid": False,
            "error": "Invalid YAML",
        }

        input_data = ComposeValidateInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert result.valid is False
        assert "Invalid YAML" in result.error  # type: ignore


class TestComposeConfigTool:
    """Test Compose config tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeConfigTool:
        """Create a ComposeConfigTool instance."""
        return ComposeConfigTool(docker_client, safety_config, compose_client)

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeConfigTool, compose_file: Path) -> None:
        """Test successful compose config execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": '{"services": {"web": {"image": "nginx"}}}',
            "stderr": "",
            "data": {"services": {"web": {"image": "nginx"}}},
        }

        input_data = ComposeConfigInput(compose_file=str(compose_file))

        result = await tool.execute(input_data)

        assert "services" in result.config
        assert "web" in result.config["services"]


class TestComposeBuildTool:
    """Test Compose build tool."""

    @pytest.fixture
    def tool(
        self,
        docker_client: MagicMock,
        safety_config: SafetyConfig,
        compose_client: MagicMock,
    ) -> ComposeBuildTool:
        """Create a ComposeBuildTool instance."""
        return ComposeBuildTool(docker_client, safety_config, compose_client)

    def test_safety_level(self, tool: ComposeBuildTool) -> None:
        """Test tool safety level is moderate."""
        assert tool.safety_level == OperationSafety.MODERATE

    @pytest.mark.asyncio
    async def test_execute_success(self, tool: ComposeBuildTool, compose_file: Path) -> None:
        """Test successful compose build execution."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Building web...",
            "stderr": "",
        }

        input_data = ComposeBuildInput(
            compose_file=str(compose_file),
            services=["web"],
            no_cache=True,
        )

        result = await tool.execute(input_data)

        assert result.success is True
        assert "built successfully" in result.message
        # Verify --no-cache was passed
        call_args = tool.compose.execute.call_args
        assert "--no-cache" in call_args[1]["args"]

    @pytest.mark.asyncio
    async def test_execute_with_parallel(self, tool: ComposeBuildTool, compose_file: Path) -> None:
        """Test compose build with parallel option."""
        tool.compose.execute.return_value = {
            "success": True,
            "stdout": "Building...",
            "stderr": "",
        }

        input_data = ComposeBuildInput(
            compose_file=str(compose_file),
            parallel=True,
        )

        result = await tool.execute(input_data)

        assert result.success is True
        # Verify --parallel was passed
        call_args = tool.compose.execute.call_args
        assert "--parallel" in call_args[1]["args"]
