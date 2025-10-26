"""Integration tests for Docker Compose operations.

These tests require Docker Compose v2 to be running and will create/remove test compose projects.
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.config import Config
from mcp_docker.server import MCPDockerServer
from mcp_docker.utils.errors import DockerConnectionError, DockerOperationError


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    cfg = Config()
    cfg.safety.allow_destructive_operations = True
    cfg.safety.require_confirmation_for_destructive = False
    return cfg


@pytest.fixture
def mcp_server(integration_config: Config) -> MCPDockerServer:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    yield server


@pytest.fixture
def compose_client() -> ComposeClient:
    """Create ComposeClient instance."""
    return ComposeClient()


@pytest.fixture
def test_compose_file(tmp_path: Path) -> Path:
    """Create a temporary test compose file."""
    compose_content = {
        "services": {
            "web": {
                "image": "nginx:alpine",
                "ports": ["8080:80"],
                "environment": {"TEST_VAR": "integration_test"},
            }
        }
    }

    compose_file = tmp_path / "docker-compose.yml"
    with compose_file.open("w") as f:
        yaml.dump(compose_content, f)

    return compose_file


@pytest.fixture
def test_project_name() -> str:
    """Generate unique test project name."""
    return "mcp-docker-test-compose"


@pytest.fixture
async def cleanup_test_project(
    compose_client: ComposeClient, test_compose_file: Path, test_project_name: str
):
    """Cleanup fixture to remove test compose project after tests."""
    yield
    # Cleanup after test
    try:
        compose_client.execute(
            "down",
            args=["--volumes", "--remove-orphans"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )
    except Exception:
        pass  # Project doesn't exist or already removed


@pytest.mark.integration
class TestComposeClientIntegration:
    """Integration tests for ComposeClient."""

    async def test_verify_compose_v2(self, compose_client: ComposeClient):
        """Test verifying Docker Compose v2 installation."""
        result = compose_client.verify_compose_v2()

        assert result["is_v2"] is True
        assert "version" in result
        assert result["version"].startswith("2") or result["version"].startswith("v2")

    async def test_validate_compose_file(
        self, compose_client: ComposeClient, test_compose_file: Path
    ):
        """Test validating a compose file."""
        result = compose_client.validate_compose_file(test_compose_file)

        assert result["valid"] is True
        assert result["file"] == str(test_compose_file)

    async def test_validate_invalid_compose_file(
        self, compose_client: ComposeClient, tmp_path: Path
    ):
        """Test validating an invalid compose file."""
        invalid_file = tmp_path / "invalid.yml"
        invalid_file.write_text("invalid: yaml: content:\n  - broken")

        result = compose_client.validate_compose_file(invalid_file)

        assert result["valid"] is False
        assert "error" in result

    async def test_get_config_json(self, compose_client: ComposeClient, test_compose_file: Path):
        """Test getting compose config as JSON."""
        config = compose_client.get_config(test_compose_file, format_json=True)

        assert isinstance(config, dict)
        assert "services" in config
        assert "web" in config["services"]

    async def test_get_config_yaml(self, compose_client: ComposeClient, test_compose_file: Path):
        """Test getting compose config as YAML."""
        config = compose_client.get_config(test_compose_file, format_json=False)

        assert isinstance(config, str)
        assert "services:" in config
        assert "web:" in config

    async def test_compose_up_and_down(
        self,
        compose_client: ComposeClient,
        test_compose_file: Path,
        test_project_name: str,
        cleanup_test_project,
    ):
        """Test compose up and down operations."""
        # Start services
        up_result = compose_client.execute(
            "up",
            args=["-d"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        assert up_result["success"] is True
        assert up_result["exit_code"] == 0

        # Check services are running
        ps_result = compose_client.execute(
            "ps",
            args=["--format", "json"],
            compose_file=test_compose_file,
            project_name=test_project_name,
            parse_json=True,
        )

        assert ps_result["success"] is True
        assert "data" in ps_result
        services = ps_result["data"]
        assert len(services) > 0

        # Stop services
        down_result = compose_client.execute(
            "down",
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        assert down_result["success"] is True

    async def test_compose_ps(
        self,
        compose_client: ComposeClient,
        test_compose_file: Path,
        test_project_name: str,
        cleanup_test_project,
    ):
        """Test compose ps command."""
        # Start services first
        compose_client.execute(
            "up",
            args=["-d"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        # Get service status
        result = compose_client.execute(
            "ps",
            args=["--format", "json"],
            compose_file=test_compose_file,
            project_name=test_project_name,
            parse_json=True,
        )

        assert result["success"] is True
        assert "data" in result
        services = result["data"]

        # Docker compose ps --format json can return a single dict or list of dicts
        if isinstance(services, dict):
            services = [services]

        assert len(services) > 0

        # Verify web service is present
        service_names = [s.get("Service") or s.get("Name", "") for s in services]
        assert any("web" in name for name in service_names)

    async def test_compose_logs(
        self,
        compose_client: ComposeClient,
        test_compose_file: Path,
        test_project_name: str,
        cleanup_test_project,
    ):
        """Test compose logs command."""
        # Start services first
        compose_client.execute(
            "up",
            args=["-d"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        # Get logs
        result = compose_client.execute(
            "logs",
            args=["--tail", "10"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        assert result["success"] is True
        assert "stdout" in result

    async def test_compose_exec_with_parentheses(
        self,
        compose_client: ComposeClient,
        test_compose_file: Path,
        test_project_name: str,
        cleanup_test_project,
    ):
        """Test compose exec with commands containing parentheses (regression test)."""
        # Start services first
        compose_client.execute(
            "up",
            args=["-d"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        # Execute command with parentheses - this should not raise ValidationError
        result = compose_client.execute(
            "exec",
            args=["-T", "web", "sh", "-c", "echo 'test(123)'"],
            compose_file=test_compose_file,
            project_name=test_project_name,
        )

        # May fail if exec isn't supported, but should not raise ValidationError
        # The key test is that _sanitize_command_args doesn't block it
        assert "exit_code" in result

    async def test_compose_sanitization_rejects_null_bytes(self, compose_client: ComposeClient):
        """Test that sanitization still blocks null bytes."""
        from mcp_docker.utils.errors import ValidationError

        with pytest.raises(ValidationError, match="null byte"):
            compose_client._sanitize_command_args(["test\x00malicious"])

    async def test_compose_sanitization_rejects_newlines(self, compose_client: ComposeClient):
        """Test that sanitization still blocks newlines."""
        from mcp_docker.utils.errors import ValidationError

        with pytest.raises(ValidationError, match="newline"):
            compose_client._sanitize_command_args(["test\nmalicious"])


@pytest.mark.integration
class TestComposeToolsIntegration:
    """Integration tests for Docker Compose MCP tools."""

    async def test_compose_write_file_tool(self, mcp_server: MCPDockerServer):
        """Test the compose write file tool."""
        compose_content = {
            "services": {
                "test": {
                    "image": "alpine:latest",
                    "command": "echo 'test'",
                }
            }
        }

        result = await mcp_server.call_tool(
            "docker_compose_write_file",
            {
                "filename": "test-integration.yml",
                "content": compose_content,
                "validate_content": True,
            },
        )

        assert result["success"] is True
        # Result is nested under "result" key
        tool_result = result.get("result", result)
        assert "file_path" in tool_result
        assert "user-test-integration.yml" in tool_result["file_path"]
        assert tool_result.get("validation_result", {}).get("valid") is True

        # Verify file exists
        file_path = Path(tool_result["file_path"])
        assert file_path.exists()

        # Cleanup
        try:
            file_path.unlink()
        except Exception:
            pass

    async def test_compose_validate_tool(
        self, mcp_server: MCPDockerServer, test_compose_file: Path
    ):
        """Test the compose validate tool."""
        result = await mcp_server.call_tool(
            "docker_compose_validate",
            {"compose_file": str(test_compose_file)},
        )

        assert result["success"] is True
        # Result is nested under "result" key
        tool_result = result.get("result", result)
        assert tool_result["valid"] is True

    async def test_compose_config_tool(self, mcp_server: MCPDockerServer, test_compose_file: Path):
        """Test the compose config tool."""
        result = await mcp_server.call_tool(
            "docker_compose_config",
            {"compose_file": str(test_compose_file)},
        )

        assert result["success"] is True
        # Result is nested under "result" key
        tool_result = result.get("result", result)
        assert "config" in tool_result
        assert isinstance(tool_result["config"], dict)
        assert "services" in tool_result["config"]
