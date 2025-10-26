"""Unit tests for Docker Compose client wrapper."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.utils.errors import DockerConnectionError, DockerOperationError, ValidationError


@pytest.fixture
def compose_client() -> ComposeClient:
    """Create a Compose client for testing."""
    return ComposeClient(compose_file="docker-compose.yml", project_name="test-project")


@pytest.fixture
def mock_subprocess_success() -> MagicMock:
    """Create a mock successful subprocess result."""
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = "success"
    mock.stderr = ""
    return mock


@pytest.fixture
def mock_subprocess_failure() -> MagicMock:
    """Create a mock failed subprocess result."""
    mock = MagicMock()
    mock.returncode = 1
    mock.stdout = ""
    mock.stderr = "error occurred"
    return mock


class TestComposeClient:
    """Test Compose client functionality."""

    def test_initialization(self) -> None:
        """Test Compose client initialization."""
        client = ComposeClient(
            compose_file="test.yml",
            project_name="myproject",
            timeout=120,
        )
        assert client.compose_file == Path("test.yml")
        assert client.project_name == "myproject"
        assert client.timeout == 120

    def test_initialization_defaults(self) -> None:
        """Test Compose client initialization with defaults."""
        client = ComposeClient()
        assert client.compose_file is None
        assert client.project_name is None
        assert client.timeout == 300

    def test_build_base_command_minimal(self, compose_client: ComposeClient) -> None:
        """Test building minimal compose command."""
        cmd = compose_client._build_base_command()
        assert cmd == [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-p",
            "test-project",
        ]

    def test_build_base_command_no_file(self) -> None:
        """Test building compose command without file."""
        client = ComposeClient()
        cmd = client._build_base_command()
        assert cmd == ["docker", "compose"]

    def test_build_base_command_override(self, compose_client: ComposeClient) -> None:
        """Test building compose command with overrides."""
        cmd = compose_client._build_base_command(
            compose_file="other.yml",
            project_name="other-project",
        )
        assert cmd == [
            "docker",
            "compose",
            "-f",
            "other.yml",
            "-p",
            "other-project",
        ]

    def test_sanitize_command_args_valid(self, compose_client: ComposeClient) -> None:
        """Test sanitizing valid command arguments."""
        args = ["up", "-d", "--build"]
        result = compose_client._sanitize_command_args(args)
        assert result == ["up", "-d", "--build"]

    def test_sanitize_command_args_with_numbers(self, compose_client: ComposeClient) -> None:
        """Test sanitizing arguments with numbers."""
        args = ["scale", "web=3"]
        result = compose_client._sanitize_command_args(args)
        assert result == ["scale", "web=3"]

    def test_sanitize_command_args_allows_shell_chars(self, compose_client: ComposeClient) -> None:
        """Test that shell metacharacters are allowed (safe without shell=True)."""
        # These characters are safe when using subprocess without shell=True
        args = ["exec", "python -c \"print('hello')\"", "echo $HOME", "test > out.txt"]
        result = compose_client._sanitize_command_args(args)
        assert result == args

    def test_sanitize_command_args_rejects_null_byte(self, compose_client: ComposeClient) -> None:
        """Test rejection of null byte character."""
        args = ["up\x00malicious"]
        with pytest.raises(ValidationError, match="null byte"):
            compose_client._sanitize_command_args(args)

    def test_sanitize_command_args_rejects_newline(self, compose_client: ComposeClient) -> None:
        """Test rejection of newline characters."""
        args = ["up\nmalicious"]
        with pytest.raises(ValidationError, match="newline"):
            compose_client._sanitize_command_args(args)

    def test_sanitize_command_args_rejects_carriage_return(
        self, compose_client: ComposeClient
    ) -> None:
        """Test rejection of carriage return characters."""
        args = ["up\rmalicious"]
        with pytest.raises(ValidationError, match="newline"):
            compose_client._sanitize_command_args(args)

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_execute_command_success(
        self,
        mock_run: MagicMock,
        compose_client: ComposeClient,
        mock_subprocess_success: MagicMock,
    ) -> None:
        """Test successful command execution."""
        mock_run.return_value = mock_subprocess_success

        result = compose_client._execute_command(["up", "-d"])

        assert result.returncode == 0
        assert result.stdout == "success"
        mock_run.assert_called_once()

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_execute_command_with_timeout(
        self,
        mock_run: MagicMock,
        compose_client: ComposeClient,
        mock_subprocess_success: MagicMock,
    ) -> None:
        """Test command execution with custom timeout."""
        mock_run.return_value = mock_subprocess_success

        compose_client._execute_command(["up"], timeout=60)

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_execute_command_timeout_expired(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test command timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=10)

        with pytest.raises(DockerOperationError, match="timed out"):
            compose_client._execute_command(["up"])

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_execute_command_failure(
        self,
        mock_run: MagicMock,
        compose_client: ComposeClient,
        mock_subprocess_failure: MagicMock,
    ) -> None:
        """Test command execution failure."""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd="docker compose up",
            stderr="error occurred",
        )

        with pytest.raises(DockerOperationError, match="Compose command failed"):
            compose_client._execute_command(["up"])

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_execute_command_not_found(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test docker compose command not found."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(DockerConnectionError, match="docker compose command not found"):
            compose_client._execute_command(["up"])

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_verify_compose_v2_success(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test successful Docker Compose v2 verification."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"version": "v2.20.0"})
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = compose_client.verify_compose_v2()

        assert result["version"] == "v2.20.0"
        assert result["is_v2"] is True

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_verify_compose_v2_cached(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test that compose v2 verification is cached."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"version": "v2.20.0"})
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        # First call
        compose_client.verify_compose_v2()
        # Second call
        result = compose_client.verify_compose_v2()

        # Should only call subprocess once due to caching
        assert mock_run.call_count == 1
        assert result["version"] == "v2.20.0"

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_verify_compose_v1_detected(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test detection of Docker Compose v1."""
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"version": "1.29.0"})
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        with pytest.raises(DockerConnectionError, match="Compose v1 detected"):
            compose_client.verify_compose_v2()

    @patch("mcp_docker.compose_wrapper.client.subprocess.run")
    def test_verify_compose_not_installed(
        self, mock_run: MagicMock, compose_client: ComposeClient
    ) -> None:
        """Test when docker compose is not installed."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(DockerConnectionError, match="docker compose command not found"):
            compose_client.verify_compose_v2()

    def test_validate_compose_file_success(self, tmp_path: Path) -> None:
        """Test successful compose file validation."""
        # Create a test compose file
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")

        client = ComposeClient()

        with patch.object(client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_exec.return_value = mock_result

            result = client.validate_compose_file(compose_file)

            assert result["valid"] is True
            assert str(compose_file) in result["file"]

    def test_validate_compose_file_not_found(self) -> None:
        """Test validation with non-existent file."""
        client = ComposeClient()

        with pytest.raises(ValidationError, match="not found"):
            client.validate_compose_file("nonexistent.yml")

    def test_validate_compose_file_invalid(self, tmp_path: Path) -> None:
        """Test validation with invalid compose file."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("invalid yaml")

        client = ComposeClient()

        with patch.object(client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "Invalid YAML"
            mock_exec.return_value = mock_result

            result = client.validate_compose_file(compose_file)

            assert result["valid"] is False
            assert "error" in result

    def test_get_config_json(self, tmp_path: Path) -> None:
        """Test getting compose config as JSON."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")

        client = ComposeClient()

        with patch.object(client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.stdout = '{"services": {"web": {"image": "nginx"}}}'
            mock_result.returncode = 0
            mock_exec.return_value = mock_result

            result = client.get_config(compose_file, format_json=True)

            assert isinstance(result, dict)
            assert "services" in result

    def test_get_config_yaml(self, tmp_path: Path) -> None:
        """Test getting compose config as YAML."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")

        client = ComposeClient()

        with patch.object(client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.stdout = "version: '3'\nservices:\n  web:\n    image: nginx\n"
            mock_result.returncode = 0
            mock_exec.return_value = mock_result

            result = client.get_config(compose_file, format_json=False)

            assert isinstance(result, str)
            assert "services:" in result

    def test_get_config_no_file(self) -> None:
        """Test getting config without specifying file."""
        client = ComposeClient()

        with pytest.raises(ValidationError, match="No compose file specified"):
            client.get_config()

    def test_execute_subcommand_success(self, compose_client: ComposeClient) -> None:
        """Test executing a compose subcommand."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "Services started"
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            result = compose_client.execute("up", ["-d"])

            assert result["success"] is True
            assert result["exit_code"] == 0
            assert "Services started" in result["stdout"]

    def test_execute_subcommand_with_json(self, compose_client: ComposeClient) -> None:
        """Test executing subcommand with JSON parsing."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = '{"status": "running"}'
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            result = compose_client.execute("ps", ["--format", "json"], parse_json=True)

            assert result["success"] is True
            assert "data" in result
            assert result["data"]["status"] == "running"

    def test_execute_subcommand_with_ndjson(self, compose_client: ComposeClient) -> None:
        """Test executing subcommand with NDJSON parsing."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            # Simulate NDJSON output (newline-delimited JSON)
            mock_result.stdout = (
                '{"Name":"nginx","Service":"nginx","State":"running"}\n'
                '{"Name":"redis","Service":"redis","State":"running"}'
            )
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            result = compose_client.execute("ps", ["--format", "json"], parse_json=True)

            assert result["success"] is True
            assert "data" in result
            assert isinstance(result["data"], list)
            assert len(result["data"]) == 2
            assert result["data"][0]["Name"] == "nginx"
            assert result["data"][1]["Name"] == "redis"

    def test_execute_subcommand_with_ndjson_and_logs(self, compose_client: ComposeClient) -> None:
        """Test executing subcommand with NDJSON and log messages."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            # Simulate NDJSON output with log messages that should be filtered
            mock_result.stdout = (
                'time="2025-10-26T16:00:00Z" level=warning msg="test warning"\n'
                '{"Name":"nginx","Service":"nginx","State":"running"}\n'
                'time="2025-10-26T16:00:01Z" level=info msg="another log"\n'
                '{"Name":"redis","Service":"redis","State":"running"}'
            )
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            result = compose_client.execute("ps", ["--format", "json"], parse_json=True)

            assert result["success"] is True
            assert "data" in result
            assert isinstance(result["data"], list)
            assert len(result["data"]) == 2  # Only JSON objects, logs filtered out
            assert result["data"][0]["Name"] == "nginx"
            assert result["data"][1]["Name"] == "redis"

    def test_execute_subcommand_with_invalid_json(self, compose_client: ComposeClient) -> None:
        """Test executing subcommand with invalid JSON that can't be parsed."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            # Invalid JSON output
            mock_result.stdout = "not json at all"
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            result = compose_client.execute("ps", ["--format", "json"], parse_json=True)

            assert result["success"] is True
            assert "data" not in result  # No data when parsing fails

    def test_execute_subcommand_override_file(self, compose_client: ComposeClient) -> None:
        """Test executing subcommand with file override."""
        with patch.object(compose_client, "_execute_command") as mock_exec:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "success"
            mock_result.stderr = ""
            mock_exec.return_value = mock_result

            # Store original values
            original_file = compose_client.compose_file
            original_project = compose_client.project_name

            compose_client.execute(
                "up",
                compose_file="override.yml",
                project_name="override-project",
            )

            # Verify values were restored
            assert compose_client.compose_file == original_file
            assert compose_client.project_name == original_project

    def test_repr(self, compose_client: ComposeClient) -> None:
        """Test string representation."""
        repr_str = repr(compose_client)
        assert "ComposeClient" in repr_str
        assert "docker-compose.yml" in repr_str
        assert "test-project" in repr_str
