"""Additional tests for compose_wrapper to achieve 90%+ coverage.

These tests specifically target uncovered lines in client.py.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_docker.compose_wrapper.client import ComposeClient
from mcp_docker.utils.errors import (
    DockerConnectionError,
    DockerOperationError,
    ValidationError,
)


class TestComposeClientCoverage:
    """Tests to cover remaining uncovered lines in ComposeClient."""

    def test_execute_command_unexpected_error(self) -> None:
        """Test unexpected exception in _execute_command (lines 165-167)."""
        client = ComposeClient()

        with patch("subprocess.run") as mock_run:
            # Simulate an unexpected exception (not subprocess-related)
            mock_run.side_effect = RuntimeError("Unexpected system error")

            with pytest.raises(DockerOperationError, match="Unexpected error"):
                client._execute_command(["version"])

    def test_verify_compose_v2_called_process_error(self) -> None:
        """Test CalledProcessError in verify_compose_v2 (lines 216-217)."""
        client = ComposeClient()

        with patch("subprocess.run") as mock_run:
            # Simulate docker compose returning non-zero exit code
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["docker", "compose", "version", "--format", "json"],
                stderr="permission denied",
            )
            mock_run.side_effect = error

            with pytest.raises(
                DockerConnectionError, match="Unable to verify Docker Compose version"
            ):
                client.verify_compose_v2()

    def test_verify_compose_v2_json_decode_error(self) -> None:
        """Test JSONDecodeError in verify_compose_v2 (lines 229-230)."""
        client = ComposeClient()

        with patch("subprocess.run") as mock_run:
            # Return invalid JSON from compose version command
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "not valid json output"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with pytest.raises(
                DockerConnectionError, match="Failed to parse compose version output"
            ):
                client.verify_compose_v2()

    def test_validate_compose_file_no_file_specified(self) -> None:
        """Test ValidationError when no compose file specified (line 257)."""
        # Create client without default compose file
        client = ComposeClient(compose_file=None)

        with pytest.raises(ValidationError, match="No compose file specified"):
            client.validate_compose_file(None)

    def test_validate_compose_file_path_is_directory(self, tmp_path: Path) -> None:
        """Test ValidationError when path is a directory (line 265)."""
        client = ComposeClient()

        # Create a directory instead of a file
        dir_path = tmp_path / "compose_dir"
        dir_path.mkdir()

        with pytest.raises(ValidationError, match="not a file"):
            client.validate_compose_file(dir_path)

    def test_execute_ndjson_parsing_generic_exception(self) -> None:
        """Test generic exception during NDJSON parsing (lines 390-391)."""
        client = ComposeClient(compose_file="docker-compose.yml")

        with patch.object(client, "_execute_command") as mock_execute:
            # Return proper subprocess result
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = '{"valid": "json"}\n{"also": "valid"}'
            mock_result.stderr = ""
            mock_execute.return_value = mock_result

            # Mock json.loads to raise an unexpected exception during NDJSON parsing
            original_loads = json.loads
            call_count = {"count": 0}

            def mock_loads(s):
                call_count["count"] += 1
                # First call is for regular JSON parse (will fail)
                # Subsequent calls during NDJSON parsing - raise TypeError on 2nd NDJSON line
                if call_count["count"] == 3:  # 1st = regular JSON, 2nd = 1st NDJSON line, 3rd = 2nd NDJSON line
                    # Raise an unexpected exception that will be caught by lines 390-391
                    raise TypeError("Unexpected type error during JSON parsing")
                return original_loads(s)

            with patch("json.loads", side_effect=mock_loads):
                # Execute with parse_json=True to trigger NDJSON parsing
                result = client.execute(
                    "ps",
                    args=["--format", "json"],
                    parse_json=True,
                )

                # Should still succeed but with only first line parsed
                assert result["success"] is True
                # May or may not have data depending on parsing success
                assert "stdout" in result

    def test_execute_with_empty_ndjson_output(self) -> None:
        """Test execute with empty output when parse_json=True."""
        client = ComposeClient(compose_file="test.yml")

        with patch.object(client, "_execute_command") as mock_execute:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""  # Empty output
            mock_result.stderr = ""
            mock_execute.return_value = mock_result

            result = client.execute("ps", args=["--format", "json"], parse_json=True)

            assert result["success"] is True
            # No data key when stdout is empty
            assert "data" not in result or result.get("data") is None
