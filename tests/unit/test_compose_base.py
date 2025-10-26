"""Unit tests for ComposeBaseTool."""

from unittest.mock import MagicMock, patch

import pytest

from mcp_docker.config import SafetyConfig
from mcp_docker.tools.compose_base import ComposeBaseTool
from mcp_docker.utils.errors import ValidationError


class TestComposeValidation:
    """Tests for ComposeBaseTool validation methods."""

    @pytest.fixture
    def docker_client(self):
        """Create a mock Docker client."""
        return MagicMock()

    @pytest.fixture
    def safety_config(self):
        """Create a safety configuration."""
        return SafetyConfig()

    @pytest.fixture
    def compose_client(self):
        """Create a mock Compose client."""
        return MagicMock()

    @pytest.fixture
    def compose_tool(self, docker_client, safety_config, compose_client, tmp_path):
        """Create a ComposeBaseTool instance for testing."""
        # Create a temporary compose file
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("""
version: '3.8'
services:
  test:
    image: nginx:latest
""")

        class TestComposeTool(ComposeBaseTool):
            """Test implementation of ComposeBaseTool."""

            @property
            def name(self) -> str:
                return "test_compose_tool"

            @property
            def description(self) -> str:
                return "Test tool"

            @property
            def input_schema(self):
                return dict

            @property
            def safety_level(self):
                from mcp_docker.utils.safety import OperationSafety

                return OperationSafety.SAFE

            async def execute(self, input_data):
                return {}

        return TestComposeTool(docker_client, safety_config, compose_client)

    def test_validate_compose_file_with_full_validation(self, compose_tool, tmp_path) -> None:
        """Test validating compose file with full validation enabled."""
        # Create a valid compose file
        compose_file = tmp_path / "test-compose.yml"
        compose_file.write_text("""
version: '3.8'
services:
  nginx:
    image: nginx:latest
    ports:
      - "8080:80"
""")

        # This should trigger lines 70-71 (full validation path)
        result = compose_tool.validate_compose_file(str(compose_file), full_validation=True)

        assert result == compose_file
        assert compose_file.exists()

    def test_validate_compose_file_without_full_validation(self, compose_tool, tmp_path) -> None:
        """Test validating compose file without full validation."""
        compose_file = tmp_path / "test-compose.yml"
        compose_file.write_text("""
version: '3.8'
services:
  nginx:
    image: nginx:latest
""")

        # This should skip the full validation path (lines 70-71)
        result = compose_tool.validate_compose_file(str(compose_file), full_validation=False)

        assert result == compose_file

    def test_validate_service_name(self, compose_tool) -> None:
        """Test validating service name."""
        # Valid service name
        result = compose_tool.validate_service_name("nginx")
        assert result == "nginx"

        # Another valid service name
        result = compose_tool.validate_service_name("my-service_1")
        assert result == "my-service_1"

    def test_validate_service_name_invalid(self, compose_tool) -> None:
        """Test validating invalid service name."""
        # Invalid service name (too long)
        with pytest.raises(ValidationError, match="cannot exceed 255 characters"):
            compose_tool.validate_service_name("a" * 256)

        # Invalid service name (empty)
        with pytest.raises(ValidationError, match="cannot be empty"):
            compose_tool.validate_service_name("")

    def test_validate_project_name(self, compose_tool) -> None:
        """Test validating project name (lines 108-110)."""
        # Valid project name
        result = compose_tool.validate_project_name("myproject")
        assert result == "myproject"

        # Another valid project name
        result = compose_tool.validate_project_name("my-project_1")
        assert result == "my-project_1"

    def test_validate_project_name_invalid(self, compose_tool) -> None:
        """Test validating invalid project name."""
        # Invalid project name (too long)
        with pytest.raises(ValidationError, match="cannot exceed 255 characters"):
            compose_tool.validate_project_name("a" * 256)

        # Invalid project name (empty)
        with pytest.raises(ValidationError, match="cannot be empty"):
            compose_tool.validate_project_name("")

    def test_verify_compose_available(self, compose_tool) -> None:
        """Test verifying Docker Compose is available (lines 119-120)."""
        # Mock the compose client's verify method
        with patch.object(compose_tool.compose, "verify_compose_v2") as mock_verify:
            mock_verify.return_value = {
                "version": "v2.20.0",
                "is_v2": True,
            }

            # This should trigger lines 119-120
            compose_tool.verify_compose_available()

            mock_verify.assert_called_once()

    def test_verify_compose_not_available(self, compose_tool) -> None:
        """Test verifying Docker Compose when it's not available."""
        from mcp_docker.utils.errors import DockerConnectionError

        # Mock the compose client's verify method to raise error
        with patch.object(compose_tool.compose, "verify_compose_v2") as mock_verify:
            mock_verify.side_effect = DockerConnectionError("Docker Compose v2 not found")

            # This should raise an error
            with pytest.raises(DockerConnectionError, match="not found"):
                compose_tool.verify_compose_available()
