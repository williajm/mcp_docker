"""Simple tests to increase coverage for compose functionality."""

import pytest

from mcp_docker.utils.compose_validation import (
    validate_project_name,
    validate_service_name,
)
from mcp_docker.utils.errors import ValidationError


class TestComposeValidationCoverage:
    """Test compose validation utilities for coverage."""

    def test_validate_service_name_valid(self) -> None:
        """Test validation of valid service names."""
        # Valid service names
        result = validate_service_name("web")
        assert result == "web"

        result = validate_service_name("api-server")
        assert result == "api-server"

        result = validate_service_name("db_primary")
        assert result == "db_primary"

        result = validate_service_name("cache123")
        assert result == "cache123"

    def test_validate_service_name_invalid_empty(self) -> None:
        """Test validation rejects empty service names."""
        with pytest.raises(ValidationError, match="Service name cannot be empty"):
            validate_service_name("")

    def test_validate_service_name_invalid_chars(self) -> None:
        """Test validation rejects invalid characters."""
        with pytest.raises(ValidationError, match="Invalid service name"):
            validate_service_name("web@service")

        with pytest.raises(ValidationError, match="Invalid service name"):
            validate_service_name("api service")

        with pytest.raises(ValidationError, match="Invalid service name"):
            validate_service_name("web/service")

    def test_validate_project_name_valid(self) -> None:
        """Test validation of valid project names."""
        result = validate_project_name("myproject")
        assert result == "myproject"

        result = validate_project_name("my-project")
        assert result == "my-project"

        result = validate_project_name("project_123")
        assert result == "project_123"

    def test_validate_project_name_invalid_empty(self) -> None:
        """Test validation rejects empty project names."""
        with pytest.raises(ValidationError, match="Project name cannot be empty"):
            validate_project_name("")

    def test_validate_project_name_invalid_chars(self) -> None:
        """Test validation rejects invalid characters."""
        with pytest.raises(ValidationError, match="Invalid project name"):
            validate_project_name("my@project")

        with pytest.raises(ValidationError, match="Invalid project name"):
            validate_project_name("my project")

        with pytest.raises(ValidationError, match="Invalid project name"):
            validate_project_name("project/name")
