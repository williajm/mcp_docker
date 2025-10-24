"""Tests for validation utilities."""

import pytest

from mcp_docker.utils.errors import ValidationError
from mcp_docker.utils.validation import (
    sanitize_command,
    validate_container_name,
    validate_image_name,
    validate_label,
    validate_memory_string,
    validate_port,
)


class TestValidateContainerName:
    """Tests for container name validation."""

    def test_valid_names(self) -> None:
        """Test valid container names."""
        valid_names = [
            "mycontainer",
            "my-container",
            "my_container",
            "my.container",
            "container123",
            "123container",
            "/mycontainer",
        ]
        for name in valid_names:
            assert validate_container_name(name) == name

    def test_invalid_names(self) -> None:
        """Test invalid container names."""
        with pytest.raises(ValidationError):
            validate_container_name("")

        with pytest.raises(ValidationError):
            validate_container_name("a" * 256)

        with pytest.raises(ValidationError):
            validate_container_name("-container")

        with pytest.raises(ValidationError):
            validate_container_name(".container")


class TestValidateImageName:
    """Tests for image name validation."""

    def test_valid_names(self) -> None:
        """Test valid image names."""
        valid_names = [
            "ubuntu",
            "ubuntu:22.04",
            "ubuntu:latest",
            "myregistry.com/ubuntu",
            "myregistry.com/namespace/ubuntu:22.04",
            "localhost:5000/myimage",
        ]
        for name in valid_names:
            assert validate_image_name(name) == name

    def test_invalid_names(self) -> None:
        """Test invalid image names."""
        with pytest.raises(ValidationError):
            validate_image_name("")

        with pytest.raises(ValidationError):
            validate_image_name("a" * 256)

        with pytest.raises(ValidationError):
            validate_image_name("UPPERCASE")


class TestValidateLabel:
    """Tests for label validation."""

    def test_valid_labels(self) -> None:
        """Test valid labels."""
        key, value = validate_label("app.name", "myapp")
        assert key == "app.name"
        assert value == "myapp"

        key, value = validate_label("version", 123)
        assert key == "version"
        assert value == "123"

    def test_invalid_labels(self) -> None:
        """Test invalid labels."""
        with pytest.raises(ValidationError):
            validate_label("", "value")

        with pytest.raises(ValidationError):
            validate_label("invalid key", "value")


class TestValidatePort:
    """Tests for port validation."""

    def test_valid_ports(self) -> None:
        """Test valid ports."""
        assert validate_port(80) == 80
        assert validate_port("8080") == 8080
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_invalid_ports(self) -> None:
        """Test invalid ports."""
        with pytest.raises(ValidationError):
            validate_port(0)

        with pytest.raises(ValidationError):
            validate_port(65536)

        with pytest.raises(ValidationError):
            validate_port(-1)

        with pytest.raises(ValidationError):
            validate_port("invalid")


class TestValidateMemoryString:
    """Tests for memory string validation."""

    def test_valid_memory(self) -> None:
        """Test valid memory strings."""
        assert validate_memory_string("512m") == "512m"
        assert validate_memory_string("2g") == "2g"
        assert validate_memory_string("1024k") == "1024k"
        assert validate_memory_string("1024") == "1024"
        assert validate_memory_string("512M") == "512m"

    def test_invalid_memory(self) -> None:
        """Test invalid memory strings."""
        with pytest.raises(ValidationError):
            validate_memory_string("")

        with pytest.raises(ValidationError):
            validate_memory_string("abc")

        with pytest.raises(ValidationError):
            validate_memory_string("512 m")


class TestSanitizeCommand:
    """Tests for command sanitization."""

    def test_string_command(self) -> None:
        """Test string command."""
        result = sanitize_command("echo hello")
        assert result == ["echo hello"]

    def test_list_command(self) -> None:
        """Test list command."""
        result = sanitize_command(["echo", "hello"])
        assert result == ["echo", "hello"]

    def test_invalid_command(self) -> None:
        """Test invalid commands."""
        with pytest.raises(ValidationError):
            sanitize_command("")

        with pytest.raises(ValidationError):
            sanitize_command([])

        with pytest.raises(ValidationError):
            sanitize_command(["echo", 123])  # type: ignore[list-item]

        with pytest.raises(ValidationError):
            sanitize_command(123)  # type: ignore[arg-type]
