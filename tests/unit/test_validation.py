"""Tests for validation utilities."""

import pytest

from mcp_docker.utils.errors import ValidationError
from mcp_docker.utils.validation import (
    sanitize_command,
    validate_command,
    validate_container_name,
    validate_image_name,
    validate_label,
    validate_memory,
    validate_memory_string,
    validate_port,
    validate_port_mapping,
)


class TestValidateContainerName:
    """Tests for container name validation."""

    @pytest.mark.parametrize(
        "name",
        [
            "mycontainer",
            "my-container",
            "my_container",
            "my.container",
            "container123",
            "123container",
            "/mycontainer",
        ],
    )
    def test_valid_names(self, name: str) -> None:
        """Test valid container names."""
        assert validate_container_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "a" * 256,
            "-container",
            ".container",
        ],
        ids=["empty", "too_long", "starts_with_dash", "starts_with_dot"],
    )
    def test_invalid_names(self, name: str) -> None:
        """Test invalid container names."""
        with pytest.raises(ValidationError):
            validate_container_name(name)


class TestValidateImageName:
    """Tests for image name validation."""

    @pytest.mark.parametrize(
        "name",
        [
            "ubuntu",
            "ubuntu:22.04",
            "ubuntu:latest",
            "myregistry.com/ubuntu",
            "myregistry.com/namespace/ubuntu:22.04",
            "localhost:5000/myimage",
        ],
    )
    def test_valid_names(self, name: str) -> None:
        """Test valid image names."""
        assert validate_image_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "a" * 256,
            "UPPERCASE",
        ],
        ids=["empty", "too_long", "uppercase"],
    )
    def test_invalid_names(self, name: str) -> None:
        """Test invalid image names."""
        with pytest.raises(ValidationError):
            validate_image_name(name)


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

    @pytest.mark.parametrize(
        "port,expected",
        [
            (80, 80),
            ("8080", 8080),
            (1, 1),
            (65535, 65535),
        ],
        ids=["80", "8080_str", "1", "65535_max"],
    )
    def test_valid_ports(self, port: int | str, expected: int) -> None:
        """Test valid ports."""
        assert validate_port(port) == expected

    @pytest.mark.parametrize(
        "port",
        [0, 65536, -1, "invalid"],
        ids=["0_too_low", "65536_too_high", "negative", "invalid_string"],
    )
    def test_invalid_ports(self, port: int | str) -> None:
        """Test invalid ports."""
        with pytest.raises(ValidationError):
            validate_port(port)


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
            sanitize_command(123)


class TestValidateCommand:
    """Tests for validate_command function."""

    def test_valid_string_command(self) -> None:
        """Test valid string command."""
        result = validate_command("echo hello")
        assert result == "echo hello"

    def test_valid_list_command(self) -> None:
        """Test valid list command."""
        result = validate_command(["echo", "hello"])
        assert result == ["echo", "hello"]

    def test_empty_string_command(self) -> None:
        """Test empty string command raises error."""
        with pytest.raises(ValidationError, match="Command cannot be empty"):
            validate_command("")

    def test_whitespace_only_command(self) -> None:
        """Test whitespace-only command raises error."""
        with pytest.raises(ValidationError, match="Command cannot be empty"):
            validate_command("   ")

    @pytest.mark.parametrize(
        "command",
        [
            "echo hello; rm -rf /",
            "echo hello && whoami",
            "echo hello || whoami",
            "echo hello | whoami",
            "echo `whoami`",
            "echo $(whoami)",
        ],
        ids=["semicolon", "and", "or", "pipe", "backtick", "command_subst"],
    )
    def test_dangerous_patterns_in_command(self, command: str) -> None:
        """Test dangerous patterns in commands."""
        with pytest.raises(ValidationError, match="contains potentially dangerous patterns"):
            validate_command(command)

    def test_empty_list_command(self) -> None:
        """Test empty list command raises error."""
        with pytest.raises(ValidationError, match="Command list cannot be empty"):
            validate_command([])

    def test_list_with_non_string_items(self) -> None:
        """Test list command with non-string items."""
        with pytest.raises(ValidationError, match="All command items must be strings"):
            validate_command(["echo", 123])  # type: ignore[list-item]

    def test_invalid_command_type(self) -> None:
        """Test invalid command type."""
        with pytest.raises(ValidationError, match="Command must be a string or list"):
            validate_command(123)

    def test_string_command_exceeds_length_limit(self) -> None:
        """Test string command exceeding 64KB limit."""
        # Create a command larger than 64KB (65536 bytes)
        large_command = "echo " + "A" * 70000
        with pytest.raises(ValidationError, match="Command too long"):
            validate_command(large_command)

    def test_list_command_exceeds_length_limit(self) -> None:
        """Test list command exceeding 64KB limit (security fix verification)."""
        # Create a list command where total length exceeds 64KB
        # This tests the fix for the security issue where list commands bypassed validation
        large_arg = "A" * 70000
        with pytest.raises(ValidationError, match="Command too long"):
            validate_command(["/bin/echo", large_arg])

    def test_list_command_within_length_limit(self) -> None:
        """Test list command within 64KB limit passes validation."""
        # Create a list command just under the limit
        medium_arg = "A" * 30000
        result = validate_command(["/bin/echo", medium_arg])
        assert result == ["/bin/echo", medium_arg]


class TestValidateMemory:
    """Tests for validate_memory wrapper function."""

    def test_validate_memory_wrapper(self) -> None:
        """Test validate_memory wrapper function."""
        assert validate_memory("512m") == "512m"
        assert validate_memory("2g") == "2g"


class TestValidatePortMapping:
    """Tests for port mapping validation."""

    def test_valid_port_mapping_int(self) -> None:
        """Test valid port mapping with integer container port."""
        container_port, host_port = validate_port_mapping(80, 8080)
        assert container_port == "80"
        assert host_port == 8080

    def test_valid_port_mapping_string(self) -> None:
        """Test valid port mapping with string container port."""
        container_port, host_port = validate_port_mapping("80", 8080)
        assert container_port == "80"
        assert host_port == 8080

    def test_valid_port_mapping_with_protocol(self) -> None:
        """Test valid port mapping with protocol."""
        container_port, host_port = validate_port_mapping("80/tcp", 8080)
        assert container_port == "80/tcp"
        assert host_port == 8080

        container_port, host_port = validate_port_mapping("53/udp", 5353)
        assert container_port == "53/udp"
        assert host_port == 5353

        container_port, host_port = validate_port_mapping("132/sctp", 1320)
        assert container_port == "132/sctp"
        assert host_port == 1320

    def test_invalid_protocol(self) -> None:
        """Test invalid protocol in port mapping."""
        with pytest.raises(ValidationError, match="Invalid protocol"):
            validate_port_mapping("80/http", 8080)

    def test_invalid_port_in_mapping(self) -> None:
        """Test invalid port numbers in mapping."""
        with pytest.raises(ValidationError):
            validate_port_mapping(80, 0)  # Invalid host port

        with pytest.raises(ValidationError):
            validate_port_mapping("99999", 8080)  # Invalid container port
