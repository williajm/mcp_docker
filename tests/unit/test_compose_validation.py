"""Unit tests for Docker Compose validation utilities."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml

from mcp_docker.utils.compose_validation import (
    validate_compose_environment_variables,
    validate_compose_file_format,
    validate_compose_file_path,
    validate_compose_networks,
    validate_compose_ports,
    validate_compose_volume_mounts,
    validate_full_compose_file,
    validate_project_name,
    validate_service_name,
)
from mcp_docker.utils.errors import UnsafeOperationError, ValidationError


class TestValidateServiceName:
    """Test service name validation."""

    def test_valid_service_names(self) -> None:
        """Test validation of valid service names."""
        valid_names = [
            "web",
            "api-server",
            "database_1",
            "my-service-123",
            "service_with_underscores",
        ]
        for name in valid_names:
            result = validate_service_name(name)
            assert result == name

    def test_empty_service_name(self) -> None:
        """Test validation rejects empty service name."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_service_name("")

    def test_service_name_too_long(self) -> None:
        """Test validation rejects service name over 255 characters."""
        long_name = "a" * 256
        with pytest.raises(ValidationError, match="cannot exceed 255 characters"):
            validate_service_name(long_name)

    def test_service_name_invalid_characters(self) -> None:
        """Test validation rejects service names with invalid characters."""
        invalid_names = [
            "service with spaces",
            "service@special",
            "service#hash",
            "service!bang",
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError, match="Invalid service name"):
                validate_service_name(name)

    def test_service_name_not_string(self) -> None:
        """Test validation rejects non-string service names."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_service_name(123)  # type: ignore


class TestValidateProjectName:
    """Test project name validation."""

    def test_valid_project_names(self) -> None:
        """Test validation of valid project names."""
        valid_names = [
            "myproject",
            "my-project",
            "my_project",
            "project123",
        ]
        for name in valid_names:
            result = validate_project_name(name)
            assert result == name

    def test_empty_project_name(self) -> None:
        """Test validation rejects empty project name."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_project_name("")

    def test_project_name_too_long(self) -> None:
        """Test validation rejects project name over 255 characters."""
        long_name = "a" * 256
        with pytest.raises(ValidationError, match="cannot exceed 255 characters"):
            validate_project_name(long_name)

    def test_project_name_invalid_characters(self) -> None:
        """Test validation rejects project names with invalid characters."""
        invalid_names = [
            "project with spaces",
            "project@special",
            "project#hash",
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError, match="Invalid project name"):
                validate_project_name(name)

    def test_project_name_not_string(self) -> None:
        """Test validation rejects non-string project names."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_project_name(123)  # type: ignore


class TestValidateComposeFilePath:
    """Test compose file path validation."""

    def test_valid_file_path(self, tmp_path: Path) -> None:
        """Test validation of valid compose file path."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")

        result = validate_compose_file_path(compose_file)
        assert result.is_absolute()
        assert result.exists()

    def test_file_not_found(self) -> None:
        """Test validation rejects non-existent file."""
        with pytest.raises(ValidationError, match="not found"):
            validate_compose_file_path("nonexistent.yml")

    def test_path_is_directory(self, tmp_path: Path) -> None:
        """Test validation rejects directory path."""
        with pytest.raises(ValidationError, match="not a file"):
            validate_compose_file_path(tmp_path)

    def test_invalid_extension(self, tmp_path: Path) -> None:
        """Test validation rejects invalid file extension."""
        invalid_file = tmp_path / "docker-compose.txt"
        invalid_file.write_text("content")

        with pytest.raises(ValidationError, match="Invalid compose file extension"):
            validate_compose_file_path(invalid_file)

    def test_yaml_extension_allowed(self, tmp_path: Path) -> None:
        """Test validation allows .yaml extension."""
        compose_file = tmp_path / "docker-compose.yaml"
        compose_file.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")

        result = validate_compose_file_path(compose_file)
        assert result.suffix == ".yaml"


class TestValidateComposeFileFormat:
    """Test compose file format validation."""

    def test_valid_compose_file(self, tmp_path: Path) -> None:
        """Test validation of valid compose file."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {
            "version": "3.8",
            "services": {
                "web": {"image": "nginx:latest"},
                "db": {"image": "postgres:13"},
            },
        }
        compose_file.write_text(yaml.dump(content))

        result = validate_compose_file_format(compose_file)
        assert "services" in result
        assert "web" in result["services"]

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        """Test validation rejects invalid YAML."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("invalid: yaml: content:")

        with pytest.raises(ValidationError, match="Invalid YAML"):
            validate_compose_file_format(compose_file)

    def test_missing_services_section(self, tmp_path: Path) -> None:
        """Test validation rejects file without services section."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {"version": "3.8"}
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(ValidationError, match="must contain a 'services' section"):
            validate_compose_file_format(compose_file)

    def test_empty_services_section(self, tmp_path: Path) -> None:
        """Test validation rejects empty services section."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {"version": "3.8", "services": {}}
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(ValidationError, match="'services' section cannot be empty"):
            validate_compose_file_format(compose_file)

    def test_services_not_dict(self, tmp_path: Path) -> None:
        """Test validation rejects non-dict services section."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {"version": "3.8", "services": ["not", "a", "dict"]}
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(ValidationError, match="'services' section must be a dictionary"):
            validate_compose_file_format(compose_file)


class TestValidateComposeVolumeMounts:
    """Test volume mount validation."""

    def test_valid_volume_mounts(self) -> None:
        """Test validation of safe volume mounts."""
        compose_data = {
            "services": {
                "web": {
                    "volumes": [
                        "./data:/app/data",
                        "named_volume:/app/data",
                    ]
                }
            }
        }
        # Should not raise
        validate_compose_volume_mounts(compose_data)

    def test_dangerous_root_mount(self) -> None:
        """Test validation rejects mounting root filesystem."""
        compose_data = {"services": {"web": {"volumes": ["/:/host"]}}}
        with pytest.raises(UnsafeOperationError, match="Dangerous volume mount"):
            validate_compose_volume_mounts(compose_data)

    def test_dangerous_etc_passwd_mount(self) -> None:
        """Test validation rejects mounting /etc/passwd."""
        compose_data = {"services": {"web": {"volumes": ["/etc/passwd:/app/passwd"]}}}
        with pytest.raises(UnsafeOperationError, match="Dangerous volume mount"):
            validate_compose_volume_mounts(compose_data)

    def test_dangerous_bin_mount(self) -> None:
        """Test validation rejects mounting /bin."""
        compose_data = {"services": {"web": {"volumes": ["/bin:/binaries"]}}}
        with pytest.raises(UnsafeOperationError, match="Dangerous volume mount"):
            validate_compose_volume_mounts(compose_data)

    def test_long_syntax_dangerous_mount(self) -> None:
        """Test validation rejects dangerous bind mounts in long syntax."""
        compose_data = {
            "services": {
                "web": {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/etc/shadow",
                            "target": "/app/shadow",
                        }
                    ]
                }
            }
        }
        with pytest.raises(UnsafeOperationError, match="Dangerous volume mount"):
            validate_compose_volume_mounts(compose_data)

    def test_named_volume_allowed(self) -> None:
        """Test that named volumes are allowed."""
        compose_data = {"services": {"web": {"volumes": ["db_data:/var/lib/postgresql/data"]}}}
        # Should not raise
        validate_compose_volume_mounts(compose_data)


class TestValidateComposeEnvironmentVariables:
    """Test environment variable validation."""

    def test_valid_env_dict_format(self) -> None:
        """Test validation of valid environment variables in dict format."""
        compose_data = {
            "services": {
                "web": {
                    "environment": {
                        "DEBUG": "true",
                        "API_KEY": "secret123",
                    }
                }
            }
        }
        # Should not raise
        validate_compose_environment_variables(compose_data)

    def test_valid_env_list_format(self) -> None:
        """Test validation of valid environment variables in list format."""
        compose_data = {
            "services": {
                "web": {
                    "environment": [
                        "DEBUG=true",
                        "API_KEY=secret123",
                    ]
                }
            }
        }
        # Should not raise
        validate_compose_environment_variables(compose_data)

    def test_empty_env_key(self) -> None:
        """Test validation rejects empty environment variable key."""
        compose_data = {"services": {"web": {"environment": {"": "value"}}}}
        with pytest.raises(ValidationError, match="Empty environment variable key"):
            validate_compose_environment_variables(compose_data)

    def test_invalid_env_list_format(self) -> None:
        """Test validation rejects invalid list format."""
        compose_data = {"services": {"web": {"environment": ["MISSING_EQUALS_SIGN"]}}}
        with pytest.raises(ValidationError, match="Invalid environment variable format"):
            validate_compose_environment_variables(compose_data)

    def test_invalid_env_section_type(self) -> None:
        """Test validation rejects invalid environment section type."""
        compose_data = {"services": {"web": {"environment": "not a dict or list"}}}
        with pytest.raises(ValidationError, match="Invalid environment section type"):
            validate_compose_environment_variables(compose_data)


class TestValidateComposePorts:
    """Test port mapping validation."""

    def test_valid_port_number(self) -> None:
        """Test validation of valid port number."""
        compose_data = {"services": {"web": {"ports": [8080]}}}
        # Should not raise
        validate_compose_ports(compose_data)

    def test_valid_port_mapping(self) -> None:
        """Test validation of valid port mapping."""
        compose_data = {"services": {"web": {"ports": ["8080:80", "443:443"]}}}
        # Should not raise
        validate_compose_ports(compose_data)

    def test_valid_port_with_protocol(self) -> None:
        """Test validation of port with protocol."""
        compose_data = {"services": {"web": {"ports": ["8080:80/tcp"]}}}
        # Should not raise
        validate_compose_ports(compose_data)

    def test_valid_port_long_syntax(self) -> None:
        """Test validation of port in long syntax."""
        compose_data = {
            "services": {
                "web": {
                    "ports": [
                        {
                            "target": 80,
                            "published": 8080,
                            "protocol": "tcp",
                        }
                    ]
                }
            }
        }
        # Should not raise
        validate_compose_ports(compose_data)

    def test_invalid_port_number_too_high(self) -> None:
        """Test validation rejects port number too high."""
        compose_data = {"services": {"web": {"ports": [70000]}}}
        with pytest.raises(ValidationError, match="Invalid port number"):
            validate_compose_ports(compose_data)

    def test_invalid_port_number_zero(self) -> None:
        """Test validation rejects port number zero."""
        compose_data = {"services": {"web": {"ports": [0]}}}
        with pytest.raises(ValidationError, match="Invalid port number"):
            validate_compose_ports(compose_data)

    def test_invalid_port_mapping_format(self) -> None:
        """Test validation rejects invalid port mapping format."""
        compose_data = {"services": {"web": {"ports": ["invalid:port:mapping:format"]}}}
        # Ports section validation should pass as this is > 3 parts
        # The docker compose command itself will reject this
        validate_compose_ports(compose_data)

    def test_ports_not_list(self) -> None:
        """Test validation rejects non-list ports section."""
        compose_data = {"services": {"web": {"ports": "not a list"}}}
        with pytest.raises(ValidationError, match="'ports' .* must be a list"):
            validate_compose_ports(compose_data)


class TestValidateComposeNetworks:
    """Test network configuration validation."""

    def test_valid_network_list(self) -> None:
        """Test validation of valid network list."""
        compose_data = {"services": {"web": {"networks": ["frontend", "backend"]}}}
        # Should not raise
        validate_compose_networks(compose_data)

    def test_valid_network_dict(self) -> None:
        """Test validation of valid network dict."""
        compose_data = {
            "services": {
                "web": {
                    "networks": {
                        "frontend": {"aliases": ["web"]},
                        "backend": {},
                    }
                }
            }
        }
        # Should not raise
        validate_compose_networks(compose_data)

    def test_top_level_networks(self) -> None:
        """Test validation of top-level networks section."""
        compose_data = {
            "services": {"web": {"image": "nginx"}},
            "networks": {
                "frontend": {"driver": "bridge"},
                "backend": {"driver": "bridge"},
            },
        }
        # Should not raise
        validate_compose_networks(compose_data)

    def test_invalid_networks_section_type(self) -> None:
        """Test validation rejects invalid top-level networks type."""
        compose_data = {
            "services": {"web": {"image": "nginx"}},
            "networks": "not a dict",
        }
        with pytest.raises(ValidationError, match="'networks' section must be a dictionary"):
            validate_compose_networks(compose_data)

    def test_invalid_service_networks_format(self) -> None:
        """Test validation rejects invalid service networks format."""
        compose_data = {"services": {"web": {"networks": 123}}}
        with pytest.raises(ValidationError, match="Invalid networks format"):
            validate_compose_networks(compose_data)


class TestValidateFullComposeFile:
    """Test full compose file validation."""

    def test_valid_complete_file(self, tmp_path: Path) -> None:
        """Test validation of complete valid compose file."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "ports": ["8080:80"],
                    "environment": {"DEBUG": "true"},
                    "volumes": ["./data:/app/data"],
                    "networks": ["frontend"],
                }
            },
            "networks": {"frontend": {"driver": "bridge"}},
        }
        compose_file.write_text(yaml.dump(content))

        result = validate_full_compose_file(compose_file)
        assert "services" in result
        assert "web" in result["services"]

    def test_file_with_dangerous_volumes(self, tmp_path: Path) -> None:
        """Test validation rejects file with dangerous volumes."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "volumes": ["/etc/passwd:/app/passwd"],
                }
            },
        }
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(UnsafeOperationError, match="Dangerous volume mount"):
            validate_full_compose_file(compose_file)

    def test_file_with_invalid_ports(self, tmp_path: Path) -> None:
        """Test validation rejects file with invalid ports."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "ports": [99999],
                }
            },
        }
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(ValidationError, match="Invalid port"):
            validate_full_compose_file(compose_file)

    def test_file_with_invalid_environment(self, tmp_path: Path) -> None:
        """Test validation rejects file with invalid environment variables."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {
            "version": "3.8",
            "services": {
                "web": {
                    "image": "nginx:latest",
                    "environment": ["MISSING_EQUALS"],
                }
            },
        }
        compose_file.write_text(yaml.dump(content))

        with pytest.raises(ValidationError, match="Invalid environment variable format"):
            validate_full_compose_file(compose_file)


class TestValidateComposeFilePathEdgeCases:
    """Test edge cases for compose file path validation."""

    def test_path_resolve_oserror(self, tmp_path: Path) -> None:
        """Test handling of OSError during path resolution."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3.8'\nservices:\n  web:\n    image: nginx")

        # Mock path.resolve() to raise OSError
        with (
            patch.object(Path, "resolve", side_effect=OSError("Permission denied")),
            pytest.raises(ValidationError, match="Failed to resolve compose file path"),
        ):
            validate_compose_file_path(compose_file)

    def test_path_resolve_runtime_error(self, tmp_path: Path) -> None:
        """Test handling of RuntimeError during path resolution."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3.8'\nservices:\n  web:\n    image: nginx")

        # Mock path.resolve() to raise RuntimeError
        with (
            patch.object(Path, "resolve", side_effect=RuntimeError("Too many symlinks")),
            pytest.raises(ValidationError, match="Failed to resolve compose file path"),
        ):
            validate_compose_file_path(compose_file)

    def test_path_with_double_dots_after_resolution(self, tmp_path: Path) -> None:
        """Test rejection of paths containing '..' after resolution."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3.8'\nservices:\n  web:\n    image: nginx")

        # Mock resolve to return a path with ".." in it
        mock_resolved = Mock(spec=Path)
        mock_resolved.is_absolute.return_value = True
        mock_resolved.__str__ = lambda self: "/path/with/../dots"

        with (
            patch.object(Path, "resolve", return_value=mock_resolved),
            pytest.raises(UnsafeOperationError, match="suspicious pattern"),
        ):
            validate_compose_file_path(compose_file)

    def test_non_absolute_path_after_resolution(self, tmp_path: Path) -> None:
        """Test rejection of non-absolute paths after resolution."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3.8'\nservices:\n  web:\n    image: nginx")

        # Mock resolve to return a non-absolute path
        mock_resolved = Mock(spec=Path)
        mock_resolved.is_absolute.return_value = False
        mock_resolved.__str__ = lambda self: "relative/path"

        with (
            patch.object(Path, "resolve", return_value=mock_resolved),
            pytest.raises(UnsafeOperationError, match="must be absolute"),
        ):
            validate_compose_file_path(compose_file)


class TestValidateComposeFileFormatEdgeCases:
    """Test edge cases for compose file format validation."""

    def test_file_read_oserror(self, tmp_path: Path) -> None:
        """Test handling of OSError during file read."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("version: '3.8'\nservices:\n  web:\n    image: nginx")

        # Mock open inside the validate module to raise OSError
        with (
            patch(
                "mcp_docker.utils.compose_validation.Path.open",
                side_effect=OSError("Permission denied"),
            ),
            pytest.raises(ValidationError, match="Failed to read compose file"),
        ):
            validate_compose_file_format(compose_file)

    def test_yaml_is_not_dict(self, tmp_path: Path) -> None:
        """Test rejection when YAML is not a dictionary."""
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("- item1\n- item2\n")  # List instead of dict

        with pytest.raises(ValidationError, match="must contain a YAML dictionary"):
            validate_compose_file_format(compose_file)

    def test_version_field_present_but_unsupported(self, tmp_path: Path) -> None:
        """Test that unsupported versions don't fail (just logged)."""
        compose_file = tmp_path / "docker-compose.yml"
        content = {"version": "9.9", "services": {"web": {"image": "nginx"}}}
        compose_file.write_text(yaml.dump(content))

        # Should not raise even with unsupported version
        result = validate_compose_file_format(compose_file)
        assert result["version"] == "9.9"


class TestValidateComposeVolumeMountsEdgeCases:
    """Test edge cases for volume mount validation."""

    def test_service_config_not_dict(self) -> None:
        """Test handling when service config is not a dict."""
        compose_data = {
            "services": {
                "web": "invalid_config",  # Not a dict
                "api": {"image": "nginx"},
            }
        }
        # Should not raise - non-dict services are skipped
        validate_compose_volume_mounts(compose_data)

    def test_volume_with_relative_path(self) -> None:
        """Test handling of relative path volumes."""
        compose_data = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": ["./data:/app/data"],
                }
            }
        }
        # Should not raise for relative paths (not dangerous)
        validate_compose_volume_mounts(compose_data)

    def test_volume_with_parent_directory(self) -> None:
        """Test handling of parent directory volumes."""
        compose_data = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": ["../data:/app/data"],
                }
            }
        }
        # Should not raise for parent directory (not dangerous)
        validate_compose_volume_mounts(compose_data)

    def test_volume_long_syntax_without_source(self) -> None:
        """Test handling of long syntax volume without source."""
        compose_data = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": [{"type": "bind", "target": "/app"}],  # No source
                }
            }
        }
        # Should not raise - no source to validate
        validate_compose_volume_mounts(compose_data)


class TestValidateComposePortsEdgeCases:
    """Test edge cases for port validation."""

    def test_port_string_with_three_parts(self) -> None:
        """Test port string with IP:host:container format."""
        compose_data = {"services": {"web": {"ports": ["127.0.0.1:8080:80"]}}}
        # Should not raise
        validate_compose_ports(compose_data)

    def test_port_long_syntax_with_target(self) -> None:
        """Test port long syntax with target port."""
        compose_data = {
            "services": {
                "web": {
                    "ports": [
                        {"target": 80, "published": 8080},  # Published as int, not string
                    ]
                }
            }
        }
        # Should not raise
        validate_compose_ports(compose_data)

    def test_port_long_syntax_with_invalid_target(self) -> None:
        """Test port long syntax with invalid target port."""
        compose_data = {
            "services": {
                "web": {
                    "ports": [
                        {"target": 99999, "published": 8080},
                    ]
                }
            }
        }
        with pytest.raises(ValidationError, match="Invalid target port"):
            validate_compose_ports(compose_data)

    def test_port_long_syntax_with_invalid_published(self) -> None:
        """Test port long syntax with invalid published port."""
        compose_data = {
            "services": {
                "web": {
                    "ports": [
                        {"target": 80, "published": 99999},
                    ]
                }
            }
        }
        with pytest.raises(ValidationError, match="Invalid published port"):
            validate_compose_ports(compose_data)


class TestValidateComposeEnvironmentEdgeCases:
    """Test edge cases for environment variable validation."""

    def test_service_without_environment(self) -> None:
        """Test service without environment section."""
        compose_data = {"services": {"web": {"image": "nginx"}}}
        # Should not raise
        validate_compose_environment_variables(compose_data)

    def test_empty_environment_dict(self) -> None:
        """Test empty environment dictionary."""
        compose_data = {"services": {"web": {"environment": {}}}}
        # Should not raise
        validate_compose_environment_variables(compose_data)

    def test_empty_environment_list(self) -> None:
        """Test empty environment list."""
        compose_data = {"services": {"web": {"environment": []}}}
        # Should not raise
        validate_compose_environment_variables(compose_data)


class TestValidateComposeNetworksEdgeCases:
    """Test edge cases for network validation."""

    def test_service_without_networks(self) -> None:
        """Test service without networks section."""
        compose_data = {"services": {"web": {"image": "nginx"}}}
        # Should not raise
        validate_compose_networks(compose_data)

    def test_empty_networks_list(self) -> None:
        """Test empty networks list."""
        compose_data = {"services": {"web": {"networks": []}}}
        # Should not raise
        validate_compose_networks(compose_data)

    def test_empty_networks_dict(self) -> None:
        """Test empty networks dictionary."""
        compose_data = {"services": {"web": {"networks": {}}}}
        # Should not raise
        validate_compose_networks(compose_data)


class TestValidateComposePortsStringParsing:
    """Test port string parsing edge cases."""

    def test_port_single_value_invalid_number(self) -> None:
        """Test single port value that's not a valid number."""
        compose_data = {"services": {"web": {"ports": ["not_a_number"]}}}
        with pytest.raises(ValidationError, match="Invalid port format"):
            validate_compose_ports(compose_data)

    def test_port_two_parts_invalid_host_port(self) -> None:
        """Test two-part port string with invalid host port."""
        compose_data = {"services": {"web": {"ports": ["invalid:80"]}}}
        with pytest.raises(ValidationError, match="Invalid port format"):
            validate_compose_ports(compose_data)

    def test_port_three_parts_invalid_host_port(self) -> None:
        """Test three-part port string with invalid host port."""
        compose_data = {"services": {"web": {"ports": ["127.0.0.1:invalid:80"]}}}
        with pytest.raises(ValidationError, match="Invalid port format"):
            validate_compose_ports(compose_data)
