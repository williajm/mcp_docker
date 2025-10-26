"""Docker Compose client wrapper with subprocess command execution."""

import json
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger

from mcp_docker.utils.errors import DockerConnectionError, DockerOperationError, ValidationError


class ComposeClient:
    """Docker Compose v2 client wrapper using subprocess calls."""

    def __init__(
        self,
        compose_file: str | Path | None = None,
        project_name: str | None = None,
        timeout: int = 300,
    ) -> None:
        """Initialize Docker Compose client wrapper.

        Args:
            compose_file: Path to docker-compose.yml file (optional, can be set per command)
            project_name: Project name for compose operations (optional)
            timeout: Default timeout for compose commands in seconds

        """
        self.compose_file = Path(compose_file) if compose_file else None
        self.project_name = project_name
        self.timeout = timeout
        self._compose_version: str | None = None
        self._is_v2: bool | None = None

        logger.debug(
            f"Initialized ComposeClient with file={self.compose_file}, "
            f"project={self.project_name}, timeout={self.timeout}s"
        )

    def _build_base_command(
        self,
        compose_file: str | Path | None = None,
        project_name: str | None = None,
    ) -> list[str]:
        """Build base docker compose command with common options.

        Args:
            compose_file: Override compose file for this command
            project_name: Override project name for this command

        Returns:
            Base command list

        """
        cmd = ["docker", "compose"]

        # Add compose file if specified
        file_path = compose_file or self.compose_file
        if file_path:
            cmd.extend(["-f", str(file_path)])

        # Add project name if specified
        proj_name = project_name or self.project_name
        if proj_name:
            cmd.extend(["-p", proj_name])

        return cmd

    def _sanitize_command_args(self, args: list[str]) -> list[str]:
        """Sanitize command arguments to prevent injection attacks.

        Since we use subprocess.run() without shell=True, most shell metacharacters
        are treated as literal characters and pose no security risk. We only need
        to check for characters that could cause issues at the OS/process level.

        Args:
            args: Command arguments to sanitize

        Returns:
            Sanitized arguments

        Raises:
            ValidationError: If arguments contain unsafe patterns

        """
        sanitized = []
        for arg in args:
            # Convert to string if not already
            arg_str = str(arg)

            # Check for truly dangerous characters in subprocess context:
            # - Null bytes can truncate arguments at the C level
            # - Newlines can cause issues with argument parsing
            if "\x00" in arg_str:
                raise ValidationError(f"Argument contains null byte: {arg_str!r}")
            if "\n" in arg_str or "\r" in arg_str:
                raise ValidationError(f"Argument contains newline character: {arg_str!r}")

            sanitized.append(arg_str)

        return sanitized

    def _execute_command(
        self,
        args: list[str],
        timeout: int | None = None,
        capture_output: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a docker compose command.

        Args:
            args: Command arguments (after 'docker compose')
            timeout: Command timeout in seconds (None = use default)
            capture_output: Whether to capture stdout/stderr
            check: Whether to raise exception on non-zero exit code

        Returns:
            Completed process result

        Raises:
            DockerOperationError: If command execution fails

        """
        # Sanitize arguments
        sanitized_args = self._sanitize_command_args(args)

        # Build full command
        cmd = self._build_base_command() + sanitized_args

        # Log command (sanitized for security)
        logger.debug(f"Executing compose command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout or self.timeout,
                check=check,
            )

            logger.debug(f"Command completed with exit code: {result.returncode}")
            return result

        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out after {timeout or self.timeout}s")
            raise DockerOperationError(
                f"Compose command timed out after {timeout or self.timeout}s"
            ) from e

        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with exit code {e.returncode}: {e.stderr}")
            raise DockerOperationError(
                f"Compose command failed: {e.stderr or e.stdout or 'Unknown error'}"
            ) from e

        except FileNotFoundError as e:
            logger.error("docker compose command not found")
            raise DockerConnectionError(
                "docker compose command not found. Please ensure Docker Compose v2 is installed."
            ) from e

        except Exception as e:
            logger.error(f"Unexpected error executing command: {e}")
            raise DockerOperationError(f"Unexpected error: {e}") from e

    def verify_compose_v2(self) -> dict[str, Any]:
        """Verify that docker compose v2 is available and get version info.

        Returns:
            Version information dictionary

        Raises:
            DockerConnectionError: If compose v2 is not available

        """
        if self._is_v2 is not None and self._compose_version is not None:
            return {
                "version": self._compose_version,
                "is_v2": self._is_v2,
            }

        try:
            # Execute version command without using base command builder
            result = subprocess.run(
                ["docker", "compose", "version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )

            # Parse JSON output
            version_data = json.loads(result.stdout)
            version_str = version_data.get("version", "")

            # Check if it's v2 (version starts with "v2" or "2")
            self._is_v2 = version_str.startswith("v2") or version_str.startswith("2")
            self._compose_version = version_str

            if not self._is_v2:
                raise DockerConnectionError(
                    f"Docker Compose v1 detected (version: {version_str}). "
                    "Please upgrade to Docker Compose v2."
                )

            logger.success(f"Docker Compose v2 verified: {version_str}")
            return {
                "version": self._compose_version,
                "is_v2": self._is_v2,
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get compose version: {e.stderr}")
            raise DockerConnectionError(
                "Unable to verify Docker Compose version. "
                "Please ensure Docker Compose v2 is installed."
            ) from e

        except FileNotFoundError as e:
            logger.error("docker compose command not found")
            raise DockerConnectionError(
                "docker compose command not found. Please ensure Docker Compose v2 is installed."
            ) from e

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse compose version JSON: {e}")
            raise DockerConnectionError(
                "Failed to parse compose version output. "
                "Please ensure Docker Compose v2 is properly installed."
            ) from e

        except Exception as e:
            logger.error(f"Unexpected error verifying compose version: {e}")
            raise DockerConnectionError(f"Unexpected error: {e}") from e

    def validate_compose_file(
        self,
        compose_file: str | Path | None = None,
    ) -> dict[str, Any]:
        """Validate a docker-compose file.

        Args:
            compose_file: Path to compose file (uses instance file if not specified)

        Returns:
            Validation result

        Raises:
            DockerOperationError: If validation fails

        """
        file_path = compose_file or self.compose_file
        if not file_path:
            raise ValidationError("No compose file specified")

        # Verify file exists
        path_obj = Path(file_path)
        if not path_obj.exists():
            raise ValidationError(f"Compose file not found: {file_path}")

        if not path_obj.is_file():
            raise ValidationError(f"Compose file path is not a file: {file_path}")

        # Execute config command to validate
        result = self._execute_command(
            ["-f", str(file_path), "config", "--quiet"],
            check=False,
        )

        if result.returncode != 0:
            return {
                "valid": False,
                "error": result.stderr or "Validation failed",
            }

        return {
            "valid": True,
            "file": str(file_path),
        }

    def get_config(
        self,
        compose_file: str | Path | None = None,
        format_json: bool = True,
    ) -> dict[str, Any] | str:
        """Get resolved compose configuration.

        Args:
            compose_file: Path to compose file (uses instance file if not specified)
            format_json: Return as JSON dict (True) or YAML string (False)

        Returns:
            Configuration as dict or YAML string

        Raises:
            DockerOperationError: If config retrieval fails

        """
        file_path = compose_file or self.compose_file
        if not file_path:
            raise ValidationError("No compose file specified")

        if format_json:
            result = self._execute_command(["-f", str(file_path), "config", "--format", "json"])
            config_data: dict[str, Any] = json.loads(result.stdout)
            return config_data

        result = self._execute_command(["-f", str(file_path), "config"])
        return result.stdout

    def execute(  # noqa: PLR0912
        self,
        subcommand: str,
        args: list[str] | None = None,
        compose_file: str | Path | None = None,
        project_name: str | None = None,
        timeout: int | None = None,
        parse_json: bool = False,
    ) -> dict[str, Any]:
        """Execute a compose subcommand.

        Args:
            subcommand: Compose subcommand (e.g., 'up', 'down', 'ps')
            args: Additional arguments for the subcommand
            compose_file: Override compose file for this command
            project_name: Override project name for this command
            timeout: Override timeout for this command
            parse_json: Try to parse output as JSON

        Returns:
            Command result dictionary with stdout, stderr, and exit code

        Raises:
            DockerOperationError: If command execution fails

        """
        # Build command arguments
        cmd_args = []
        if subcommand:  # Only add subcommand if not empty
            cmd_args.append(subcommand)
        if args:
            cmd_args.extend(args)

        # Temporarily override compose file and project name for this command
        original_file = self.compose_file
        original_project = self.project_name

        try:
            if compose_file:
                self.compose_file = Path(compose_file)
            if project_name:
                self.project_name = project_name

            result = self._execute_command(cmd_args, timeout=timeout, check=False)

            # Build response
            response: dict[str, Any] = {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

            # Try to parse as JSON if requested
            if parse_json and result.stdout:
                try:
                    # Try parsing as a single JSON object/array first
                    response["data"] = json.loads(result.stdout)
                except json.JSONDecodeError:
                    # If that fails, try parsing as NDJSON (newline-delimited JSON)
                    # Common for commands like 'docker compose ps --format json'
                    try:
                        parsed_lines = []
                        for raw_line in result.stdout.strip().split("\n"):
                            stripped_line = raw_line.strip()
                            # Skip empty lines and log messages (start with 'time=')
                            if stripped_line and not stripped_line.startswith("time="):
                                try:
                                    parsed_lines.append(json.loads(stripped_line))
                                except json.JSONDecodeError:
                                    # Skip lines that aren't valid JSON
                                    continue
                        if parsed_lines:
                            response["data"] = parsed_lines
                        else:
                            logger.debug("Failed to parse output as JSON or NDJSON")
                    except Exception as e:
                        logger.debug(f"Failed to parse output as NDJSON: {e}")

            return response

        finally:
            # Restore original values
            self.compose_file = original_file
            self.project_name = original_project

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"ComposeClient(file={self.compose_file}, "
            f"project={self.project_name}, "
            f"version={self._compose_version or 'unknown'})"
        )
