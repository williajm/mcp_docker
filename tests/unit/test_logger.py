"""Unit tests for logger module."""

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from unittest.mock import patch

import pytest
from loguru import logger

from mcp_docker.config import ServerConfig
from mcp_docker.utils.logger import setup_logger


@pytest.fixture
def server_config() -> ServerConfig:
    """Create a server configuration for testing."""
    return ServerConfig(
        log_level="INFO",
        log_format="<level>{level}</level> - {message}",
    )


class TestSetupLogger:
    """Test logger setup functionality."""

    def test_setup_logger_console_only(self, server_config: ServerConfig) -> None:
        """Test setting up logger with console output only."""
        # Remove all handlers first
        logger.remove()

        # Setup logger
        setup_logger(server_config)

        # Logger should be configured (we can't easily test the handlers directly,
        # but we can verify it doesn't raise an error)
        logger.info("Test message")

    def test_setup_logger_with_file(self, server_config: ServerConfig) -> None:
        """Test setting up logger with file output."""
        # Remove all handlers first
        logger.remove()

        with NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp_file:
            log_file = Path(tmp_file.name)

        try:
            # Setup logger with file
            setup_logger(server_config, log_file=log_file)

            # Write a test message
            logger.info("Test file message")

            # Give it a moment to flush
            import time

            time.sleep(0.1)

            # Verify file was created (message should be written)
            assert log_file.exists()
        finally:
            # Cleanup - remove all handlers to release file locks first
            logger.remove()
            # Give Windows time to release the file lock
            import time

            time.sleep(0.2)
            if log_file.exists():
                try:
                    log_file.unlink()
                except PermissionError:
                    pass  # File still locked on Windows, cleanup will happen later

    def test_setup_logger_custom_level(self) -> None:
        """Test setting up logger with custom log level."""
        # Remove all handlers first
        logger.remove()

        config = ServerConfig(log_level="DEBUG")
        setup_logger(config)

        # Should accept debug messages
        logger.debug("Debug message")

    def test_setup_logger_custom_format(self) -> None:
        """Test setting up logger with custom format."""
        # Remove all handlers first
        logger.remove()

        config = ServerConfig(log_level="INFO", log_format="{level} | {message}")
        setup_logger(config)

        logger.info("Custom format message")

    @patch("mcp_docker.utils.logger.logger")
    def test_setup_logger_removes_default_handler(
        self, mock_logger: Any, server_config: ServerConfig
    ) -> None:
        """Test that default handler is removed."""
        setup_logger(server_config)
        mock_logger.remove.assert_called_once()

    def test_setup_logger_with_nonexistent_file_path(self, server_config: ServerConfig) -> None:
        """Test setting up logger with a file in a directory that will be created."""
        # Remove all handlers first
        logger.remove()

        # Use a temporary file that will be created
        with NamedTemporaryFile(mode="w", suffix=".log", delete=True) as tmp_file:
            log_file = Path(tmp_file.name)

        # File should not exist yet
        assert not log_file.exists()

        try:
            # Setup logger - loguru should handle file creation
            setup_logger(server_config, log_file=log_file)

            # Write a message
            logger.info("Test message")

            # Give it a moment to flush
            import time

            time.sleep(0.1)

            # File should now exist
            assert log_file.exists()
        finally:
            # Cleanup - remove all handlers to release file locks first
            logger.remove()
            # Give Windows time to release the file lock
            import time

            time.sleep(0.2)
            if log_file.exists():
                try:
                    log_file.unlink()
                except PermissionError:
                    pass  # File still locked on Windows, cleanup will happen later
