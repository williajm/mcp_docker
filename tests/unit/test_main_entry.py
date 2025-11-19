"""Unit tests for __main__.py entry point."""

from unittest.mock import ANY, AsyncMock, Mock, patch

import pytest
from typer.testing import CliRunner


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def mock_fastmcp_server():
    """Create a mock FastMCPDockerServer."""
    server_instance = Mock()
    server_instance.start = AsyncMock()
    server_instance.stop = AsyncMock()
    server_instance.get_app = Mock()

    # Mock the FastMCP app
    app_mock = Mock()
    app_mock.run = Mock()
    server_instance.get_app.return_value = app_mock

    return server_instance


@pytest.fixture
def mock_fastmcp_app():
    """Create a mock FastMCP app."""
    app_mock = Mock()
    app_mock.run = Mock()
    return app_mock


@pytest.fixture
def mock_config():
    """Create a mock Config."""
    config_instance = Mock()
    config_instance.server = Mock()
    config_instance.security = Mock()
    config_instance.security.allowed_client_ips = []
    return config_instance


class TestRunStdio:
    """Test the run_stdio function."""

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_stdio_basic_flow(
        self, mock_asyncio_run, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test basic stdio transport flow."""
        from mcp_docker.__main__ import run_stdio

        # Run stdio with required arguments
        run_stdio(mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        # Verify startup and shutdown were called
        assert mock_asyncio_run.call_count >= 2

        # Verify app.run was called with stdio transport
        mock_fastmcp_app.run.assert_called_once_with(transport="stdio")

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_stdio_cleanup_on_error(
        self, mock_asyncio_run, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test cleanup happens even if app.run raises."""
        from mcp_docker.__main__ import run_stdio

        # Make app.run raise an error
        mock_fastmcp_app.run = Mock(side_effect=RuntimeError("Test error"))

        # Run stdio - should raise but still cleanup
        with pytest.raises(RuntimeError, match="Test error"):
            run_stdio(mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        # Verify shutdown was called even after error
        assert mock_asyncio_run.call_count >= 2


class TestRunHttp:
    """Test the run_http function."""

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_http_localhost(
        self, mock_asyncio_run, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test HTTP transport with localhost."""
        from mcp_docker.__main__ import run_http

        # Run HTTP with localhost
        run_http("127.0.0.1", 8000, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        # Verify app.run was called with http transport
        mock_fastmcp_app.run.assert_called_once_with(
            transport="http",
            host="127.0.0.1",
            port=8000,
        )

        # Verify no security warnings for localhost
        warning_calls = list(mock_logger.warning.call_args_list)
        security_warnings = [call for call in warning_calls if "SECURITY WARNING" in str(call)]
        assert len(security_warnings) == 0

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_http_non_localhost_warning(
        self, mock_asyncio_run, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test HTTP transport with non-localhost shows security warning."""
        from mcp_docker.__main__ import run_http

        # Run HTTP with non-localhost
        run_http("0.0.0.0", 8080, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        # Verify security warning was logged
        mock_logger.warning.assert_called()
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any("SECURITY WARNING" in call for call in warning_calls)

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_http_no_ip_allowlist_warning(
        self, mock_asyncio_run, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test HTTP transport without IP allowlist shows warning."""
        from mcp_docker.__main__ import run_http

        # Run HTTP with non-localhost and no allowlist
        run_http("0.0.0.0", 8080, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        # Verify IP allowlist warning was logged
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any("IP allowlist is NOT configured" in call for call in warning_calls)

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_http_cleanup_on_error(
        self, mock_asyncio_run, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app
    ):
        """Test cleanup happens even if app.run raises."""
        from mcp_docker.__main__ import run_http

        # Make app.run raise an error
        mock_fastmcp_app.run = Mock(side_effect=RuntimeError("Test error"))

        # Run HTTP - should raise but still cleanup
        with pytest.raises(RuntimeError, match="Test error"):
            run_http(
                "127.0.0.1", 8000, mock_config, mock_logger, mock_fastmcp_server, mock_fastmcp_app
            )

        # Verify shutdown was called even after error
        assert mock_asyncio_run.call_count >= 2


class TestMain:
    """Test the main function using Typer CLI runner."""

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    def test_main_stdio_transport(
        self, mock_config_cls, mock_server_cls, mock_get_logger, mock_setup_logger, mock_run_stdio
    ):
        """Test main with stdio transport."""
        from mcp_docker.__main__ import app

        # Setup mocks
        mock_config = Mock()
        mock_config.server = Mock()
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_server.get_app = Mock(return_value=Mock())
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        # Run CLI
        runner = CliRunner()
        result = runner.invoke(app, ["--transport", "stdio"])

        # Verify it ran successfully
        assert result.exit_code == 0
        mock_run_stdio.assert_called_once_with(mock_logger, mock_server, ANY)

    @patch("mcp_docker.__main__.run_http")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    def test_main_http_transport(
        self, mock_config_cls, mock_server_cls, mock_get_logger, mock_setup_logger, mock_run_http
    ):
        """Test main with http transport."""
        from mcp_docker.__main__ import app

        # Setup mocks
        mock_config = Mock()
        mock_config.server = Mock()
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_server.get_app = Mock(return_value=Mock())
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        # Run CLI
        runner = CliRunner()
        result = runner.invoke(app, ["--transport", "http", "--host", "0.0.0.0", "--port", "9000"])

        # Verify it ran successfully
        assert result.exit_code == 0
        mock_run_http.assert_called_once_with(
            "0.0.0.0", 9000, mock_config, mock_logger, mock_server, ANY
        )

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    def test_main_default_transport(
        self, mock_config_cls, mock_server_cls, mock_get_logger, mock_setup_logger, mock_run_stdio
    ):
        """Test main with default transport (stdio)."""
        from mcp_docker.__main__ import app

        # Setup mocks
        mock_config = Mock()
        mock_config.server = Mock()
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_server.get_app = Mock(return_value=Mock())
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        # Run CLI with no arguments (default transport)
        runner = CliRunner()
        result = runner.invoke(app, [])

        # Verify it ran successfully with default stdio transport
        assert result.exit_code == 0
        mock_run_stdio.assert_called_once()

    def test_main_invalid_transport(self):
        """Test main with invalid transport."""
        from mcp_docker.__main__ import app

        # Run CLI with invalid transport
        runner = CliRunner()
        result = runner.invoke(app, ["--transport", "invalid"])

        # Typer will fail with invalid choice
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "invalid" in result.output.lower()

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    def test_main_keyboard_interrupt(
        self, mock_config_cls, mock_server_cls, mock_get_logger, mock_setup_logger, mock_run_stdio
    ):
        """Test main handles KeyboardInterrupt gracefully."""
        from mcp_docker.__main__ import app

        # Setup mocks
        mock_config = Mock()
        mock_config.server = Mock()
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_server.get_app = Mock(return_value=Mock())
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        # Make run_stdio raise KeyboardInterrupt
        mock_run_stdio.side_effect = KeyboardInterrupt()

        # Run CLI
        runner = CliRunner()
        result = runner.invoke(app, [])

        # Should handle interrupt gracefully (exit code 0 since it's caught)
        assert result.exit_code == 0
        mock_logger.info.assert_called_with("Received interrupt signal")

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    def test_main_unexpected_error(
        self, mock_config_cls, mock_server_cls, mock_get_logger, mock_setup_logger, mock_run_stdio
    ):
        """Test main handles unexpected errors."""
        from mcp_docker.__main__ import app

        # Setup mocks
        mock_config = Mock()
        mock_config.server = Mock()
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_server.get_app = Mock(return_value=Mock())
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        # Make run_stdio raise an unexpected error
        test_error = RuntimeError("Unexpected error")
        mock_run_stdio.side_effect = test_error

        # Run CLI
        runner = CliRunner()
        result = runner.invoke(app, [])

        # Should raise the error (Typer catches and exits with code 1)
        assert result.exit_code == 1
        mock_logger.exception.assert_called_with("Server error: Unexpected error")

    def test_version_flag(self):
        """Test --version flag."""
        from mcp_docker.__main__ import app

        # Run CLI with --version
        runner = CliRunner()
        result = runner.invoke(app, ["--version"])

        # Should show version and exit
        assert result.exit_code == 0
        assert "mcp-docker" in result.output

    def test_help_flag(self):
        """Test --help flag."""
        from mcp_docker.__main__ import app

        # Run CLI with --help
        runner = CliRunner()
        result = runner.invoke(app, ["--help"])

        # Should show help and exit
        assert result.exit_code == 0
        # Typer shows the function docstring, not the app help
        assert "Run the MCP Docker server" in result.output or "MCP Docker Server" in result.output
        # Check for key options - case-insensitive to handle different terminal formats
        assert "transport" in result.output.lower()
        assert "stdio" in result.output.lower()
        assert "http" in result.output.lower()
