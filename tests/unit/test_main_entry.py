"""Unit tests for __main__.py entry point."""

from unittest.mock import AsyncMock, Mock, patch

import pytest


@pytest.fixture
def mock_fastmcp_server():
    """Create a mock FastMCPDockerServer."""
    with patch("mcp_docker.__main__.FastMCPDockerServer") as mock:
        server_instance = Mock()
        server_instance.start = AsyncMock()
        server_instance.stop = AsyncMock()
        server_instance.get_app = Mock()

        # Mock the FastMCP app
        app_mock = Mock()
        app_mock.run = Mock()
        server_instance.get_app.return_value = app_mock

        mock.return_value = server_instance
        yield mock


@pytest.fixture
def mock_config():
    """Create a mock Config."""
    with patch("mcp_docker.__main__.Config") as mock:
        config_instance = Mock()
        config_instance.server = Mock()
        config_instance.security = Mock()
        config_instance.security.allowed_client_ips = []
        mock.return_value = config_instance
        yield mock


# Version and help tests removed - they test module-level early exit code
# which is difficult to test properly in pytest


class TestRunStdio:
    """Test the run_stdio function."""

    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    def test_run_stdio_basic_flow(self, mock_app, mock_server, mock_asyncio_run):
        """Test basic stdio transport flow."""
        from mcp_docker.__main__ import run_stdio

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock()

        # Run stdio
        run_stdio()

        # Verify startup was called
        assert mock_asyncio_run.call_count >= 2

        # Verify app.run was called with stdio transport
        mock_app.run.assert_called_once_with(transport="stdio")

    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    def test_run_stdio_cleanup_on_error(self, mock_app, mock_server, mock_asyncio_run):
        """Test cleanup happens even if app.run raises."""
        from mcp_docker.__main__ import run_stdio

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock(side_effect=RuntimeError("Test error"))

        # Run stdio - should raise but still cleanup
        with pytest.raises(RuntimeError, match="Test error"):
            run_stdio()

        # Verify shutdown was called even after error
        assert mock_asyncio_run.call_count >= 2


class TestRunHttp:
    """Test the run_http function."""

    @patch("mcp_docker.__main__.logger")
    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    @patch("mcp_docker.__main__.config")
    def test_run_http_localhost(
        self, mock_config, mock_app, mock_server, mock_asyncio_run, mock_logger
    ):
        """Test HTTP transport with localhost."""
        from mcp_docker.__main__ import run_http

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock()
        mock_config.security.allowed_client_ips = []

        # Run HTTP with localhost
        run_http("127.0.0.1", 8000)

        # Verify app.run was called with http transport
        mock_app.run.assert_called_once_with(
            transport="http",
            host="127.0.0.1",
            port=8000,
        )

        # Verify no security warnings for localhost
        warning_calls = list(mock_logger.warning.call_args_list)
        security_warnings = [call for call in warning_calls if "SECURITY WARNING" in str(call)]
        assert len(security_warnings) == 0

    @patch("mcp_docker.__main__.logger")
    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    @patch("mcp_docker.__main__.config")
    def test_run_http_non_localhost_warning(
        self, mock_config, mock_app, mock_server, mock_asyncio_run, mock_logger
    ):
        """Test HTTP transport with non-localhost shows security warning."""
        from mcp_docker.__main__ import run_http

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock()
        mock_config.security.allowed_client_ips = []

        # Run HTTP with non-localhost
        run_http("0.0.0.0", 8080)

        # Verify security warning was logged
        mock_logger.warning.assert_called()
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any("SECURITY WARNING" in call for call in warning_calls)

    @patch("mcp_docker.__main__.logger")
    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    @patch("mcp_docker.__main__.config")
    def test_run_http_no_ip_allowlist_warning(
        self, mock_config, mock_app, mock_server, mock_asyncio_run, mock_logger
    ):
        """Test HTTP transport without IP allowlist shows warning."""
        from mcp_docker.__main__ import run_http

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock()
        mock_config.security.allowed_client_ips = []

        # Run HTTP with non-localhost and no allowlist
        run_http("0.0.0.0", 8080)

        # Verify IP allowlist warning was logged
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any("IP allowlist is NOT configured" in call for call in warning_calls)

    @patch("mcp_docker.__main__.asyncio.run")
    @patch("mcp_docker.__main__.fastmcp_docker_server")
    @patch("mcp_docker.__main__.fastmcp_app")
    @patch("mcp_docker.__main__.config")
    def test_run_http_cleanup_on_error(self, mock_config, mock_app, mock_server, mock_asyncio_run):
        """Test cleanup happens even if app.run raises."""
        from mcp_docker.__main__ import run_http

        # Setup mocks
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_app.run = Mock(side_effect=RuntimeError("Test error"))
        mock_config.security.allowed_client_ips = []

        # Run HTTP - should raise but still cleanup
        with pytest.raises(RuntimeError, match="Test error"):
            run_http("127.0.0.1", 8000)

        # Verify shutdown was called even after error
        assert mock_asyncio_run.call_count >= 2


class TestMain:
    """Test the main function."""

    @patch("mcp_docker.__main__.run_stdio")
    @patch("sys.argv", ["mcp-docker", "--transport", "stdio"])
    def test_main_stdio_transport(self, mock_run_stdio):
        """Test main with stdio transport."""
        from mcp_docker.__main__ import main

        main()

        mock_run_stdio.assert_called_once()

    @patch("mcp_docker.__main__.run_http")
    @patch("sys.argv", ["mcp-docker", "--transport", "http", "--host", "0.0.0.0", "--port", "9000"])
    def test_main_http_transport(self, mock_run_http):
        """Test main with http transport."""
        from mcp_docker.__main__ import main

        main()

        mock_run_http.assert_called_once_with("0.0.0.0", 9000)

    @patch("mcp_docker.__main__.run_stdio")
    @patch("sys.argv", ["mcp-docker"])
    def test_main_default_transport(self, mock_run_stdio):
        """Test main with default transport (stdio)."""
        from mcp_docker.__main__ import main

        main()

        mock_run_stdio.assert_called_once()

    @patch("mcp_docker.__main__.logger")
    @patch("sys.argv", ["mcp-docker", "--transport", "invalid"])
    def test_main_invalid_transport(self, mock_logger):
        """Test main with invalid transport."""
        from mcp_docker.__main__ import main

        # Should exit with error
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code != 0

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.logger")
    @patch("sys.argv", ["mcp-docker"])
    def test_main_keyboard_interrupt(self, mock_logger, mock_run_stdio):
        """Test main handles KeyboardInterrupt gracefully."""
        from mcp_docker.__main__ import main

        mock_run_stdio.side_effect = KeyboardInterrupt()

        # Should not raise
        main()

        # Should log the interrupt
        mock_logger.info.assert_called()

    @patch("mcp_docker.__main__.run_stdio")
    @patch("mcp_docker.__main__.logger")
    @patch("sys.argv", ["mcp-docker"])
    def test_main_unexpected_error(self, mock_logger, mock_run_stdio):
        """Test main handles unexpected errors."""
        from mcp_docker.__main__ import main

        test_error = RuntimeError("Unexpected error")
        mock_run_stdio.side_effect = test_error

        # Should raise the error
        with pytest.raises(RuntimeError, match="Unexpected error"):
            main()

        # Should log the exception
        mock_logger.exception.assert_called()
