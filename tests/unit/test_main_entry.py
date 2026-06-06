"""Unit tests for __main__.py entry point."""

from unittest.mock import AsyncMock, Mock, patch

import pytest


def _close_coroutine(coro: object) -> None:
    """Close coroutine objects passed to a mocked asyncio.run."""
    close = getattr(coro, "close", None)
    if callable(close):
        close()


@pytest.fixture
def mock_logger() -> Mock:
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def mock_fastmcp_server() -> Mock:
    """Create a mock FastMCPDockerServer."""
    server_instance = Mock()
    server_instance.start = AsyncMock()
    server_instance.stop = AsyncMock()
    server_instance.get_app = Mock()
    return server_instance


@pytest.fixture
def mock_fastmcp_app() -> Mock:
    """Create a mock FastMCP app."""
    app_mock = Mock()
    app_mock.run = Mock()
    return app_mock


class TestRunStdio:
    """Test the _run_stdio function."""

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_stdio_basic_flow(
        self,
        mock_asyncio_run: Mock,
        mock_logger: Mock,
        mock_fastmcp_server: Mock,
        mock_fastmcp_app: Mock,
    ) -> None:
        """Test basic stdio transport flow."""
        from mcp_docker.__main__ import _run_stdio

        mock_asyncio_run.side_effect = _close_coroutine
        _run_stdio(mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        assert mock_asyncio_run.call_count >= 2
        mock_fastmcp_app.run.assert_called_once_with(transport="stdio")

    @patch("mcp_docker.__main__.asyncio.run")
    def test_run_stdio_cleanup_on_error(
        self,
        mock_asyncio_run: Mock,
        mock_logger: Mock,
        mock_fastmcp_server: Mock,
        mock_fastmcp_app: Mock,
    ) -> None:
        """Test cleanup happens even if app.run raises."""
        from mcp_docker.__main__ import _run_stdio

        mock_asyncio_run.side_effect = _close_coroutine
        mock_fastmcp_app.run = Mock(side_effect=RuntimeError("Test error"))

        with pytest.raises(RuntimeError, match="Test error"):
            _run_stdio(mock_logger, mock_fastmcp_server, mock_fastmcp_app)

        assert mock_asyncio_run.call_count >= 2


class TestMain:
    """Test main function."""

    @patch("mcp_docker.__main__._run_stdio")
    @patch("mcp_docker.__main__.setup_logger")
    @patch("mcp_docker.__main__.get_logger")
    @patch("mcp_docker.__main__.FastMCPDockerServer")
    @patch("mcp_docker.__main__.Config")
    @patch("sys.argv", ["mcp-docker"])
    def test_main_starts_stdio(
        self,
        mock_config_cls: Mock,
        mock_server_cls: Mock,
        mock_get_logger: Mock,
        mock_setup_logger: Mock,
        mock_run_stdio: Mock,
    ) -> None:
        """Test main starts the stdio server."""
        from mcp_docker.__main__ import main

        mock_config = Mock()
        mock_config.server = Mock()
        mock_config.docker.base_url = "unix:///var/run/docker.sock"
        mock_config.safety.allow_moderate_operations = True
        mock_config_cls.return_value = mock_config

        mock_server = Mock()
        mock_app = Mock()
        mock_server.get_app.return_value = mock_app
        mock_server_cls.return_value = mock_server

        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        main()

        mock_setup_logger.assert_called_once()
        mock_run_stdio.assert_called_once_with(mock_logger, mock_server, mock_app)

    @patch("sys.argv", ["mcp-docker", "--version"])
    def test_main_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test --version exits after printing version."""
        from mcp_docker.__main__ import main
        from mcp_docker.version import __version__

        main()

        captured = capsys.readouterr()
        assert captured.out == f"mcp-docker {__version__}\n"
