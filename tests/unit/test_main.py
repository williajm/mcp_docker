"""Unit tests for __main__.py MCP server entry point."""

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

# Import the module components we need to test
from mcp_docker import __main__ as main_module


class TestMCPServerHandlers:
    """Tests for MCP server handler functions."""

    @pytest.mark.asyncio
    async def test_handle_list_tools(self):
        """Test list_tools handler."""
        # Mock the docker_server
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_tools.return_value = [
                {
                    "name": "test_tool",
                    "description": "Test tool",
                    "inputSchema": {"type": "object"},
                }
            ]

            result = await main_module.handle_list_tools()

            assert len(result) == 1
            assert result[0].name == "test_tool"
            assert result[0].description == "Test tool"

    @pytest.mark.asyncio
    async def test_handle_call_tool_success(self):
        """Test call_tool handler with successful result."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": True, "result": {"output": "test output"}}
            )

            result = await main_module.handle_call_tool("test_tool", {})

            assert len(result) == 1
            assert result[0]["type"] == "text"
            assert "test output" in result[0]["text"]

    @pytest.mark.asyncio
    async def test_handle_call_tool_error(self):
        """Test call_tool handler with error result."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.call_tool = AsyncMock(
                return_value={"success": False, "error": "Test error message"}
            )

            result = await main_module.handle_call_tool("test_tool", {})

            assert len(result) == 1
            assert result[0]["type"] == "text"
            assert "Error: Test error message" in result[0]["text"]

    @pytest.mark.asyncio
    async def test_handle_list_resources(self):
        """Test list_resources handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_resources.return_value = [
                {"uri": "docker://container/test", "name": "Test Container"}
            ]

            result = await main_module.handle_list_resources()

            assert len(result) == 1
            assert result[0]["uri"] == "docker://container/test"

    @pytest.mark.asyncio
    async def test_handle_read_resource_with_text(self):
        """Test read_resource handler with text content."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.read_resource = AsyncMock(return_value={"text": "Resource content"})

            result = await main_module.handle_read_resource("docker://test")

            assert result == "Resource content"

    @pytest.mark.asyncio
    async def test_handle_read_resource_without_text(self):
        """Test read_resource handler without text field."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.read_resource = AsyncMock(return_value={"data": "some data"})

            result = await main_module.handle_read_resource("docker://test")

            assert "data" in result

    @pytest.mark.asyncio
    async def test_handle_list_prompts(self):
        """Test list_prompts handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.list_prompts.return_value = [
                {"name": "test_prompt", "description": "Test prompt"}
            ]

            result = await main_module.handle_list_prompts()

            assert len(result) == 1
            assert result[0]["name"] == "test_prompt"

    @pytest.mark.asyncio
    async def test_handle_get_prompt(self):
        """Test get_prompt handler."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.get_prompt = AsyncMock(
                return_value={
                    "name": "test_prompt",
                    "messages": [{"role": "user", "content": "Test message"}],
                }
            )

            result = await main_module.handle_get_prompt("test_prompt", None)

            assert result["name"] == "test_prompt"
            mock_server.get_prompt.assert_called_once_with("test_prompt", {})

    @pytest.mark.asyncio
    async def test_handle_get_prompt_with_arguments(self):
        """Test get_prompt handler with arguments."""
        with patch.object(main_module, "docker_server") as mock_server:
            mock_server.get_prompt = AsyncMock(return_value={"name": "test_prompt"})

            args = {"param": "value"}
            result = await main_module.handle_get_prompt("test_prompt", args)

            mock_server.get_prompt.assert_called_once_with("test_prompt", args)


class TestServerRunFunction:
    """Tests for run_server function."""

    @pytest.mark.asyncio
    async def test_run_server(self):
        """Test run_server function."""
        # Mock all the async components
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()

        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch.object(main_module, "mcp_server") as mock_mcp_server:
                mock_mcp_server.run = AsyncMock()
                mock_mcp_server.create_initialization_options = Mock(
                    return_value={"options": "test"}
                )

                with patch("mcp_docker.__main__.stdio_server") as mock_stdio:
                    # Setup async context manager
                    mock_stdio.return_value.__aenter__ = AsyncMock(
                        return_value=(mock_read_stream, mock_write_stream)
                    )
                    mock_stdio.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Run the server function
                    await main_module.run_server()

                    # Verify calls
                    mock_docker_server.start.assert_called_once()
                    mock_mcp_server.run.assert_called_once()
                    mock_docker_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_server_cleanup_on_error(self):
        """Test run_server cleans up on error."""
        with patch.object(main_module, "docker_server") as mock_docker_server:
            mock_docker_server.start = AsyncMock()
            mock_docker_server.stop = AsyncMock()

            with patch.object(main_module, "mcp_server") as mock_mcp_server:
                mock_mcp_server.run = AsyncMock(side_effect=Exception("Test error"))
                mock_mcp_server.create_initialization_options = Mock(
                    return_value={"options": "test"}
                )

                with patch("mcp_docker.__main__.stdio_server") as mock_stdio:
                    mock_stdio.return_value.__aenter__ = AsyncMock(
                        return_value=(AsyncMock(), AsyncMock())
                    )
                    mock_stdio.return_value.__aexit__ = AsyncMock(return_value=None)

                    # Should raise the exception
                    with pytest.raises(Exception, match="Test error"):
                        await main_module.run_server()

                    # But should still call stop
                    mock_docker_server.stop.assert_called_once()


class TestMainFunction:
    """Tests for main function."""

    def test_main_success(self):
        """Test main function with successful execution."""
        with patch("asyncio.run") as mock_asyncio_run:
            main_module.main()
            mock_asyncio_run.assert_called_once()

    def test_main_keyboard_interrupt(self):
        """Test main function handles KeyboardInterrupt."""
        with patch("asyncio.run", side_effect=KeyboardInterrupt()):
            # Should not raise, just log
            main_module.main()

    def test_main_exception(self):
        """Test main function handles exceptions."""
        with patch("asyncio.run", side_effect=Exception("Test error")):
            with pytest.raises(Exception, match="Test error"):
                main_module.main()
