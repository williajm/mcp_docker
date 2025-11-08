"""Helper utilities for E2E tests.

This module provides type guards and utility functions for working with
MCP protocol types in E2E tests, ensuring type safety and reducing
code duplication.
"""

from typing import Any

from mcp.types import (
    AudioContent,
    CallToolResult,
    EmbeddedResource,
    ImageContent,
    ResourceLink,
    TextContent,
)


def extract_text_content(
    content: TextContent | ImageContent | AudioContent | ResourceLink | EmbeddedResource,
) -> str:
    """Extract text from MCP content, with type narrowing.

    Args:
        content: MCP content union type

    Returns:
        Text content string

    Raises:
        TypeError: If content is not TextContent
    """
    if isinstance(content, TextContent):
        return content.text
    raise TypeError(f"Expected TextContent, got {type(content).__name__}")


def get_tool_result_text(result: CallToolResult, index: int = 0) -> str:
    """Extract text from tool result content at specified index.

    Args:
        result: MCP CallToolResult
        index: Index of content item (default: 0)

    Returns:
        Text content string

    Raises:
        IndexError: If index out of range
        TypeError: If content is not TextContent
    """
    if not result.content or index >= len(result.content):
        raise IndexError(f"Content index {index} out of range")

    return extract_text_content(result.content[index])


def assert_tool_success(result: CallToolResult) -> None:
    """Assert that a tool call was successful.

    Args:
        result: MCP CallToolResult

    Raises:
        AssertionError: If tool call failed or content is missing
    """
    assert result.content, "Tool result has no content"
    text = get_tool_result_text(result)
    assert "error" not in text.lower() or "success" in text.lower(), f"Tool call failed: {text}"


def assert_tool_error(result: CallToolResult, expected_error: str | None = None) -> None:
    """Assert that a tool call failed with expected error.

    Args:
        result: MCP CallToolResult
        expected_error: Optional substring to check in error message

    Raises:
        AssertionError: If tool call succeeded or error message doesn't match
    """
    assert result.content, "Tool result has no content"
    text = get_tool_result_text(result)
    assert "error" in text.lower(), f"Expected error but got: {text}"

    if expected_error:
        assert expected_error.lower() in text.lower(), (
            f"Expected error containing '{expected_error}', got: {text}"
        )


def is_text_content(content: Any) -> bool:
    """Type guard for TextContent.

    Args:
        content: Content to check

    Returns:
        True if content is TextContent
    """
    return isinstance(content, TextContent)


def is_image_content(content: Any) -> bool:
    """Type guard for ImageContent.

    Args:
        content: Content to check

    Returns:
        True if content is ImageContent
    """
    return isinstance(content, ImageContent)


def is_audio_content(content: Any) -> bool:
    """Type guard for AudioContent.

    Args:
        content: Content to check

    Returns:
        True if content is AudioContent
    """
    return isinstance(content, AudioContent)
