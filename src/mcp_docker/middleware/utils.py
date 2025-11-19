"""Utility functions for middleware operations."""

from typing import Any

from fastmcp.server.middleware import MiddlewareContext


def get_operation_type(context: MiddlewareContext[Any]) -> str:
    """Determine the type of MCP operation from context.

    This function extracts the operation type from the middleware context,
    identifying whether it's a tool call, MCP protocol operation (tools/list,
    prompts/list, etc.), or other operation type.

    Args:
        context: FastMCP middleware context

    Returns:
        Operation type string (e.g., "tools/list", "tool_call:docker_list_containers", etc.)

    Examples:
        - Tool call: "tool_call:docker_list_containers"
        - MCP protocol: "tools/list", "prompts/list", "resources/list"
        - Other: message type class name or "mcp_protocol"
    """
    message = context.message

    # Check if it's a tool call (has 'name' attribute for tool name)
    if hasattr(message, "name") and hasattr(message, "arguments"):
        tool_name = getattr(message, "name", None)
        if tool_name:
            return f"tool_call:{tool_name}"

    # Check for MCP protocol methods (tools/list, prompts/list, resources/list, etc.)
    if hasattr(message, "method"):
        method = getattr(message, "method", None)
        if method:
            return str(method)

    # Check for _meta or other FastMCP internal attributes
    if hasattr(context, "operation"):
        return str(context.operation)

    # Try to infer from message dictionary if it's a dict-like object
    if isinstance(message, dict):
        if "method" in message:
            return str(message["method"])
        if "name" in message and "arguments" in message:
            return f"tool_call:{message['name']}"

    # Try to infer from message type class name (but not generic types)
    message_type = type(message).__name__
    return message_type if message_type not in ["object", "dict"] else "mcp_protocol"


def get_operation_name(context: MiddlewareContext[Any]) -> str:
    """Get a human-readable operation name from context.

    This is similar to get_operation_type but returns just the tool/operation name
    without the "tool_call:" prefix, suitable for logging.

    Args:
        context: FastMCP middleware context

    Returns:
        Operation name string

    Examples:
        - Tool call: "docker_list_containers"
        - MCP protocol: "tools/list", "prompts/list", "resources/list"
    """
    # First try to get the tool name directly
    tool_name = getattr(context.message, "name", None)
    if tool_name:
        return str(tool_name)

    # Fall back to operation type
    operation_type = get_operation_type(context)

    # Remove "tool_call:" prefix if present
    if operation_type.startswith("tool_call:"):
        return operation_type[10:]  # len("tool_call:") == 10

    return operation_type
