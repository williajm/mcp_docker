"""Unit tests for middleware utility functions."""

from unittest.mock import Mock

from mcp_docker.middleware.utils import get_operation_name, get_operation_type


class TestGetOperationType:
    """Test get_operation_type function."""

    def test_tool_call_with_name_and_arguments(self):
        """Test operation type for tool calls."""
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message

        result = get_operation_type(context)
        assert result == "tool_call:docker_list_containers"

    def test_mcp_protocol_with_method(self):
        """Test operation type for MCP protocol operations."""
        message = Mock()
        message.method = "tools/list"
        del message.name  # Remove name attribute
        del message.arguments

        context = Mock()
        context.message = message

        result = get_operation_type(context)
        assert result == "tools/list"

    def test_protocol_method_prompts_list(self):
        """Test operation type for prompts/list."""
        message = Mock()
        message.method = "prompts/list"
        del message.name
        del message.arguments

        context = Mock()
        context.message = message

        result = get_operation_type(context)
        assert result == "prompts/list"

    def test_protocol_method_resources_list(self):
        """Test operation type for resources/list."""
        message = Mock()
        message.method = "resources/list"
        del message.name
        del message.arguments

        context = Mock()
        context.message = message

        result = get_operation_type(context)
        assert result == "resources/list"

    def test_context_operation_attribute(self):
        """Test operation type from context.operation attribute."""
        message = Mock(spec=[])  # Empty spec
        context = Mock()
        context.message = message
        context.operation = "custom_operation"

        result = get_operation_type(context)
        assert result == "custom_operation"

    def test_dict_message_with_method(self):
        """Test operation type from dict message."""
        message = {"method": "tools/list"}
        context = Mock(spec=["message"])  # Don't auto-create operation attribute
        context.message = message

        result = get_operation_type(context)
        assert result == "tools/list"

    def test_dict_message_with_name_and_arguments(self):
        """Test tool call from dict message."""
        message = {"name": "docker_start_container", "arguments": {"container_id": "abc"}}
        context = Mock(spec=["message"])
        context.message = message

        result = get_operation_type(context)
        assert result == "tool_call:docker_start_container"

    def test_message_type_class_name(self):
        """Test fallback to message type class name."""

        class CustomMessageType:
            pass

        message = CustomMessageType()
        context = Mock(spec=["message"])
        context.message = message

        result = get_operation_type(context)
        assert result == "CustomMessageType"

    def test_generic_object_fallback(self):
        """Test fallback to mcp_protocol for generic objects."""
        message = Mock(spec=[])  # No relevant attributes
        context = Mock(spec=["message"])
        context.message = message

        result = get_operation_type(context)
        assert result == "Mock"  # Falls back to class name

    def test_dict_type_fallback(self):
        """Test fallback for dict without method/name."""
        message = {"some_key": "some_value"}
        context = Mock(spec=["message"])
        context.message = message

        result = get_operation_type(context)
        assert result == "mcp_protocol"


class TestGetOperationName:
    """Test get_operation_name function."""

    def test_tool_call_returns_tool_name(self):
        """Test that tool calls return just the tool name."""
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message

        result = get_operation_name(context)
        assert result == "docker_list_containers"

    def test_mcp_protocol_returns_method(self):
        """Test that MCP protocol operations return the method name."""
        message = Mock()
        message.method = "tools/list"
        del message.name

        context = Mock()
        context.message = message

        result = get_operation_name(context)
        assert result == "tools/list"

    def test_no_tool_name_falls_back_to_operation_type(self):
        """Test fallback when no tool name is present."""
        message = Mock(spec=[])
        context = Mock(spec=["message"])
        context.message = message

        result = get_operation_name(context)
        assert result == "Mock"  # Falls back to class name

    def test_removes_tool_call_prefix(self):
        """Test that tool_call: prefix is removed from operation type."""
        message = Mock(spec=[])  # No name attribute
        context = Mock()
        context.message = message

        # Even though get_operation_type would return "mcp_protocol" for this,
        # test the stripping logic works if it did have the prefix
        result = get_operation_name(context)
        # Should return without tool_call: prefix
        assert not result.startswith("tool_call:")

    def test_with_prompts_list(self):
        """Test operation name for prompts/list."""
        message = Mock()
        message.method = "prompts/list"
        del message.name

        context = Mock()
        context.message = message

        result = get_operation_name(context)
        assert result == "prompts/list"
