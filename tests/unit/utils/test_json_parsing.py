"""Unit tests for JSON parsing utilities."""

import pytest

from mcp_docker.utils.json_parsing import parse_json_string_field


class TestParseJsonStringField:
    """Tests for parse_json_string_field function."""

    def test_parse_valid_json_string(self) -> None:
        """Test parsing valid JSON string."""
        json_str = '{"key": "value", "number": 42}'
        result = parse_json_string_field(json_str, "test_field")

        assert result == {"key": "value", "number": 42}
        assert isinstance(result, dict)

    def test_parse_dict_returns_unchanged(self) -> None:
        """Test that dict values are returned unchanged."""
        original_dict = {"key": "value", "number": 42}
        result = parse_json_string_field(original_dict, "test_field")

        assert result is original_dict
        assert result == {"key": "value", "number": 42}

    def test_parse_invalid_json_string_raises_error(self) -> None:
        """Test that invalid JSON string raises ValueError."""
        invalid_json = "{invalid json syntax"

        with pytest.raises(ValueError) as exc_info:
            parse_json_string_field(invalid_json, "test_field")

        assert "Received invalid JSON string for test_field" in str(exc_info.value)
        assert "Expected an object/dict" in str(exc_info.value)

    def test_parse_non_json_non_dict_returns_unchanged(self) -> None:
        """Test that non-JSON, non-dict values are returned unchanged."""
        # Integer
        assert parse_json_string_field(42, "test_field") == 42

        # List
        test_list = [1, 2, 3]
        assert parse_json_string_field(test_list, "test_field") == test_list

        # None
        assert parse_json_string_field(None, "test_field") is None

    def test_parse_empty_json_object_string(self) -> None:
        """Test parsing empty JSON object string."""
        result = parse_json_string_field("{}", "test_field")
        assert result == {}

    def test_parse_json_array_string(self) -> None:
        """Test parsing JSON array string."""
        json_array = '[1, 2, 3, "four"]'
        result = parse_json_string_field(json_array, "test_field")
        assert result == [1, 2, 3, "four"]

    def test_parse_nested_json_string(self) -> None:
        """Test parsing nested JSON structure."""
        nested_json = '{"outer": {"inner": {"value": 123}}}'
        result = parse_json_string_field(nested_json, "test_field")
        assert result == {"outer": {"inner": {"value": 123}}}

    def test_error_message_truncates_long_strings(self) -> None:
        """Test that error messages truncate very long invalid JSON strings."""
        long_invalid_json = "{invalid" + ("x" * 200)

        with pytest.raises(ValueError) as exc_info:
            parse_json_string_field(long_invalid_json, "test_field")

        error_msg = str(exc_info.value)
        # Should truncate to 100 chars + "..."
        assert len(error_msg) < len(long_invalid_json) + 100

    def test_custom_field_name_in_error(self) -> None:
        """Test that custom field name appears in error message."""
        with pytest.raises(ValueError) as exc_info:
            parse_json_string_field("{bad json", "custom_field_name")

        assert "custom_field_name" in str(exc_info.value)

    def test_parse_json_with_special_characters(self) -> None:
        """Test parsing JSON with special characters and unicode."""
        json_str = '{"emoji": "🚀", "newline": "line1\\nline2", "quote": "He said \\"hello\\""}'
        result = parse_json_string_field(json_str, "test_field")

        assert result["emoji"] == "🚀"
        assert result["newline"] == "line1\nline2"
        assert result["quote"] == 'He said "hello"'
