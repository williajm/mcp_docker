"""Unit tests for output limiting utilities."""

from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    format_size,
    truncate_dict_fields,
    truncate_lines,
    truncate_list,
    truncate_text,
)


class TestTruncateText:
    """Tests for truncate_text function."""

    def test_no_truncation_when_under_limit(self) -> None:
        """Test that text under limit is not truncated."""
        text = "Hello, World!"
        result, was_truncated = truncate_text(text, max_bytes=1000)

        assert result == text
        assert was_truncated is False

    def test_no_truncation_when_limit_is_zero(self) -> None:
        """Test that zero limit means no truncation."""
        text = "Hello, World!"
        result, was_truncated = truncate_text(text, max_bytes=0)

        assert result == text
        assert was_truncated is False

    def test_truncation_when_over_limit(self) -> None:
        """Test that text over limit is truncated."""
        text = "Hello, World! This is a longer message."
        result, was_truncated = truncate_text(text, max_bytes=10)

        assert len(result.encode("utf-8")) <= 10
        assert was_truncated is True
        assert result.startswith("Hello")

    def test_truncation_with_message(self) -> None:
        """Test that truncation message is appended."""
        text = "Hello, World! This is a longer message."
        msg = "[truncated]"
        result, was_truncated = truncate_text(text, max_bytes=10, truncation_message=msg)

        assert was_truncated is True
        assert msg in result

    def test_utf8_boundary_handling(self) -> None:
        """Test that UTF-8 boundaries are respected."""
        text = "こんにちは世界"  # Japanese text
        result, was_truncated = truncate_text(text, max_bytes=10)

        # Should not break UTF-8 sequences
        assert result.encode("utf-8")  # Should not raise
        assert was_truncated is True


class TestTruncateLines:
    """Tests for truncate_lines function."""

    def test_no_truncation_when_under_limit(self) -> None:
        """Test that text with few lines is not truncated."""
        text = "Line 1\nLine 2\nLine 3"
        result, was_truncated = truncate_lines(text, max_lines=10)

        assert result == text
        assert was_truncated is False

    def test_no_truncation_when_limit_is_zero(self) -> None:
        """Test that zero limit means no truncation."""
        text = "Line 1\nLine 2\nLine 3"
        result, was_truncated = truncate_lines(text, max_lines=0)

        assert result == text
        assert was_truncated is False

    def test_truncation_when_over_limit(self) -> None:
        """Test that text with many lines is truncated."""
        text = "\n".join(f"Line {i}" for i in range(100))
        result, was_truncated = truncate_lines(text, max_lines=10)

        assert len(result.splitlines()) <= 10
        assert was_truncated is True
        assert "Line 0" in result
        assert "Line 9" in result
        assert "Line 50" not in result

    def test_truncation_with_message(self) -> None:
        """Test that truncation message is appended."""
        text = "\n".join(f"Line {i}" for i in range(100))
        msg = "[truncated]"
        result, was_truncated = truncate_lines(text, max_lines=10, truncation_message=msg)

        assert was_truncated is True
        assert msg in result


class TestTruncateList:
    """Tests for truncate_list function."""

    def test_no_truncation_when_under_limit(self) -> None:
        """Test that list under limit is not truncated."""
        items = [1, 2, 3, 4, 5]
        result, was_truncated = truncate_list(items, max_items=10)

        assert result == items
        assert was_truncated is False

    def test_no_truncation_when_limit_is_zero(self) -> None:
        """Test that zero limit means no truncation."""
        items = [1, 2, 3, 4, 5]
        result, was_truncated = truncate_list(items, max_items=0)

        assert result == items
        assert was_truncated is False

    def test_truncation_when_over_limit(self) -> None:
        """Test that list over limit is truncated."""
        items = list(range(100))
        result, was_truncated = truncate_list(items, max_items=10)

        assert len(result) == 10
        assert was_truncated is True
        assert result == list(range(10))


class TestTruncateDictFields:
    """Tests for truncate_dict_fields function."""

    def test_no_truncation_when_under_limit(self) -> None:
        """Test that dict with small fields is not truncated."""
        data = {"key1": "short", "key2": "value"}
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=1000)

        assert result == data
        assert len(truncated_fields) == 0

    def test_no_truncation_when_limit_is_zero(self) -> None:
        """Test that zero limit means no truncation."""
        data = {"key1": "short", "key2": "value"}
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=0)

        assert result == data
        assert len(truncated_fields) == 0

    def test_truncation_of_large_string_field(self) -> None:
        """Test that large string fields are truncated."""
        data = {"key1": "x" * 1000, "key2": "short"}
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=100)

        assert len(result["key1"].encode("utf-8")) <= 100
        assert result["key2"] == "short"
        assert "key1" in truncated_fields
        assert truncated_fields["key1"] == 1000

    def test_nested_dict_truncation(self) -> None:
        """Test that nested dicts are truncated recursively."""
        data = {
            "outer": {
                "inner": "x" * 1000,
                "small": "value",
            }
        }
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=100)

        assert len(result["outer"]["inner"].encode("utf-8")) <= 100
        assert result["outer"]["small"] == "value"
        assert "outer.inner" in truncated_fields

    def test_list_in_dict_truncation(self) -> None:
        """Test that lists in dicts are handled."""
        data = {"key": ["short", "x" * 1000]}
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=100)

        assert result["key"][0] == "short"
        assert len(result["key"][1].encode("utf-8")) <= 100
        assert "key[1]" in truncated_fields

    def test_non_string_values_preserved(self) -> None:
        """Test that non-string values are not truncated."""
        data = {
            "str": "x" * 1000,
            "int": 42,
            "float": 3.14,
            "bool": True,
            "none": None,
        }
        result, truncated_fields = truncate_dict_fields(data, max_field_bytes=100)

        assert result["int"] == 42
        assert result["float"] == 3.14
        assert result["bool"] is True
        assert result["none"] is None
        assert "str" in truncated_fields


class TestFormatSize:
    """Tests for format_size function."""

    def test_bytes(self) -> None:
        """Test formatting of byte values."""
        assert format_size(0) == "0.0 B"
        assert format_size(512) == "512.0 B"
        assert format_size(1023) == "1023.0 B"

    def test_kilobytes(self) -> None:
        """Test formatting of kilobyte values."""
        assert "KB" in format_size(1024)
        assert "KB" in format_size(1024 * 512)

    def test_megabytes(self) -> None:
        """Test formatting of megabyte values."""
        assert "MB" in format_size(1024 * 1024)
        assert "MB" in format_size(1024 * 1024 * 50)

    def test_gigabytes(self) -> None:
        """Test formatting of gigabyte values."""
        assert "GB" in format_size(1024 * 1024 * 1024)
        assert "GB" in format_size(1024 * 1024 * 1024 * 5)

    def test_terabytes(self) -> None:
        """Test formatting of terabyte values."""
        assert "TB" in format_size(1024 * 1024 * 1024 * 1024)


class TestCreateTruncationMetadata:
    """Tests for create_truncation_metadata function."""

    def test_not_truncated(self) -> None:
        """Test metadata when nothing was truncated."""
        metadata = create_truncation_metadata(was_truncated=False)

        assert metadata == {"truncated": False}

    def test_size_truncation(self) -> None:
        """Test metadata for size-based truncation."""
        metadata = create_truncation_metadata(
            was_truncated=True,
            original_size=1000,
            truncated_size=500,
        )

        assert metadata["truncated"] is True
        assert metadata["original_bytes"] == 1000
        assert metadata["truncated_bytes"] == 500
        assert "original_size_human" in metadata
        assert "truncated_size_human" in metadata

    def test_count_truncation(self) -> None:
        """Test metadata for count-based truncation."""
        metadata = create_truncation_metadata(
            was_truncated=True,
            original_count=100,
            truncated_count=10,
        )

        assert metadata["truncated"] is True
        assert metadata["original_count"] == 100
        assert metadata["truncated_count"] == 10

    def test_field_truncation(self) -> None:
        """Test metadata for field-based truncation."""
        truncated_fields = {
            "field1": 1000,
            "field2": 2000,
        }
        metadata = create_truncation_metadata(
            was_truncated=True,
            truncated_fields=truncated_fields,
        )

        assert metadata["truncated"] is True
        assert metadata["truncated_fields_count"] == 2
        assert "field1" in metadata["truncated_fields"]
        assert metadata["truncated_fields"]["field1"]["original_bytes"] == 1000

    def test_combined_metadata(self) -> None:
        """Test metadata with multiple truncation types."""
        metadata = create_truncation_metadata(
            was_truncated=True,
            original_size=1000,
            truncated_size=500,
            original_count=100,
            truncated_count=10,
        )

        assert metadata["truncated"] is True
        assert "original_bytes" in metadata
        assert "original_count" in metadata
