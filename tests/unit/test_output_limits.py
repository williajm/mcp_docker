"""Unit tests for output limiting utilities."""

from humanfriendly import format_size

from mcp_docker.utils.output_limits import (
    create_truncation_metadata,
    truncate_lines,
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


class TestFormatSize:
    """Tests for humanfriendly.format_size function."""

    def test_bytes(self) -> None:
        """Test formatting of byte values."""
        assert format_size(0) == "0 bytes"
        assert format_size(512) == "512 bytes"

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
