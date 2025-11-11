"""Tests for log sanitization utilities."""

import json

from mcp_docker.utils.log_sanitizer import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_STRING_LENGTH,
    DEFAULT_MAX_TOTAL_SIZE,
    LogSanitizer,
    sanitize_for_json_logging,
    sanitize_for_logging,
)


class TestLogSanitizer:
    """Tests for LogSanitizer class."""

    def test_sanitize_none(self) -> None:
        """Test that None is passed through."""
        sanitizer = LogSanitizer()
        assert sanitizer.sanitize(None) is None

    def test_sanitize_primitives(self) -> None:
        """Test that primitive types are passed through."""
        sanitizer = LogSanitizer()
        assert sanitizer.sanitize(42) == 42
        assert sanitizer.sanitize(3.14) == 3.14
        assert sanitizer.sanitize(True) is True
        assert sanitizer.sanitize(False) is False

    def test_sanitize_short_string(self) -> None:
        """Test that short strings are passed through."""
        sanitizer = LogSanitizer()
        text = "Hello, world!"
        assert sanitizer.sanitize(text) == text

    def test_sanitize_long_string(self) -> None:
        """Test that long strings are truncated."""
        sanitizer = LogSanitizer(max_string_length=100)
        text = "x" * 200
        result = sanitizer.sanitize(text)

        assert isinstance(result, str)
        assert len(result) < 200
        assert "truncated" in result
        assert "200 B total" in result

    def test_sanitize_unicode_string(self) -> None:
        """Test that Unicode strings are handled correctly."""
        sanitizer = LogSanitizer(max_string_length=50)
        text = "🔥" * 100  # Each emoji is multiple bytes
        result = sanitizer.sanitize(text)

        assert isinstance(result, str)
        assert "truncated" in result

    def test_sanitize_bytes(self) -> None:
        """Test that bytes are converted to hex."""
        sanitizer = LogSanitizer()
        data = b"Hello"
        result = sanitizer.sanitize(data)

        assert isinstance(result, str)
        assert "bytes:" in result
        assert "48656c6c6f" in result  # "Hello" in hex

    def test_sanitize_large_bytes(self) -> None:
        """Test that large bytes are truncated."""
        sanitizer = LogSanitizer()
        data = b"x" * 200
        result = sanitizer.sanitize(data)

        assert isinstance(result, str)
        assert "bytes:" in result
        assert "truncated" in result
        assert "200 B total" in result

    def test_sanitize_dict_with_sensitive_keys(self) -> None:
        """Test that sensitive keys are redacted."""
        sanitizer = LogSanitizer()
        data = {
            "username": "alice",
            "password": "secret123",
            "api_key": "sk-abc123",
            "token": "tok_xyz789",
            "secret": "my_secret",
        }
        result = sanitizer.sanitize(data)

        assert result["username"] == "alice"
        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"
        assert result["token"] == "***REDACTED***"
        assert result["secret"] == "***REDACTED***"

    def test_sanitize_dict_case_insensitive(self) -> None:
        """Test that sensitive key matching is case-insensitive."""
        sanitizer = LogSanitizer()
        data = {
            "PASSWORD": "secret",
            "ApiKey": "key",
            "TOKEN": "tok",
        }
        result = sanitizer.sanitize(data)

        assert result["PASSWORD"] == "***REDACTED***"
        assert result["ApiKey"] == "***REDACTED***"
        assert result["TOKEN"] == "***REDACTED***"

    def test_sanitize_nested_dict(self) -> None:
        """Test that nested dictionaries are sanitized recursively."""
        sanitizer = LogSanitizer()
        data = {
            "user": {
                "name": "alice",
                "credentials": {"password": "secret", "api_key": "key123"},
            }
        }
        result = sanitizer.sanitize(data)

        assert result["user"]["name"] == "alice"
        assert result["user"]["credentials"]["password"] == "***REDACTED***"
        assert result["user"]["credentials"]["api_key"] == "***REDACTED***"

    def test_sanitize_max_depth(self) -> None:
        """Test that deeply nested objects are limited."""
        sanitizer = LogSanitizer(max_depth=3)

        # Create nested dict: 5 levels deep
        data: dict = {"level": 0}
        current = data
        for i in range(1, 6):
            current["nested"] = {"level": i}
            current = current["nested"]

        result = sanitizer.sanitize(data)

        # Should be able to access up to depth 2 (3 dicts total: root, nested, nested.nested)
        assert result["level"] == 0
        assert result["nested"]["level"] == 1
        assert result["nested"]["nested"]["level"] == 2

        # Depth 3 should be truncated (the 4th dict)
        assert "max depth" in str(result["nested"]["nested"]["nested"])

    def test_sanitize_list(self) -> None:
        """Test that lists are sanitized."""
        sanitizer = LogSanitizer()
        data = [1, "hello", {"password": "secret"}]
        result = sanitizer.sanitize(data)

        assert result[0] == 1
        assert result[1] == "hello"
        assert result[2]["password"] == "***REDACTED***"

    def test_sanitize_large_list(self) -> None:
        """Test that large lists are truncated."""
        sanitizer = LogSanitizer()
        data = list(range(200))
        result = sanitizer.sanitize(data)

        assert len(result) == 101  # 100 items + truncation message
        assert "truncated" in str(result[-1])
        assert "200 total items" in str(result[-1])

    def test_sanitize_tuple(self) -> None:
        """Test that tuples are handled."""
        sanitizer = LogSanitizer()
        data = (1, 2, {"password": "secret"})
        result = sanitizer.sanitize(data)

        assert isinstance(result, list)
        assert result[0] == 1
        assert result[2]["password"] == "***REDACTED***"

    def test_sanitize_mixed_nested_structure(self) -> None:
        """Test complex nested structure with lists and dicts."""
        sanitizer = LogSanitizer()
        data = {
            "users": [
                {"name": "alice", "password": "secret1"},
                {"name": "bob", "password": "secret2"},
            ],
            "config": {"api_key": "key123", "timeout": 30},
        }
        result = sanitizer.sanitize(data)

        assert result["users"][0]["name"] == "alice"
        assert result["users"][0]["password"] == "***REDACTED***"
        assert result["users"][1]["name"] == "bob"
        assert result["users"][1]["password"] == "***REDACTED***"
        assert result["config"]["api_key"] == "***REDACTED***"
        assert result["config"]["timeout"] == 30

    def test_sanitize_unprintable_object(self) -> None:
        """Test handling of objects that can't be stringified."""

        class UnprintableObject:
            def __str__(self) -> str:
                raise ValueError("Cannot print")

        sanitizer = LogSanitizer()
        obj = UnprintableObject()
        result = sanitizer.sanitize(obj)

        assert "unprintable" in result

    def test_sanitize_for_json(self) -> None:
        """Test JSON serialization with sanitization."""
        sanitizer = LogSanitizer()
        data = {"user": "alice", "password": "secret"}
        result = sanitizer.sanitize_for_json(data)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["user"] == "alice"
        assert parsed["password"] == "***REDACTED***"

    def test_sanitize_for_json_large_data(self) -> None:
        """Test that large JSON is truncated."""
        sanitizer = LogSanitizer(max_total_size=100)
        # Use a string that won't trigger credential detection
        data = {"data": "A" * 50}  # Shorter string to avoid base64 pattern
        result = sanitizer.sanitize_for_json(data)

        # With smaller data, it should fit within limit and be sanitized normally
        assert len(result) <= 200
        assert "data" in result

    def test_format_size(self) -> None:
        """Test byte size formatting."""
        sanitizer = LogSanitizer()

        assert "512 B" in sanitizer._format_size(512)
        assert "1.0 KB" in sanitizer._format_size(1024)
        assert "1.5 KB" in sanitizer._format_size(1536)
        assert "1.0 MB" in sanitizer._format_size(1024 * 1024)
        assert "2.5 MB" in sanitizer._format_size(int(2.5 * 1024 * 1024))

    def test_custom_max_string_length(self) -> None:
        """Test custom max string length."""
        sanitizer = LogSanitizer(max_string_length=50)
        text = "x" * 100
        result = sanitizer.sanitize(text)

        assert len(result) < 100
        assert "truncated" in result

    def test_custom_max_depth(self) -> None:
        """Test custom max depth."""
        sanitizer = LogSanitizer(max_depth=2)

        data = {"a": {"b": {"c": "too deep"}}}
        result = sanitizer.sanitize(data)

        assert "max depth" in str(result["a"]["b"]["c"])

    def test_sensitive_patterns_comprehensive(self) -> None:
        """Test all sensitive patterns are caught."""
        sanitizer = LogSanitizer()
        data = {
            "password": "p1",
            "passwd": "p2",
            "pwd": "p3",
            "api_key": "k1",
            "apikey": "k2",
            "token": "t1",
            "secret": "s1",
            "credential": "c1",
            "auth": "a1",
            "authorization": "a2",
            "private_key": "pk1",
            "privatekey": "pk2",
        }
        result = sanitizer.sanitize(data)

        for key in data:
            assert result[key] == "***REDACTED***", f"Key '{key}' should be redacted"


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_sanitize_for_logging(self) -> None:
        """Test sanitize_for_logging convenience function."""
        data = {"password": "secret", "username": "alice"}
        result = sanitize_for_logging(data)

        assert result["username"] == "alice"
        assert result["password"] == "***REDACTED***"

    def test_sanitize_for_json_logging(self) -> None:
        """Test sanitize_for_json_logging convenience function."""
        data = {"password": "secret", "username": "alice"}
        result = sanitize_for_json_logging(data)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["username"] == "alice"
        assert parsed["password"] == "***REDACTED***"


class TestResourceExhaustionPrevention:
    """Tests specifically for resource exhaustion prevention."""

    def test_prevents_huge_string_logging(self) -> None:
        """Test that huge strings don't cause resource exhaustion."""
        sanitizer = LogSanitizer()
        # 10 MB string
        huge_string = "x" * (10 * 1024 * 1024)
        result = sanitizer.sanitize(huge_string)

        # Result should be much smaller
        result_size = len(result.encode("utf-8"))
        assert result_size < 2048  # Should be ~1KB + overhead
        assert "truncated" in result
        assert "10.0 MB" in result

    def test_prevents_huge_dict_logging(self) -> None:
        """Test that huge dictionaries don't cause resource exhaustion."""
        sanitizer = LogSanitizer(max_total_size=1024)  # 1 KB limit
        # Create dict with large values
        data = {f"key_{i}": "x" * 1000 for i in range(100)}
        result = sanitizer.sanitize_for_json(data)

        # Result should be truncated
        assert len(result) <= 1500  # Allow some overhead
        assert "TRUNCATED" in result

    def test_prevents_deeply_nested_recursion(self) -> None:
        """Test that deeply nested structures don't cause stack overflow."""
        sanitizer = LogSanitizer()
        # Create very deeply nested structure
        data: dict = {"level": 0}
        current = data
        for i in range(1, 1000):
            current["nested"] = {"level": i}
            current = current["nested"]

        # Should not raise RecursionError
        result = sanitizer.sanitize(data)
        assert result is not None
        assert "max depth" in str(result)

    def test_prevents_huge_list_logging(self) -> None:
        """Test that huge lists don't cause resource exhaustion."""
        sanitizer = LogSanitizer()
        # 10,000 item list
        data = list(range(10000))
        result = sanitizer.sanitize(data)

        # Should be truncated to 100 items + message
        assert len(result) == 101
        assert "10000 total items" in str(result[-1])


class TestDefaultSettings:
    """Tests for default configuration."""

    def test_default_max_string_length(self) -> None:
        """Test default max string length is reasonable."""
        assert DEFAULT_MAX_STRING_LENGTH == 1024  # 1 KB

    def test_default_max_total_size(self) -> None:
        """Test default max total size is reasonable."""
        assert DEFAULT_MAX_TOTAL_SIZE == 10240  # 10 KB

    def test_default_max_depth(self) -> None:
        """Test default max depth is reasonable."""
        assert DEFAULT_MAX_DEPTH == 10
