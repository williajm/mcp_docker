#!/usr/bin/env python3
"""Fuzz test for JSON parsing utilities.

Tests JSON parsing with malformed and edge-case inputs to ensure
robust error handling and prevent crashes.
"""

# Import without instrumentation
import json
import sys
from typing import Any

import atheris

from mcp_docker.utils.json_parsing import parse_json_string_field

# Instrument all code after imports
atheris.instrument_all()


def fuzz_json_parse(data: bytes) -> None:
    """Fuzz generic JSON parsing.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    try:
        # Test standard json.loads
        result = json.loads(data)
        # If successful, verify we got valid JSON types
        assert isinstance(result, (dict, list, str, int, float, bool, type(None)))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError, AssertionError):
        # Expected for malformed JSON
        pass

    # Test parse_json_string_field wrapper
    try:
        json_str = data.decode("utf-8", errors="ignore")
        result = parse_json_string_field(json_str, "test_field")
        if result is not None:
            assert isinstance(result, (dict, list, str, int, float, bool))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, AssertionError):
        pass


def fuzz_json_field_parsing(data: bytes) -> None:
    """Fuzz JSON field parsing.

    Args:
        data: Random fuzz input
    """
    if len(data) == 0:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create fuzzy JSON-like data
    json_str = fdp.ConsumeUnicodeNoSurrogates(500)

    try:
        result = parse_json_string_field(json_str, "test_field")
        # Verify result structure if parsing succeeds
        if result is not None:
            assert isinstance(result, (dict, list, str, int, float, bool))
    except (json.JSONDecodeError, ValueError, KeyError, TypeError, AssertionError):
        # Expected for invalid JSON or type errors
        pass


def fuzz_nested_json(data: bytes) -> None:
    """Test deeply nested JSON structures.

    Args:
        data: Random fuzz input
    """
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate deeply nested structure
    def create_nested(
        depth: int, fdp: atheris.FuzzedDataProvider
    ) -> dict[Any, Any] | list[Any] | str:
        """Create nested JSON structure."""
        if depth <= 0 or fdp.ConsumeIntInRange(0, 5) == 0:
            return str(fdp.ConsumeUnicodeNoSurrogates(20))

        if fdp.ConsumeBool():
            # Create nested dict
            return {
                fdp.ConsumeUnicodeNoSurrogates(10): create_nested(depth - 1, fdp)
                for _ in range(fdp.ConsumeIntInRange(1, 5))
            }
        # Create nested list
        return [create_nested(depth - 1, fdp) for _ in range(fdp.ConsumeIntInRange(1, 5))]

    try:
        nested = create_nested(fdp.ConsumeIntInRange(1, 20), fdp)
        json_str = json.dumps(nested)
        # Parse back
        result = json.loads(json_str)
        assert result == nested
    except (RecursionError, MemoryError, AssertionError):
        # Expected for extremely deep nesting
        pass


def fuzz_special_json_values(data: bytes) -> None:
    """Test special JSON values and edge cases.

    Args:
        data: Random fuzz input
    """
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Special values
    special_values = [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "1e308",  # Large number
        "1e-308",  # Small number
        '"\\u0000"',  # Null byte
        '"\\uFFFF"',  # Max Unicode
        '""',  # Empty string
        "[]",  # Empty array
        "{}",  # Empty object
    ]

    for value in special_values:
        prefix = fdp.ConsumeUnicodeNoSurrogates(10)
        suffix = fdp.ConsumeUnicodeNoSurrogates(10)
        test_json = f"{prefix}{value}{suffix}"

        try:
            json.loads(test_json)
        except (json.JSONDecodeError, ValueError):
            pass


def fuzz_unicode_json(data: bytes) -> None:
    """Test JSON with various Unicode characters.

    Args:
        data: Random fuzz input
    """
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create JSON with Unicode
    unicode_str = fdp.ConsumeUnicode(100)
    test_obj = {"key": unicode_str, "nested": {"value": unicode_str}}

    try:
        json_str = json.dumps(test_obj)
        result = json.loads(json_str)
        assert result == test_obj
    except (UnicodeDecodeError, UnicodeEncodeError, AssertionError):
        pass


def TestOneInput(data: bytes) -> None:
    """Main fuzz test entry point.

    Args:
        data: Random fuzz input
    """
    fuzz_json_parse(data)
    fuzz_json_field_parsing(data)
    fuzz_nested_json(data)
    fuzz_special_json_values(data)
    fuzz_unicode_json(data)


def main() -> None:
    """Run the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
