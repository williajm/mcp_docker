"""Unit tests for utils/model_mixins.py."""

from typing import Any

import pytest
from pydantic import Field, ValidationError

from mcp_docker.utils.model_mixins import (
    DESC_TRUNCATION_INFO,
    JsonParsingMixin,
    TruncationInfoMixin,
)


class TestJsonParsingMixin:
    """Test JsonParsingMixin functionality."""

    def test_json_field_validator_parses_string(self):
        """Test that JSON string is parsed to dict."""

        class TestModel(JsonParsingMixin):
            config: dict[str, str] | None = None
            _parse_config = JsonParsingMixin.json_field_validator("config")

        # JSON string should be parsed
        model = TestModel(config='{"key": "value"}')
        assert model.config == {"key": "value"}

    def test_json_field_validator_accepts_dict(self):
        """Test that dict is passed through unchanged."""

        class TestModel(JsonParsingMixin):
            config: dict[str, str] | None = None
            _parse_config = JsonParsingMixin.json_field_validator("config")

        # Dict should pass through unchanged
        model = TestModel(config={"key": "value"})
        assert model.config == {"key": "value"}

    def test_json_field_validator_accepts_none(self):
        """Test that None is accepted for optional fields."""

        class TestModel(JsonParsingMixin):
            config: dict[str, str] | None = None
            _parse_config = JsonParsingMixin.json_field_validator("config")

        # None should be accepted
        model = TestModel(config=None)
        assert model.config is None

        # Omitting field should default to None
        model2 = TestModel()
        assert model2.config is None

    def test_json_field_validator_rejects_invalid_json(self):
        """Test that invalid JSON string raises error."""

        class TestModel(JsonParsingMixin):
            config: dict[str, str] | None = None
            _parse_config = JsonParsingMixin.json_field_validator("config")

        # Invalid JSON should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            TestModel(config="{invalid json}")

        assert "received invalid json" in str(exc_info.value).lower()

    def test_multiple_json_fields(self):
        """Test model with multiple JSON-parsed fields."""

        class TestModel(JsonParsingMixin):
            filters: dict[str, list[str]] | None = None
            labels: dict[str, str] | None = None

            _parse_filters = JsonParsingMixin.json_field_validator("filters")
            _parse_labels = JsonParsingMixin.json_field_validator("labels")

        # Both fields should be parsed independently
        model = TestModel(
            filters='{"type": ["container", "image"]}',
            labels='{"env": "prod"}',
        )
        assert model.filters == {"type": ["container", "image"]}
        assert model.labels == {"env": "prod"}

    def test_json_field_with_complex_structure(self):
        """Test parsing of complex nested JSON structures."""

        class TestModel(JsonParsingMixin):
            data: dict[str, Any] | None = None
            _parse_data = JsonParsingMixin.json_field_validator("data")

        complex_json = '{"a": {"b": [1, 2, 3]}, "c": null, "d": true}'
        model = TestModel(data=complex_json)
        assert model.data == {"a": {"b": [1, 2, 3]}, "c": None, "d": True}


class TestTruncationInfoMixin:
    """Test TruncationInfoMixin functionality."""

    def test_truncation_info_field_exists(self):
        """Test that truncation_info field is added to model."""

        class TestOutput(TruncationInfoMixin):
            items: list[str] = Field(default_factory=list)

        # Field should exist
        assert "truncation_info" in TestOutput.model_fields
        assert TestOutput.model_fields["truncation_info"].is_required() is False

    def test_truncation_info_accepts_none(self):
        """Test that truncation_info accepts None."""

        class TestOutput(TruncationInfoMixin):
            items: list[str] = Field(default_factory=list)

        output = TestOutput(items=["a", "b"], truncation_info=None)
        assert output.truncation_info is None

    def test_truncation_info_accepts_dict(self):
        """Test that truncation_info accepts dict with metadata."""

        class TestOutput(TruncationInfoMixin):
            items: list[str] = Field(default_factory=list)

        truncation_data = {
            "truncated": True,
            "limit": 10,
            "total": 100,
            "message": "Showing first 10 of 100 items",
        }
        output = TestOutput(items=["a", "b"], truncation_info=truncation_data)
        assert output.truncation_info == truncation_data

    def test_truncation_info_description(self):
        """Test that truncation_info has the standard description."""

        class TestOutput(TruncationInfoMixin):
            items: list[str] = Field(default_factory=list)

        field_info = TestOutput.model_fields["truncation_info"]
        assert field_info.description == DESC_TRUNCATION_INFO

    def test_multiple_models_with_mixin(self):
        """Test that multiple models can use the mixin independently."""

        class ListOutput(TruncationInfoMixin):
            containers: list[str] = Field(default_factory=list)

        class InspectOutput(TruncationInfoMixin):
            details: dict[str, Any] = Field(default_factory=dict)

        # Both should have truncation_info field
        list_out = ListOutput(containers=["a"], truncation_info={"truncated": False})
        inspect_out = InspectOutput(details={}, truncation_info=None)

        assert list_out.truncation_info == {"truncated": False}
        assert inspect_out.truncation_info is None


class TestCombinedMixins:
    """Test using both mixins together."""

    def test_model_with_both_mixins(self):
        """Test model that uses both JsonParsingMixin and TruncationInfoMixin."""

        class CombinedModel(JsonParsingMixin, TruncationInfoMixin):
            items: list[dict[str, Any]] = Field(default_factory=list)
            filters: dict[str, str] | None = None

            _parse_filters = JsonParsingMixin.json_field_validator("filters")

        # Should support both JSON parsing and truncation info
        model = CombinedModel(
            items=[{"id": "123"}],
            filters='{"status": "running"}',
            truncation_info={"truncated": True, "limit": 1, "total": 10},
        )

        assert model.items == [{"id": "123"}]
        assert model.filters == {"status": "running"}
        assert model.truncation_info["truncated"] is True
