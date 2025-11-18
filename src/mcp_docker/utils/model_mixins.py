"""Pydantic model mixins for MCP Docker.

This module provides reusable mixins for common patterns in tool input/output models,
reducing code duplication and providing single points of maintenance for shared logic.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from mcp_docker.utils.json_parsing import parse_json_string_field

# Truncation info description used across all list/inspect output models
DESC_TRUNCATION_INFO = (
    "Information about truncated data. Contains 'truncated' (bool), "
    "'limit' (int), 'total' (int), and 'message' (str) if data was truncated"
)


class JsonParsingMixin(BaseModel):
    """Mixin that provides automatic JSON string parsing for dict fields.

    This mixin works around MCP client serialization issues where dict fields
    may be received as JSON strings instead of objects.

    Usage:
        class MyInput(JsonParsingMixin):
            filters: dict[str, Any] | None = Field(default=None)
            labels: dict[str, str] | None = Field(default=None)

            # Enable JSON parsing for specific fields
            _parse_filters = JsonParsingMixin.json_field_validator("filters")
            _parse_labels = JsonParsingMixin.json_field_validator("labels")

    This is equivalent to writing:
        @field_validator("filters", mode="before")
        @classmethod
        def parse_filters(cls, v: Any) -> Any:
            return parse_json_string_field(v, "filters")
    """

    @classmethod
    def json_field_validator(cls, field_name: str) -> classmethod:  # type: ignore[type-arg]
        """Create a field validator that parses JSON strings for a dict field.

        Args:
            field_name: Name of the field to validate

        Returns:
            A field_validator decorator for the specified field

        Example:
            class MyModel(JsonParsingMixin):
                config: dict[str, Any] | None = None
                _parse_config = JsonParsingMixin.json_field_validator("config")
        """

        @field_validator(field_name, mode="before")  # type: ignore[misc]
        @classmethod
        def _parse_json_field(cls: type, v: Any) -> Any:  # noqa: N805, ARG001
            return parse_json_string_field(v, field_name)

        return _parse_json_field  # type: ignore[return-value]


class TruncationInfoMixin(BaseModel):
    """Mixin that provides the standard truncation_info field for output models.

    This mixin ensures consistent truncation metadata across all list/inspect tools.

    Usage:
        class MyListOutput(TruncationInfoMixin):
            items: list[dict[str, Any]]
            count: int

    The truncation_info field will be automatically added with the standard schema.
    """

    truncation_info: dict[str, Any] | None = Field(
        default=None,
        description=DESC_TRUNCATION_INFO,
    )


__all__ = [
    "JsonParsingMixin",
    "TruncationInfoMixin",
    "DESC_TRUNCATION_INFO",
]
