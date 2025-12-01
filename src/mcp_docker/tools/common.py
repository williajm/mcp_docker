"""Shared helpers and models for FastMCP tool modules."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.config import SafetyConfig
from mcp_docker.utils.logger import get_logger
from mcp_docker.utils.output_limits import create_truncation_metadata

logger = get_logger(__name__)

# Shared field description constants (avoids duplication per SonarCloud S1192)
DESC_TRUNCATION_INFO = "Information about output truncation if applied"
DESC_CONTAINER_ID = "Container ID or name"
DESC_IMAGE_ID = "Image name or ID"
DESC_NETWORK_ID = "Network ID or name"
DESC_VOLUME_NAME = "Volume name"


class FiltersInput(BaseModel):
    """Base model for Docker list endpoints supporting filters."""

    filters: dict[str, str | list[str]] | None = Field(
        default=None,
        description=(
            "Filters to apply as key-value pairs matching Docker API semantics "
            "(e.g., {'status': ['running']}, {'driver': ['bridge']})."
        ),
    )


class PaginatedListOutput(BaseModel):
    """Base model for list outputs with count and truncation metadata."""

    count: int = Field(description="Total number of items found")
    truncation_info: dict[str, Any] = Field(
        default_factory=dict,
        description=DESC_TRUNCATION_INFO,
    )


def apply_list_pagination(
    items: list[dict[str, Any]],
    safety_config: SafetyConfig,
    item_label: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    """Apply SAFETY_MAX_LIST_RESULTS truncation logic shared by list_* tools."""

    original_count = len(items)
    truncation_info: dict[str, Any] = {}

    if safety_config.max_list_results > 0 and len(items) > safety_config.max_list_results:
        # Truncate list inline (was truncate_list function)
        items = items[: safety_config.max_list_results]
        logger.debug(f"Truncated list from {original_count} items to {len(items)} items")

        truncation_info = create_truncation_metadata(
            was_truncated=True,
            original_count=original_count,
            truncated_count=len(items),
        )
        truncation_info["message"] = (
            f"Results truncated: showing {len(items)} of {original_count} {item_label}. "
            "Set SAFETY_MAX_LIST_RESULTS=0 to disable limit."
        )

    return items, truncation_info, original_count
