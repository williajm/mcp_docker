"""Shared helpers and models for FastMCP tool modules."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from mcp_docker.services.safety import OperationSafety
from mcp_docker.utils.logger import get_logger

logger = get_logger(__name__)

# Tool timeout tiers (seconds). Used as ToolSpec.timeout overrides
# for tools that need longer than the config default.
TIMEOUT_MEDIUM: float = 60.0  # logs, events, exec, prune operations
TIMEOUT_SLOW: float = 300.0  # pull, build, push (network I/O)


@dataclass(slots=True, frozen=True)
class ToolSpec:
    """Specification for registering a FastMCP tool."""

    name: str
    description: str
    safety: OperationSafety
    func: Callable[..., Any]
    idempotent: bool = field(default=False)
    open_world: bool = field(default=False)
    timeout: float | None = field(default=None)  # None = use config default


# Shared field description constants (avoids duplication per SonarCloud S1192)
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
