"""Authentication models for MCP Docker server."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ClientInfo(BaseModel):
    """Information about an authenticated client."""

    client_id: str = Field(description="Unique client identifier")
    api_key_hash: str = Field(description="SHA-256 hash of the API key")
    description: str | None = Field(default=None, description="Human-readable description")
    ip_address: str | None = Field(default=None, description="Client IP address")
    authenticated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of authentication",
    )
