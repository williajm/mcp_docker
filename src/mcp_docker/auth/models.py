"""Authentication models for MCP Docker server."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ClientInfo(BaseModel):
    """Information about an authenticated client."""

    client_id: str = Field(description="Unique client identifier (IP address, OAuth sub, etc.)")
    auth_method: str = Field(
        default="ip",
        description="Authentication method used (ip, oauth, etc.)",
    )
    api_key_hash: str = Field(
        default="none",
        description="SHA-256 hash of the API key (legacy field, not used with OAuth)",
    )
    description: str | None = Field(default=None, description="Human-readable description")
    ip_address: str | None = Field(default=None, description="Client IP address")
    scopes: list[str] = Field(
        default_factory=list,
        description="OAuth scopes granted to this client",
    )
    extra: dict[str, str] = Field(
        default_factory=dict,
        description="Additional auth metadata (e.g., client_id, email, name from JWT claims)",
    )
    authenticated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of authentication",
    )
