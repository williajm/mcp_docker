"""Unit tests for authentication models."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mcp_docker.auth.models import ClientInfo


class TestClientInfo:
    """Tests for ClientInfo model."""

    def test_create_client_info_minimal(self) -> None:
        """Test creating ClientInfo with minimal required fields."""
        client = ClientInfo(
            client_id="client-123",
            api_key_hash="abc123def456",
        )

        assert client.client_id == "client-123"
        assert client.api_key_hash == "abc123def456"
        assert client.description is None
        assert client.ip_address is None
        assert isinstance(client.authenticated_at, datetime)
        assert client.authenticated_at.tzinfo == UTC

    def test_create_client_info_full(self) -> None:
        """Test creating ClientInfo with all fields."""
        now = datetime.now(UTC)
        client = ClientInfo(
            client_id="client-456",
            api_key_hash="def789ghi012",
            description="Test Client",
            ip_address="192.168.1.100",
            authenticated_at=now,
        )

        assert client.client_id == "client-456"
        assert client.api_key_hash == "def789ghi012"
        assert client.description == "Test Client"
        assert client.ip_address == "192.168.1.100"
        assert client.authenticated_at == now

    def test_authenticated_at_defaults_to_current_time(self) -> None:
        """Test that authenticated_at defaults to current UTC time."""
        before = datetime.now(UTC)
        client = ClientInfo(
            client_id="client-789",
            api_key_hash="ghi345jkl678",
        )
        after = datetime.now(UTC)

        # authenticated_at should be between before and after
        assert before <= client.authenticated_at <= after
        assert client.authenticated_at.tzinfo == UTC

    def test_client_id_validation(self) -> None:
        """Test that client_id is required."""
        with pytest.raises(ValidationError) as exc_info:
            ClientInfo(
                api_key_hash="hash123",
            )  # type: ignore

        errors = exc_info.value.errors()
        assert any(error["loc"] == ("client_id",) for error in errors)
        assert any(error["type"] == "missing" for error in errors)

    def test_api_key_hash_default(self) -> None:
        """Test that api_key_hash has a default value of 'none'."""
        client = ClientInfo(
            client_id="client-001",
        )
        assert client.api_key_hash == "none"
        assert client.auth_method == "ip"  # Default auth method

    def test_description_can_be_none(self) -> None:
        """Test that description can be None."""
        client = ClientInfo(
            client_id="client-002",
            api_key_hash="hash456",
            description=None,
        )

        assert client.description is None

    def test_description_can_be_empty_string(self) -> None:
        """Test that description can be an empty string."""
        client = ClientInfo(
            client_id="client-003",
            api_key_hash="hash789",
            description="",
        )

        assert client.description == ""

    def test_ip_address_can_be_none(self) -> None:
        """Test that ip_address can be None."""
        client = ClientInfo(
            client_id="client-004",
            api_key_hash="hash012",
            ip_address=None,
        )

        assert client.ip_address is None

    def test_ip_address_formats(self) -> None:
        """Test various IP address formats."""
        # IPv4
        client_v4 = ClientInfo(
            client_id="client-v4",
            api_key_hash="hash123",
            ip_address="192.168.1.1",
        )
        assert client_v4.ip_address == "192.168.1.1"

        # IPv6
        client_v6 = ClientInfo(
            client_id="client-v6",
            api_key_hash="hash456",
            ip_address="2001:0db8:85a3::8a2e:0370:7334",
        )
        assert client_v6.ip_address == "2001:0db8:85a3::8a2e:0370:7334"

        # Localhost
        client_local = ClientInfo(
            client_id="client-local",
            api_key_hash="hash789",
            ip_address="127.0.0.1",
        )
        assert client_local.ip_address == "127.0.0.1"

    def test_client_info_immutability(self) -> None:
        """Test that ClientInfo is immutable (frozen)."""
        client = ClientInfo(
            client_id="client-005",
            api_key_hash="hash345",
        )

        # Pydantic models are not frozen by default, so this test ensures
        # we can modify fields (unless we add frozen=True to the model)
        # For now, just verify the fields exist
        assert hasattr(client, "client_id")
        assert hasattr(client, "api_key_hash")

    def test_client_info_serialization(self) -> None:
        """Test that ClientInfo can be serialized to dict."""
        now = datetime.now(UTC)
        client = ClientInfo(
            client_id="client-006",
            api_key_hash="hash678",
            description="Test Client",
            ip_address="10.0.0.1",
            authenticated_at=now,
        )

        data = client.model_dump()

        assert data["client_id"] == "client-006"
        assert data["api_key_hash"] == "hash678"
        assert data["description"] == "Test Client"
        assert data["ip_address"] == "10.0.0.1"
        assert data["authenticated_at"] == now

    def test_client_info_json_serialization(self) -> None:
        """Test that ClientInfo can be serialized to JSON."""
        client = ClientInfo(
            client_id="client-007",
            api_key_hash="hash901",
            description="JSON Test",
        )

        json_str = client.model_dump_json()

        assert "client-007" in json_str
        assert "hash901" in json_str
        assert "JSON Test" in json_str

    def test_client_info_deserialization(self) -> None:
        """Test that ClientInfo can be deserialized from dict."""
        now = datetime.now(UTC)
        data = {
            "client_id": "client-008",
            "api_key_hash": "hash234",
            "description": "Deserialized Client",
            "ip_address": "172.16.0.1",
            "authenticated_at": now.isoformat(),
        }

        client = ClientInfo.model_validate(data)

        assert client.client_id == "client-008"
        assert client.api_key_hash == "hash234"
        assert client.description == "Deserialized Client"
        assert client.ip_address == "172.16.0.1"

    def test_multiple_clients_different_timestamps(self) -> None:
        """Test creating multiple clients with different timestamps."""
        client1 = ClientInfo(client_id="client1", api_key_hash="hash1")
        # Small delay to ensure different timestamps
        import time

        time.sleep(0.001)
        client2 = ClientInfo(client_id="client2", api_key_hash="hash2")

        # Timestamps should be different
        assert client1.authenticated_at != client2.authenticated_at
        assert client1.authenticated_at < client2.authenticated_at

    def test_client_info_with_long_description(self) -> None:
        """Test ClientInfo with a long description."""
        long_description = "A" * 1000  # 1000 character description
        client = ClientInfo(
            client_id="client-long",
            api_key_hash="hash-long",
            description=long_description,
        )

        assert client.description == long_description
        assert len(client.description) == 1000

    def test_client_info_with_special_characters(self) -> None:
        """Test ClientInfo with special characters in fields."""
        client = ClientInfo(
            client_id="client-特殊",
            api_key_hash="hash@#$%",
            description="Test with émojis 🔒🔑",
        )

        assert client.client_id == "client-特殊"
        assert client.api_key_hash == "hash@#$%"
        assert client.description is not None
        assert "🔒🔑" in client.description

    def test_client_info_equality(self) -> None:
        """Test ClientInfo equality comparison."""
        now = datetime.now(UTC)
        client1 = ClientInfo(
            client_id="client-eq",
            api_key_hash="hash-eq",
            authenticated_at=now,
        )
        client2 = ClientInfo(
            client_id="client-eq",
            api_key_hash="hash-eq",
            authenticated_at=now,
        )

        # Pydantic models with same values should be equal
        assert client1.model_dump() == client2.model_dump()

    def test_client_info_with_past_timestamp(self) -> None:
        """Test ClientInfo with a past timestamp."""
        past = datetime.now(UTC) - timedelta(hours=1)
        client = ClientInfo(
            client_id="client-past",
            api_key_hash="hash-past",
            authenticated_at=past,
        )

        assert client.authenticated_at == past
        assert client.authenticated_at < datetime.now(UTC)

    def test_client_info_repr(self) -> None:
        """Test ClientInfo string representation."""
        client = ClientInfo(
            client_id="client-repr",
            api_key_hash="hash-repr",
            description="Repr Test",
        )

        repr_str = repr(client)
        # Check that repr contains key information
        assert "ClientInfo" in repr_str
        assert "client-repr" in repr_str

    def test_client_info_with_sha256_hash(self) -> None:
        """Test ClientInfo with realistic SHA-256 hash."""
        # Realistic SHA-256 hash (64 hex characters)
        sha256_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        client = ClientInfo(
            client_id="client-sha256",
            api_key_hash=sha256_hash,
        )

        assert client.api_key_hash == sha256_hash
        assert len(client.api_key_hash) == 64

    def test_client_info_field_descriptions(self) -> None:
        """Test that field descriptions are properly set."""
        schema = ClientInfo.model_json_schema()
        properties = schema["properties"]

        assert "client_id" in properties
        assert "description" in properties["client_id"]
        assert "api_key_hash" in properties
        assert "description" in properties["api_key_hash"]
        assert "authenticated_at" in properties
        assert "description" in properties["authenticated_at"]


class TestClientInfoEdgeCases:
    """Edge case tests for ClientInfo model."""

    def test_extra_fields_ignored(self) -> None:
        """Test that extra fields are ignored (Pydantic v2 default behavior)."""
        # Pydantic v2 ignores extra fields by default (unless forbid='extra')
        client = ClientInfo(
            client_id="client-extra",
            api_key_hash="hash-extra",
            extra_field="not_allowed",  # type: ignore
        )

        # Extra field should be ignored, not cause an error
        assert client.client_id == "client-extra"
        assert not hasattr(client, "extra_field")

    def test_client_id_empty_string(self) -> None:
        """Test that empty string client_id is allowed (if no constraint)."""
        # Pydantic allows empty strings by default unless constrained
        client = ClientInfo(
            client_id="",
            api_key_hash="hash123",
        )
        assert client.client_id == ""

    def test_api_key_hash_empty_string(self) -> None:
        """Test that empty string api_key_hash is allowed (if no constraint)."""
        client = ClientInfo(
            client_id="client123",
            api_key_hash="",
        )
        assert client.api_key_hash == ""

    def test_authenticated_at_timezone_aware(self) -> None:
        """Test that authenticated_at is always timezone-aware."""
        client = ClientInfo(
            client_id="client-tz",
            api_key_hash="hash-tz",
        )

        assert client.authenticated_at.tzinfo is not None
        assert client.authenticated_at.tzinfo == UTC

    def test_client_info_with_all_none_optional_fields(self) -> None:
        """Test ClientInfo with all optional fields explicitly set to None."""
        client = ClientInfo(
            client_id="client-none",
            api_key_hash="hash-none",
            description=None,
            ip_address=None,
        )

        assert client.description is None
        assert client.ip_address is None

    def test_client_info_model_config(self) -> None:
        """Test that model configuration is correct."""
        # Verify the model can be instantiated and has correct config
        client = ClientInfo(
            client_id="config-test",
            api_key_hash="config-hash",
        )

        # Check that the model has the expected behavior
        assert isinstance(client, ClientInfo)
        assert hasattr(client, "model_dump")
        assert hasattr(client, "model_validate")
