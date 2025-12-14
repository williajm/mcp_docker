"""Tests for audit logging secret redaction."""

from unittest.mock import Mock, patch

from mcp_docker.auth.models import ClientInfo
from mcp_docker.services.audit import (
    REDACTED,
    AuditLogger,
    _is_sensitive_key,
    _redact_sensitive_values,
)


class TestIsSensitiveKey:
    """Tests for _is_sensitive_key function."""

    def test_matches_password_variations(self) -> None:
        """Test matching password-related keys."""
        assert _is_sensitive_key("password") is True
        assert _is_sensitive_key("Password") is True
        assert _is_sensitive_key("PASSWORD") is True
        assert _is_sensitive_key("user_password") is True
        assert _is_sensitive_key("password_hash") is True
        assert _is_sensitive_key("db_password_encrypted") is True

    def test_matches_token_variations(self) -> None:
        """Test matching token-related keys."""
        assert _is_sensitive_key("token") is True
        assert _is_sensitive_key("access_token") is True
        assert _is_sensitive_key("refresh_token") is True
        assert _is_sensitive_key("api_token") is True
        assert _is_sensitive_key("TOKEN") is True

    def test_matches_secret_variations(self) -> None:
        """Test matching secret-related keys."""
        assert _is_sensitive_key("secret") is True
        assert _is_sensitive_key("client_secret") is True
        assert _is_sensitive_key("secret_key") is True
        assert _is_sensitive_key("SECRET") is True

    def test_matches_api_key_variations(self) -> None:
        """Test matching API key related keys."""
        assert _is_sensitive_key("api_key") is True
        assert _is_sensitive_key("apikey") is True
        assert _is_sensitive_key("API_KEY") is True
        assert _is_sensitive_key("x_api_key") is True

    def test_matches_auth_variations(self) -> None:
        """Test matching auth-related keys."""
        assert _is_sensitive_key("auth") is True
        assert _is_sensitive_key("authorization") is True
        assert _is_sensitive_key("auth_token") is True
        assert _is_sensitive_key("basic_auth") is True

    def test_matches_credential_variations(self) -> None:
        """Test matching credential-related keys."""
        assert _is_sensitive_key("credential") is True
        assert _is_sensitive_key("credentials") is True
        assert _is_sensitive_key("user_credentials") is True

    def test_matches_jwt_and_bearer(self) -> None:
        """Test matching JWT and bearer token keys."""
        assert _is_sensitive_key("jwt") is True
        assert _is_sensitive_key("jwt_token") is True
        assert _is_sensitive_key("bearer") is True
        assert _is_sensitive_key("bearer_token") is True

    def test_matches_private_key(self) -> None:
        """Test matching private key related keys."""
        assert _is_sensitive_key("private_key") is True
        assert _is_sensitive_key("private") is True
        assert _is_sensitive_key("ssh_private_key") is True

    def test_does_not_match_non_sensitive_keys(self) -> None:
        """Test that non-sensitive keys are not matched."""
        assert _is_sensitive_key("container_id") is False
        assert _is_sensitive_key("name") is False
        assert _is_sensitive_key("status") is False
        assert _is_sensitive_key("image") is False
        assert _is_sensitive_key("port") is False
        assert _is_sensitive_key("volume") is False


class TestRedactSensitiveValues:
    """Tests for _redact_sensitive_values function."""

    def test_redacts_top_level_sensitive_keys(self) -> None:
        """Test redacting sensitive keys at top level."""
        data = {
            "container_id": "abc123",
            "password": "secret123",
            "api_key": "key-12345",
        }
        result = _redact_sensitive_values(data)
        assert result["container_id"] == "abc123"
        assert result["password"] == REDACTED
        assert result["api_key"] == REDACTED

    def test_redacts_nested_sensitive_keys(self) -> None:
        """Test redacting sensitive keys in nested dicts."""
        data = {
            "container": {
                "id": "abc123",
                "env": {
                    "DATABASE_PASSWORD": "secret",
                    "APP_NAME": "myapp",
                },
            }
        }
        result = _redact_sensitive_values(data)
        assert result["container"]["id"] == "abc123"
        assert result["container"]["env"]["DATABASE_PASSWORD"] == REDACTED
        assert result["container"]["env"]["APP_NAME"] == "myapp"

    def test_redacts_sensitive_keys_in_lists(self) -> None:
        """Test redacting sensitive keys in dicts inside lists."""
        data = {
            "items": [
                {"name": "db-connection", "value": "connection-string"},
                {"name": "api-config", "token": "tok-456"},
            ]
        }
        result = _redact_sensitive_values(data)
        # 'value' is not sensitive, but 'token' is
        assert result["items"][0]["name"] == "db-connection"
        assert result["items"][0]["value"] == "connection-string"
        assert result["items"][1]["name"] == "api-config"
        assert result["items"][1]["token"] == REDACTED

    def test_preserves_empty_dict(self) -> None:
        """Test that empty dicts are preserved."""
        result = _redact_sensitive_values({})
        assert result == {}

    def test_preserves_empty_list(self) -> None:
        """Test that empty lists are preserved."""
        result = _redact_sensitive_values([])
        assert result == []

    def test_handles_primitive_types(self) -> None:
        """Test handling of primitive types (returned as-is)."""
        assert _redact_sensitive_values("string") == "string"
        assert _redact_sensitive_values(123) == 123
        assert _redact_sensitive_values(True) is True
        assert _redact_sensitive_values(None) is None

    def test_max_depth_prevents_infinite_recursion(self) -> None:
        """Test that max_depth parameter limits recursion."""
        # Create deeply nested structure
        data: dict = {"level": 1}
        current = data
        for i in range(2, 15):
            current["nested"] = {"level": i, "password": "secret"}
            current = current["nested"]

        # With max_depth=5, should stop redacting after 5 levels
        result = _redact_sensitive_values(data, max_depth=5)

        # Verify shallow levels are redacted
        assert result["nested"]["password"] == REDACTED  # depth 2
        assert result["nested"]["nested"]["password"] == REDACTED  # depth 3

        # At max_depth, the nested data is returned as-is (not processed further)
        # So at depth 5+, we just return the data unchanged

    def test_handles_mixed_list_contents(self) -> None:
        """Test handling lists with mixed content types."""
        data = [
            "string",
            123,
            {"password": "secret"},
            ["nested", {"token": "tok123"}],
        ]
        result = _redact_sensitive_values(data)
        assert result[0] == "string"
        assert result[1] == 123
        assert result[2]["password"] == REDACTED
        assert result[3][0] == "nested"
        assert result[3][1]["token"] == REDACTED

    def test_case_insensitive_matching(self) -> None:
        """Test that key matching is case-insensitive."""
        data = {
            "PASSWORD": "secret1",
            "Password": "secret2",
            "password": "secret3",
            "PaSsWoRd": "secret4",
        }
        result = _redact_sensitive_values(data)
        assert all(v == REDACTED for v in result.values())


class TestAuditLoggerRedaction:
    """Integration tests for AuditLogger with redaction."""

    def test_log_tool_call_redacts_arguments(self, tmp_path) -> None:
        """Test that log_tool_call redacts sensitive arguments."""
        with patch("mcp_docker.services.audit.loguru_logger") as mock_logger:
            mock_bind = Mock()
            mock_logger.bind.return_value = mock_bind

            audit_file = tmp_path / "audit.log"
            logger = AuditLogger(audit_log_file=audit_file, enabled=True)
            client_info = ClientInfo(
                client_id="test",
                api_key_hash="hash",
                ip_address="127.0.0.1",
            )

            logger.log_tool_call(
                client_info=client_info,
                tool_name="docker_create_container",
                arguments={"name": "mycontainer", "password": "secret123"},
                result={"id": "abc123"},
            )

            # Check that bind was called with redacted arguments
            call_kwargs = mock_logger.bind.call_args[1]
            assert call_kwargs["arguments"]["name"] == "mycontainer"
            assert call_kwargs["arguments"]["password"] == REDACTED

    def test_log_tool_call_redacts_result(self, tmp_path) -> None:
        """Test that log_tool_call redacts sensitive result fields."""
        with patch("mcp_docker.services.audit.loguru_logger") as mock_logger:
            mock_bind = Mock()
            mock_logger.bind.return_value = mock_bind

            audit_file = tmp_path / "audit.log"
            logger = AuditLogger(audit_log_file=audit_file, enabled=True)
            client_info = ClientInfo(
                client_id="test",
                api_key_hash="hash",
                ip_address="127.0.0.1",
            )

            logger.log_tool_call(
                client_info=client_info,
                tool_name="docker_inspect",
                arguments={"container_id": "abc123"},
                result={"env": {"API_TOKEN": "tok-secret", "APP_NAME": "myapp"}},
            )

            call_kwargs = mock_logger.bind.call_args[1]
            assert call_kwargs["result"]["env"]["API_TOKEN"] == REDACTED
            assert call_kwargs["result"]["env"]["APP_NAME"] == "myapp"

    def test_log_tool_call_preserves_empty_result(self, tmp_path) -> None:
        """Test that empty results ({}, []) are preserved, not converted to None."""
        with patch("mcp_docker.services.audit.loguru_logger") as mock_logger:
            mock_bind = Mock()
            mock_logger.bind.return_value = mock_bind

            audit_file = tmp_path / "audit.log"
            logger = AuditLogger(audit_log_file=audit_file, enabled=True)
            client_info = ClientInfo(
                client_id="test",
                api_key_hash="hash",
                ip_address="127.0.0.1",
            )

            # Test with empty dict
            logger.log_tool_call(
                client_info=client_info,
                tool_name="docker_list_containers",
                arguments={},
                result={},
            )

            call_kwargs = mock_logger.bind.call_args[1]
            assert call_kwargs["result"] == {}

            # Test with empty list (as result)
            logger.log_tool_call(
                client_info=client_info,
                tool_name="docker_list_containers",
                arguments={},
                result={"containers": []},
            )

            call_kwargs = mock_logger.bind.call_args[1]
            assert call_kwargs["result"] == {"containers": []}

    def test_log_tool_call_handles_none_result(self, tmp_path) -> None:
        """Test that None result stays None."""
        with patch("mcp_docker.services.audit.loguru_logger") as mock_logger:
            mock_bind = Mock()
            mock_logger.bind.return_value = mock_bind

            audit_file = tmp_path / "audit.log"
            logger = AuditLogger(audit_log_file=audit_file, enabled=True)
            client_info = ClientInfo(
                client_id="test",
                api_key_hash="hash",
                ip_address="127.0.0.1",
            )

            logger.log_tool_call(
                client_info=client_info,
                tool_name="docker_start",
                arguments={"container_id": "abc123"},
                result=None,
            )

            call_kwargs = mock_logger.bind.call_args[1]
            assert call_kwargs["result"] is None
