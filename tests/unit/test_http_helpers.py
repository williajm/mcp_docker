"""Tests for HTTP helper utilities."""

from unittest.mock import MagicMock, Mock, patch

from mcp_docker.utils.http_helpers import extract_client_ip


class TestExtractClientIp:
    """Tests for extract_client_ip function."""

    def test_extract_from_fastmcp_dependency_injection(self) -> None:
        """Test extracting IP from FastMCP's get_http_request()."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result == "192.168.1.100"

    def test_fallback_to_context_extraction_on_runtime_error(self) -> None:
        """Test fallback when get_http_request() raises RuntimeError."""
        # Create mocked context with nested request structure
        mock_client = Mock()
        mock_client.host = "10.0.0.50"

        mock_request = Mock()
        mock_request.client = mock_client

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result == "10.0.0.50"

    def test_fallback_to_context_extraction_on_lookup_error(self) -> None:
        """Test fallback when get_http_request() raises LookupError."""
        mock_client = Mock()
        mock_client.host = "172.16.0.1"

        mock_request = Mock()
        mock_request.client = mock_client

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=LookupError("Dependency not available"),
        ):
            result = extract_client_ip(mock_context)

        assert result == "172.16.0.1"

    def test_returns_none_when_no_fastmcp_context(self) -> None:
        """Test returns None when fastmcp_context is not available."""
        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_no_request_context(self) -> None:
        """Test returns None when request_context attribute is missing."""
        mock_fastmcp_context = Mock(spec=[])  # No request_context attribute

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_request_context_is_none(self) -> None:
        """Test returns None when request_context is None."""
        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = None

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_no_request_in_context(self) -> None:
        """Test returns None when request is missing from request_context."""
        mock_request_context = Mock(spec=[])  # No request attribute

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_request_is_none(self) -> None:
        """Test returns None when request is None."""
        mock_request_context = Mock()
        mock_request_context.request = None

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_no_client_in_request(self) -> None:
        """Test returns None when client is missing from request."""
        mock_request = Mock(spec=[])  # No client attribute

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_client_is_none(self) -> None:
        """Test returns None when client is None."""
        mock_request = Mock()
        mock_request.client = None

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_client_host_is_none(self) -> None:
        """Test returns None when client.host is None."""
        mock_client = Mock()
        mock_client.host = None

        mock_request = Mock()
        mock_request.client = mock_client

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_returns_none_when_client_has_no_host_attribute(self) -> None:
        """Test returns None when client lacks host attribute."""
        mock_client = Mock(spec=[])  # No host attribute

        mock_request = Mock()
        mock_request.client = mock_client

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_handles_ipv6_address(self) -> None:
        """Test extracting IPv6 address."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "::1"

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result == "::1"

    def test_handles_full_ipv6_address(self) -> None:
        """Test extracting full IPv6 address."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_dependency_injection_returns_none(self) -> None:
        """Test when get_http_request() returns None."""
        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=None):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_dependency_injection_request_has_no_client_attr(self) -> None:
        """Test when request from dependency injection has no client attribute."""
        mock_request = Mock(spec=[])  # No client attribute

        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_dependency_injection_client_is_none(self) -> None:
        """Test when request.client from dependency injection is None."""
        mock_request = Mock()
        mock_request.client = None

        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_dependency_injection_client_has_no_host(self) -> None:
        """Test when request.client from dependency injection has no host."""
        mock_client = Mock(spec=[])  # No host attribute
        mock_request = Mock()
        mock_request.client = mock_client

        mock_context = MagicMock()
        mock_context.fastmcp_context = None

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        assert result is None

    def test_converts_non_string_host_to_string(self) -> None:
        """Test that non-string host values are converted to string."""
        mock_client = Mock()
        mock_client.host = 12345  # Integer instead of string

        mock_request = Mock()
        mock_request.client = mock_client

        mock_request_context = Mock()
        mock_request_context.request = mock_request

        mock_fastmcp_context = Mock()
        mock_fastmcp_context.request_context = mock_request_context

        mock_context = MagicMock()
        mock_context.fastmcp_context = mock_fastmcp_context

        with patch(
            "mcp_docker.utils.http_helpers.get_http_request",
            side_effect=RuntimeError("Not in HTTP context"),
        ):
            result = extract_client_ip(mock_context)

        assert result == "12345"
