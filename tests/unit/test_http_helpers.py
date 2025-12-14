"""Tests for HTTP helper utilities."""

from unittest.mock import MagicMock, Mock, patch

from mcp_docker.utils.http_helpers import (
    _is_ip_in_trusted_proxies,
    _parse_x_forwarded_for,
    extract_client_ip,
)


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


class TestIsIpInTrustedProxies:
    """Tests for _is_ip_in_trusted_proxies function."""

    def test_empty_trusted_proxies_returns_false(self) -> None:
        """Test that empty trusted_proxies list returns False."""
        assert _is_ip_in_trusted_proxies("192.168.1.1", []) is False

    def test_exact_ip_match(self) -> None:
        """Test exact IP address matching."""
        trusted = ["10.0.0.1", "192.168.1.100"]
        assert _is_ip_in_trusted_proxies("10.0.0.1", trusted) is True
        assert _is_ip_in_trusted_proxies("192.168.1.100", trusted) is True
        assert _is_ip_in_trusted_proxies("10.0.0.2", trusted) is False

    def test_cidr_range_match(self) -> None:
        """Test CIDR notation matching."""
        trusted = ["10.0.0.0/24"]
        assert _is_ip_in_trusted_proxies("10.0.0.1", trusted) is True
        assert _is_ip_in_trusted_proxies("10.0.0.255", trusted) is True
        assert _is_ip_in_trusted_proxies("10.0.1.1", trusted) is False

    def test_cidr_larger_range(self) -> None:
        """Test larger CIDR range."""
        trusted = ["10.0.0.0/8"]
        assert _is_ip_in_trusted_proxies("10.255.255.255", trusted) is True
        assert _is_ip_in_trusted_proxies("11.0.0.1", trusted) is False

    def test_mixed_exact_and_cidr(self) -> None:
        """Test mix of exact IPs and CIDR ranges."""
        trusted = ["192.168.1.1", "10.0.0.0/24"]
        assert _is_ip_in_trusted_proxies("192.168.1.1", trusted) is True
        assert _is_ip_in_trusted_proxies("10.0.0.50", trusted) is True
        assert _is_ip_in_trusted_proxies("172.16.0.1", trusted) is False

    def test_invalid_ip_returns_false(self) -> None:
        """Test that invalid IP addresses return False without crashing."""
        trusted = ["10.0.0.0/24"]
        assert _is_ip_in_trusted_proxies("not-an-ip", trusted) is False
        assert _is_ip_in_trusted_proxies("", trusted) is False
        assert _is_ip_in_trusted_proxies("256.256.256.256", trusted) is False

    def test_invalid_cidr_in_trusted_is_skipped(self) -> None:
        """Test that invalid CIDR in trusted list is skipped gracefully."""
        trusted = ["invalid-cidr", "10.0.0.1"]
        # Should still match the valid entry
        assert _is_ip_in_trusted_proxies("10.0.0.1", trusted) is True
        # Should not crash on invalid entry
        assert _is_ip_in_trusted_proxies("10.0.0.2", trusted) is False

    def test_ipv6_exact_match(self) -> None:
        """Test IPv6 exact matching."""
        trusted = ["::1", "2001:db8::1"]
        assert _is_ip_in_trusted_proxies("::1", trusted) is True
        assert _is_ip_in_trusted_proxies("2001:db8::1", trusted) is True
        assert _is_ip_in_trusted_proxies("2001:db8::2", trusted) is False

    def test_ipv6_cidr_match(self) -> None:
        """Test IPv6 CIDR matching."""
        trusted = ["2001:db8::/32"]
        assert _is_ip_in_trusted_proxies("2001:db8::1", trusted) is True
        assert _is_ip_in_trusted_proxies("2001:db8:ffff::1", trusted) is True
        assert _is_ip_in_trusted_proxies("2001:db9::1", trusted) is False


class TestParseXForwardedFor:
    """Tests for _parse_x_forwarded_for function."""

    def test_single_ip_in_xff(self) -> None:
        """Test XFF with single IP (not trusted)."""
        result = _parse_x_forwarded_for("203.0.113.50", ["10.0.0.1"], "10.0.0.1")
        assert result == "203.0.113.50"

    def test_multiple_hops_all_proxies_trusted(self) -> None:
        """Test XFF with multiple hops where intermediate proxies are trusted."""
        trusted = ["10.0.0.1", "10.0.0.2"]
        # XFF: client, proxy1 -> direct connection from proxy2
        result = _parse_x_forwarded_for("203.0.113.50, 10.0.0.1", trusted, "10.0.0.2")
        assert result == "203.0.113.50"

    def test_multiple_hops_partial_trust(self) -> None:
        """Test XFF where only rightmost proxy is trusted."""
        trusted = ["10.0.0.2"]
        # XFF: client, proxy1 -> direct from proxy2
        # proxy1 is NOT trusted, so we stop there
        result = _parse_x_forwarded_for("203.0.113.50, 10.0.0.1", trusted, "10.0.0.2")
        assert result == "10.0.0.1"

    def test_empty_xff_returns_direct_ip(self) -> None:
        """Test empty XFF header returns direct client IP."""
        result = _parse_x_forwarded_for("", ["10.0.0.1"], "10.0.0.1")
        assert result == "10.0.0.1"

    def test_whitespace_only_xff_returns_direct_ip(self) -> None:
        """Test whitespace-only XFF returns direct client IP."""
        result = _parse_x_forwarded_for("   ", ["10.0.0.1"], "10.0.0.1")
        assert result == "10.0.0.1"

    def test_xff_with_spaces(self) -> None:
        """Test XFF parsing handles spaces correctly."""
        trusted = ["10.0.0.1"]
        result = _parse_x_forwarded_for("  203.0.113.50 ,  10.0.0.1  ", trusted, "10.0.0.1")
        # Should still find 203.0.113.50 as first non-trusted
        assert result == "203.0.113.50"

    def test_all_ips_trusted_returns_leftmost(self) -> None:
        """Test edge case where all IPs in chain are trusted."""
        trusted = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        # All IPs trusted - should return leftmost
        result = _parse_x_forwarded_for("10.0.0.1, 10.0.0.2", trusted, "10.0.0.3")
        assert result == "10.0.0.1"

    def test_cidr_matching_in_xff_chain(self) -> None:
        """Test that CIDR ranges work in XFF chain parsing."""
        trusted = ["10.0.0.0/24"]
        # Client is not in 10.0.0.0/24, proxies are
        result = _parse_x_forwarded_for("203.0.113.50, 10.0.0.1", trusted, "10.0.0.2")
        assert result == "203.0.113.50"


class TestExtractClientIpWithTrustedProxies:
    """Tests for extract_client_ip with trusted_proxies parameter."""

    def test_xff_parsed_when_direct_ip_trusted(self) -> None:
        """Test that XFF is parsed when direct connection is from trusted proxy."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"x-forwarded-for": "203.0.113.50"}

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context, trusted_proxies=["10.0.0.1"])

        assert result == "203.0.113.50"

    def test_xff_ignored_when_direct_ip_not_trusted(self) -> None:
        """Test that XFF is ignored when direct connection is NOT from trusted proxy."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.headers = {"x-forwarded-for": "spoofed.ip.address"}

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context, trusted_proxies=["10.0.0.1"])

        # Should return direct IP, ignoring XFF (prevents spoofing)
        assert result == "192.168.1.100"

    def test_xff_ignored_when_no_trusted_proxies(self) -> None:
        """Test that XFF is ignored when trusted_proxies is empty."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"x-forwarded-for": "203.0.113.50"}

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context, trusted_proxies=[])

        # Should return direct IP since no proxies are trusted
        assert result == "10.0.0.1"

    def test_xff_ignored_when_trusted_proxies_none(self) -> None:
        """Test that XFF is ignored when trusted_proxies is None (default)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"x-forwarded-for": "203.0.113.50"}

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context)

        # Should return direct IP since trusted_proxies defaults to None
        assert result == "10.0.0.1"

    def test_no_xff_header_returns_direct_ip(self) -> None:
        """Test that missing XFF header returns direct IP even with trusted proxies."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {}  # No XFF header

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context, trusted_proxies=["10.0.0.1"])

        assert result == "10.0.0.1"

    def test_cidr_trusted_proxy(self) -> None:
        """Test XFF parsing with CIDR range for trusted proxies."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.50"  # In 10.0.0.0/24 range
        mock_request.headers = {"x-forwarded-for": "203.0.113.50"}

        mock_context = MagicMock()

        with patch("mcp_docker.utils.http_helpers.get_http_request", return_value=mock_request):
            result = extract_client_ip(mock_context, trusted_proxies=["10.0.0.0/24"])

        assert result == "203.0.113.50"
