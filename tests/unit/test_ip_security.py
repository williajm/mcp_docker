"""Tests for IP extraction security (X-Forwarded-For validation)."""

from mcp_docker.__main__ import _extract_client_ip


class TestClientIPExtraction:
    """Test secure client IP extraction from ASGI scope."""

    def test_extract_ip_from_direct_connection(self) -> None:
        """Test extracting IP from direct connection (no proxy)."""
        scope = {
            "type": "http",
            "client": ("192.168.1.100", 12345),
            "headers": [],
        }
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip == "192.168.1.100"

    def test_ignores_forwarded_header_without_trusted_proxies(self) -> None:
        """Test that X-Forwarded-For is ignored when no proxies are trusted.

        This is the critical security fix - without trusted proxy configuration,
        an attacker could spoof any IP address.
        """
        scope = {
            "type": "http",
            "client": ("10.0.0.50", 12345),  # Real client IP
            "headers": [
                (b"x-forwarded-for", b"1.2.3.4"),  # Attacker-controlled
            ],
        }
        # Without trusted proxies, should use real client IP
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip == "10.0.0.50"  # Real IP, not spoofed one

    def test_uses_forwarded_header_from_trusted_proxy(self) -> None:
        """Test that X-Forwarded-For is used when connection is from trusted proxy."""
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),  # Trusted proxy
            "headers": [
                (b"x-forwarded-for", b"203.0.113.42"),  # Actual client IP
            ],
        }
        # Connection from trusted proxy, use forwarded header
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1"])
        assert ip == "203.0.113.42"

    def test_ignores_forwarded_header_from_untrusted_proxy(self) -> None:
        """Test that X-Forwarded-For is ignored from untrusted proxy."""
        scope = {
            "type": "http",
            "client": ("203.0.113.99", 12345),  # Untrusted proxy
            "headers": [
                (b"x-forwarded-for", b"1.2.3.4"),  # Potentially spoofed
            ],
        }
        # Proxy not in trusted list, ignore forwarded header
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1", "10.0.0.1"])
        assert ip == "203.0.113.99"  # Use real socket IP

    def test_handles_multiple_forwarded_ips_from_trusted_proxy(self) -> None:
        """Test extracting leftmost IP from X-Forwarded-For chain."""
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),  # Trusted proxy
            "headers": [
                # Client -> Proxy1 -> Proxy2 -> Us
                (b"x-forwarded-for", b"203.0.113.42, 10.0.0.1, 10.0.0.2"),
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1"])
        # Should extract leftmost (original client) IP
        assert ip == "203.0.113.42"

    def test_handles_ipv6_addresses(self) -> None:
        """Test handling IPv6 addresses."""
        scope = {
            "type": "http",
            "client": ("::1", 12345),  # IPv6 localhost
            "headers": [],
        }
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip == "::1"

    def test_handles_ipv6_in_trusted_proxies(self) -> None:
        """Test IPv6 addresses in trusted proxy list."""
        scope = {
            "type": "http",
            "client": ("::1", 12345),  # IPv6 localhost (trusted)
            "headers": [
                (b"x-forwarded-for", b"2001:db8::1"),
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=["::1"])
        assert ip == "2001:db8::1"

    def test_handles_missing_client_field(self) -> None:
        """Test handling scope without client field."""
        scope: dict[str, object] = {
            "type": "http",
            "headers": [],
        }
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip is None

    def test_handles_none_client_field(self) -> None:
        """Test handling scope with None client."""
        scope: dict[str, object] = {
            "type": "http",
            "client": None,
            "headers": [],
        }
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip is None

    def test_handles_malformed_forwarded_header(self) -> None:
        """Test handling malformed X-Forwarded-For header."""
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b""),  # Empty
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1"])
        # Should fall back to client IP when forwarded header is empty
        assert ip == "127.0.0.1"

    def test_strips_whitespace_from_forwarded_ips(self) -> None:
        """Test that whitespace is stripped from forwarded IPs."""
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b"  203.0.113.42  ,  10.0.0.1  "),
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1"])
        assert ip == "203.0.113.42"  # Whitespace stripped

    def test_cidr_notation_in_trusted_proxies(self) -> None:
        """Test CIDR notation support for trusted proxy networks."""
        scope = {
            "type": "http",
            "client": ("10.0.0.50", 12345),  # In 10.0.0.0/24
            "headers": [
                (b"x-forwarded-for", b"203.0.113.42"),
            ],
        }
        # Should support CIDR notation for proxy networks
        ip = _extract_client_ip(scope, trusted_proxies=["10.0.0.0/24"])
        assert ip == "203.0.113.42"

    def test_multiple_proxy_headers_uses_first(self) -> None:
        """Test that first X-Forwarded-For header is used if multiple present."""
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"x-forwarded-for", b"203.0.113.42"),
                (b"x-forwarded-for", b"198.51.100.1"),  # Duplicate header
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=["127.0.0.1"])
        assert ip == "203.0.113.42"  # First header wins


class TestIPSpoofingAttackPrevention:
    """Test that common IP spoofing attacks are prevented."""

    def test_prevents_allowlist_bypass_via_header_spoofing(self) -> None:
        """Test that attackers cannot bypass IP allowlists by spoofing headers.

        Attack scenario: Server has IP allowlist [192.168.1.0/24].
        Attacker from 203.0.113.99 sends X-Forwarded-For: 192.168.1.100
        to bypass the allowlist.
        """
        scope = {
            "type": "http",
            "client": ("203.0.113.99", 12345),  # Attacker IP
            "headers": [
                (b"x-forwarded-for", b"192.168.1.100"),  # Spoofed allowlisted IP
            ],
        }
        # Without trusted proxy config, should use real IP
        ip = _extract_client_ip(scope, trusted_proxies=[])
        assert ip == "203.0.113.99"  # Attack prevented

    def test_prevents_rate_limit_evasion_via_rotating_ips(self) -> None:
        """Test that attackers cannot evade rate limits by rotating fake IPs.

        Attack scenario: Attacker rapidly tries different client IDs with
        different spoofed X-Forwarded-For IPs to evade per-IP rate limiting.
        """
        attacker_real_ip = "203.0.113.99"
        spoofed_ips = [f"10.0.0.{i}" for i in range(1, 11)]

        for spoofed in spoofed_ips:
            scope = {
                "type": "http",
                "client": (attacker_real_ip, 12345),
                "headers": [
                    (b"x-forwarded-for", spoofed.encode()),
                ],
            }
            ip = _extract_client_ip(scope, trusted_proxies=[])
            # All requests should be tracked under attacker's real IP
            assert ip == attacker_real_ip

    def test_prevents_audit_log_poisoning(self) -> None:
        """Test that attackers cannot poison audit logs with fake IPs.

        Attack scenario: Attacker wants to frame another IP or hide their
        real IP from audit logs.
        """
        scope = {
            "type": "http",
            "client": ("203.0.113.99", 12345),  # Real attacker IP
            "headers": [
                (b"x-forwarded-for", b"192.0.2.1"),  # Fake IP for logs
            ],
        }
        ip = _extract_client_ip(scope, trusted_proxies=[])
        # Audit logs should record real IP, not spoofed one
        assert ip == "203.0.113.99"
