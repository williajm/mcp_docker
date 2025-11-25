"""Tests for stats_formatter utility module."""

import pytest

from mcp_docker.utils.stats_formatter import (
    calculate_cpu_usage,
    calculate_memory_usage,
    format_network_stats,
)


class TestCalculateMemoryUsage:
    """Tests for calculate_memory_usage function."""

    def test_normal_memory_usage(self) -> None:
        """Test calculating memory usage with typical values."""
        stats = {
            "memory_stats": {
                "usage": 104857600,  # 100 MB
                "limit": 1073741824,  # 1 GB
            }
        }

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 104857600
        assert result["limit_bytes"] == 1073741824
        assert result["usage_mb"] == pytest.approx(100.0)
        assert result["limit_mb"] == pytest.approx(1024.0)
        assert result["percent"] == pytest.approx(9.765625)

    def test_empty_stats(self) -> None:
        """Test calculating memory usage with empty stats."""
        stats: dict = {}

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 0
        assert result["limit_bytes"] == 0
        assert result["usage_mb"] == 0.0
        assert result["limit_mb"] == 0.0
        assert result["percent"] == 0  # Division by zero handled

    def test_missing_memory_stats(self) -> None:
        """Test calculating memory usage when memory_stats key is missing."""
        stats = {"cpu_stats": {"online_cpus": 4}}

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 0
        assert result["limit_bytes"] == 0
        assert result["percent"] == 0

    def test_zero_limit_prevents_division_error(self) -> None:
        """Test that zero limit doesn't cause division by zero."""
        stats = {
            "memory_stats": {
                "usage": 1000000,
                "limit": 0,
            }
        }

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 1000000
        assert result["limit_bytes"] == 0
        assert result["percent"] == 0  # Should be 0, not ZeroDivisionError

    def test_partial_memory_stats(self) -> None:
        """Test calculating memory usage with partial memory_stats."""
        stats = {
            "memory_stats": {
                "usage": 500000,
                # limit is missing
            }
        }

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 500000
        assert result["limit_bytes"] == 0
        assert result["percent"] == 0

    def test_very_large_values(self) -> None:
        """Test with very large memory values (64GB container)."""
        stats = {
            "memory_stats": {
                "usage": 68719476736,  # 64 GB
                "limit": 137438953472,  # 128 GB
            }
        }

        result = calculate_memory_usage(stats)

        assert result["usage_bytes"] == 68719476736
        assert result["limit_bytes"] == 137438953472
        assert result["usage_mb"] == pytest.approx(65536.0)
        assert result["limit_mb"] == pytest.approx(131072.0)
        assert result["percent"] == pytest.approx(50.0)


class TestCalculateCpuUsage:
    """Tests for calculate_cpu_usage function."""

    def test_normal_cpu_usage(self) -> None:
        """Test calculating CPU usage with typical values."""
        stats = {
            "cpu_stats": {
                "online_cpus": 4,
                "cpu_usage": {
                    "total_usage": 123456789,
                },
                "system_cpu_usage": 987654321,
            }
        }

        result = calculate_cpu_usage(stats)

        assert result["online_cpus"] == 4
        assert result["total_usage"] == 123456789
        assert result["system_usage"] == 987654321

    def test_empty_stats(self) -> None:
        """Test calculating CPU usage with empty stats."""
        stats: dict = {}

        result = calculate_cpu_usage(stats)

        assert result["online_cpus"] == 1  # Default to 1 CPU
        assert result["total_usage"] == 0
        assert result["system_usage"] == 0

    def test_missing_cpu_stats(self) -> None:
        """Test calculating CPU usage when cpu_stats key is missing."""
        stats = {"memory_stats": {"usage": 1000}}

        result = calculate_cpu_usage(stats)

        assert result["online_cpus"] == 1
        assert result["total_usage"] == 0
        assert result["system_usage"] == 0

    def test_partial_cpu_stats(self) -> None:
        """Test calculating CPU usage with partial cpu_stats."""
        stats = {
            "cpu_stats": {
                "online_cpus": 8,
                # cpu_usage and system_cpu_usage missing
            }
        }

        result = calculate_cpu_usage(stats)

        assert result["online_cpus"] == 8
        assert result["total_usage"] == 0
        assert result["system_usage"] == 0

    def test_missing_cpu_usage_nested(self) -> None:
        """Test when cpu_usage dict is present but total_usage is missing."""
        stats = {
            "cpu_stats": {
                "online_cpus": 2,
                "cpu_usage": {},  # Empty, no total_usage
                "system_cpu_usage": 1000,
            }
        }

        result = calculate_cpu_usage(stats)

        assert result["online_cpus"] == 2
        assert result["total_usage"] == 0
        assert result["system_usage"] == 1000


class TestFormatNetworkStats:
    """Tests for format_network_stats function."""

    def test_single_interface(self) -> None:
        """Test formatting stats for a single network interface."""
        stats = {
            "networks": {
                "eth0": {
                    "rx_bytes": 1048576,  # 1 MB = 1024 KB
                    "tx_bytes": 524288,  # 0.5 MB = 512 KB
                }
            }
        }

        result = format_network_stats(stats)

        assert "eth0" in result
        assert "RX 1024.00 KB" in result
        assert "TX 512.00 KB" in result

    def test_multiple_interfaces(self) -> None:
        """Test formatting stats for multiple network interfaces."""
        stats = {
            "networks": {
                "eth0": {"rx_bytes": 1024, "tx_bytes": 2048},
                "eth1": {"rx_bytes": 4096, "tx_bytes": 8192},
            }
        }

        result = format_network_stats(stats)

        assert "eth0" in result
        assert "eth1" in result
        assert "RX 1.00 KB" in result  # eth0 rx
        assert "RX 4.00 KB" in result  # eth1 rx

    def test_no_network_interfaces(self) -> None:
        """Test formatting when no network interfaces exist."""
        stats = {"networks": {}}

        result = format_network_stats(stats)

        assert "No network interfaces" in result

    def test_missing_networks_key(self) -> None:
        """Test formatting when networks key is missing."""
        stats: dict = {}

        result = format_network_stats(stats)

        assert "No network interfaces" in result

    def test_partial_interface_stats(self) -> None:
        """Test formatting with partial interface statistics."""
        stats = {
            "networks": {
                "eth0": {
                    "rx_bytes": 1000,
                    # tx_bytes missing
                }
            }
        }

        result = format_network_stats(stats)

        assert "eth0" in result
        assert "RX" in result
        assert "TX 0.00 KB" in result  # Default to 0

    def test_zero_bytes(self) -> None:
        """Test formatting with zero traffic."""
        stats = {"networks": {"lo": {"rx_bytes": 0, "tx_bytes": 0}}}

        result = format_network_stats(stats)

        assert "lo" in result
        assert "RX 0.00 KB" in result
        assert "TX 0.00 KB" in result

    def test_very_large_traffic(self) -> None:
        """Test formatting with very large traffic values (10 GB)."""
        stats = {
            "networks": {
                "eth0": {
                    "rx_bytes": 10737418240,  # 10 GB
                    "tx_bytes": 5368709120,  # 5 GB
                }
            }
        }

        result = format_network_stats(stats)

        assert "eth0" in result
        # 10 GB = 10485760 KB
        assert "10485760.00 KB" in result
