"""Utilities for formatting Docker container statistics."""

from typing import Any


def calculate_memory_usage(stats: dict[str, Any]) -> dict[str, float]:
    """Calculate memory usage metrics from Docker stats.

    Args:
        stats: Docker stats dictionary from container.stats()

    Returns:
        Dict with usage_bytes, limit_bytes, usage_mb, limit_mb, and percent

    """
    memory_stats = stats.get("memory_stats", {})
    usage = memory_stats.get("usage", 0)
    limit = memory_stats.get("limit", 0)

    return {
        "usage_bytes": usage,
        "limit_bytes": limit,
        "usage_mb": usage / 1024 / 1024,
        "limit_mb": limit / 1024 / 1024,
        "percent": (usage / limit * 100) if limit > 0 else 0,
    }


def calculate_cpu_usage(stats: dict[str, Any]) -> dict[str, int]:
    """Calculate CPU usage metrics from Docker stats.

    Args:
        stats: Docker stats dictionary from container.stats()

    Returns:
        Dict with online_cpus, total_usage, and system_usage

    """
    cpu_stats = stats.get("cpu_stats", {})

    return {
        "online_cpus": cpu_stats.get("online_cpus", 1),
        "total_usage": cpu_stats.get("cpu_usage", {}).get("total_usage", 0),
        "system_usage": cpu_stats.get("system_cpu_usage", 0),
    }


def format_network_stats(stats: dict[str, Any]) -> str:
    """Format network statistics as human-readable text.

    Args:
        stats: Docker stats dictionary from container.stats()

    Returns:
        Formatted network stats string

    """
    network_stats = stats.get("networks", {})

    if not network_stats:
        return " No network interfaces"

    lines = []
    for interface, stats_data in network_stats.items():
        rx_bytes = stats_data.get("rx_bytes", 0)
        tx_bytes = stats_data.get("tx_bytes", 0)
        lines.append(f"\n  {interface}: RX {rx_bytes / 1024:.2f} KB, TX {tx_bytes / 1024:.2f} KB")

    return "".join(lines)
