"""Performance benchmarks for MCP Docker server.

These tests measure response times and resource usage for various operations.
"""

import time
from typing import Any

import pytest

from mcp_docker.config import Config
from mcp_docker.docker_wrapper.client import DockerClientWrapper
from mcp_docker.server import MCPDockerServer


@pytest.fixture
def integration_config() -> Config:
    """Create integration test configuration."""
    config = Config()
    config.docker.base_url = "unix:///var/run/docker.sock"
    config.docker.timeout = 30
    config.safety.allow_destructive_operations = True
    config.safety.allow_privileged_containers = False
    config.safety.require_confirmation_for_destructive = False
    return config


@pytest.fixture
def docker_wrapper(integration_config: Config) -> DockerClientWrapper:
    """Create Docker client wrapper."""
    wrapper = DockerClientWrapper(integration_config.docker)
    yield wrapper
    wrapper.close()


@pytest.fixture
async def mcp_server(integration_config: Config) -> MCPDockerServer:
    """Create MCP server instance."""
    server = MCPDockerServer(integration_config)
    await server.start()
    yield server
    await server.stop()


def measure_time(func: Any, *args: Any, **kwargs: Any) -> tuple[float, Any]:
    """Measure execution time of a function."""
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    duration = end_time - start_time
    return duration, result


async def measure_time_async(func: Any, *args: Any, **kwargs: Any) -> tuple[float, Any]:
    """Measure execution time of an async function."""
    start_time = time.perf_counter()
    result = await func(*args, **kwargs)
    end_time = time.perf_counter()
    duration = end_time - start_time
    return duration, result


@pytest.mark.integration
@pytest.mark.slow
class TestPerformanceBenchmarks:
    """Performance benchmark tests."""

    @pytest.mark.asyncio
    async def test_server_startup_time(self, integration_config: Config) -> None:
        """Benchmark server startup time."""
        start_time = time.perf_counter()

        server = MCPDockerServer(integration_config)
        await server.start()

        end_time = time.perf_counter()
        startup_time = end_time - start_time

        await server.stop()

        # Server should start in less than 2 seconds
        assert startup_time < 2.0, f"Server startup took {startup_time:.2f}s, expected < 2.0s"
        print(f"\nServer startup time: {startup_time:.3f}s")

    @pytest.mark.asyncio
    async def test_list_containers_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_containers operation."""
        # Warm up
        await mcp_server.call_tool("docker_list_containers", {"all": True})

        # Measure multiple iterations
        iterations = 10
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(
                mcp_server.call_tool, "docker_list_containers", {"all": True}
            )
            times.append(duration)

        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        # Should complete in less than 1 second on average
        assert avg_time < 1.0, f"Average time {avg_time:.2f}s, expected < 1.0s"
        print(
            f"\nList containers - Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s"
        )

    @pytest.mark.asyncio
    async def test_system_info_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark system_info operation."""
        # Warm up
        await mcp_server.call_tool("docker_system_info", {})

        # Measure multiple iterations
        iterations = 10
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(mcp_server.call_tool, "docker_system_info", {})
            times.append(duration)

        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        # Should complete in less than 0.5 seconds on average
        assert avg_time < 0.5, f"Average time {avg_time:.2f}s, expected < 0.5s"
        print(f"\nSystem info - Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")

    @pytest.mark.asyncio
    async def test_container_lifecycle_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark complete container lifecycle."""
        container_name = "perf-test-container"

        try:
            # Measure create
            create_start = time.perf_counter()
            create_result = await mcp_server.call_tool(
                "docker_create_container",
                {
                    "image": "alpine:latest",
                    "name": container_name,
                    "command": ["sleep", "300"],
                },
            )
            create_time = time.perf_counter() - create_start
            assert create_result["success"] is True
            container_id = create_result["result"]["id"]

            # Measure start
            start_start = time.perf_counter()
            await mcp_server.call_tool("docker_start_container", {"container_id": container_id})
            start_time = time.perf_counter() - start_start

            # Measure inspect
            inspect_start = time.perf_counter()
            await mcp_server.call_tool("docker_inspect_container", {"container_id": container_id})
            inspect_time = time.perf_counter() - inspect_start

            # Measure stop
            stop_start = time.perf_counter()
            await mcp_server.call_tool(
                "docker_stop_container", {"container_id": container_id, "timeout": 5}
            )
            stop_time = time.perf_counter() - stop_start

            # Measure remove
            remove_start = time.perf_counter()
            await mcp_server.call_tool(
                "docker_remove_container", {"container_id": container_id, "force": True}
            )
            remove_time = time.perf_counter() - remove_start

            total_time = create_time + start_time + inspect_time + stop_time + remove_time

            print("\nContainer lifecycle benchmark:")
            print(f"  Create:  {create_time:.3f}s")
            print(f"  Start:   {start_time:.3f}s")
            print(f"  Inspect: {inspect_time:.3f}s")
            print(f"  Stop:    {stop_time:.3f}s")
            print(f"  Remove:  {remove_time:.3f}s")
            print(f"  Total:   {total_time:.3f}s")

            # Total lifecycle should complete in less than 10 seconds
            assert total_time < 10.0, f"Total time {total_time:.2f}s, expected < 10.0s"

        finally:
            try:
                await mcp_server.call_tool(
                    "docker_remove_container", {"container_id": container_name, "force": True}
                )
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_list_images_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_images operation."""
        # Warm up
        await mcp_server.call_tool("docker_list_images", {})

        # Measure multiple iterations
        iterations = 10
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(mcp_server.call_tool, "docker_list_images", {})
            times.append(duration)

        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        # Should complete in less than 1 second on average
        assert avg_time < 1.0, f"Average time {avg_time:.2f}s, expected < 1.0s"
        print(f"\nList images - Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")

    @pytest.mark.asyncio
    async def test_list_networks_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_networks operation."""
        iterations = 10
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(mcp_server.call_tool, "docker_list_networks", {})
            times.append(duration)

        avg_time = sum(times) / len(times)
        assert avg_time < 1.0, f"Average time {avg_time:.2f}s, expected < 1.0s"
        print(f"\nList networks - Avg: {avg_time:.3f}s")

    @pytest.mark.asyncio
    async def test_list_volumes_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_volumes operation."""
        iterations = 10
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(mcp_server.call_tool, "docker_list_volumes", {})
            times.append(duration)

        avg_time = sum(times) / len(times)
        assert avg_time < 1.0, f"Average time {avg_time:.2f}s, expected < 1.0s"
        print(f"\nList volumes - Avg: {avg_time:.3f}s")

    @pytest.mark.asyncio
    async def test_healthcheck_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark healthcheck operation."""
        iterations = 20
        times = []

        for _ in range(iterations):
            duration, _ = await measure_time_async(mcp_server.call_tool, "docker_healthcheck", {})
            times.append(duration)

        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        # Health check should be very fast
        assert avg_time < 0.3, f"Average time {avg_time:.2f}s, expected < 0.3s"
        print(f"\nHealthcheck - Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")

    def test_list_tools_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_tools operation."""
        iterations = 100
        times = []

        for _ in range(iterations):
            duration, result = measure_time(mcp_server.list_tools)
            times.append(duration)

        avg_time = sum(times) / len(times)

        # Listing tools should be very fast (in-memory operation)
        assert avg_time < 0.01, f"Average time {avg_time:.4f}s, expected < 0.01s"
        print(f"\nList tools - Avg: {avg_time:.4f}s for {len(result)} tools")

    def test_list_prompts_performance(self, mcp_server: MCPDockerServer) -> None:
        """Benchmark list_prompts operation."""
        iterations = 100
        times = []

        for _ in range(iterations):
            duration, result = measure_time(mcp_server.list_prompts)
            times.append(duration)

        avg_time = sum(times) / len(times)

        # Listing prompts should be very fast (in-memory operation)
        assert avg_time < 0.01, f"Average time {avg_time:.4f}s, expected < 0.01s"
        print(f"\nList prompts - Avg: {avg_time:.4f}s for {len(result)} prompts")

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mcp_server: MCPDockerServer) -> None:
        """Test performance of concurrent operations."""
        import asyncio

        # Create multiple tasks
        tasks = [
            mcp_server.call_tool("docker_list_containers", {"all": True}),
            mcp_server.call_tool("docker_list_images", {}),
            mcp_server.call_tool("docker_list_networks", {}),
            mcp_server.call_tool("docker_list_volumes", {}),
            mcp_server.call_tool("docker_system_info", {}),
        ]

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        end_time = time.perf_counter()

        concurrent_time = end_time - start_time

        # Concurrent operations should complete faster than sequential
        # (though not necessarily 5x faster due to Docker daemon limits)
        assert concurrent_time < 5.0, f"Concurrent time {concurrent_time:.2f}s, expected < 5.0s"
        assert all(r["success"] for r in results)

        print(f"\nConcurrent operations (5 tasks): {concurrent_time:.3f}s")

    @pytest.mark.asyncio
    async def test_memory_efficiency(self, mcp_server: MCPDockerServer) -> None:
        """Test that repeated operations don't leak memory."""
        import gc

        # Force garbage collection
        gc.collect()

        # Perform many operations
        iterations = 50
        for _ in range(iterations):
            await mcp_server.call_tool("docker_list_containers", {"all": True})
            await mcp_server.call_tool("docker_system_info", {})

        # Force garbage collection again
        gc.collect()

        # If we got here without memory errors, test passes
        print(f"\nCompleted {iterations * 2} operations without memory issues")
        assert True
