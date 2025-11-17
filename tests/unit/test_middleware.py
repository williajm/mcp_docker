"""Unit tests for middleware components."""

from unittest.mock import AsyncMock, Mock

import pytest

from mcp_docker.middleware.audit import AuditMiddleware
from mcp_docker.middleware.rate_limit import RateLimitMiddleware
from mcp_docker.middleware.safety import SafetyMiddleware
from mcp_docker.safety import SafetyEnforcer
from mcp_docker.security.audit import AuditLogger
from mcp_docker.security.rate_limiter import RateLimiter, RateLimitExceeded
from mcp_docker.utils.errors import UnsafeOperationError
from mcp_docker.utils.safety import OperationSafety


class TestSafetyMiddleware:
    """Test SafetyMiddleware."""

    def test_init(self):
        """Test SafetyMiddleware initialization."""
        enforcer = Mock(spec=SafetyEnforcer)
        middleware = SafetyMiddleware(enforcer)

        assert middleware.enforcer == enforcer

    @pytest.mark.asyncio
    async def test_call_safe_tool(self):
        """Test calling a safe tool."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(return_value=None)  # Allow tool

        middleware = SafetyMiddleware(enforcer)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context
        tool_func = Mock()
        tool_func._safety_level = OperationSafety.SAFE
        context = {
            "tool_name": "docker_list_containers",
            "arguments": {"all": True},
            "tool_func": tool_func,
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        enforcer.enforce_all_checks.assert_called_once_with(
            "docker_list_containers", OperationSafety.SAFE, {"all": True}
        )
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_denied_tool(self):
        """Test calling a denied tool."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(side_effect=UnsafeOperationError("Tool not allowed"))

        middleware = SafetyMiddleware(enforcer)

        # Mock next middleware
        call_next = AsyncMock()

        # Create context
        tool_func = Mock()
        tool_func._safety_level = OperationSafety.DESTRUCTIVE
        context = {
            "tool_name": "docker_remove_container",
            "arguments": {"container_id": "test"},
            "tool_func": tool_func,
        }

        # Call middleware should raise
        with pytest.raises(UnsafeOperationError, match="Tool not allowed"):
            await middleware(call_next, context)

        # Next middleware should not be called
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_call_no_tool_name(self):
        """Test calling with missing tool_name in context."""
        enforcer = Mock(spec=SafetyEnforcer)
        middleware = SafetyMiddleware(enforcer)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context without tool_name
        context = {"arguments": {}}

        # Should proceed without checking
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        enforcer.enforce_all_checks.assert_not_called()
        call_next.assert_called_once()


class TestRateLimitMiddleware:
    """Test RateLimitMiddleware."""

    def test_init(self):
        """Test RateLimitMiddleware initialization."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        middleware = RateLimitMiddleware(rate_limiter)

        assert middleware.rate_limiter == rate_limiter

    @pytest.mark.asyncio
    async def test_call_within_limit(self):
        """Test calling when within rate limit."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)  # Allow

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "client_ip": "192.168.1.100",
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        rate_limiter.check_rate_limit.assert_called_once_with("192.168.1.100")
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_rate_limited(self):
        """Test calling when rate limited."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        # Rate limiter raises RateLimitExceeded when limit exceeded
        rate_limiter.check_rate_limit = AsyncMock(
            side_effect=RateLimitExceeded("Rate limit exceeded for client test-client")
        )

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock()

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "client_ip": "test-client",
        }

        # Call middleware should raise
        with pytest.raises(RateLimitExceeded, match="Rate limit exceeded"):
            await middleware(call_next, context)

        # Next middleware should not be called
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_call_disabled(self):
        """Test calling when rate limiting is disabled."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = False
        rate_limiter.rpm = 60
        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context
        context = {"tool_name": "docker_list_containers"}

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        # check_rate_limit should not be called when disabled
        rate_limiter.check_rate_limit.assert_not_called()
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_slot_acquired_and_released(self):
        """Regression test: Verify concurrent slots are acquired and released."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)
        rate_limiter.acquire_concurrent_slot = AsyncMock(return_value=None)
        rate_limiter.release_concurrent_slot = Mock(return_value=None)

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "client_ip": "192.168.1.100",
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        # Verify concurrent slot was acquired
        rate_limiter.acquire_concurrent_slot.assert_called_once_with("192.168.1.100")
        # Verify concurrent slot was released
        rate_limiter.release_concurrent_slot.assert_called_once_with("192.168.1.100")
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_slot_released_on_exception(self):
        """Regression test: Verify concurrent slot is released even on exception."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)
        rate_limiter.acquire_concurrent_slot = AsyncMock(return_value=None)
        rate_limiter.release_concurrent_slot = Mock(return_value=None)

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware that raises
        error = RuntimeError("Tool execution failed")
        call_next = AsyncMock(side_effect=error)

        # Create context
        context = {
            "tool_name": "docker_remove_container",
            "client_ip": "10.0.0.1",
        }

        # Call middleware - should raise but still release slot
        with pytest.raises(RuntimeError, match="Tool execution failed"):
            await middleware(call_next, context)

        # Verify concurrent slot was acquired
        rate_limiter.acquire_concurrent_slot.assert_called_once_with("10.0.0.1")
        # Verify concurrent slot was released (in finally block)
        rate_limiter.release_concurrent_slot.assert_called_once_with("10.0.0.1")

    @pytest.mark.asyncio
    async def test_concurrent_slot_limit_exceeded(self):
        """Regression test: Verify concurrent limit is enforced."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)
        # Concurrent slot acquisition fails
        rate_limiter.acquire_concurrent_slot = AsyncMock(
            side_effect=RateLimitExceeded("Concurrent request limit exceeded")
        )

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock()

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "client_ip": "192.168.1.100",
        }

        # Call middleware should raise
        with pytest.raises(RateLimitExceeded, match="Concurrent request limit exceeded"):
            await middleware(call_next, context)

        # Next middleware should not be called
        call_next.assert_not_called()


class TestAuditMiddleware:
    """Test AuditMiddleware."""

    def test_init(self):
        """Test AuditMiddleware initialization."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        assert middleware.audit_logger == audit_logger

    @pytest.mark.asyncio
    async def test_call_logs_success(self):
        """Test calling logs successful operation."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success", "data": "test"})

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "client_ip": "192.168.1.100",
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success", "data": "test"}
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_logs_failure(self):
        """Test calling logs failed operation."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware that raises
        error = RuntimeError("Operation failed")
        call_next = AsyncMock(side_effect=error)

        # Create context
        context = {
            "tool_name": "docker_remove_container",
            "client_ip": "10.0.0.1",
        }

        # Call middleware - should raise but still log
        with pytest.raises(RuntimeError, match="Operation failed"):
            await middleware(call_next, context)

        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_unknown_client(self):
        """Test calling with unknown client defaults."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context without client info
        context = {"tool_name": "docker_list_containers"}

        # Call middleware - should use "unknown" for client
        result = await middleware(call_next, context)

        assert result == {"status": "success"}
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_success(self):
        """Regression test: Verify AuditLogger.log_tool_call is called on success."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success", "data": "test"})

        # Create context
        context = {
            "tool_name": "docker_list_containers",
            "arguments": {"all": True},
            "client_ip": "192.168.1.100",
            "session_id": "session-123",
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success", "data": "test"}
        call_next.assert_called_once()

        # Verify log_tool_call was called with ClientInfo
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args

        # Check that ClientInfo was passed
        client_info = call_args.kwargs["client_info"]
        assert client_info.client_id == "session-123"
        assert client_info.ip_address == "192.168.1.100"

        # Check that tool details were passed
        assert call_args.kwargs["tool_name"] == "docker_list_containers"
        assert call_args.kwargs["arguments"] == {"all": True}
        assert call_args.kwargs["result"] == {"status": "success", "data": "test"}
        assert call_args.kwargs.get("error") is None

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_failure(self):
        """Regression test: Verify AuditLogger.log_tool_call is called on failure."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware that raises
        error = RuntimeError("Container not found")
        call_next = AsyncMock(side_effect=error)

        # Create context
        context = {
            "tool_name": "docker_remove_container",
            "arguments": {"container_id": "abc123"},
            "client_ip": "10.0.0.1",
        }

        # Call middleware - should raise but still log
        with pytest.raises(RuntimeError, match="Container not found"):
            await middleware(call_next, context)

        call_next.assert_called_once()

        # Verify log_tool_call was called with error
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args

        # Check that ClientInfo was passed
        client_info = call_args.kwargs["client_info"]
        assert client_info.client_id == "10.0.0.1"  # Uses IP when no session_id
        assert client_info.ip_address == "10.0.0.1"

        # Check that error was logged
        assert call_args.kwargs["tool_name"] == "docker_remove_container"
        assert call_args.kwargs["arguments"] == {"container_id": "abc123"}
        assert call_args.kwargs["error"] == "Container not found"
        assert call_args.kwargs.get("result") is None

    @pytest.mark.asyncio
    async def test_audit_logger_with_api_key_hash(self):
        """Regression test: Verify API key hash is logged for authenticated requests."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context with API key hash
        context = {
            "tool_name": "docker_list_containers",
            "arguments": {},
            "client_ip": "192.168.1.100",
            "session_id": "session-456",
            "api_key_hash": "sha256:abc123",
            "user_agent": "mcp-client/1.0",
        }

        # Call middleware
        result = await middleware(call_next, context)

        assert result == {"status": "success"}

        # Verify ClientInfo includes API key hash and user agent
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args
        client_info = call_args.kwargs["client_info"]

        assert client_info.api_key_hash == "sha256:abc123"
        assert client_info.description == "mcp-client/1.0"
