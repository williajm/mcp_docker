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
