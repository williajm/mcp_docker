"""Unit tests for middleware components."""

from unittest.mock import AsyncMock, Mock

import pytest

from mcp_docker.middleware.audit import AuditMiddleware, create_audit_middleware
from mcp_docker.middleware.rate_limit import RateLimitMiddleware, create_rate_limit_middleware
from mcp_docker.middleware.safety import SafetyMiddleware, create_safety_middleware
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
        app = Mock()
        middleware = SafetyMiddleware(enforcer, app)

        assert middleware.enforcer == enforcer
        assert middleware.app == app

    @pytest.mark.asyncio
    async def test_call_safe_tool(self):
        """Test calling a safe tool."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(return_value=None)  # Allow tool

        # Create mock app with a safe tool
        app = Mock()
        safe_func = AsyncMock()
        safe_func._safety_level = OperationSafety.SAFE
        mock_tool = Mock()
        mock_tool.fn = safe_func
        app.get_tool = AsyncMock(return_value=mock_tool)

        middleware = SafetyMiddleware(enforcer, app)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}
        context = Mock()
        context.message = message

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        enforcer.enforce_all_checks.assert_called_once_with(
            "docker_list_containers", OperationSafety.SAFE, {"all": True}
        )
        app.get_tool.assert_called_once_with("docker_list_containers")
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_denied_tool(self):
        """Test calling a denied tool."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(side_effect=UnsafeOperationError("Tool not allowed"))

        # Create mock app with a destructive tool
        app = Mock()
        destructive_func = AsyncMock()
        destructive_func._safety_level = OperationSafety.DESTRUCTIVE
        mock_tool = Mock()
        mock_tool.fn = destructive_func
        app.get_tool = AsyncMock(return_value=mock_tool)

        middleware = SafetyMiddleware(enforcer, app)

        # Mock next middleware
        call_next = AsyncMock()

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "test"}
        context = Mock()
        context.message = message

        # Call middleware should raise
        with pytest.raises(UnsafeOperationError, match="Tool not allowed"):
            await middleware(context, call_next)

        # Next middleware should not be called
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_call_no_tool_name(self):
        """Test calling with missing tool_name in context."""
        enforcer = Mock(spec=SafetyEnforcer)
        app = Mock()
        middleware = SafetyMiddleware(enforcer, app)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create context without tool_name (message has no name attribute)
        message = Mock(spec=[])  # No 'name' attribute
        context = Mock()
        context.message = message

        # Should proceed without checking
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        enforcer.enforce_all_checks.assert_not_called()
        app.get_tool.assert_not_called()
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_no_safety_level_defaults_to_safe(self):
        """Test calling when tool_func has no safety level defaults to SAFE."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(return_value=None)

        # Create mock app with tool that has no _safety_level attribute
        app = Mock()
        tool_func = AsyncMock(spec=[])  # No _safety_level attribute
        mock_tool = Mock()
        mock_tool.fn = tool_func
        app.get_tool = AsyncMock(return_value=mock_tool)

        middleware = SafetyMiddleware(enforcer, app)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}
        context = Mock()
        context.message = message

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        # Should default to SAFE level
        enforcer.enforce_all_checks.assert_called_once_with(
            "docker_list_containers", OperationSafety.SAFE, {}
        )
        app.get_tool.assert_called_once_with("docker_list_containers")
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_no_tool_func_defaults_to_safe(self):
        """Test calling when get_tool fails defaults to SAFE."""
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(return_value=None)

        # Create mock app that raises when getting tool
        app = Mock()
        app.get_tool = AsyncMock(side_effect=Exception("Tool not found"))

        middleware = SafetyMiddleware(enforcer, app)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}
        context = Mock()
        context.message = message

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        # Should default to SAFE level when tool lookup fails
        enforcer.enforce_all_checks.assert_called_once_with(
            "docker_list_containers", OperationSafety.SAFE, {"all": True}
        )
        app.get_tool.assert_called_once_with("docker_list_containers")
        call_next.assert_called_once()

    def test_create_safety_middleware_factory(self):
        """Test create_safety_middleware factory function."""
        enforcer = Mock(spec=SafetyEnforcer)
        app = Mock()
        middleware = create_safety_middleware(enforcer, app)

        assert isinstance(middleware, SafetyMiddleware)
        assert middleware.enforcer == enforcer
        assert middleware.app == app

    @pytest.mark.asyncio
    async def test_reads_actual_tool_safety_level_not_default_safe(self):
        """Regression test for P0 bug: Safety middleware must read actual tool safety level.

        Previously, the middleware always set safety_level = OperationSafety.SAFE,
        which allowed DESTRUCTIVE operations to bypass safety checks.
        This test ensures the middleware reads the tool's actual _safety_level metadata.
        """
        enforcer = Mock(spec=SafetyEnforcer)
        enforcer.enforce_all_checks = Mock(return_value=None)

        # Create mock app with a destructive tool
        app = Mock()
        destructive_func = AsyncMock()
        destructive_func._safety_level = OperationSafety.DESTRUCTIVE
        destructive_func._tool_name = "docker_remove_container"

        mock_tool = Mock()
        mock_tool.fn = destructive_func
        app.get_tool = AsyncMock(return_value=mock_tool)

        middleware = SafetyMiddleware(enforcer, app)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "test123"}

        context = Mock()
        context.message = message

        call_next = AsyncMock(return_value={"status": "success"})

        # Call middleware
        await middleware(context, call_next)

        # CRITICAL: Verify enforcer was called with DESTRUCTIVE level, not SAFE
        enforcer.enforce_all_checks.assert_called_once_with(
            "docker_remove_container",
            OperationSafety.DESTRUCTIVE,  # Must be DESTRUCTIVE, not SAFE
            {"container_id": "test123"},
        )
        # Verify app.get_tool was called to fetch metadata
        app.get_tool.assert_called_once_with("docker_remove_container")
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
        rate_limiter.acquire_concurrent_slot = AsyncMock(return_value=None)
        rate_limiter.release_concurrent_slot = Mock(return_value=None)

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None  # No session for stdio

        # Call middleware with correct parameter order
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        rate_limiter.check_rate_limit.assert_called_once_with("unknown")
        call_next.assert_called_once_with(context)

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware should raise
        with pytest.raises(RateLimitExceeded, match="Rate limit exceeded"):
            await middleware(context, call_next)

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        # check_rate_limit should not be called when disabled
        rate_limiter.check_rate_limit.assert_not_called()
        call_next.assert_called_once_with(context)

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        # Verify concurrent slot was acquired
        rate_limiter.acquire_concurrent_slot.assert_called_once_with("unknown")
        # Verify concurrent slot was released
        rate_limiter.release_concurrent_slot.assert_called_once_with("unknown")
        call_next.assert_called_once_with(context)

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "test123"}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware - should raise but still release slot
        with pytest.raises(RuntimeError, match="Tool execution failed"):
            await middleware(context, call_next)

        # Verify concurrent slot was acquired
        rate_limiter.acquire_concurrent_slot.assert_called_once_with("unknown")
        # Verify concurrent slot was released (in finally block)
        rate_limiter.release_concurrent_slot.assert_called_once_with("unknown")

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware should raise
        with pytest.raises(RateLimitExceeded, match="Concurrent request limit exceeded"):
            await middleware(context, call_next)

        # Next middleware should not be called
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_client_id_extraction_with_session(self):
        """Test client_id extraction when session_id is available (no client_info)."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)
        rate_limiter.acquire_concurrent_slot = AsyncMock(return_value=None)
        rate_limiter.release_concurrent_slot = Mock(return_value=None)

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Test 1: session_id is extracted from fastmcp_context when client_info not present
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message

        # Mock fastmcp_context with session_id but no client_info
        fastmcp_ctx = Mock(spec=["request_context", "session_id"])
        fastmcp_ctx.request_context = Mock()  # Session established
        fastmcp_ctx.session_id = "session-123"
        context.fastmcp_context = fastmcp_ctx

        await middleware(context, call_next)
        rate_limiter.check_rate_limit.assert_called_with("session-123")

        # Test 2: "unknown" is used when fastmcp_context is None
        rate_limiter.reset_mock()
        context.fastmcp_context = None
        await middleware(context, call_next)
        rate_limiter.check_rate_limit.assert_called_with("unknown")

    @pytest.mark.asyncio
    async def test_client_id_extraction_with_authenticated_client_info(self):
        """Test client_id extraction from authenticated client_info (from auth middleware)."""
        from mcp_docker.auth.models import ClientInfo

        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        rate_limiter.check_rate_limit = AsyncMock(return_value=None)
        rate_limiter.acquire_concurrent_slot = AsyncMock(return_value=None)
        rate_limiter.release_concurrent_slot = Mock(return_value=None)

        middleware = RateLimitMiddleware(rate_limiter)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Test: client_info from auth middleware takes precedence over session_id
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message

        # Create authenticated client info (as set by auth middleware)
        client_info = ClientInfo(
            client_id="oauth:user@example.com",
            auth_method="oauth",
            ip_address="192.168.1.100",
        )

        # Mock fastmcp_context with both client_info and session_id
        fastmcp_ctx = Mock(spec=["client_info", "request_context", "session_id"])
        fastmcp_ctx.client_info = client_info
        fastmcp_ctx.request_context = Mock()  # Session established
        fastmcp_ctx.session_id = "session-456"  # This should be ignored
        context.fastmcp_context = fastmcp_ctx

        await middleware(context, call_next)

        # Should use client_info.client_id, not session_id
        rate_limiter.check_rate_limit.assert_called_with("oauth:user@example.com")

    def test_create_rate_limit_middleware_factory(self):
        """Test create_rate_limit_middleware factory function."""
        rate_limiter = Mock(spec=RateLimiter)
        rate_limiter.enabled = True
        rate_limiter.rpm = 60
        middleware = create_rate_limit_middleware(rate_limiter)

        assert isinstance(middleware, RateLimitMiddleware)
        assert middleware.rate_limiter == rate_limiter


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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success", "data": "test"}
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_logs_failure(self):
        """Test calling logs failed operation."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware that raises
        error = RuntimeError("Operation failed")
        call_next = AsyncMock(side_effect=error)

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "test123"}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware - should raise but still log
        with pytest.raises(RuntimeError, match="Operation failed"):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_call_unknown_client(self):
        """Test calling with unknown client defaults."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context without client info
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware - should use "unknown" for client
        result = await middleware(context, call_next)

        assert result == {"status": "success"}
        call_next.assert_called_once_with(context)

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_success(self):
        """Regression test: Verify AuditLogger.log_tool_call is called on success."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success", "data": "test"})

        # Create FastMCP 2.0 middleware context with client info
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message

        # Mock fastmcp_context with session_id and client IP (but no client_info)
        fastmcp_ctx = Mock(spec=["session_id", "request_context"])
        fastmcp_ctx.session_id = "session-123"

        # Mock request_context with client IP
        request_ctx = Mock()
        request = Mock()
        client = Mock()
        client.host = "192.168.1.100"
        request.client = client
        request_ctx.request = request
        fastmcp_ctx.request_context = request_ctx

        context.fastmcp_context = fastmcp_ctx

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success", "data": "test"}
        call_next.assert_called_once_with(context)

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

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_remove_container"
        message.arguments = {"container_id": "abc123"}

        context = Mock()
        context.message = message

        # Mock fastmcp_context with client IP but no session_id (and no client_info)
        fastmcp_ctx = Mock(spec=["session_id", "request_context"])
        fastmcp_ctx.session_id = None  # No session

        # Mock request_context with client IP
        request_ctx = Mock()
        request = Mock()
        client = Mock()
        client.host = "10.0.0.1"
        request.client = client
        request_ctx.request = request
        fastmcp_ctx.request_context = request_ctx

        context.fastmcp_context = fastmcp_ctx

        # Call middleware - should raise but still log
        with pytest.raises(RuntimeError, match="Container not found"):
            await middleware(context, call_next)

        call_next.assert_called_once_with(context)

        # Verify log_tool_call was called with error
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args

        # Check that ClientInfo was passed
        client_info = call_args.kwargs["client_info"]
        assert client_info.client_id == "unknown"  # No session_id, defaults to "unknown"
        assert client_info.ip_address == "10.0.0.1"

        # Check that error was logged
        assert call_args.kwargs["tool_name"] == "docker_remove_container"
        assert call_args.kwargs["arguments"] == {"container_id": "abc123"}
        assert call_args.kwargs["error"] == "Container not found"
        assert call_args.kwargs.get("result") is None

    @pytest.mark.asyncio
    async def test_audit_logger_with_default_values(self):
        """Regression test: Verify ClientInfo has default values when not provided."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context without extra info
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware
        result = await middleware(context, call_next)

        assert result == {"status": "success"}

        # Verify ClientInfo has default values
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args
        client_info = call_args.kwargs["client_info"]

        # Default values when fastmcp_context is None
        assert client_info.client_id == "unknown"
        assert client_info.ip_address == "unknown"
        assert client_info.api_key_hash == "none"
        assert client_info.description is None

    @pytest.mark.asyncio
    async def test_client_info_extraction_from_session(self):
        """Test client_id extraction from session_id when available."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message

        # Test 1: session_id is extracted from fastmcp_context (when client_info not available)
        fastmcp_ctx = Mock(spec=["session_id", "request_context"])
        fastmcp_ctx.session_id = "session-123"

        # Mock request_context properly to avoid auto-creating Mock objects
        request_ctx = Mock()
        request_ctx.request = None  # No request info available (stdio mode)
        fastmcp_ctx.request_context = request_ctx

        context.fastmcp_context = fastmcp_ctx

        await middleware(context, call_next)
        call_args = audit_logger.log_tool_call.call_args
        assert call_args.kwargs["client_info"].client_id == "session-123"

        # Test 2: "unknown" is used when fastmcp_context is None
        audit_logger.reset_mock()
        context.fastmcp_context = None
        await middleware(context, call_next)
        call_args = audit_logger.log_tool_call.call_args
        assert call_args.kwargs["client_info"].client_id == "unknown"

    @pytest.mark.asyncio
    async def test_non_dict_result_handling(self):
        """Test that non-dict results are wrapped correctly."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware returning a string
        call_next = AsyncMock(return_value="success")

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {}

        context = Mock()
        context.message = message
        context.fastmcp_context = None

        # Call middleware
        result = await middleware(context, call_next)

        assert result == "success"

        # Verify result was wrapped
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args
        assert call_args.kwargs["result"] == {"value": "success"}

    @pytest.mark.asyncio
    async def test_audit_uses_authenticated_client_info(self):
        """Test audit middleware uses authenticated client_info from auth middleware."""
        from mcp_docker.auth.models import ClientInfo

        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        audit_logger.log_tool_call = Mock(return_value=None)

        middleware = AuditMiddleware(audit_logger)

        # Mock next middleware
        call_next = AsyncMock(return_value={"status": "success"})

        # Create FastMCP 2.0 middleware context
        message = Mock()
        message.name = "docker_list_containers"
        message.arguments = {"all": True}

        context = Mock()
        context.message = message

        # Create authenticated client info (as set by auth middleware)
        authenticated_client_info = ClientInfo(
            client_id="oauth:user@example.com",
            auth_method="oauth",
            ip_address="192.168.1.100",
            scopes=["read", "write"],
            extra={"email": "user@example.com", "name": "Test User"},
        )

        # Mock fastmcp_context with authenticated client_info
        fastmcp_ctx = Mock(spec=["client_info"])
        fastmcp_ctx.client_info = authenticated_client_info
        context.fastmcp_context = fastmcp_ctx

        # Call middleware
        await middleware(context, call_next)

        # Verify audit logger was called with the authenticated client_info
        audit_logger.log_tool_call.assert_called_once()
        call_args = audit_logger.log_tool_call.call_args

        # The client_info passed to audit logger should be the authenticated one
        logged_client_info = call_args.kwargs["client_info"]
        assert logged_client_info.client_id == "oauth:user@example.com"
        assert logged_client_info.auth_method == "oauth"
        assert logged_client_info.ip_address == "192.168.1.100"
        assert logged_client_info.scopes == ["read", "write"]
        assert logged_client_info.extra["email"] == "user@example.com"

    def test_create_audit_middleware_factory(self):
        """Test create_audit_middleware factory function."""
        audit_logger = Mock(spec=AuditLogger)
        audit_logger.enabled = True
        middleware = create_audit_middleware(audit_logger)

        assert isinstance(middleware, AuditMiddleware)
        assert middleware.audit_logger == audit_logger
