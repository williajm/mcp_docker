# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2025-11-18

### ⚠️ Breaking Changes
- **FastMCP 2.0 Migration**: Updated all middleware to FastMCP 2.0 protocol signature
  - Middleware now uses `MiddlewareContext[Any]` and `CallNext[Any, Any]` types
  - Context extraction updated for FastMCP 2.0 request structure
  - **Action Required**: If using custom middleware, update to FastMCP 2.0 API
  - All built-in middleware (auth, safety, rate limiting, audit) updated and tested

### Security
- **CRITICAL: P0 Safety Bypass Fix**: Fixed middleware ignoring tool safety metadata
  - Safety middleware now correctly reads `_safety_level` from tool functions
  - DESTRUCTIVE operations no longer bypass safety checks
  - Regression test added to prevent future bypasses
  - **Impact**: Tools with DESTRUCTIVE safety level are now properly enforced

### Added
- **New System Tools**: Added Docker system information and event streaming
  - `docker_version`: Get Docker daemon version, API version, and system info
  - `docker_events`: Stream real-time Docker events with filters and time bounds
  - Both tools include comprehensive validation and error handling
- **Tool Filtering at Registration**: Performance optimization for large tool sets
  - Tools now filtered at registration time based on safety configuration
  - Reduces MCP protocol overhead for clients
  - Improves initial handshake performance
  - Configuration: `SAFETY_ALLOWED_TOOLS`, `SAFETY_DENIED_TOOLS`

### Fixed
- **Middleware Context Propagation**: Fixed authenticated client info propagation
  - Auth middleware now stores `client_info` in `fastmcp_context`
  - Downstream middleware (rate limiting, audit) can access authentication details
  - Fixes missing client information in audit logs
- **Empty String Environment Variables**: Fixed Pydantic Settings validation
  - Empty strings in environment variables now handled correctly
  - Prevents validation errors for unset optional configurations
  - Affects OAuth and other optional security settings
- **Docker Events Parameter Validation**: Improved `docker_events` tool
  - `until` parameter now required to prevent indefinite hangs
  - Fixed timestamp parameter descriptions for clarity
  - Better error messages for invalid time ranges
- **Type Safety**: Added type ignore comments for Docker SDK calls
  - Suppresses mypy errors for calls without type stubs
  - Maintains strict type checking for project code
- **Circular Import**: Resolved tool registration circular dependency
  - Refactored registration to eliminate import cycles
  - Improves module initialization reliability
- **E2E Test Stability**: Suppressed cancel scope errors in teardown
  - Async cleanup errors no longer fail tests
  - Improves CI reliability

### Code Quality
- **Reduced Cognitive Complexity**: Refactored complex middleware methods
  - `AuthMiddleware.__call__`: 24 → 15 (extracted 2 helper methods)
  - `AuditMiddleware.__call__`: 33 → 15 (extracted 6 helper methods)
  - Improved readability and maintainability
  - Resolves SonarQube code smell issues
- **100% Auth Middleware Coverage**: Added comprehensive unit tests
  - 15 new tests for `AuthMiddleware.__call__` method
  - Tests cover IP extraction, bearer token extraction, and edge cases
  - Validates FastMCP 2.0 context handling
  - Total: 35 auth middleware tests, all passing

### Tests
- **15 new unit tests** for AuthMiddleware FastMCP 2.0 integration
- **8 new unit tests** for safety middleware (including P0 regression test)
- **Multiple integration tests** for Docker system tools
- All 769+ unit tests passing
- CI/CD: Ruff, mypy, pytest all passing

### Performance
- Tool filtering reduces protocol overhead for filtered tool sets
- Faster client initialization with pre-filtered tool inventory
- Reduced memory footprint for safety-restricted configurations

## [1.1.1] - 2025-11-15

### Added
- **Simple volume mount validation**: Prevent accidental mounting of sensitive Linux paths
  - **Named volume detection**: Docker-managed volumes always allowed (they're safe)
  - **System path blocklist**: Block sensitive system paths (`/etc`, `/root`, `/var/run/docker.sock`)
  - **Credential directory protection**: Substring matching blocks credential dirs anywhere in path
    - Always blocks: `.ssh`, `.aws`, `.kube`, `.docker` (even under `/home/user/`)
    - Prevents accidental exposure of SSH keys, cloud credentials, Kubernetes configs
  - **Optional allowlist**: Restrict to specific paths if needed
  - **YOLO mode**: `SAFETY_YOLO_MODE=true` bypasses all checks (for advanced users)
  - **Linux-focused**: Simple protection for common mistakes, not a security fortress
  - Configuration: `SAFETY_VOLUME_MOUNT_BLOCKLIST`, `SAFETY_VOLUME_MOUNT_ALLOWLIST`, `SAFETY_YOLO_MODE`
- **Rate limiter max clients limit**: Prevent memory exhaustion DoS attacks
  - New config: `SECURITY_RATE_LIMIT_MAX_CLIENTS` (default: 10, max: 100)
  - Rejects new clients when limit reached with clear error message
  - Existing clients unaffected at limit
- **Audit log file permissions**: Restrictive permissions on audit logs
  - Directory permissions: 0o700 (owner-only access)
  - File permissions: 0o600 (owner-only read/write)
  - Automatic permission fixing for existing directories

### Security
- **CRITICAL: Command injection via environment variables (H1)**: Prevent command injection in `docker_exec_command`
  - Validates environment variables before passing to Docker
  - Blocks dangerous characters: `$(`, `` ` ``, `;`, `&`, `|`, `\n`, `\r`
  - Prevents exploits like `{"MALICIOUS": "$(cat /etc/passwd)"}`
- **HIGH: Secret leakage in prompts (H2)**: Redact environment variable values in MCP prompts
  - `generate_compose` prompt now redacts all env var values
  - Shows keys but not values: `DATABASE_URL=<REDACTED>`
  - Prevents credential leakage to remote LLM APIs (Claude, OpenAI, etc.)
  - Protection is always enabled, cannot be disabled
  - Documented in SECURITY.md
- **HIGH: Rate limiter memory exhaustion DoS (H5)**: Prevent unbounded client tracking
  - Added `max_clients` limit to rate limiter (default: 10, max: 100)
  - Prevents attackers from exhausting memory with many fake client IDs
  - Clear error message when limit reached
- **LOW: Audit log file permissions (L2)**: Set restrictive permissions on audit logs
  - Directory: 0o700 (was 0o755 - world-readable)
  - File: 0o600 (was 0o644 - world-readable)
  - Prevents information disclosure on multi-user systems

### Fixed
- **Environment variable validation**: Command injection protection with practical limits
  - Validates environment variables for dangerous characters (command substitution, separators)
  - Allows ampersands and pipes (common in connection strings like `postgres://...?ssl=true&pool=10`)
  - Blocks only truly dangerous patterns: `$(`, backticks, semicolons, newlines
- **Documentation accuracy**: Fixed misleading OAuth claims in startup scripts
  - `start-mcp-docker-httpstream.sh` and `start-mcp-docker-sse.sh` documentation
  - Clarified that OAuth is disabled by default (set `SECURITY_OAUTH_ENABLED=false`)
  - Accurately describe enabled features: TLS, rate limiting, audit logging
- **Rate limiter race condition**: Fixed KeyError in concurrent operations
  - Race condition in cleanup logic where concurrent releases deleted semaphore entries
  - Fixes CI integration test failures in concurrent operation tests
- **Rate limiter memory exhaustion**: Fixed memory leak from unique client IDs
  - Implements LRU eviction of idle clients when at max_clients capacity
  - Prevents unbounded memory growth while allowing normal multi-user operation
  - Only rejects new clients when all tracked clients have active requests

### Tests
- **20 new unit tests** for volume mount validation (all passing in 0.12s)
- **7 new unit tests** for rate limiter max clients and idle client eviction (all passing)
- **8 new unit tests** for environment variable command injection protection
- **6 new unit tests** for list-based command validation coverage
- **3 new unit tests** for audit log file permissions
- **1 new unit test** for prompt secret redaction
- Total: **45 new tests**, all fast unit tests

## [1.1.0] - 2025-11-14

### Added
- **HTTP Stream Transport**: Modern MCP transport protocol for network deployments
  - Single unified endpoint (POST /) for all MCP operations
  - Session management with `mcp-session-id` header tracking
  - Stream resumability with InMemoryEventStore for message replay
  - Flexible response modes (streaming SSE or batch JSON)
  - Configurable event store (max events, TTL, resumability toggle)
  - Production startup script (`start-mcp-docker-httpstream.sh`)
  - Environment variables: `HTTPSTREAM_RESUMABILITY_ENABLED`, `HTTPSTREAM_EVENT_STORE_MAX_EVENTS`, `HTTPSTREAM_EVENT_STORE_TTL_SECONDS`, `HTTPSTREAM_JSON_RESPONSE_MODE`
- **Enhanced CORS Configuration**: Strict security validation for HTTP Stream Transport
  - Prevents CORS wildcard (`*`) origin with credentials (security violation)
  - Validates explicit origins when credentials are enabled
  - Environment variables: `CORS_ENABLED`, `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, `CORS_ALLOWED_METHODS`, `CORS_ALLOWED_HEADERS`, `CORS_EXPOSE_HEADERS`, `CORS_MAX_AGE`
- **DNS Rebinding Protection**: Configurable allowed hosts validation
  - Prevents DNS rebinding attacks via Host header validation
  - Automatic localhost variants for localhost binds
  - Fail-secure policy requiring explicit configuration for non-localhost binds
  - Environment variable: `HTTPSTREAM_ALLOWED_HOSTS`
- **CONFIGURATION.md**: Comprehensive configuration reference guide
  - All environment variables documented with types and examples
  - Common configuration scenarios (development, production, Docker Compose)
  - Security best practices and troubleshooting tips
- **Test Coverage**: 28 new tests for HTTP Stream Transport
  - 11 E2E tests (protocol validation, session management, resumability, OAuth, rate limiting)
  - 17 unit tests (configuration validation, event store, DNS rebinding protection)
  - All tests pass with 91% coverage for `__main__.py`

### Security
- **DNS Rebinding Attack Prevention**: Host header validation prevents DNS rebinding
  - Blocks requests with mismatched Host headers
  - Configurable allowed hosts list for production deployments
  - Documented in SECURITY.md with attack vectors and mitigation strategies
- **Host Header Injection Protection**: Prevents cache poisoning and SSRF attacks
  - Uses Starlette's TrustedHostMiddleware
  - Automatic localhost variants only for localhost binds
  - Fail-secure: non-localhost binds require explicit `HTTPSTREAM_ALLOWED_HOSTS`
- **Session Enumeration Protection**: Cryptographically secure session IDs
  - 128-bit random session IDs prevent enumeration attacks
  - Session isolation ensures no cross-session data leakage
  - Documented in SECURITY.md
- **CORS Security Validation**: Prevents common CORS misconfigurations
  - Rejects wildcard origin with credentials (CORS spec violation)
  - Validates explicit origins when credentials enabled
  - Comprehensive CORS configuration with security warnings

### Fixed
- **Validation Regex Security**: Fixed regex patterns to prevent newline bypass
  - Changed `$` to `\Z` in validation patterns (CONTAINER_NAME_PATTERN, IMAGE_NAME_PATTERN, LABEL_KEY_PATTERN, memory pattern)
  - Previously, inputs like `"0\n"` would incorrectly pass validation due to `$` matching before trailing newline
  - Now strictly matches end of string only, preventing control character injection
- **SSE Wildcard Bind Behavior**: Fixed SSE transport wildcard bind host handling
  - Previously added localhost variants to all non-wildcard binds, creating DNS rebinding vulnerability
  - Now only includes localhost variants when binding to localhost addresses
  - Wildcard binds (0.0.0.0, ::) require explicit `HTTPSTREAM_ALLOWED_HOSTS` configuration
- **Stress Test Reliability**: Fixed flaky stress tests in CI environments
  - Added response checking to `test_httpstream_resumability_1000_events` to catch errors early
  - Periodically check server process health during stress tests
  - Tests now pass consistently (3/3 runs) by properly awaiting responses

### Changed
- **Test Categorization**: Reclassified tests by type (stress vs slow), exclude stress from CI
  - Added `@pytest.mark.stress` marker for stress/performance tests (high resource usage)
  - Stress tests now skip in CI, run locally only (GitHub Actions runners not suitable for stress testing)
  - `@pytest.mark.slow` remains for functional tests that take longer but still run in CI
  - Updated CI to run: `-m "e2e and not stress"` (62 tests, ~66 seconds)
  - Stress tests: 2 tests (`test_httpstream_resumability_1000_events`, `test_httpstream_concurrent_sessions_with_replay`)
- **Code Quality**: Replaced magic numbers and duplicated strings with named constants
  - Event store constants: `EVENT_STORE_MAX_EVENTS_DEFAULT`, `EVENT_STORE_MAX_EVENTS_LIMIT`, `EVENT_STORE_TTL_SECONDS_DEFAULT`, etc.
  - Message constants: `SHUTDOWN_COMPLETE_MSG`, `CONTENT_TYPE_JSON`
  - Improved maintainability and reduced code duplication
- **Transport Neutrality**: Both SSE and HTTP Stream Transport presented as equal options
  - Removed "Recommended" and "Legacy" labels from transport descriptions
  - Both transports fully supported with complete feature parity (OAuth, TLS, rate limiting)
  - Documentation updated to be neutral without preference

### Documentation
- **README.md**: Updated with HTTP Stream Transport usage and configuration
- **SECURITY.md**: Added comprehensive Host Header Injection protection documentation
  - Attack vectors (DNS rebinding, password reset poisoning, cache poisoning, SSRF)
  - Protection mechanisms (TrustedHostMiddleware, fail-secure policy)
  - Behavior by transport type and bind address
  - Example attack scenarios and mitigation strategies
- **CONFIGURATION.md**: Complete environment variable reference (NEW)
  - All configuration options documented with types, defaults, and examples
  - Common scenarios: development, production, Docker Compose
  - Security best practices and troubleshooting
- **CLAUDE.md**: Updated with HTTP Stream Transport architecture and testing patterns

## [1.0.4] - 2025-11-13

### Added
- **OAuth/OIDC Authentication**: Full OAuth 2.0 and OpenID Connect support for network-accessible deployments
  - JWT signature validation with RS256, RS384, RS512, ES256, ES384, ES512 algorithms
  - JWKS (JSON Web Key Set) endpoint integration with automatic key discovery
  - JWKS caching with 15-minute TTL and automatic refresh on key rotation failures
  - Token introspection endpoint support for opaque tokens
  - Issuer (`iss`), audience (`aud`), expiration (`exp`), and not-before (`nbf`) claim validation
  - Required scope enforcement with flexible scope claim detection (OAuth2, Azure AD, custom)
  - Configurable clock skew tolerance for time-based validations
  - IP allowlist enforcement with OAuth for defense-in-depth security
  - Environment variables: `SECURITY_OAUTH_ENABLED`, `SECURITY_OAUTH_ISSUER`, `SECURITY_OAUTH_JWKS_URL`, `SECURITY_OAUTH_AUDIENCE`, `SECURITY_OAUTH_REQUIRED_SCOPES`, `SECURITY_OAUTH_INTROSPECTION_URL`, `SECURITY_OAUTH_CLIENT_ID`, `SECURITY_OAUTH_CLIENT_SECRET`, `SECURITY_OAUTH_CLOCK_SKEW_SECONDS`
  - Example configuration in `examples/.env.oauth`
- **OAuth Security Tests**: Comprehensive test suite covering 18 OAuth security vulnerabilities per RFC 8725
  - Algorithm substitution attacks (`alg: none`, HS256 confusion)
  - Malformed token handling (invalid JWT structure, missing sections, bad base64)
  - Token tampering detection (modified payload without signature change)
  - Claim validation (missing required claims, expired tokens, nbf validation)
  - JWKS endpoint failure scenarios (404, malformed JSON, timeout)
  - Key ID (`kid`) mismatch and rotation handling
  - Audience validation edge cases (multiple audiences, partial matches)
  - DoS prevention (extremely large tokens, short token lifetimes)
  - Empty scope handling
- **ClusterFuzzLite Support for OAuth**: Updated fuzzer configuration
  - Added authlib==1.6.5, httpx==0.28.1 to requirements.txt with SHA256 hashes
  - Upgraded cryptography from 44.0.1 to 46.0.3
  - Added 7 transitive dependencies with hash pinning
  - Updated PyInstaller hidden imports for authlib.jose, httpx, httpcore

### Security
- **CRITICAL: IP Allowlist Bypass with OAuth** (P1, Defense-in-Depth Failure)
  - Fixed: IP allowlist was not enforced when OAuth was enabled
  - Impact: Any attacker with a stolen valid OAuth token could connect from any IP
  - Resolution: Now validates both OAuth token AND IP allowlist when both are configured
  - Prevents lateral movement attacks where tokens are stolen but network access should be restricted
- **RFC 7235/6750 Compliance: Case-Sensitive Bearer Token Parsing** (P2)
  - Fixed: Authorization header only accepted "Bearer" (capital B), rejecting lowercase variants
  - Impact: Clients sending `authorization: bearer <token>` or `AUTHORIZATION: BEARER <token>` received spurious 401 errors
  - Resolution: Now accepts case-insensitive authentication schemes per RFC 7235 §2.1
  - Improves compatibility with HTTP stacks that normalize headers

### Fixed
- **Stdio Transport IP Allowlist Bypass**: Fixed stdio transport incorrectly checking IP allowlist
  - Previously rejected stdio connections when `SECURITY_ALLOWED_CLIENT_IPS` was configured
  - Stdio transport (local connections) now correctly bypasses IP filtering as intended
  - IP allowlist only applies to network transports (SSE over HTTP/HTTPS)
- **OAuth Cognitive Complexity Reduction**: Refactored `authenticate_token()` from complexity 22 to 15
  - Extracted `_build_client_info_from_claims()` helper to eliminate code duplication
  - Extracted `_retry_jwt_with_fresh_jwks()` for JWKS cache refresh flow
  - Extracted `_handle_jwt_failure_with_introspection()` for introspection fallback
  - Improved testability and maintainability
- **SSE Endpoint Cognitive Complexity Reduction**: Refactored `run_sse()` from complexity 25 to 15
  - Extracted 6 helper functions: `_authenticate_sse_request()`, `_send_unauthorized_response()`, `_route_sse_request()`, `_create_sse_handler()`, `_create_security_headers_middleware()`, `_setup_signal_handlers()`
  - Eliminated nested try-except blocks and improved code organization
- **String Literal Duplication**: Replaced 6 occurrences of path literals with constants
  - Added `SSE_PATH = "/sse"` and `MESSAGES_PATH = "/messages"` constants
  - Improved maintainability and reduced SonarCloud code smells

### Changed
- **Authentication System**: Replaced SSH authentication with OAuth/OIDC
  - BREAKING: Removed `SECURITY_AUTH_ENABLED`, `SECURITY_SSH_AUTH_ENABLED`, `SECURITY_SSH_AUTHORIZED_KEYS_FILE`, and `SECURITY_SSH_SIGNATURE_MAX_AGE`
  - BREAKING: Removed `_auth` parameter from tool calls
  - Rationale: No standard MCP clients support custom SSH authentication; OAuth is industry standard
  - Migration: Use OAuth configuration or `SECURITY_ALLOWED_CLIENT_IPS` for access control
  - Removed files: `src/mcp_docker/auth/ssh_*.py`, all SSH auth tests
  - Simplified `AuthMiddleware` - now supports OAuth + IP filtering or IP filtering only
  - Removed `cryptography` from production dependencies (OAuth uses authlib's built-in crypto)
- **Test Coverage**: Added 20 unit tests for SSE authentication helper functions
  - Covers `_authenticate_sse_request()` edge cases (HEAD bypass, non-SSE paths)
  - Tests `_extract_bearer_token()` with various case combinations
  - Tests OAuth + IP allowlist combinations (defense-in-depth)
  - All 1,350+ OAuth-related tests pass

### Documentation
- **OAuth Configuration Guide**: Added comprehensive OAuth setup guide in `examples/.env.oauth`
  - Covers Auth0, Keycloak, Azure AD, and custom OAuth providers
  - Includes JWKS endpoint configuration and troubleshooting
  - Documents required scopes and audience validation
- **README.md**: Updated authentication section with OAuth examples
- **CLAUDE.md**: Updated architecture section with OAuth authenticator details

## [1.0.3] - 2025-11-12

### Added
- **Tool Filtering by Name**: Allow and deny list configuration for fine-grained tool access control
  - `SAFETY_ALLOWED_TOOLS`: Explicitly allow specific tools by name (empty list = allow all based on safety level)
  - `SAFETY_DENIED_TOOLS`: Deny specific tools by name (takes precedence over allow list)
  - Filtering works alongside existing safety level restrictions (SAFE/MODERATE/DESTRUCTIVE)
  - Tools filtered from `list_tools()` to reduce context window usage
  - Defense-in-depth validation at execution time
- **Configurable Output Size Limits**: Prevent resource exhaustion from large responses
  - `SAFETY_MAX_LIST_RESULTS`: Limit number of items in list operations (default: 100)
  - `SAFETY_MAX_LOG_LINES`: Limit log output lines (default: 1000)
  - `SAFETY_MAX_OUTPUT_SIZE`: Limit total output size in bytes (default: 10MB)
  - Automatic truncation with metadata when limits exceeded
  - Clear indication of truncation in responses

### Fixed
- **Container Count Preservation**: `docker_list_containers` now correctly reports total container count even when results are truncated
  - Previously showed truncated count, breaking cleanup loops and pagination
  - Now provides accurate inventory size via `count` field
- **Type Safety**: All 101 files now pass mypy --strict type checking
  - Fixed type assignment issues in output_limits.py
  - Added proper Mock object handling in test suite
  - Improved type annotations throughout codebase

### Changed
- **Code Quality Improvements**
  - Extracted `_is_tool_allowed_by_name_filters()` helper method to eliminate code duplication
  - Added `_should_filter_tool()` method to reduce cyclomatic complexity
  - Improved separation of concerns in tool filtering logic
  - Enhanced test coverage with 15 additional test cases for tool filtering
  - Dynamic test assertions replacing magic numbers

### Documentation
- **README.md**: Added tool filtering configuration section with examples
- **SETUP.md**: Added output size limit configuration guidance
- **CLAUDE.md**: Updated with tool filtering architecture and testing patterns

## [1.0.2] - 2025-11-11

### Security
- **CRITICAL: Command Injection Fix** (CVE-severity: 8.8/10)
  - Fixed command injection bypass when using list-format commands in `docker_exec_command`
  - Added `validate_command_safety()` to check dangerous patterns in ALL command formats (string and list)
  - Previously, list-format commands bypassed safety validation entirely
- **Authentication Timing Attack Fix** (CVE-severity: 6.5/10)
  - Implemented constant-time SSH key verification to prevent timing side-channels
  - SSH authenticator now checks ALL keys before returning result (eliminates early-exit timing leak)
  - Prevents attackers from enumerating key positions through response time analysis
- **Replay Attack Window Reduction** (CVE-severity: 6.8/10)
  - Reduced maximum SSH signature timestamp window from 1 hour to 5 minutes
  - Changed default from 5 minutes to 1 minute for improved security
  - Significantly reduces credential exposure time and replay attack surface
- **Authentication Brute Force Protection** (CVE-severity: 6.5/10)
  - Added authentication rate limiting: 5 failed attempts per 5 minutes per client
  - Prevents brute force attacks on SSH signature verification
  - Rate limit cleared on successful authentication
- **Information Disclosure Fixes**
  - ValueError exceptions now use generic messages instead of exposing internal details
  - Added generic error message: "Invalid input parameter for operation '{operation}'"
  - Prevents leakage of file paths, internal IDs, and system details
- **Enhanced Log Sanitization**
  - Added 14 new sensitive field patterns (access_token, refresh_token, bearer, ssh_key, db_password, etc.)
  - Added regex-based credential detection for URLs with embedded passwords
  - Detects private keys and long base64-encoded tokens
  - Connection strings and credentials now redacted in logs
- **Input Validation & Resource Exhaustion Prevention**
  - Added input length limits: 64KB for commands, 32KB for env vars, 4KB for paths
  - Prevents DoS attacks via memory exhaustion from unbounded inputs
  - Validates command length for both string and list formats
- **TLS & Docker Socket Security Validation**
  - Added validation requiring `tls_ca_cert` when `tls_verify=True`
  - Warns when TLS certificates configured but verification disabled
  - Blocks insecure HTTP Docker sockets (only HTTPS allowed)
  - Warns when Docker socket exposed on network without TLS

### Changed
- **Authentication System Hardened**
  - Removed API key authentication (security decision - SSH-only authentication)
  - Fixed catch-all exception handlers to only catch expected exceptions (KeyError, ValueError)
  - Removed redundant type assertions in favor of proper type narrowing with isinstance checks
  - Fixed circular import in config.py by using warnings module instead of logger
- **Code Quality Improvements**
  - Extracted magic number (100) to named constant `DEFAULT_MAX_LIST_ITEMS`
  - Improved error handling specificity in SSH authentication
  - Enhanced type safety in authentication middleware

### Fixed
- **Test Compatibility**
  - Updated test expectations for sanitized ValueError messages
  - Fixed test for large JSON data sanitization
  - All 631 unit tests passing

### Documentation
- **README.md**: Updated authentication description to reflect SSH-only authentication
- **CLAUDE.md**: Added comprehensive security feature list including all new protections
- **Security configuration examples**: Updated to show SSH authentication setup instead of API keys
- **SETUP.md**: Removed API key references from Remote Connector guidance (lines 236, 272, 413-417)
- **SSH_AUTHENTICATION.md**: Removed API key comparisons and alternative auth examples (lines 7, 223-237, 458-483)
- **SUPPORT.md**: Replaced API key troubleshooting with SSH key troubleshooting (lines 82-84)

### Compliance
- **OWASP Top 10 Coverage**
  - A03:2021 (Injection): Fixed command injection vulnerability ✅
  - A02:2021 (Cryptographic Failures): Fixed timing attack ✅
  - A07:2021 (Auth Failures): Fixed replay attacks and brute force ✅
- **CWE Coverage**
  - CWE-78 (OS Command Injection): Fixed ✅
  - CWE-208 (Observable Timing Discrepancy): Fixed ✅
  - CWE-294 (Authentication Bypass by Capture-Replay): Improved ✅
  - CWE-307 (Improper Restriction of Excessive Authentication Attempts): Fixed ✅
  - CWE-209 (Information Exposure Through Error Message): Fixed ✅
  - CWE-770 (Allocation of Resources Without Limits): Fixed ✅

### Removed
- API key authentication code (`src/mcp_docker/auth/api_key.py`)
- API key authentication tests
- API key references from all documentation
- Legacy SSE startup script (`start_sse_server.sh`) - replaced by `start-mcp-docker-sse.sh` with TLS/HTTPS support

## [1.0.1] - 2025-11-09

### Fixed
- **SSE Server Shutdown**: Fixed server hanging indefinitely on Ctrl+C requiring kill -9
  - Added SIGINT/SIGTERM signal handlers for immediate shutdown detection
  - Implemented 5-second graceful shutdown timeout
  - Added proper CancelledError exception handling following asyncio best practices
  - Server now exits cleanly within 5 seconds with clear log messages
  - Reduced cognitive complexity from 26 to ~8 by extracting helper functions

### Changed
- Refactored `run_sse()` function to reduce cognitive complexity
  - Extracted 5 helper functions for better maintainability and testability
  - Improved code organization and readability

### Added
- Comprehensive test coverage for shutdown functionality (8 new tests, 37 total)
  - Tests for signal handler registration and execution
  - Tests for graceful and forced shutdown scenarios
  - Tests for exception handling during shutdown
  - Overall test coverage maintained at 94%

## [1.0.0] - 2025-11-09

### Added
- PyPI publishing via Trusted Publishers (OIDC authentication)
- SLSA provenance attestations published to PyPI
- CODEOWNERS file requiring owner approval for all changes
- Automatic GitHub issue creation for fuzzing crashes

### Changed
- Version bumped to 1.0.0 (first stable release)
- Development status: Beta → Production/Stable
- Source distribution excludes CI and development files

## [0.4.1] - 2025-11-08

### Security
- **Token Permissions Fix**: Added top-level `permissions: contents: read` to all 11 GitHub Actions workflows
  - Implements principle of least privilege for GITHUB_TOKEN
  - Job-level write permissions remain where needed
  - Fixes OpenSSF Scorecard Token-Permissions check (score: 4 → 10)
  - Affected workflows: ci.yml, codeql.yml, dependency-review.yml, docs.yml, license-compliance.yml, pages.yml, pre-commit.yml, release.yml, scorecard.yml, sonarcloud.yml, stale.yml
- **Signed Releases Enhancement**: Release workflow now uploads SLSA provenance attestation bundles as release assets
  - Downloads attestation bundles using `gh attestation download`
  - Uploads `.intoto.jsonl` files alongside artifacts for offline verification
  - Fixes OpenSSF Scorecard Signed-Releases check (score: 0 → 10)
  - Users can now verify downloads offline with attestation bundles
  - Expected overall Scorecard improvement: 5.9 → ~7.9/10

### Changed
- Updated release workflow summary to document both online (GitHub CLI) and offline (attestation bundle) verification methods

## [0.4.0] - 2025-11-08

### Added
- **Automated Release Workflow**: GitHub Actions workflow for building and signing releases
  - Automatically builds Python wheel and source distribution on release
  - Signs artifacts with GitHub attestations (Sigstore/SLSA compliant)
  - Uploads signed artifacts to GitHub releases
  - Provides verification instructions for users
  - Users can verify downloads: `gh attestation verify <artifact> --owner williajm`

### Security
- **OpenSSF Scorecard Improvements**: Addressed critical security issues (score improved from 5.5 to ~7.5)
  - **Pinned Dependencies**: All 22 GitHub Actions now pinned to commit SHAs (score: 9 → 10)
  - **Token Permissions**: Added explicit minimal permissions to all workflow jobs (score: 0 → 10)
  - **Branch Protection**: Configured comprehensive branch protection for main branch (score: 4 → 10)
    - Require 1 PR approval before merging
    - Dismiss stale reviews on new commits
    - Require conversation resolution
    - Required status checks: Python 3.11-3.14, Integration Tests, Security Scan, CodeQL
    - Require linear history, block force pushes and branch deletion
  - **Code Review**: Enabled required approvals in branch protection (score: 0 → 10)
  - **Signed Releases**: Automated artifact signing with attestations (score: -1/N/A → 10)
- **README Badge Reorganization**: Added OpenSSF Scorecard badge and reorganized badges logically

### Changed
- Moved workflow permissions from workflow-level to job-level for better security isolation
- Most workflow jobs now use `contents: read` only, with write permissions only where necessary

## [0.3.0] - 2025-11-04

### Added
- **SSE Transport Support**: Implemented proper Server-Sent Events (SSE) transport handler
  - GET /sse endpoint for SSE connections
  - POST /messages endpoint for message handling
  - Built-in session management using MCP's connect_sse and handle_post_message
  - Comprehensive logging wrappers for debugging HTTP requests/responses
- **Enhanced Event Tool**: docker_events now supports flexible timestamp parsing
  - Unix timestamps (e.g., "1699456800")
  - ISO format (e.g., "2025-11-04T16:30:00Z")
  - Relative times (e.g., "5m", "1h", "24h", "7d")
- **SSE Startup Script**: New `start_sse_server.sh` convenience script (**Deprecated in v1.0.2**)
  - Enables all Docker operations including destructive ones
  - Pre-configured for SSE transport mode
  - Simplified server startup for development and testing
  - **Note**: Replaced by `start-mcp-docker-sse.sh` with TLS/HTTPS and secure defaults
- **Improved API Key Hashing**: Replaced Python's hash() with SHA-256
  - Deterministic hashes across process restarts
  - Reliable audit log correlation over time
  - Comprehensive test coverage for hash stability

### Changed
- **Reduced Logging Verbosity**: Converted excessive info-level logs to debug-level
  - MCP handler calls (list_tools, call_tool) now at debug level
  - SSE request/response handling now at debug level
  - HTTP body logging now at debug level
  - Maintained info-level for server initialization, startup, and state changes
- **Development Dependencies**: Added httpx and httpx-sse for SSE client testing

### Fixed
- **Container Stats Tool**: Removed unsupported decode parameter from container.stats()
  - Fixed issue where docker_container_stats would fail with stream=False
  - Re-enabled previously skipped integration test
  - Updated test assertions to check actual Docker stats fields

## [0.2.0] - 2025-10-28

### Breaking Changes
- **Removed Docker Compose support**: All Docker Compose wrapper, tools, and validation code have been removed
- **Tool count reduced**: From 48 tools to 36 tools (removed 12 Docker Compose tools)
- Removed `compose_files/` directory and example compose files
- Removed `src/mcp_docker/compose_wrapper/` module
- Removed `src/mcp_docker/tools/compose_tools.py`
- Removed `src/mcp_docker/utils/compose_validation.py`

### Added
- **Read-only mode**: New `SAFETY_ALLOW_MODERATE_OPERATIONS` environment variable to enable read-only mode
  - When set to `false`, blocks all MODERATE operations (create, start, stop, restart, pull, etc.)
  - Allows only SAFE operations (list, inspect, version, logs, stats)
- **Comprehensive read-only mode testing**: Added 12 new integration tests covering read-only mode functionality
- **Enhanced test coverage**: 478 tests passing (up from 467), 95.41% code coverage
- **Better safety validation**: Improved error messages for blocked operations

### Changed
- **StartContainerTool safety level**: Fixed to return `MODERATE` instead of `SAFE`
- **Documentation updates**: All documentation updated to reflect Docker Compose removal
  - Updated tool counts from 48 to 36
  - Removed Docker Compose sections from examples
  - Updated version numbers to 0.2.0

### Removed
- All Docker Compose functionality and related code (~8,000 lines of code removed)
- Redundant documentation files:
  - `SECURITY_IMPLEMENTATION.md` (merged into `SECURITY.md`)
  - `TESTING_SECURITY.md` (content moved to `DEVELOPMENT.md`)
  - `VERSION_TRACKING.md` (outdated)

### Fixed
- Safety level classification for container start operations
- Documentation consistency across all language versions

## [0.1.0] - 2025-10-24

### Added
- Initial release with 48 Docker tools
- Container management (10 tools)
- Image management (9 tools)
- Network management (6 tools)
- Volume management (5 tools)
- System operations (6 tools)
- Docker Compose management (12 tools)
- 3 AI prompts (troubleshoot, optimize, generate_compose)
- 2 resources (container logs, container stats)
- Three-tier safety system (SAFE/MODERATE/DESTRUCTIVE)
- Comprehensive documentation
- 88%+ test coverage
- Support for Python 3.11-3.13
