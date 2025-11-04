# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **SSE Startup Script**: New `start_sse_server.sh` convenience script
  - Enables all Docker operations including destructive ones
  - Pre-configured for SSE transport mode
  - Simplified server startup for development and testing
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
