# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
