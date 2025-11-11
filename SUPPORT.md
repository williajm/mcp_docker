# Support

Thank you for using MCP Docker! This document provides guidance on how to get help.

## Documentation

Before seeking help, please check our documentation:

- **[README](README.md)** - Quick start, installation, and usage overview
- **[Full Documentation](https://williajm.github.io/mcp_docker/)** - Comprehensive guides and examples
- **[API Documentation](https://williajm.github.io/mcp_docker/)** - Complete tool reference
- **[Security Guide](SECURITY.md)** - Security features and configuration
- **[Contributing Guide](CONTRIBUTING.md)** - Development setup and guidelines

## Getting Help

### Questions and Discussions

For general questions, usage help, and discussions:

- **[GitHub Discussions](https://github.com/williajm/mcp_docker/discussions)** - Ask questions, share ideas, and engage with the community
- **[Issue Tracker](https://github.com/williajm/mcp_docker/issues)** - Search existing issues for similar problems

### Reporting Bugs

If you've found a bug:

1. **Search existing issues** to see if it's already reported
2. **Use the bug report template** when opening a new issue
3. **Provide complete information**:
   - MCP Docker version
   - Python version
   - Docker version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

[Report a Bug](https://github.com/williajm/mcp_docker/issues/new?template=bug_report.yml)

### Feature Requests

To suggest a new feature or enhancement:

1. **Check existing feature requests** to avoid duplicates
2. **Use the feature request template**
3. **Describe your use case** and why the feature would be valuable

[Request a Feature](https://github.com/williajm/mcp_docker/issues/new?template=feature_request.yml)

### Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.**

For security issues:

1. **Use GitHub Private Vulnerability Reporting**: Go to the [Security tab](https://github.com/williajm/mcp_docker/security/advisories) and click "Report a vulnerability"
2. **Or email the maintainers** directly (if private reporting is not available)
3. **See [SECURITY.md](SECURITY.md)** for detailed security reporting guidelines

We take security seriously and will respond promptly to security reports.

## Common Issues

### Installation Problems

**Issue**: `uv sync` fails with dependency conflicts
- **Solution**: Ensure you're using Python 3.11+ and have the latest version of uv

**Issue**: Docker connection errors
- **Solution**: Verify Docker daemon is running (`docker ps`) and check `DOCKER_BASE_URL` configuration

### Configuration Issues

**Issue**: Tools are blocked (MODERATE or DESTRUCTIVE operations)
- **Solution**: Check your safety configuration in environment variables:
  ```bash
  SAFETY_ALLOW_MODERATE_OPERATIONS=true
  SAFETY_ALLOW_DESTRUCTIVE_OPERATIONS=true  # Use with caution
  ```

**Issue**: SSH authentication failures
- **Solution**: Verify SSH key configuration:
  - Check public key is in `~/.ssh/mcp_authorized_keys`
  - Verify `SECURITY_SSH_AUTH_ENABLED=true` is set
  - Confirm `SECURITY_SSH_AUTHORIZED_KEYS_FILE` points to correct file
  - Check signature timestamp is recent (within 5 minutes by default)
  - Ensure nonce is unique for each request (no replay)
  - See [SSH_AUTHENTICATION.md](docs/SSH_AUTHENTICATION.md) for details

### Runtime Problems

**Issue**: Rate limiting errors
- **Solution**: Adjust rate limit settings or disable rate limiting (not recommended for production)

**Issue**: Tools not appearing in Claude Desktop
- **Solution**: Check MCP server is running, verify configuration in Claude Desktop settings

## Response Times

This is an open-source project maintained by volunteers. Response times may vary:

- **Critical security issues**: We aim to respond within 24-48 hours
- **Bug reports**: Typically reviewed within 1-2 weeks
- **Feature requests**: Reviewed and triaged as time permits
- **Questions**: Community members usually respond within a few days

## Community Guidelines

When seeking support:

- **Be respectful** to maintainers and community members
- **Provide complete information** to help us help you
- **Search first** before opening new issues
- **Follow up** on your issues with additional information if requested
- **Consider contributing** fixes or improvements if you're able

See our [Code of Conduct](CODE_OF_CONDUCT.md) for community expectations.

## Contributing

If you've resolved your issue and think others might face the same problem:

- **Improve documentation** with a pull request
- **Share your solution** in GitHub Discussions
- **Contribute bug fixes** or new features

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Commercial Support

For commercial support, consulting, or custom development:

- Contact the project maintainers through GitHub
- Check if any contributors offer commercial services

## Additional Resources

- **PyPI Package**: https://pypi.org/project/mcp-docker/
- **Source Code**: https://github.com/williajm/mcp_docker
- **Changelog**: https://github.com/williajm/mcp_docker/releases
- **License**: MIT License (see [LICENSE](LICENSE))

Thank you for using MCP Docker!
