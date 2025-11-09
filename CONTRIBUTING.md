# Contributing to MCP Docker

Thank you for your interest in contributing to MCP Docker! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Docker daemon running (for integration/E2E tests)
- [uv](https://github.com/astral-sh/uv) package manager

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp_docker.git
   cd mcp_docker
   ```

2. Install dependencies:
   ```bash
   uv sync --all-extras
   ```

3. Verify your setup:
   ```bash
   # Run unit tests (fast, no Docker required)
   uv run pytest tests/unit/ -v

   # Run integration tests (requires Docker)
   uv run pytest tests/integration/ -v
   ```

## Development Workflow

### Running Tests

```bash
# All tests with coverage
uv run pytest --cov=mcp_docker --cov-report=html --cov-report=term

# Unit tests only (fast)
uv run pytest tests/unit/ -v

# Integration tests only
uv run pytest tests/integration/ -v -m integration

# Specific test file
uv run pytest tests/unit/test_validation.py -v
```

### Code Quality

Before submitting a PR, ensure your code passes all quality checks:

```bash
# Linting
uv run ruff check src tests

# Auto-fix linting issues
uv run ruff check --fix src tests

# Format code
uv run ruff format src tests

# Type checking
uv run mypy src tests
```

### Pre-commit Hooks

We use pre-commit hooks to ensure code quality. The CI will run these checks, but you can run them locally:

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feat/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test improvements

### Commit Messages

Follow conventional commit format:
- `feat: Add new Docker tool for X`
- `fix: Resolve issue with Y`
- `docs: Update README with Z`
- `test: Add tests for W`
- `refactor: Simplify V logic`
- `chore: Update dependencies`

### Code Standards

1. **Type Hints**: All functions must have complete type hints
2. **Docstrings**: Use Google-style docstrings with Args, Returns, Raises
3. **Testing**: Write tests for new features and bug fixes
4. **Error Handling**: Use domain-specific exceptions from `mcp_docker.utils.errors`
5. **Async-First**: Tool `execute()` methods should be async
6. **Pydantic Models**: Use Pydantic for all input/output validation

### Adding New Tools

To add a new Docker tool:

1. Create your tool class in the appropriate module under `src/mcp_docker/tools/`
2. Inherit from `BaseTool` and implement required properties
3. Create a Pydantic input model with field validators
4. Implement the `execute()` method
5. Write unit tests in `tests/unit/tools/`
6. Write integration tests in `tests/integration/tools/`
7. Update documentation if needed

Example:
```python
from pydantic import BaseModel, Field
from mcp_docker.tools.base import BaseTool, OperationSafety, ToolResult

class YourToolInput(BaseModel):
    """Input validation model."""
    container_id: str = Field(description="Container ID or name")

class YourTool(BaseTool):
    """Tool description."""

    @property
    def name(self) -> str:
        return "docker_your_tool"

    @property
    def description(self) -> str:
        return "Brief description"

    @property
    def input_model(self) -> type[YourToolInput]:
        return YourToolInput

    @property
    def safety_level(self) -> OperationSafety:
        return OperationSafety.MODERATE

    async def execute(self, input_data: YourToolInput) -> ToolResult:
        """Execute the tool operation."""
        # Implementation
```

## Pull Request Process

1. **Update Tests**: Ensure all tests pass and add new tests for your changes
2. **Update Documentation**: Update README, docstrings, and docs/ as needed
3. **Run Quality Checks**: Ensure ruff, mypy, and pytest all pass
4. **Create PR**: Use the pull request template and fill out all sections
5. **Code Review**: Address any feedback from reviewers
6. **Approval**: PRs require approval from a code owner before merging

### PR Checklist

- [ ] Tests pass (`pytest`)
- [ ] Linting passes (`ruff check`)
- [ ] Type checking passes (`mypy`)
- [ ] Code is formatted (`ruff format`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (for significant changes)
- [ ] Commit messages follow conventional format

## Testing Guidelines

### Test Coverage

- Aim for 85%+ coverage overall
- 100% coverage for critical paths (auth, safety checks)
- Unit tests for business logic
- Integration tests for Docker operations
- E2E tests for critical workflows

### Writing Tests

```python
# Unit test example
def test_validate_container_name():
    """Test container name validation."""
    assert validate_container_name("valid-name")
    assert not validate_container_name("Invalid@Name")

# Integration test example (requires Docker)
@pytest.mark.integration
async def test_list_containers_integration():
    """Test listing containers with real Docker."""
    # Test implementation
```

## Documentation

- **README.md**: User-facing documentation
- **docs/**: Detailed guides and examples
- **CLAUDE.md**: Instructions for Claude Code
- **Docstrings**: Inline code documentation

## Security

### Reporting Security Issues

**Do not** open public GitHub issues for security vulnerabilities. Instead:

1. Use GitHub's [Private Vulnerability Reporting](https://github.com/williajm/mcp_docker/security/advisories)
2. Or email the maintainers directly
3. See [SECURITY.md](SECURITY.md) for details

### Security Best Practices

- Never commit API keys, credentials, or secrets
- Validate all inputs using Pydantic models
- Sanitize commands before execution
- Follow principle of least privilege
- Add security tests for new features

## Questions?

- Check the [Documentation](https://williajm.github.io/mcp_docker/)
- Search [existing issues](https://github.com/williajm/mcp_docker/issues)
- Open a [question issue](https://github.com/williajm/mcp_docker/issues/new/choose)
- See [SUPPORT.md](SUPPORT.md) for more help options

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors are recognized in the project's release notes and GitHub contributors page. Thank you for making MCP Docker better!
