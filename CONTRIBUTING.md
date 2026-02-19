# Contributing to yubikey-init

Thank you for your interest in contributing to yubikey-init.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) package manager
- GnuPG 2.2 or higher (for integration tests)
- YubiKey Manager 5.0 or higher (for integration tests)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/lclose/yubikey-init
cd yubikey-init

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest tests/unit -v
```

## Code Quality

This project maintains high code quality standards:

- **Type Safety**: All code must pass `mypy --strict`
- **Linting**: All code must pass `ruff check`
- **Formatting**: Code is formatted with `ruff format`
- **Coverage**: Minimum 90% test coverage required

### Running Quality Checks

```bash
# Type checking
uv run mypy src/yubikey_init --strict

# Linting
uv run ruff check src/ tests/

# Formatting
uv run ruff format src/ tests/

# All tests with coverage
uv run pytest tests/ --cov=yubikey_init --cov-report=term-missing
```

## Testing

### Test Categories

- **Unit tests** (`tests/unit/`): Fast, no external dependencies
- **Integration tests** (`tests/integration/`): Require GPG installed
- **Hardware tests** (`tests/hardware/`): Require physical YubiKey
- **E2E tests** (`tests/e2e/`): Full workflow tests

### Running Tests

```bash
# Unit tests only (fast, recommended during development)
uv run pytest tests/unit -v

# Unit and integration tests
uv run pytest tests/unit tests/integration -v

# All tests except hardware
uv run pytest tests/unit tests/integration tests/e2e -v

# Hardware tests (requires YubiKey)
uv run pytest tests/hardware -v
```

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Write tests**: Add tests for new functionality
3. **Update documentation**: Update relevant documentation
4. **Run quality checks**: Ensure all checks pass locally
5. **Create PR**: Submit a pull request with a clear description

### PR Guidelines

- Keep changes focused and atomic
- Write clear commit messages
- Reference any related issues
- Ensure CI passes before requesting review

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) conventions
- Use type hints for all function signatures
- Write docstrings for public functions and classes
- Keep functions focused and small
- Prefer explicit over implicit

## Architecture Guidelines

- **State Machine**: All workflow changes go through the state machine
- **Result Types**: Use `Result[T, E]` for operations that can fail
- **No Secrets Stored**: Never persist sensitive data
- **Explicit Confirmation**: Require confirmation for destructive operations

## Reporting Issues

When reporting issues, please include:

- Python version (`python --version`)
- Operating system and version
- GnuPG version (`gpg --version`)
- YubiKey Manager version (`ykman --version`)
- Steps to reproduce
- Expected vs actual behavior
- Any error messages or logs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
