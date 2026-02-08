# Contributing to Oubliette Shield

Thank you for your interest in contributing to Oubliette Shield! This document provides guidelines for contributing.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/oubliettesecurity/oubliette-shield.git
   cd oubliette-shield
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

3. Install in development mode with test dependencies:
   ```bash
   pip install -e ".[dev,flask]"
   ```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=oubliette_shield --cov-report=term-missing

# Run a specific test file
python -m pytest tests/test_shield.py -v
python -m pytest tests/test_cef_logger.py -v
```

## Code Style

- Follow PEP 8 conventions
- Use type hints where practical
- Keep functions focused and under 50 lines when possible
- Add docstrings for public classes and functions

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure all tests pass: `python -m pytest tests/ -v`
4. Verify the package builds cleanly: `python -m build && python -m twine check dist/*`
5. Update `CHANGELOG.md` with a description of your changes under an `[Unreleased]` section
6. Submit the pull request with a clear description of the changes

## What to Contribute

We welcome contributions in these areas:

- **New detection patterns**: Additional pre-filter rules for emerging attack types
- **LLM provider adapters**: Support for new LLM backends
- **Performance improvements**: Faster pattern matching, reduced memory usage
- **Documentation**: Improved examples, tutorials, and API docs
- **Bug fixes**: Especially false positives/negatives in detection
- **Test coverage**: Additional test cases for edge cases

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
