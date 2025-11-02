# Developer Guide

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- pip or poetry for dependency management

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/vietcgi/devkit.git
cd devkit

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run full test suite
pytest tests/ -v

# Run specific test file
pytest tests/test_integration.py -v

# Run with coverage
pytest tests/ --cov=cli --cov-report=html

# Run performance tests
pytest tests/test_performance.py --benchmark-only

# Run with specific markers
pytest -m "not slow" tests/
```

### Code Quality

```bash
# Type checking (strict mode)
mypy cli/

# Linting
pylint cli/

# Security scanning
bandit -r cli/

# Code formatting
black cli/

# Import sorting
isort cli/

# Complexity analysis
radon cc cli/ -a
radon mi cli/ -n C
```

### Pre-commit Hooks

All changes are validated automatically:

```bash
# Run all pre-commit hooks
pre-commit run --all-files

# Run specific hook
pre-commit run mypy --all-files
```

## Project Structure

```
devkit/
├── cli/                          # Source code
│   ├── config_engine.py         # Configuration management
│   ├── plugin_system.py         # Plugin framework
│   ├── plugin_validator.py      # Plugin validation
│   ├── git_config_manager.py    # Git integration
│   ├── health_check.py          # Health monitoring
│   ├── performance.py           # Performance optimization
│   ├── log.py                   # Logging utilities
│   └── ...
├── tests/                        # Test suite (747 tests)
│   ├── test_integration.py      # Integration tests (14)
│   ├── test_performance.py      # Performance tests
│   ├── test_plugin_system.py    # Plugin tests
│   └── ...
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md          # System architecture
│   ├── API_DOCUMENTATION.md     # API reference
│   └── DEVELOPER_GUIDE.md       # This file
├── .github/
│   └── workflows/               # CI/CD pipelines
├── pyproject.toml              # Project configuration
├── pytest.ini                  # Test configuration
└── pre-commit-config.yaml      # Pre-commit hooks

```

## Writing Tests

### Test Structure

Tests are organized by component:

```python
"""Unit tests for my_component.

Tests:
- Component initialization
- Core functionality
- Error handling
- Edge cases
"""

import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

class TestMyComponent(unittest.TestCase):
    """Test my_component module."""

    def setUp(self):
        """Set up test fixtures."""
        # Initialize test data

    def tearDown(self):
        """Clean up after tests."""
        # Clean up resources

    def test_happy_path(self):
        """Test normal operation."""
        # Arrange
        component = MyComponent()

        # Act
        result = component.do_something()

        # Assert
        self.assertEqual(result, expected)
```

### Test Categories

1. **Unit Tests** - Test individual functions

   ```python
   def test_validate_config_valid():
       """Test validation with valid input."""
       result = validate_config(valid_config)
       assert result is True
   ```

2. **Integration Tests** - Test component interactions

   ```python
   def test_plugin_discovery_and_loading():
       """Test plugin discovery workflow."""
       loader.add_plugin_path(plugins_dir)
       discovered = loader.discover_plugins()
       assert len(discovered) > 0
   ```

3. **Performance Tests** - Test with benchmarks

   ```python
   def test_config_load_performance(benchmark):
       """Benchmark config loading."""
       result = benchmark(engine.load_file, config_path)
       assert result is not None
   ```

### Mocking External Dependencies

```python
from unittest.mock import patch, MagicMock

@patch('cli.git_config_manager.subprocess.run')
def test_git_operation(mock_subprocess):
    """Test git operation with mocked subprocess."""
    mock_subprocess.return_value = MagicMock(returncode=0)

    manager = GitConfigManager(Path("."))
    result = manager.get_current_branch()

    mock_subprocess.assert_called_once()
```

## Writing Plugins

### Plugin Template

Create a plugin directory structure:

```
my_plugin/
├── manifest.json
├── __init__.py
└── roles/
    └── my_role/
```

### manifest.json

```json
{
    "name": "my_plugin",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Description of your plugin",
    "permissions": ["system", "filesystem"],
    "requires": {
        "devkit": ">=3.0.0"
    }
}
```

### **init**.py

```python
"""My custom plugin."""

from cli.plugin_system import PluginInterface, HookInterface, HookContext
from pathlib import Path

class MyPreSetupHook(HookInterface):
    """Hook executed before setup."""

    def execute(self, context: HookContext) -> bool:
        """Execute pre-setup hook."""
        print(f"Pre-setup for role: {context.role}")
        return True

class Plugin(PluginInterface):
    """My custom plugin implementation."""

    name = "my_plugin"
    version = "1.0.0"
    description = "My custom plugin"

    def initialize(self) -> None:
        """Initialize plugin."""
        print("Plugin initialized")

    def get_roles(self) -> dict[str, Path]:
        """Provide custom roles."""
        roles_dir = Path(__file__).parent / "roles"
        return {
            "my_role": roles_dir / "my_role"
        }

    def get_hooks(self) -> dict[str, list[HookInterface]]:
        """Register hooks for lifecycle events."""
        return {
            "pre_setup": [MyPreSetupHook()],
        }

    def validate(self) -> tuple[bool, list[str]]:
        """Validate plugin configuration."""
        # Add validation logic
        return True, []
```

## Code Style Guide

### Python Style

Follow PEP 8 with these guidelines:

```python
# Imports - organize in groups
import sys
from pathlib import Path
from typing import Any, ClassVar

# Constants - UPPER_CASE
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Type hints - always use them
def process_data(data: dict[str, Any]) -> bool:
    """Process data and return result.

    Args:
        data: Input data dictionary

    Returns:
        Success status
    """
    pass

# Class structure
class MyComponent:
    """Docstring using Google style."""

    class_var: ClassVar[int] = 10

    def __init__(self, param: str) -> None:
        """Initialize component."""
        self.param = param

    def public_method(self) -> None:
        """Public method."""
        self._private_method()

    def _private_method(self) -> None:
        """Private method (single underscore)."""
        pass
```

### Documentation

Use Google-style docstrings:

```python
def complex_function(param1: str, param2: int) -> bool:
    """Brief description of function.

    Longer description explaining what the function does
    and any important implementation details.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When parameter is invalid
        TypeError: When parameter is wrong type

    Example:
        >>> result = complex_function("test", 42)
        >>> print(result)
        True
    """
    pass
```

### Type Hints

```python
# Basic types
name: str = "test"
count: int = 10
active: bool = True
data: list[str] = []
mapping: dict[str, int] = {}

# Union types
value: int | str = 42

# Optional types
optional_value: str | None = None

# Function types
from typing import Callable
callback: Callable[[int], str] = lambda x: str(x)

# Generic types
from typing import TypeVar
T = TypeVar('T')
def process(items: list[T]) -> list[T]:
    pass
```

## Contributing Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

```bash
# Edit files
vim cli/my_component.py

# Add tests
vim tests/test_my_component.py

# Run tests
pytest tests/test_my_component.py -v
```

### 3. Code Quality

```bash
# Format code
black cli/ tests/

# Sort imports
isort cli/ tests/

# Type check
mypy cli/

# Lint
pylint cli/

# Run pre-commit
pre-commit run --all-files
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add my new feature"
```

Follow commit message format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Test improvements
- `chore:` Maintenance

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Create pull request on GitHub with:

- Clear title describing change
- Description of changes
- Link to related issues
- Test coverage details

## Performance Optimization

### Profiling

```python
import cProfile
import pstats

# Profile code
profiler = cProfile.Profile()
profiler.enable()

# ... code to profile ...

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 functions
```

### Benchmarking

```bash
# Run performance tests
pytest tests/test_performance.py --benchmark-only

# Compare benchmarks
pytest tests/test_performance.py --benchmark-compare
```

## Debugging

### Using Python Debugger

```python
import pdb

def buggy_function():
    x = 10
    pdb.set_trace()  # Debugger stops here
    y = x / 0  # Bug here
```

### Logging for Debugging

```python
import logging

logger = logging.getLogger(__name__)

# Different log levels
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
logger.critical("Critical message")
```

## Common Issues

### Issue: Pre-commit hooks fail

**Solution:**

```bash
# Run hooks and auto-fix
pre-commit run --all-files

# Or run specific tool
black cli/
```

### Issue: Tests fail locally but pass in CI

**Solution:**

- Ensure same Python version (3.13)
- Clear pytest cache: `pytest --cache-clear`
- Check environment variables

### Issue: Slow test execution

**Solution:**

```bash
# Run tests in parallel
pytest tests/ -n auto

# Run only changed tests
pytest --lf  # Last failed
pytest --ff  # Failed first
```

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG
3. Create release commit
4. Tag release: `git tag v3.1.0`
5. Push: `git push && git push --tags`
6. GitHub Actions builds and publishes to PyPI

## Resources

- [Architecture Documentation](ARCHITECTURE.md)
- [API Documentation](API_DOCUMENTATION.md)
- [Performance Report](PERFORMANCE_REPORT.md)
- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [Pytest Documentation](https://docs.pytest.org/)
- [Type Hints Documentation](https://docs.python.org/3/library/typing.html)
