"""
Pytest configuration and shared fixtures for Devkit test suite.

Provides:
- Temporary directories for testing
- Logging configuration
- Test markers
- Shared test utilities
"""

import logging
import tempfile
from pathlib import Path
from typing import Generator

import pytest


# Configure logging for tests
@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    """Configure logging for test session."""
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")


# Temporary directories
@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_config_dir(temp_dir) -> Path:
    """Provide a temporary config directory."""
    config_dir = temp_dir / "config"
    config_dir.mkdir(parents=True)
    return config_dir


@pytest.fixture
def temp_cache_dir(temp_dir) -> Path:
    """Provide a temporary cache directory."""
    cache_dir = temp_dir / "cache"
    cache_dir.mkdir(parents=True)
    return cache_dir


@pytest.fixture
def temp_audit_dir(temp_dir) -> Path:
    """Provide a temporary audit log directory."""
    audit_dir = temp_dir / "audit"
    audit_dir.mkdir(parents=True)
    return audit_dir


@pytest.fixture
def temp_log_dir(temp_dir) -> Path:
    """Provide a temporary log directory."""
    log_dir = temp_dir / "logs"
    log_dir.mkdir(parents=True)
    return log_dir


# Config file fixtures
@pytest.fixture
def sample_config_file(temp_config_dir) -> Path:
    """Create a sample configuration file for testing."""
    config_file = temp_config_dir / "config.yaml"
    config_file.write_text(
        """
global:
  setup_name: "Test Setup"
  setup_environment: development

  enabled_roles:
    - core
    - shell
    - development

  disabled_roles: []

  logging:
    enabled: true
    level: info
    logfile: ~/.devkit/logs/setup.log

  security:
    enable_ssh_setup: false
    enable_gpg_setup: false
    enable_audit_logging: true
"""
    )
    config_file.chmod(0o600)
    return config_file


@pytest.fixture
def invalid_yaml_file(temp_config_dir) -> Path:
    """Create an invalid YAML file for testing."""
    invalid_file = temp_config_dir / "invalid.yaml"
    invalid_file.write_text(
        """
global:
  invalid yaml: [
  unclosed: list
"""
    )
    return invalid_file


# Markers
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "edge_case: mark test as testing edge cases")
    config.addinivalue_line("markers", "security: mark test as security-focused")
    config.addinivalue_line("markers", "performance: mark test as performance test")


# Test utilities
@pytest.fixture
def create_file():
    """Factory fixture to create files with specific content."""

    def _create(path: Path, content: str = "", mode: int = 0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    return _create


@pytest.fixture
def create_dir():
    """Factory fixture to create directories with specific permissions."""

    def _create(path: Path, mode: int = 0o755):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
        return path

    return _create


# Parametrize helpers
@pytest.fixture(params=[0o644, 0o755])
def file_permission_modes(request):
    """Parametrize over common file permission modes."""
    return request.param


@pytest.fixture(params=["healthy", "warning", "critical", "unknown"])
def health_status(request):
    """Parametrize over health check statuses."""
    return request.param


# Cleanup helpers
@pytest.fixture(autouse=True)
def cleanup_after_test(temp_dir):
    """Automatically clean up temporary files after each test."""
    yield
    # Cleanup is handled by temp_dir context manager


# Performance helpers
@pytest.fixture
def timer():
    """Provide a simple timer for performance testing."""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        @property
        def elapsed(self):
            if self.start_time is None or self.end_time is None:
                return None
            return self.end_time - self.start_time

    return Timer()
