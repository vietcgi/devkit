"""
Tests for enhanced error messages and exception handling.

Validates that custom exceptions provide:
- Clear, user-friendly error messages
- Root cause explanations
- Actionable recovery suggestions
- Documentation references
"""

import sys
import unittest
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.exceptions import (  # noqa: E402
    BootstrapError,
    ConfigError,
    DependencyError,
    DevkitError,
    PluginError,
    SecurityError,
    VerificationError,
)


@pytest.mark.unit
class TestDevkitError(unittest.TestCase):
    """Test base DevkitError class."""

    def test_exception_creation_with_all_fields(self):
        """Test creating exception with all fields."""
        exc = DevkitError(
            message="Test error",
            cause="Root cause",
            solutions=["Solution 1", "Solution 2"],
            documentation="See docs",
        )

        self.assertEqual(exc.message, "Test error")
        self.assertEqual(exc.cause, "Root cause")
        self.assertEqual(exc.solutions, ["Solution 1", "Solution 2"])
        self.assertEqual(exc.documentation, "See docs")

    def test_exception_with_minimal_fields(self):
        """Test creating exception with minimal fields."""
        exc = DevkitError(message="Test error")

        self.assertEqual(exc.message, "Test error")
        self.assertIsNone(exc.cause)
        self.assertEqual(exc.solutions, [])
        self.assertIsNone(exc.documentation)

    def test_formatted_message_includes_all_parts(self):
        """Test formatted message includes all information."""
        exc = DevkitError(
            message="Test error",
            cause="Root cause explanation",
            solutions=["Fix 1", "Fix 2"],
            documentation="See DOCS.md",
        )

        formatted = exc.format_message()

        # Check all parts are present
        self.assertIn("❌ Test error", formatted)
        self.assertIn("📋 Cause:", formatted)
        self.assertIn("Root cause explanation", formatted)
        self.assertIn("💡 How to fix:", formatted)
        self.assertIn("1. Fix 1", formatted)
        self.assertIn("2. Fix 2", formatted)
        self.assertIn("📖 See:", formatted)
        self.assertIn("See DOCS.md", formatted)

    def test_str_representation_shows_formatted_message(self):
        """Test string representation shows formatted message."""
        exc = DevkitError(message="Test error", cause="Reason")
        exc_str = str(exc)

        self.assertIn("Test error", exc_str)
        self.assertIn("Reason", exc_str)


@pytest.mark.unit
class TestBootstrapError(unittest.TestCase):
    """Test BootstrapError and its static factory methods."""

    def test_integrity_check_failed_error(self):
        """Test integrity check failure exception."""
        exc = BootstrapError.integrity_check_failed()

        self.assertIn("integrity check failed", exc.message.lower())
        self.assertIsNotNone(exc.cause)
        self.assertTrue(len(exc.solutions) > 0)
        self.assertIsNotNone(exc.documentation)

    def test_network_error(self):
        """Test network error exception."""
        exc = BootstrapError.network_error("Connection timeout")

        self.assertIn("download", exc.message.lower())
        self.assertIn("Connection timeout", exc.cause)
        self.assertTrue(len(exc.solutions) > 0)

    def test_permission_denied_error(self):
        """Test permission denied exception."""
        exc = BootstrapError.permission_denied()

        self.assertIn("permission", exc.message.lower())
        self.assertTrue(any("chmod" in sol for sol in exc.solutions))
        self.assertTrue(any("bash" in sol for sol in exc.solutions))

    def test_insufficient_space_error(self):
        """Test insufficient disk space exception."""
        exc = BootstrapError.insufficient_space()

        self.assertIn("disk space", exc.message.lower())
        self.assertTrue(any("df -h" in sol for sol in exc.solutions))
        self.assertTrue(any("cleanup" in sol for sol in exc.solutions))


@pytest.mark.unit
class TestConfigError(unittest.TestCase):
    """Test ConfigError and its static factory methods."""

    def test_missing_config_error(self):
        """Test missing configuration exception."""
        exc = ConfigError.missing_config()

        self.assertIn("configuration file not found", exc.message.lower())
        self.assertTrue(any("mkdir" in sol for sol in exc.solutions))
        self.assertTrue(any("bootstrap" in sol for sol in exc.solutions))

    def test_invalid_yaml_error(self):
        """Test invalid YAML exception."""
        exc = ConfigError.invalid_yaml("Missing colon at line 5")

        self.assertIn("yaml syntax", exc.message.lower())
        self.assertIn("Missing colon", exc.cause)
        self.assertTrue(any("yamllint" in sol for sol in exc.solutions))
        self.assertTrue(any("indentation" in sol for sol in exc.solutions))

    def test_permission_denied_config_error(self):
        """Test config permission denied exception."""
        exc = ConfigError.permission_denied("~/.devkit/config.yaml")

        self.assertIn("permission", exc.message.lower())
        self.assertIn("~/.devkit/config.yaml", exc.message)
        self.assertTrue(any("chmod 600" in sol for sol in exc.solutions))

    def test_invalid_ownership_error(self):
        """Test invalid ownership exception."""
        exc = ConfigError.invalid_ownership("~/.devkit/config.yaml", "root")

        self.assertIn("wrong user", exc.message.lower())
        self.assertIn("root", exc.message)
        self.assertTrue(any("chown" in sol for sol in exc.solutions))


@pytest.mark.unit
class TestPluginError(unittest.TestCase):
    """Test PluginError and its static factory methods."""

    def test_validation_failed_error(self):
        """Test plugin validation failure exception."""
        exc = PluginError.validation_failed("my-plugin", "Missing manifest.json")

        self.assertIn("validation failed", exc.message.lower())
        self.assertIn("my-plugin", exc.message)
        self.assertIn("Missing manifest.json", exc.cause)
        self.assertTrue(len(exc.solutions) > 0)

    def test_missing_manifest_error(self):
        """Test missing manifest exception."""
        exc = PluginError.missing_manifest("my-plugin")

        self.assertIn("manifest not found", exc.message.lower())
        self.assertIn("my-plugin", exc.message)
        self.assertTrue(any("manifest.json" in sol for sol in exc.solutions))

    def test_invalid_version_error(self):
        """Test invalid version exception."""
        exc = PluginError.invalid_version("1.0")

        self.assertIn("version invalid", exc.message.lower())
        self.assertIn("1.0", exc.message)
        self.assertTrue(any("MAJOR.MINOR.PATCH" in sol for sol in exc.solutions))

    def test_missing_class_error(self):
        """Test missing plugin class exception."""
        exc = PluginError.missing_class("my-plugin")

        self.assertIn("class not found", exc.message.lower())
        self.assertIn("my-plugin", exc.message)
        self.assertTrue(any("PluginInterface" in sol for sol in exc.solutions))
        self.assertTrue(any("__init__.py" in sol for sol in exc.solutions))


@pytest.mark.unit
class TestSecurityError(unittest.TestCase):
    """Test SecurityError and its static factory methods."""

    def test_checksum_mismatch_error(self):
        """Test checksum mismatch exception."""
        exc = SecurityError.checksum_mismatch("abc123", "def456")

        self.assertIn("checksum", exc.message.lower())
        self.assertIn("verification failed", exc.message.lower())
        self.assertTrue(len(exc.solutions) > 0)

    def test_insecure_permissions_error(self):
        """Test insecure permissions exception."""
        exc = SecurityError.insecure_permissions("~/.devkit/secret.key", "0644", "0600")

        self.assertIn("insecure permissions", exc.message.lower())
        self.assertIn("~/.devkit/secret.key", exc.message)
        self.assertIn("0644", exc.cause)
        self.assertIn("0600", exc.cause)
        self.assertTrue(any("chmod" in sol for sol in exc.solutions))


@pytest.mark.unit
class TestDependencyError(unittest.TestCase):
    """Test DependencyError and its static factory methods."""

    def test_tool_not_found_error(self):
        """Test tool not found exception."""
        exc = DependencyError.tool_not_found("ansible", "brew install ansible")

        self.assertIn("tool not found", exc.message.lower())
        self.assertIn("ansible", exc.message)
        self.assertTrue(any("brew install" in sol for sol in exc.solutions))
        self.assertTrue(any("which" in sol for sol in exc.solutions))

    def test_version_incompatible_error(self):
        """Test version incompatibility exception."""
        exc = DependencyError.version_incompatible("python3", "3.9+", "3.8.2")

        self.assertIn("version incompatible", exc.message.lower())
        self.assertIn("python3", exc.message)
        self.assertIn("3.9+", exc.cause)
        self.assertIn("3.8.2", exc.cause)
        self.assertTrue(any("upgrade" in sol.lower() for sol in exc.solutions))


@pytest.mark.unit
class TestVerificationError(unittest.TestCase):
    """Test VerificationError and its static factory methods."""

    def test_some_tools_missing_error(self):
        """Test some tools missing exception."""
        missing = ["ansible", "docker", "git"]
        exc = VerificationError.some_tools_missing(missing)

        self.assertIn("setup verification failed", exc.message.lower())
        self.assertIn("3 tool", exc.message)
        self.assertTrue(all(tool in exc.cause for tool in missing))
        self.assertTrue(any("brew install" in sol for sol in exc.solutions))

    def test_setup_incomplete_error(self):
        """Test setup incomplete exception."""
        exc = VerificationError.setup_incomplete("Config file is corrupted")

        self.assertIn("incomplete", exc.message.lower())
        self.assertIn("Config file is corrupted", exc.cause)
        self.assertTrue(any("bootstrap" in sol.lower() for sol in exc.solutions))
        self.assertTrue(any("logs" in sol.lower() for sol in exc.solutions))


@pytest.mark.unit
class TestErrorMessageFormatting(unittest.TestCase):
    """Test that error messages are properly formatted and helpful."""

    def test_error_message_uses_emojis(self):
        """Test that error messages include helpful emoji indicators."""
        exc = BootstrapError.integrity_check_failed()
        formatted = exc.format_message()

        # Check for emoji presence
        self.assertIn("❌", formatted)  # Error emoji
        self.assertIn("📋", formatted)  # Cause emoji
        self.assertIn("💡", formatted)  # Suggestion emoji
        self.assertIn("📖", formatted)  # Documentation emoji

    def test_solutions_are_numbered(self):
        """Test that solutions are properly numbered."""
        exc = ConfigError.missing_config()
        formatted = exc.format_message()

        # Check solutions are numbered
        self.assertIn("1.", formatted)
        self.assertIn("2.", formatted)

    def test_multiline_error_formatting(self):
        """Test that multi-line errors are properly formatted."""
        exc = DevkitError(
            message="Complex error",
            cause="Multiple reasons",
            solutions=["First solution", "Second solution", "Third solution"],
        )
        formatted = exc.format_message()

        lines = formatted.split("\n")
        # Should have multiple lines (message + cause + solutions + docs)
        self.assertGreater(len(lines), 5)


if __name__ == "__main__":
    unittest.main()
