#!/usr/bin/env python3
"""
Plugin System Security Tests

Tests for plugin validation, manifest validation, and secure loading.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "cli"))

from plugin_validator import PluginManifest, PluginValidator, validate_plugin_manifest  # noqa: E402


@pytest.mark.unit
class TestPluginManifestValidation(unittest.TestCase):
    """Test plugin manifest validation."""

    def setUp(self):
        """Create temporary directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Cleanup."""
        self.temp_dir.cleanup()

    def create_manifest(self, **kwargs) -> Path:
        """Helper to create a manifest file."""
        manifest_path = self.temp_path / "manifest.json"
        manifest = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test description",
        }
        manifest.update(kwargs)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        return manifest_path

    def test_valid_manifest(self):
        """Test that valid manifest passes validation."""
        manifest_path = self.create_manifest()
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_missing_required_fields(self):
        """Test that missing required fields cause validation failure."""
        manifest_path = self.create_manifest()
        manifest_path.write_text('{"name": "test"}')

        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("version" in e.lower() for e in errors))

    def test_invalid_version_format(self):
        """Test that invalid version format is rejected."""
        manifest_path = self.create_manifest(version="invalid.version")
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("version" in e.lower() for e in errors))

    def test_valid_semver_formats(self):
        """Test various valid semantic version formats."""
        valid_versions = [
            "1.0.0",
            "2.1.3",
            "0.0.1",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-beta+build.1",
            "1.0.0+build",
        ]

        for version in valid_versions:
            with self.subTest(version=version):
                manifest_path = self.create_manifest(version=version)
                manifest = PluginManifest(manifest_path)
                is_valid, errors = manifest.validate()
                self.assertTrue(is_valid, f"Version {version} should be valid")

    def test_invalid_semver_formats(self):
        """Test invalid semantic version formats."""
        invalid_versions = [
            "1",
            "1.0",
            "1.0.0.0",
            "v1.0.0",
            "latest",
            "1.0.0-",
        ]

        for version in invalid_versions:
            with self.subTest(version=version):
                manifest_path = self.create_manifest(version=version)
                manifest = PluginManifest(manifest_path)
                is_valid, errors = manifest.validate()
                self.assertFalse(is_valid, f"Version {version} should be invalid")

    def test_invalid_permission_declaration(self):
        """Test that invalid permissions are rejected."""
        manifest_path = self.create_manifest(
            permissions=["filesystem", "invalid_permission", "network"]
        )
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("permission" in e.lower() for e in errors))

    def test_valid_permissions(self):
        """Test that valid permissions pass validation."""
        manifest_path = self.create_manifest(
            permissions=["filesystem", "network", "system", "environment"]
        )
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)

    def test_invalid_manifest_json(self):
        """Test that invalid JSON is handled gracefully."""
        manifest_path = self.temp_path / "manifest.json"
        manifest_path.write_text("{invalid json")

        with self.assertRaises(ValueError):
            PluginManifest(manifest_path)

    def test_missing_manifest_file(self):
        """Test that missing manifest file raises error."""
        manifest_path = self.temp_path / "nonexistent.json"

        with self.assertRaises(FileNotFoundError):
            PluginManifest(manifest_path)

    def test_optional_fields(self):
        """Test that optional fields are validated if present."""
        manifest_path = self.create_manifest(
            homepage="https://example.com",
            repository="https://github.com/example/plugin",
            license="MIT",
        )
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)

    def test_requires_field(self):
        """Test that requires field is validated."""
        manifest_path = self.create_manifest(requires={"devkit": ">=3.0.0", "python": ">=3.9"})
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)

    def test_invalid_requires_field(self):
        """Test that invalid requires field is rejected."""
        manifest_path = self.create_manifest(requires="3.0.0")  # Should be dict, not string
        manifest = PluginManifest(manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)


@pytest.mark.unit
class TestPluginValidator(unittest.TestCase):
    """Test comprehensive plugin validation."""

    def setUp(self):
        """Create temporary plugins directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Cleanup."""
        self.temp_dir.cleanup()

    def create_valid_plugin(self, name: str) -> Path:
        """Helper to create a valid plugin."""
        plugin_dir = self.temp_path / name
        plugin_dir.mkdir()

        # Create manifest
        manifest_path = plugin_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "name": name,
                    "version": "1.0.0",
                    "author": "Test Author",
                    "description": "Test plugin",
                }
            )
        )

        # Create __init__.py
        init_file = plugin_dir / "__init__.py"
        init_file.write_text(
            """
from abc import ABC

class Plugin(ABC):
    name = "test-plugin"
    version = "1.0.0"

    def initialize(self):
        pass

    def get_roles(self):
        return {}

    def get_hooks(self):
        return {}

    def validate(self):
        return True, []
"""
        )

        return plugin_dir

    def test_valid_plugin_passes(self):
        """Test that valid plugin passes validation."""
        self.create_valid_plugin("valid-plugin")
        validator = PluginValidator(self.temp_path)

        is_valid, message = validator.validate_plugin("valid-plugin")

        self.assertTrue(is_valid)
        self.assertIn("passed", message.lower())

    def test_missing_manifest(self):
        """Test that missing manifest is detected."""
        plugin_dir = self.temp_path / "no-manifest"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("pass")

        validator = PluginValidator(self.temp_path)
        is_valid, message = validator.validate_plugin("no-manifest")

        self.assertFalse(is_valid)
        self.assertIn("manifest", message.lower())

    def test_missing_init_file(self):
        """Test that missing __init__.py is detected."""
        plugin_dir = self.temp_path / "no-init"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "name": "no-init",
                    "version": "1.0.0",
                    "author": "Test",
                    "description": "Test",
                }
            )
        )

        validator = PluginValidator(self.temp_path)
        is_valid, message = validator.validate_plugin("no-init")

        self.assertFalse(is_valid)
        self.assertIn("__init__.py", message.lower())

    def test_missing_plugin_class(self):
        """Test that missing Plugin class is detected."""
        plugin_dir = self.temp_path / "no-class"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "name": "no-class",
                    "version": "1.0.0",
                    "author": "Test",
                    "description": "Test",
                }
            )
        )
        (plugin_dir / "__init__.py").write_text("# No plugin class")

        validator = PluginValidator(self.temp_path)
        is_valid, message = validator.validate_plugin("no-class")

        self.assertFalse(is_valid)

    def test_validate_all_plugins(self):
        """Test validating all plugins in directory."""
        self.create_valid_plugin("plugin1")
        self.create_valid_plugin("plugin2")

        validator = PluginValidator(self.temp_path)
        results = validator.validate_all_plugins()

        self.assertEqual(len(results), 2)
        self.assertTrue(all(valid for valid, _ in results.values()))

    def test_get_plugin_info(self):
        """Test retrieving plugin information."""
        self.create_valid_plugin("test-plugin")

        validator = PluginValidator(self.temp_path)
        info = validator.get_plugin_info("test-plugin")

        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "test-plugin")
        self.assertEqual(info["version"], "1.0.0")

    def test_nonexistent_plugin_directory(self):
        """Test that nonexistent plugin directory is handled."""
        validator = PluginValidator(self.temp_path)
        is_valid, message = validator.validate_plugin("nonexistent")

        self.assertFalse(is_valid)


@pytest.mark.unit
class TestStandaloneValidation(unittest.TestCase):
    """Test standalone validation function."""

    def setUp(self):
        """Create temporary directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Cleanup."""
        self.temp_dir.cleanup()

    def test_validate_plugin_manifest_function(self):
        """Test standalone validation function."""
        manifest_path = self.temp_path / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "name": "test",
                    "version": "1.0.0",
                    "author": "Test",
                    "description": "Test",
                }
            )
        )

        is_valid, errors = validate_plugin_manifest(manifest_path)

        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_validate_invalid_manifest(self):
        """Test standalone validation with invalid manifest."""
        manifest_path = self.temp_path / "manifest.json"
        manifest_path.write_text('{"name": "test"}')

        is_valid, errors = validate_plugin_manifest(manifest_path)

        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)

    def test_validate_nonexistent_manifest(self):
        """Test standalone validation with nonexistent file."""
        manifest_path = self.temp_path / "nonexistent.json"

        is_valid, errors = validate_plugin_manifest(manifest_path)

        self.assertFalse(is_valid)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
