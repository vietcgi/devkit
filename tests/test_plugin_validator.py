"""
Comprehensive tests for plugin_validator module.

Validates:
- PluginManifest validation
- Semantic version checking
- Permission declaration validation
- Plugin class verification
- Secure plugin loading
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.plugin_validator import (  # noqa: E402
    PluginManifest,
    PluginValidator,
)


class TestPluginManifestValidation(unittest.TestCase):
    """Test PluginManifest validation."""

    def setUp(self):
        """Set up test manifest."""
        self.temp_dir = tempfile.mkdtemp()
        self.manifest_path = Path(self.temp_dir) / "manifest.json"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_valid(self):
        """Test valid manifest."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_manifest_missing_required_field(self):
        """Test manifest missing required field."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            # Missing author and description
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("author" in err for err in errors))
        self.assertTrue(any("description" in err for err in errors))

    def test_manifest_invalid_field_type(self):
        """Test manifest with invalid field type."""
        manifest_data = {
            "name": 123,  # Should be string
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("name" in err and "type" in err for err in errors))

    def test_manifest_invalid_version(self):
        """Test manifest with invalid semantic version."""
        manifest_data = {
            "name": "test-plugin",
            "version": "not-a-version",  # Invalid semver
            "author": "Test Author",
            "description": "Test plugin",
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("version" in err for err in errors))

    def test_manifest_invalid_permission(self):
        """Test manifest with invalid permission."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
            "permissions": ["filesystem", "invalid_permission"],
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertFalse(is_valid)
        self.assertTrue(any("permission" in err for err in errors))

    def test_manifest_valid_permissions(self):
        """Test manifest with valid permissions."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
            "permissions": ["filesystem", "network", "system"],
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)

    def test_manifest_optional_fields(self):
        """Test manifest with optional fields."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
            "homepage": "https://example.com",
            "repository": "https://github.com/test/plugin",
            "license": "MIT",
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, errors = manifest.validate()

        self.assertTrue(is_valid)

    def test_manifest_not_found(self):
        """Test manifest file not found."""
        nonexistent_path = Path(self.temp_dir) / "nonexistent.json"

        with self.assertRaises(FileNotFoundError):
            PluginManifest(nonexistent_path)

    def test_manifest_invalid_json(self):
        """Test manifest with invalid JSON."""
        with open(self.manifest_path, "w") as f:
            f.write("{invalid json}")

        with self.assertRaises(ValueError):
            PluginManifest(self.manifest_path)

    def test_manifest_verify_integrity_valid(self):
        """Test manifest integrity verification."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
            "checksum": "valid",
        }
        with open(self.manifest_path, "w") as f:
            json.dump(manifest_data, f)

        manifest = PluginManifest(self.manifest_path)
        is_valid, message = manifest.verify_integrity()

        self.assertIsInstance(is_valid, bool)
        self.assertIsInstance(message, str)


class TestPluginValidator(unittest.TestCase):
    """Test PluginValidator class."""

    def setUp(self):
        """Set up test validator."""
        self.temp_dir = tempfile.mkdtemp()
        self.plugins_dir = Path(self.temp_dir)
        self.validator = PluginValidator(self.plugins_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validator_creation(self):
        """Test validator creation."""
        self.assertIsNotNone(self.validator)
        self.assertEqual(self.validator.plugins_dir, self.plugins_dir)

    def test_validate_plugin_missing_directory(self):
        """Test validating plugin with missing directory."""
        is_valid, message = self.validator.validate_plugin("nonexistent-plugin")

        self.assertFalse(is_valid)
        self.assertIn("not found", message)

    def test_validate_plugin_missing_manifest(self):
        """Test validating plugin with missing manifest."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        is_valid, message = self.validator.validate_plugin("test-plugin")

        self.assertFalse(is_valid)
        self.assertIn("manifest", message.lower())

    def test_validate_plugin_invalid_manifest(self):
        """Test validating plugin with invalid manifest."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        manifest_path = plugin_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            f.write("{invalid json}")

        is_valid, message = self.validator.validate_plugin("test-plugin")

        self.assertFalse(is_valid)

    def test_validate_plugin_missing_init(self):
        """Test validating plugin with missing __init__.py."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        manifest_path = plugin_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest_data, f)

        is_valid, message = self.validator.validate_plugin("test-plugin")

        self.assertFalse(is_valid)
        self.assertIn("__init__.py", message)

    def test_validate_plugin_empty_init(self):
        """Test validating plugin with empty __init__.py."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        manifest_path = plugin_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest_data, f)

        init_path = plugin_dir / "__init__.py"
        init_path.touch()  # Create empty file

        is_valid, message = self.validator.validate_plugin("test-plugin")

        self.assertFalse(is_valid)
        self.assertIn("empty", message.lower())

    def test_validate_plugin_missing_class(self):
        """Test validating plugin with missing Plugin class."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        manifest_path = plugin_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest_data, f)

        init_path = plugin_dir / "__init__.py"
        with open(init_path, "w") as f:
            f.write("# Empty plugin file\n")

        is_valid, message = self.validator.validate_plugin("test-plugin")

        self.assertFalse(is_valid)

    def test_validate_all_plugins_empty_dir(self):
        """Test validating all plugins in empty directory."""
        results = self.validator.validate_all_plugins()

        self.assertEqual(len(results), 0)

    def test_get_plugin_info_valid(self):
        """Test getting plugin info from valid manifest."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test Author",
            "description": "Test plugin",
        }
        manifest_path = plugin_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest_data, f)

        info = self.validator.get_plugin_info("test-plugin")

        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "test-plugin")

    def test_get_plugin_info_invalid(self):
        """Test getting plugin info from invalid plugin."""
        info = self.validator.get_plugin_info("nonexistent-plugin")

        self.assertIsNone(info)

    def test_verify_plugin_class_valid(self):
        """Test verifying valid plugin class."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        init_path = plugin_dir / "__init__.py"
        with open(init_path, "w") as f:
            f.write("""
class Plugin:
    def initialize(self): pass
    def get_roles(self): return {}
    def get_hooks(self): return {}
    def validate(self): return (True, [])
""")

        result = PluginValidator._verify_plugin_class(plugin_dir)

        self.assertTrue(result)

    def test_verify_plugin_class_invalid(self):
        """Test verifying invalid plugin class."""
        plugin_dir = self.plugins_dir / "test-plugin"
        plugin_dir.mkdir()

        init_path = plugin_dir / "__init__.py"
        with open(init_path, "w") as f:
            f.write("# No plugin class\n")

        result = PluginValidator._verify_plugin_class(plugin_dir)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
