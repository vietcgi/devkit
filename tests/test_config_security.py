#!/usr/bin/env python3
"""
Configuration Security Tests

Tests for configuration file security, including:
- File permission validation
- Ownership verification
- Permission fixing
- Secure file creation
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.config_engine import ConfigurationEngine  # noqa: E402


@pytest.mark.unit
class TestConfigSecurityPermissions(unittest.TestCase):
    """Test configuration file permission handling."""

    def setUp(self):
        """Create temporary directory for testing."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config_file = self.temp_path / "config.yaml"

    def tearDown(self):
        """Cleanup temporary directory."""
        self.temp_dir.cleanup()

    def test_secure_config_created_with_0600(self):
        """Test that missing config is created with secure 0600 permissions."""
        engine = ConfigurationEngine()

        # File doesn't exist yet
        self.assertFalse(self.config_file.exists())

        # Validate (should create with 0600)
        engine.validate_and_secure_config_file(self.config_file)

        # Verify created
        self.assertTrue(self.config_file.exists())

        # Verify permissions are 0600
        mode = os.stat(self.config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600, f"Expected 0600, got {oct(mode)}")

    def test_insecure_permissions_are_fixed(self):
        """Test that insecure config permissions are automatically fixed."""
        engine = ConfigurationEngine()

        # Create file with insecure permissions (644)
        self.config_file.write_text("test: content")
        os.chmod(self.config_file, 0o644)

        # Verify it has insecure permissions
        mode_before = os.stat(self.config_file).st_mode & 0o777
        self.assertEqual(mode_before, 0o644)

        # Validate (should fix)
        engine.validate_and_secure_config_file(self.config_file)

        # Verify permissions were fixed to 0600
        mode_after = os.stat(self.config_file).st_mode & 0o777
        self.assertEqual(mode_after, 0o600, f"Expected 0600, got {oct(mode_after)}")

    def test_secure_permissions_unchanged(self):
        """Test that already secure permissions are not changed."""
        engine = ConfigurationEngine()

        # Create file with secure permissions
        self.config_file.write_text("test: content")
        os.chmod(self.config_file, 0o600)

        # Validate
        engine.validate_and_secure_config_file(self.config_file)

        # Verify permissions unchanged
        mode = os.stat(self.config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_very_insecure_permissions_fixed(self):
        """Test that world-readable configs (444, 666, 777) are fixed."""
        engine = ConfigurationEngine()

        insecure_modes = [0o444, 0o666, 0o777, 0o755]

        for insecure_mode in insecure_modes:
            with self.subTest(mode=oct(insecure_mode)):
                # Create file with very insecure permissions
                test_file = self.temp_path / f"test_{oct(insecure_mode)}.yaml"
                test_file.write_text("test: content")
                os.chmod(test_file, insecure_mode)

                # Validate
                engine.validate_and_secure_config_file(test_file)

                # Verify fixed to 0600
                mode = os.stat(test_file).st_mode & 0o777
                self.assertEqual(
                    mode,
                    0o600,
                    f"File with {oct(insecure_mode)} should be fixed to 0600",
                )

    def test_ownership_verification(self):
        """Test that file ownership is verified."""
        engine = ConfigurationEngine()

        # Create file with correct ownership
        self.config_file.write_text("test: content")
        os.chmod(self.config_file, 0o600)

        # Should not raise (owned by current user)
        try:
            engine.validate_and_secure_config_file(self.config_file)
        except PermissionError:
            self.fail("Should not raise PermissionError for correctly owned file")

    def test_config_file_access_error_handling(self):
        """Test graceful handling of file access errors."""
        engine = ConfigurationEngine()

        # Create a file in a directory we'll remove
        test_dir = self.temp_path / "readonly"
        test_dir.mkdir()
        test_file = test_dir / "config.yaml"
        test_file.write_text("test: content")

        # Make directory read-only (prevents stat)
        os.chmod(test_dir, 0o000)

        try:
            # Should raise OSError when trying to stat
            with self.assertRaises(OSError):
                engine.validate_and_secure_config_file(test_file)
        finally:
            # Restore permissions for cleanup
            os.chmod(test_dir, 0o755)

    def test_parent_directory_created_if_missing(self):
        """Test that parent directories are created for new config files."""
        engine = ConfigurationEngine()

        # Create config in non-existent directory
        nested_path = self.temp_path / "dir1" / "dir2" / "dir3"
        config_file = nested_path / "config.yaml"

        # Verify directories don't exist
        self.assertFalse(nested_path.exists())

        # Validate (should create directories and file)
        engine.validate_and_secure_config_file(config_file)

        # Verify all created
        self.assertTrue(config_file.exists())
        self.assertTrue(nested_path.exists())

        # Verify permissions on file
        mode = os.stat(config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)


@pytest.mark.unit
class TestConfigSecurityIntegration(unittest.TestCase):
    """Integration tests for config security."""

    def setUp(self):
        """Create temporary directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Cleanup."""
        self.temp_dir.cleanup()

    def test_config_with_sensitive_data_is_protected(self):
        """Test that configs containing sensitive data are protected."""
        engine = ConfigurationEngine()

        config_file = self.temp_path / "sensitive.yaml"
        config_file.write_text(
            """
database:
  password: "secret123"
  api_key: "sk-1234567890"

aws:
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""
        )

        # Make it world-readable initially (bad!)
        os.chmod(config_file, 0o644)

        # Validate should fix
        engine.validate_and_secure_config_file(config_file)

        # Verify protected
        mode = os.stat(config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_multiple_configs_secured_independently(self):
        """Test that multiple config files can be secured independently."""
        engine = ConfigurationEngine()

        # Create multiple config files with different permissions
        configs = {
            "config1.yaml": 0o644,
            "config2.yaml": 0o755,
            "config3.yaml": 0o600,  # Already secure
        }

        config_paths = {}
        for filename, mode in configs.items():
            path = self.temp_path / filename
            path.write_text(f"# {filename}")
            os.chmod(path, mode)
            config_paths[filename] = path

        # Validate all
        for path in config_paths.values():
            engine.validate_and_secure_config_file(path)

        # Verify all are 0600
        for filename, path in config_paths.items():
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600, f"{filename} should be 0600, got {oct(mode)}")


@pytest.mark.unit
class TestConfigSecurityEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Create temporary directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Cleanup."""
        self.temp_dir.cleanup()

    def test_symlink_handled_correctly(self):
        """Test that symlinks are handled properly."""
        engine = ConfigurationEngine()

        # Create real file
        real_file = self.temp_path / "real.yaml"
        real_file.write_text("test: content")
        os.chmod(real_file, 0o644)

        # Create symlink
        symlink_file = self.temp_path / "symlink.yaml"
        symlink_file.symlink_to(real_file)

        # Validate symlink (should fix target)
        engine.validate_and_secure_config_file(symlink_file)

        # Verify real file permissions
        mode = os.stat(real_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_empty_config_file_permissions(self):
        """Test that empty config files are secured properly."""
        engine = ConfigurationEngine()

        config_file = self.temp_path / "empty.yaml"
        config_file.write_text("")
        os.chmod(config_file, 0o644)

        # Validate
        engine.validate_and_secure_config_file(config_file)

        # Verify secured
        mode = os.stat(config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_large_config_file_permissions(self):
        """Test that large config files are secured properly."""
        engine = ConfigurationEngine()

        config_file = self.temp_path / "large.yaml"
        # Write large config (1 MB)
        large_content = "key: value\n" * 100000
        config_file.write_text(large_content)
        os.chmod(config_file, 0o644)

        # Validate
        engine.validate_and_secure_config_file(config_file)

        # Verify secured
        mode = os.stat(config_file).st_mode & 0o777
        self.assertEqual(mode, 0o600)

        # Verify content preserved
        self.assertTrue(len(config_file.read_text()) > 1000000)


if __name__ == "__main__":
    unittest.main()
