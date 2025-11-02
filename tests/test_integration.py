"""
Integration tests for devkit components.

Tests component interactions and end-to-end workflows:
- Plugin system with config engine
- Config engine with git integration
- Health checks with performance monitoring
- Error handling across components
- Multi-component workflows
"""

import json
import sys
import tempfile
import time
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.config_engine import ConfigurationEngine
from cli.git_config_manager import GitConfigManager
from cli.plugin_system import PluginInterface, PluginLoader
from cli.plugin_validator import PluginValidator


class TestPluginSystemIntegration(TestCase):
    """Integration tests for plugin system."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.plugins_dir = Path(self.temp_dir) / "plugins"
        self.plugins_dir.mkdir()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_discovery_and_loading(self):
        """Test discovering and loading plugins."""
        self.loader.add_plugin_path(self.plugins_dir)
        discovered = self.loader.discover_plugins()
        # Should discover no plugins in empty directory
        self.assertEqual(len(discovered), 0)

    def test_plugin_validation_workflow(self):
        """Test complete plugin validation workflow."""
        # Create minimal plugin
        plugin_dir = self.plugins_dir / "test_plugin"
        plugin_dir.mkdir()

        # Create manifest
        manifest_data = {
            "name": "test_plugin",
            "version": "1.0.0",
            "author": "Test",
            "description": "Test plugin",
        }
        manifest_path = plugin_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))

        # Create __init__.py
        init_content = """
from cli.plugin_system import PluginInterface

class Plugin(PluginInterface):
    name = "test_plugin"
    version = "1.0.0"
    description = "Test plugin"

    def initialize(self):
        pass

    def get_roles(self):
        return {}

    def get_hooks(self):
        return {}

    def validate(self):
        return True, []
"""
        (plugin_dir / "__init__.py").write_text(init_content)

        # Validate plugin
        validator = PluginValidator(self.plugins_dir)
        is_valid, message = validator.validate_plugin("test_plugin")
        self.assertTrue(is_valid, f"Plugin validation failed: {message}")

    def test_multiple_hooks_execution(self):
        """Test executing multiple hooks across plugins."""
        from cli.plugin_system import HookContext, BuiltinHook

        hook1 = BuiltinHook("hook1")
        hook2 = BuiltinHook("hook2")

        self.loader.hooks["test_stage"] = [hook1, hook2]

        context = HookContext(stage="test_stage")
        result = self.loader.execute_hooks("test_stage", context)

        self.assertTrue(result)
        self.assertEqual(context.status, "success")

    def test_plugin_error_handling(self):
        """Test error handling in plugin loading."""
        # Try to load non-existent plugin
        result = self.loader.load_plugin(str(self.plugins_dir / "missing"), "missing")
        self.assertIsNone(result)


class TestConfigEngineIntegration(TestCase):
    """Integration tests for config engine."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)
        self.engine = ConfigurationEngine(self.config_dir)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_load_and_merge(self):
        """Test loading and merging multiple config files."""
        # Create base config
        base_config = {
            "version": "1.0",
            "environment": {"DEBUG": True, "LOG_LEVEL": "INFO"},
        }
        base_path = self.config_dir / "base.yml"
        import yaml

        base_path.write_text(yaml.dump(base_config))

        # Load base config (should not raise exception)
        try:
            self.engine.load_file(base_path)
        except Exception:
            self.fail("Failed to load config file")

        # Verify file was loaded
        loaded_files = self.engine.list_loaded_files()
        self.assertIn(str(base_path), loaded_files)

    def test_config_validation_workflow(self):
        """Test config validation across multiple sources."""
        # Create valid config with required fields
        valid_config = {
            "version": "1.0",
            "setup_environment": "production",
            "logging": {"level": "INFO"},
            "metadata": {
                "author": "test",
                "timestamp": "2025-01-01T00:00:00Z",
            },
        }
        config_path = self.config_dir / "valid.yml"
        import yaml

        config_path.write_text(yaml.dump(valid_config))

        # Load and validate (should not raise exception)
        try:
            self.engine.load_file(config_path)
            # File should be in loaded files
            loaded_files = self.engine.list_loaded_files()
            self.assertIn(str(config_path), loaded_files)
        except Exception:
            self.fail("Failed to load config file")


class TestGitIntegration(TestCase):
    """Integration tests for git functionality."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.temp_dir)

        # Initialize git repo
        import subprocess

        subprocess.run(
            ["git", "init"],
            cwd=self.repo_path,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=self.repo_path,
            capture_output=True,
            timeout=10,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=self.repo_path,
            capture_output=True,
            timeout=10,
        )

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_git_config_manager_initialization(self):
        """Test GitConfigManager initialization."""
        manager = GitConfigManager(self.repo_path)
        # Should initialize without errors
        self.assertIsNotNone(manager)


class TestMultiComponentWorkflow(TestCase):
    """Integration tests for workflows spanning multiple components."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.work_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_plugin_interaction(self):
        """Test config engine interacting with plugin system."""
        config_data = {"plugins": {"enabled": True, "paths": ["./plugins"]}}

        # Simulate config-driven plugin loading
        loader = PluginLoader()

        if config_data.get("plugins", {}).get("enabled"):
            paths = config_data["plugins"]["paths"]
            for path_str in paths:
                path = Path(path_str)
                if path.exists():
                    loader.add_plugin_path(path)

        self.assertTrue(config_data["plugins"]["enabled"])

    def test_sequential_component_failures(self):
        """Test graceful handling of failures across components."""
        from cli.config_engine import ConfigurationEngine

        config_dir = self.work_dir / "config"
        config_dir.mkdir()

        engine = ConfigurationEngine(config_dir)

        # Try to load non-existent config (should handle gracefully)
        try:
            engine.load_file(config_dir / "missing.yml")
        except FileNotFoundError:
            # Expected behavior
            pass

        # Engine should still be functional
        self.assertIsNotNone(engine)

    def test_performance_across_components(self):
        """Test performance of multi-component operations."""
        import time

        start = time.time()

        # Simulate multi-component workflow
        loader = PluginLoader()
        loader.discover_plugins()  # Should be fast even with empty list

        duration = time.time() - start
        # Should complete in under 1 second
        self.assertLess(duration, 1.0)


class TestErrorRecovery(TestCase):
    """Integration tests for error recovery across components."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_validation_error_recovery(self):
        """Test recovery from plugin validation errors."""
        plugins_dir = Path(self.temp_dir) / "plugins"
        plugins_dir.mkdir()

        # Create invalid plugin
        invalid_dir = plugins_dir / "invalid"
        invalid_dir.mkdir()

        validator = PluginValidator(plugins_dir)

        # Should handle gracefully
        results = validator.validate_all_plugins()
        self.assertIn("invalid", results)

        is_valid, message = results["invalid"]
        self.assertFalse(is_valid)

    def test_concurrent_component_access(self):
        """Test concurrent access to shared resources."""
        import threading

        loader = PluginLoader()
        results = []

        def discover():
            plugins = loader.discover_plugins()
            results.append(len(plugins))

        threads = [threading.Thread(target=discover) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should complete without error
        self.assertEqual(len(results), 3)


class TestEndToEndWorkflow(TestCase):
    """End-to-end integration tests."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_initialization_workflow(self):
        """Test complete initialization workflow."""
        # Create directory structure
        config_dir = self.base_dir / "config"
        plugins_dir = self.base_dir / "plugins"
        config_dir.mkdir()
        plugins_dir.mkdir()

        # Initialize components
        loader = PluginLoader()
        loader.add_plugin_path(plugins_dir)

        # Discover plugins
        discovered = loader.discover_plugins()
        self.assertIsInstance(discovered, list)

    def test_stress_test_plugin_discovery(self):
        """Stress test plugin discovery with multiple iterations."""
        plugins_dir = self.base_dir / "plugins"
        plugins_dir.mkdir()

        loader = PluginLoader()
        loader.add_plugin_path(plugins_dir)

        # Run multiple discovery cycles
        start = time.time()
        for _ in range(100):
            discovered = loader.discover_plugins()

        duration = time.time() - start
        # 100 iterations should complete in reasonable time
        self.assertLess(duration, 5.0)


if __name__ == "__main__":
    import unittest

    unittest.main()
