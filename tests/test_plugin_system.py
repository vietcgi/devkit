"""
Extended tests for plugin_system module.

Focus on improving coverage for:
- PluginLoader initialization and plugin path management
- Plugin discovery functionality
- Hook context and interface implementations
- Error handling and validation
"""

import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import unittest

# Mock sys.argv
sys.argv = ["pytest"]

from cli.plugin_system import (  # noqa: E402
    PluginLoader,
    PluginInterface,
    HookInterface,
    HookContext,
)


class TestHookContext(unittest.TestCase):
    """Test HookContext dataclass."""

    def test_hook_context_creation_minimal(self):
        """Test creating hook context with minimal parameters."""
        ctx = HookContext(stage="pre_setup")

        self.assertEqual(ctx.stage, "pre_setup")
        self.assertIsNone(ctx.role)
        self.assertIsNone(ctx.task)
        self.assertEqual(ctx.status, "running")
        self.assertIsNone(ctx.error)

    def test_hook_context_creation_full(self):
        """Test creating hook context with all parameters."""
        metadata = {"key": "value"}
        ctx = HookContext(
            stage="post_role",
            role="shell",
            task="install_zsh",
            status="success",
            error=None,
            metadata=metadata,
        )

        self.assertEqual(ctx.stage, "post_role")
        self.assertEqual(ctx.role, "shell")
        self.assertEqual(ctx.task, "install_zsh")
        self.assertEqual(ctx.status, "success")
        self.assertEqual(ctx.metadata, metadata)

    def test_hook_context_failed_status(self):
        """Test hook context with failed status."""
        ctx = HookContext(
            stage="pre_setup",
            status="failed",
            error="Something went wrong",
        )

        self.assertEqual(ctx.status, "failed")
        self.assertEqual(ctx.error, "Something went wrong")


class TestPluginLoader(unittest.TestCase):
    """Test PluginLoader class."""

    def setUp(self):
        """Set up test plugin loader."""
        self.temp_dir = tempfile.mkdtemp()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_plugin_loader_initialization(self):
        """Test initializing plugin loader."""
        self.assertIsNotNone(self.loader)
        self.assertIsNotNone(self.loader.logger)
        self.assertEqual(len(self.loader.plugins), 0)
        self.assertEqual(len(self.loader.hooks), 0)
        self.assertEqual(len(self.loader.plugin_paths), 0)

    def test_plugin_loader_with_custom_logger(self):
        """Test initializing loader with custom logger."""
        custom_logger = Mock()
        loader = PluginLoader(logger=custom_logger)

        self.assertEqual(loader.logger, custom_logger)

    def test_add_plugin_path_valid(self):
        """Test adding valid plugin path."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()

        self.loader.add_plugin_path(plugin_dir)

        self.assertIn(plugin_dir, self.loader.plugin_paths)

    def test_add_plugin_path_nonexistent(self):
        """Test adding non-existent plugin path."""
        missing_path = Path(self.temp_dir) / "missing"

        self.loader.add_plugin_path(missing_path)

        self.assertNotIn(missing_path, self.loader.plugin_paths)

    def test_add_plugin_path_not_directory(self):
        """Test adding file instead of directory."""
        file_path = Path(self.temp_dir) / "file.txt"
        file_path.touch()

        self.loader.add_plugin_path(file_path)

        self.assertNotIn(file_path, self.loader.plugin_paths)

    def test_add_plugin_path_with_tilde(self):
        """Test adding plugin path with tilde expansion."""
        # Create a path with tilde (though it won't exist)
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.is_dir", return_value=True):
            self.loader.add_plugin_path("~/test_plugins")
            # Should have attempted to add

    def test_discover_plugins_empty_directory(self):
        """Test discovering plugins in empty directory."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()
        self.loader.add_plugin_path(plugin_dir)

        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 0)

    def test_discover_plugins_with_python_file(self):
        """Test discovering Python file plugin."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()

        # Create a Python plugin file
        plugin_file = plugin_dir / "my_plugin.py"
        plugin_file.write_text("# Plugin code")

        self.loader.add_plugin_path(plugin_dir)
        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 1)
        path, module_name = discovered[0]
        self.assertEqual(module_name, "my_plugin")
        self.assertTrue(path.endswith("my_plugin.py"))

    def test_discover_plugins_with_package(self):
        """Test discovering Python package plugin."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()

        # Create a Python package plugin
        pkg_dir = plugin_dir / "my_plugin_pkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("# Package code")

        self.loader.add_plugin_path(plugin_dir)
        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 1)
        path, module_name = discovered[0]
        self.assertEqual(module_name, "my_plugin_pkg")

    def test_discover_plugins_ignores_private(self):
        """Test that private files are ignored."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()

        # Create private plugin (should be ignored)
        (plugin_dir / "_private_plugin.py").write_text("# Private")

        # Create normal plugins
        (plugin_dir / "public_plugin1.py").write_text("# Public 1")
        (plugin_dir / "public_plugin2.py").write_text("# Public 2")

        self.loader.add_plugin_path(plugin_dir)
        discovered = self.loader.discover_plugins()

        # Should discover 2 public plugins, not 3
        self.assertEqual(len(discovered), 2)
        module_names = {name for _, name in discovered}
        self.assertEqual(module_names, {"public_plugin1", "public_plugin2"})

    def test_discover_plugins_nonexistent_path(self):
        """Test discovering plugins with non-existent path."""
        missing_path = Path(self.temp_dir) / "missing"
        self.loader.plugin_paths.append(missing_path)  # Add directly

        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 0)

    def test_discover_plugins_multiple_paths(self):
        """Test discovering plugins in multiple paths."""
        plugin_dir1 = Path(self.temp_dir) / "plugins1"
        plugin_dir2 = Path(self.temp_dir) / "plugins2"
        plugin_dir1.mkdir()
        plugin_dir2.mkdir()

        (plugin_dir1 / "plugin1.py").write_text("# Plugin 1")
        (plugin_dir2 / "plugin2.py").write_text("# Plugin 2")

        self.loader.add_plugin_path(plugin_dir1)
        self.loader.add_plugin_path(plugin_dir2)

        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 2)
        module_names = {name for _, name in discovered}
        self.assertEqual(module_names, {"plugin1", "plugin2"})

    def test_load_plugin_with_validation_error(self):
        """Test loading plugin with validation error."""
        # Mock validator to fail
        with patch("cli.plugin_system.PluginValidator") as mock_validator_class:
            mock_validator = Mock()
            mock_validator.validate_plugin.return_value = (False, "Invalid plugin")
            mock_validator_class.return_value = mock_validator

            result = self.loader.load_plugin("/path/to/plugin.py", "bad_plugin")

            self.assertIsNone(result)

    def test_load_plugin_missing_module(self):
        """Test loading non-existent plugin."""
        result = self.loader.load_plugin("/nonexistent/plugin.py", "missing")

        self.assertIsNone(result)

    def test_get_plugin_nonexistent(self):
        """Test getting non-loaded plugin."""
        result = self.loader.get_plugin("nonexistent_plugin")

        self.assertIsNone(result)

    def test_list_plugins_empty(self):
        """Test listing plugins when none loaded."""
        plugins = self.loader.list_plugins()

        self.assertEqual(plugins, [])

    def test_list_plugins_with_plugins(self):
        """Test listing loaded plugins."""
        # Add mock plugins
        mock_plugin1 = Mock(spec=PluginInterface)
        mock_plugin1.name = "plugin1"
        mock_plugin2 = Mock(spec=PluginInterface)
        mock_plugin2.name = "plugin2"

        self.loader.plugins["plugin1"] = mock_plugin1
        self.loader.plugins["plugin2"] = mock_plugin2

        plugins = self.loader.list_plugins()

        self.assertEqual(len(plugins), 2)
        self.assertIn("plugin1", plugins)
        self.assertIn("plugin2", plugins)

    def test_get_plugin_roles_empty(self):
        """Test getting plugin roles when no plugins loaded."""
        roles = self.loader.get_plugin_roles()

        self.assertEqual(roles, {})

    def test_get_plugin_roles_with_plugins(self):
        """Test getting plugin roles from loaded plugins."""
        # Create mock plugins with roles
        mock_plugin = Mock(spec=PluginInterface)
        roles = {"shell": Path("/tmp/shell"), "editors": Path("/tmp/editors")}
        mock_plugin.get_roles.return_value = roles

        self.loader.plugins["test_plugin"] = mock_plugin

        plugin_roles = self.loader.get_plugin_roles()

        self.assertIn("shell", plugin_roles)
        self.assertIn("editors", plugin_roles)

    def test_execute_hooks_empty(self):
        """Test executing hooks when none registered."""
        ctx = HookContext(stage="pre_setup")
        result = self.loader.execute_hooks("pre_setup", ctx)

        self.assertTrue(result)

    def test_get_plugin_info_empty(self):
        """Test getting plugin info when no plugins loaded."""
        info = self.loader.get_plugin_info()

        self.assertEqual(info, {})

    def test_get_plugin_info_with_plugins(self):
        """Test getting plugin information."""
        # Create mock plugin
        mock_plugin = Mock(spec=PluginInterface)
        mock_plugin.version = "1.0.0"
        mock_plugin.description = "Test plugin"
        mock_plugin.get_roles.return_value = {"role1": Path("/tmp/role1")}
        mock_plugin.get_hooks.return_value = {"pre_setup": [Mock()]}

        self.loader.plugins["test_plugin"] = mock_plugin

        info = self.loader.get_plugin_info()

        self.assertIn("test_plugin", info)
        self.assertEqual(info["test_plugin"]["version"], "1.0.0")
        self.assertEqual(info["test_plugin"]["description"], "Test plugin")
        self.assertEqual(info["test_plugin"]["roles"], 1)
        self.assertEqual(info["test_plugin"]["hooks"], 1)


class TestPluginInterfaces(unittest.TestCase):
    """Test plugin interface implementations."""

    def test_hook_interface_is_abstract(self):
        """Test that HookInterface is abstract."""
        with self.assertRaises(TypeError):
            HookInterface()

    def test_plugin_interface_is_abstract(self):
        """Test that PluginInterface is abstract."""
        with self.assertRaises(TypeError):
            PluginInterface()

    def test_hook_interface_implementation(self):
        """Test implementing HookInterface."""

        class TestHook(HookInterface):
            def execute(self, context: HookContext) -> bool:
                return True

        hook = TestHook()
        ctx = HookContext(stage="pre_setup")

        self.assertTrue(hook.execute(ctx))

    def test_plugin_interface_implementation(self):
        """Test implementing PluginInterface."""

        class TestPlugin(PluginInterface):
            name = "test"
            version = "1.0"
            description = "Test"

            def initialize(self):
                pass

            def get_roles(self):
                return {}

            def get_hooks(self):
                return {}

            def validate(self):
                return True, []

        plugin = TestPlugin()

        self.assertEqual(plugin.name, "test")
        self.assertEqual(plugin.version, "1.0")
        self.assertTrue(plugin.validate()[0])


class TestLoadAll(unittest.TestCase):
    """Test load_all functionality."""

    def setUp(self):
        """Set up test loader."""
        self.temp_dir = tempfile.mkdtemp()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_all_no_plugins(self):
        """Test load_all with no plugins found."""
        plugin_dir = Path(self.temp_dir) / "plugins"
        plugin_dir.mkdir()
        self.loader.add_plugin_path(plugin_dir)

        count = self.loader.load_all([plugin_dir])

        self.assertEqual(count, 0)

    def test_load_all_default_paths(self):
        """Test load_all with default paths."""
        # This will use default paths, which likely don't exist
        count = self.loader.load_all()

        # Should not raise exception
        self.assertGreaterEqual(count, 0)


class TestExecuteHooksErrorHandling(unittest.TestCase):
    """Test error handling in execute_hooks."""

    def setUp(self):
        """Set up test loader."""
        self.loader = PluginLoader()

    def test_execute_hooks_with_hook_failure(self):
        """Test executing hooks when hook returns False."""
        # Create a mock hook that returns False
        mock_hook = Mock(spec=HookInterface)
        mock_hook.execute.return_value = False

        self.loader.hooks["pre_setup"] = [mock_hook]

        ctx = HookContext(stage="pre_setup")
        result = self.loader.execute_hooks("pre_setup", ctx)

        self.assertFalse(result)
        self.assertEqual(ctx.status, "failed")

    def test_execute_hooks_with_os_error(self):
        """Test executing hooks when hook raises OSError."""
        mock_hook = Mock(spec=HookInterface)
        mock_hook.execute.side_effect = OSError("Permission denied")

        self.loader.hooks["pre_setup"] = [mock_hook]

        ctx = HookContext(stage="pre_setup")
        result = self.loader.execute_hooks("pre_setup", ctx)

        self.assertFalse(result)
        self.assertEqual(ctx.status, "failed")
        self.assertIn("Permission denied", ctx.error)

    def test_execute_hooks_with_runtime_error(self):
        """Test executing hooks when hook raises RuntimeError."""
        mock_hook = Mock(spec=HookInterface)
        mock_hook.execute.side_effect = RuntimeError("Execution failed")

        self.loader.hooks["post_role"] = [mock_hook]

        ctx = HookContext(stage="post_role")
        result = self.loader.execute_hooks("post_role", ctx)

        self.assertFalse(result)
        self.assertEqual(ctx.status, "failed")

    def test_execute_hooks_with_value_error(self):
        """Test executing hooks when hook raises ValueError."""
        mock_hook = Mock(spec=HookInterface)
        mock_hook.execute.side_effect = ValueError("Invalid value")

        self.loader.hooks["setup"] = [mock_hook]

        ctx = HookContext(stage="setup")
        result = self.loader.execute_hooks("setup", ctx)

        self.assertFalse(result)
        self.assertEqual(ctx.status, "failed")

    def test_execute_hooks_with_none_context(self):
        """Test executing hooks with None context creates default context."""
        mock_hook = Mock(spec=HookInterface)
        mock_hook.execute.return_value = True

        self.loader.hooks["pre_setup"] = [mock_hook]

        result = self.loader.execute_hooks("pre_setup", None)

        self.assertTrue(result)
        # Verify hook was called with a HookContext
        mock_hook.execute.assert_called_once()
        call_args = mock_hook.execute.call_args[0]
        self.assertIsInstance(call_args[0], HookContext)
        self.assertEqual(call_args[0].stage, "pre_setup")

    def test_execute_hooks_success_multiple_hooks(self):
        """Test executing multiple hooks that all succeed."""
        mock_hook1 = Mock(spec=HookInterface)
        mock_hook1.execute.return_value = True
        mock_hook2 = Mock(spec=HookInterface)
        mock_hook2.execute.return_value = True

        self.loader.hooks["pre_setup"] = [mock_hook1, mock_hook2]

        ctx = HookContext(stage="pre_setup")
        result = self.loader.execute_hooks("pre_setup", ctx)

        self.assertTrue(result)
        self.assertEqual(ctx.status, "success")
        mock_hook1.execute.assert_called_once()
        mock_hook2.execute.assert_called_once()


class TestPluginLoadingErrorPaths(unittest.TestCase):
    """Test error handling in plugin loading."""

    def setUp(self):
        """Set up test loader."""
        self.temp_dir = tempfile.mkdtemp()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_plugin_import_error(self):
        """Test loading plugin with import error."""
        plugin_file = Path(self.temp_dir) / "broken_plugin.py"
        plugin_file.write_text("import nonexistent_module_xyz")

        with patch("cli.plugin_system.PluginValidator") as mock_validator_class:
            mock_validator = Mock()
            mock_validator.validate_plugin.return_value = (True, "Valid")
            mock_validator_class.return_value = mock_validator

            result = self.loader.load_plugin(str(plugin_file), "broken_plugin")

        self.assertIsNone(result)

    def test_load_plugin_attribute_error(self):
        """Test loading plugin with attribute error."""
        plugin_file = Path(self.temp_dir) / "no_plugin.py"
        plugin_file.write_text("# Empty plugin file with no PluginInterface")

        with patch("cli.plugin_system.PluginValidator") as mock_validator_class:
            mock_validator = Mock()
            mock_validator.validate_plugin.return_value = (True, "Valid")
            mock_validator_class.return_value = mock_validator

            result = self.loader.load_plugin(str(plugin_file), "no_plugin")

        self.assertIsNone(result)

    def test_load_plugin_validation_fails(self):
        """Test loading plugin when validation fails."""
        plugin_file = Path(self.temp_dir) / "invalid_plugin.py"
        plugin_file.write_text("""
from cli.plugin_system import PluginInterface, HookInterface

class TestPlugin(PluginInterface):
    name = "invalid"
    version = "1.0"
    description = "Invalid"

    def initialize(self):
        pass

    def get_roles(self):
        return {}

    def get_hooks(self):
        return {}

    def validate(self):
        return False, ["Invalid plugin"]
""")

        result = self.loader.load_plugin(str(plugin_file), "invalid_plugin")

        self.assertIsNone(result)

    def test_load_plugin_invalid_spec(self):
        """Test loading plugin when spec creation fails."""
        with patch("importlib.util.spec_from_file_location") as mock_spec:
            mock_spec.return_value = None

            result = self.loader.load_plugin("/path/to/plugin.py", "plugin")

            self.assertIsNone(result)

    def test_load_plugin_spec_no_loader(self):
        """Test loading plugin when spec has no loader."""
        with patch("importlib.util.spec_from_file_location") as mock_spec_fn:
            mock_spec = Mock()
            mock_spec.loader = None
            mock_spec_fn.return_value = mock_spec

            result = self.loader.load_plugin("/path/to/plugin.py", "plugin")

            self.assertIsNone(result)

    def test_load_plugin_successful(self):
        """Test successfully loading a valid plugin."""
        plugin_file = Path(self.temp_dir) / "valid_plugin.py"
        plugin_file.write_text("""
from cli.plugin_system import PluginInterface

class ValidPlugin(PluginInterface):
    name = "valid_plugin"
    version = "1.0.0"
    description = "A valid test plugin"

    def initialize(self):
        pass

    def get_roles(self):
        return {}

    def get_hooks(self):
        return {}

    def validate(self):
        return True, []
""")

        with patch("cli.plugin_system.PluginValidator") as mock_validator_class:
            mock_validator = Mock()
            mock_validator.validate_plugin.return_value = (True, "Valid")
            mock_validator_class.return_value = mock_validator

            result = self.loader.load_plugin(str(plugin_file), "valid_plugin")

            self.assertIsNotNone(result)
            self.assertEqual(result.name, "valid_plugin")
            self.assertEqual(result.version, "1.0.0")

    def test_load_plugin_no_plugin_interface_found(self):
        """Test loading plugin when no PluginInterface found in module."""
        plugin_file = Path(self.temp_dir) / "no_interface_plugin.py"
        plugin_file.write_text("""
# Plugin file with no PluginInterface class
class NotAPlugin:
    pass
""")

        with patch("cli.plugin_system.PluginValidator") as mock_validator_class:
            mock_validator = Mock()
            mock_validator.validate_plugin.return_value = (True, "Valid")
            mock_validator_class.return_value = mock_validator

            result = self.loader.load_plugin(str(plugin_file), "no_interface_plugin")

            # Should return None because no PluginInterface was found
            self.assertIsNone(result)


class TestPluginLoaderAdvanced(unittest.TestCase):
    """Test PluginLoader advanced functionality."""

    def setUp(self):
        """Set up test loader."""
        self.temp_dir = tempfile.mkdtemp()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_add_plugin_path(self):
        """Test adding plugin paths."""
        plugin_path = Path(self.temp_dir)
        self.loader.add_plugin_path(plugin_path)

        self.assertIn(plugin_path, self.loader.plugin_paths)

    def test_discover_plugins_empty_directory(self):
        """Test discovering plugins in empty directory."""
        self.loader.plugin_paths = [Path(self.temp_dir)]

        discovered = self.loader.discover_plugins()

        self.assertEqual(len(discovered), 0)

    def test_list_plugins_empty(self):
        """Test listing plugins when none are loaded."""
        plugins = self.loader.list_plugins()

        self.assertEqual(len(plugins), 0)

    def test_list_plugins_after_loading(self):
        """Test listing plugins after loading."""
        # Create a mock plugin
        plugin = Mock(spec=PluginInterface)
        plugin.name = "test_plugin"
        plugin.version = "1.0.0"

        self.loader.plugins["test_plugin"] = plugin

        plugins = self.loader.list_plugins()

        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0], "test_plugin")

    def test_execute_hooks_success(self):
        """Test successful hook execution."""
        hook = Mock(spec=HookInterface)
        hook.execute.return_value = True

        self.loader.hooks["pre_setup"] = [hook]
        ctx = HookContext(stage="pre_setup")

        result = self.loader.execute_hooks("pre_setup", ctx)

        self.assertTrue(result)
        hook.execute.assert_called_once()

    def test_execute_hooks_empty(self):
        """Test executing hooks when none are registered."""
        ctx = HookContext(stage="nonexistent")

        result = self.loader.execute_hooks("nonexistent", ctx)

        # Should handle gracefully
        self.assertTrue(result)

    def test_plugin_count(self):
        """Test plugin count."""
        plugin1 = Mock(spec=PluginInterface)
        plugin1.name = "plugin1"

        plugin2 = Mock(spec=PluginInterface)
        plugin2.name = "plugin2"

        self.loader.plugins["plugin1"] = plugin1
        self.loader.plugins["plugin2"] = plugin2

        self.assertEqual(len(self.loader.plugins), 2)

    def test_hook_count(self):
        """Test hook count."""
        hook1 = Mock(spec=HookInterface)
        hook2 = Mock(spec=HookInterface)

        self.loader.hooks["pre_setup"] = [hook1]
        self.loader.hooks["post_role"] = [hook2]

        total_hooks = sum(len(hooks) for hooks in self.loader.hooks.values())
        self.assertEqual(total_hooks, 2)


class TestBuiltinHook(unittest.TestCase):
    """Test BuiltinHook implementation."""

    def test_builtin_hook_creation(self):
        """Test creating builtin hook."""
        from cli.plugin_system import BuiltinHook

        hook = BuiltinHook("test_hook")

        self.assertEqual(hook.name, "test_hook")

    def test_builtin_hook_execute(self):
        """Test executing builtin hook."""
        from cli.plugin_system import BuiltinHook

        hook = BuiltinHook("test_hook")
        ctx = HookContext(stage="test")

        result = hook.execute(ctx)

        self.assertTrue(result)


class TestSimplePlugin(unittest.TestCase):
    """Test SimplePlugin example."""

    def test_simple_plugin_creation(self):
        """Test creating simple plugin."""
        from cli.plugin_system import SimplePlugin

        plugin = SimplePlugin()

        self.assertEqual(plugin.name, "example")
        self.assertEqual(plugin.version, "1.0.0")

    def test_simple_plugin_initialize(self):
        """Test simple plugin initialization."""
        from cli.plugin_system import SimplePlugin

        plugin = SimplePlugin()

        # Should not raise
        plugin.initialize()

    def test_simple_plugin_get_roles(self):
        """Test getting roles from simple plugin."""
        from cli.plugin_system import SimplePlugin

        plugin = SimplePlugin()
        roles = plugin.get_roles()

        self.assertEqual(roles, {})

    def test_simple_plugin_get_hooks(self):
        """Test getting hooks from simple plugin."""
        from cli.plugin_system import SimplePlugin

        plugin = SimplePlugin()
        hooks = plugin.get_hooks()

        self.assertEqual(hooks, {})

    def test_simple_plugin_validate(self):
        """Test validating simple plugin."""
        from cli.plugin_system import SimplePlugin

        plugin = SimplePlugin()
        is_valid, errors = plugin.validate()

        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)


class TestHookContextMetadata(unittest.TestCase):
    """Test HookContext metadata functionality."""

    def test_hook_context_with_metadata(self):
        """Test HookContext with metadata."""
        metadata = {"key": "value", "count": 42}
        ctx = HookContext(stage="test", metadata=metadata)

        self.assertEqual(ctx.metadata, metadata)
        self.assertEqual(ctx.metadata["key"], "value")

    def test_hook_context_status_transitions(self):
        """Test HookContext status transitions."""
        ctx = HookContext(stage="test")

        # Initial status
        self.assertEqual(ctx.status, "running")

        # Modify status
        ctx.status = "success"
        self.assertEqual(ctx.status, "success")

        ctx.status = "failed"
        self.assertEqual(ctx.status, "failed")

    def test_hook_context_error_message(self):
        """Test HookContext error messages."""
        error_msg = "Test error occurred"
        ctx = HookContext(stage="test", error=error_msg)

        self.assertEqual(ctx.error, error_msg)

    def test_hook_context_all_fields(self):
        """Test HookContext with all fields."""
        ctx = HookContext(
            stage="post_role",
            role="shell",
            task="install_zsh",
            status="success",
            error=None,
            metadata={"duration": 5.2},
        )

        self.assertEqual(ctx.stage, "post_role")
        self.assertEqual(ctx.role, "shell")
        self.assertEqual(ctx.task, "install_zsh")
        self.assertEqual(ctx.status, "success")
        self.assertIsNone(ctx.error)
        self.assertIsNotNone(ctx.metadata)


class TestPluginLoaderIntegration(unittest.TestCase):
    """Integration tests for PluginLoader."""

    def setUp(self):
        """Set up test loader."""
        self.temp_dir = tempfile.mkdtemp()
        self.loader = PluginLoader()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_loader_initialization(self):
        """Test loader is properly initialized."""
        self.assertIsNotNone(self.loader.plugins)
        self.assertIsNotNone(self.loader.hooks)
        self.assertIsNotNone(self.loader.plugin_paths)

    def test_loader_empty_plugin_dict(self):
        """Test loader starts with empty plugins."""
        self.assertEqual(len(self.loader.plugins), 0)

    def test_loader_empty_hooks_dict(self):
        """Test loader starts with empty hooks."""
        self.assertEqual(len(self.loader.hooks), 0)


if __name__ == "__main__":
    unittest.main()
