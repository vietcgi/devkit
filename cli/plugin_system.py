#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
# !/usr/bin/env python3
"""Mac-Setup Plugin System.

Allows users to extend devkit with custom roles, hooks, and tasks.
Plugins can be defined in ~/.devkit/plugins/ and are auto-discovered.

SECURITY: All plugins are validated before loading using PluginValidator.
Plugins must have a valid manifest.json and implement PluginInterface.
"""

import argparse
import importlib.util
import json
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

# Security: Import validator
from cli.utils import setup_logger

from .plugin_validator import PluginManifest, PluginValidator


class HookContext:  # pylint: disable=too-few-public-methods
    """Context passed to hooks."""

    def __init__(
        self,
        stage: str,
        role: str | None = None,
        task: str | None = None,
        status: str = "running",
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize hook context.

        Args:
            stage: Hook stage ("pre_setup", "post_setup", "pre_role", "post_role")
            role: Role name (optional)
            task: Task name (optional)
            status: Status ("running", "success", "failed")
            error: Error message (optional)
            metadata: Additional metadata (optional)
        """
        self.stage = stage
        self.role = role
        self.task = task
        self.status = status
        self.error = error
        self.metadata = metadata


class HookInterface(ABC):  # pylint: disable=too-few-public-methods
    """Base class for plugin hooks."""

    @abstractmethod
    def execute(self, context: HookContext) -> bool:
        """Execute hook.

        Args:
            context: Hook execution context

        Returns:
            True if successful, False otherwise
        """


class PluginInterface(ABC):
    """Base class for devkit plugins."""

    name: str
    version: str
    description: str

    @abstractmethod
    def initialize(self) -> None:
        """Initialize plugin."""

    @abstractmethod
    def get_roles(self) -> dict[str, Path]:
        """Get custom roles provided by plugin.

        Returns:
            Dictionary mapping role names to role directories
        """

    @abstractmethod
    def get_hooks(self) -> dict[str, list[HookInterface]]:
        """Get hooks for various stages.

        Returns:
            Dictionary mapping stage names to lists of hooks
        """

    @abstractmethod
    def validate(self) -> tuple[bool, list[str]]:
        """Validate plugin configuration.

        Returns:
            Tuple of (is_valid, error_list)
        """


class PluginLoader:
    """Loads and manages devkit plugins.

    Searches for plugins in:
    1. ~/.devkit/plugins/ (user plugins)
    2. ./plugins/ (project plugins)
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize plugin loader.

        Args:
            logger: Logger instance
        """
        self.logger = logger or self._setup_logger()
        self.plugins: dict[str, PluginInterface] = {}
        self.hooks: dict[str, list[HookInterface]] = {}
        self.plugin_paths: list[Path] = []

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Setup default logger."""
        return setup_logger("devkit.plugins")

    def add_plugin_path(self, path: Path) -> None:
        """Add directory to plugin search path."""
        path = Path(path).expanduser()
        if path.exists() and path.is_dir():
            self.plugin_paths.append(path)
            self.logger.debug("Added plugin path: %s", path)
        else:
            self.logger.warning("Plugin path not found: %s", path)

    def discover_plugins(self) -> list[tuple[str, str]]:
        """Auto-discover plugins in configured paths.

        Returns:
            List of discovered plugin (path, module_name) tuples
        """
        discovered: list[tuple[str, str]] = []

        for plugin_dir in self.plugin_paths:
            if not plugin_dir.exists():
                continue

            # Look for Python modules and packages
            for item in plugin_dir.iterdir():
                if item.name.startswith("_"):
                    continue

                if item.is_file() and item.suffix == ".py":
                    # Python file plugin
                    module_name = item.stem
                    discovered.append((str(item), module_name))

                elif item.is_dir() and (item / "__init__.py").exists():
                    # Python package plugin
                    module_name = item.name
                    discovered.append((str(item), module_name))

        self.logger.info("Discovered %d plugins", len(discovered))
        return discovered

    def _validate_plugin_manifest(self, plugin_dir: Path, module_name: str) -> bool:
        """Validate plugin manifest integrity."""
        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            return True

        try:
            manifest = PluginManifest(manifest_path)
            integrity_valid, integrity_message = manifest.verify_integrity()
            if not integrity_valid:
                self.logger.error(
                    "Plugin integrity check failed for %s: %s",
                    module_name,
                    integrity_message,
                )
                return False
            self.logger.debug("Plugin integrity verified for %s", module_name)
            return True
        except (OSError, ValueError, json.JSONDecodeError):
            self.logger.exception(
                "Failed to verify plugin integrity for %s",
                module_name,
            )
            return False

    def _load_plugin_module(
        self,
        full_module_name: str,
        plugin_path: str,
        module_name: str,
    ) -> Any:
        """Load plugin module from file."""
        spec = importlib.util.spec_from_file_location(full_module_name, plugin_path)
        if not spec or not spec.loader:
            self.logger.error("Could not load spec for %s", module_name)
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[full_module_name] = module
        spec.loader.exec_module(module)
        return module

    def _find_plugin_class(self, module: Any, module_name: str) -> PluginInterface | None:
        """Find and instantiate plugin class from module."""
        for item_name in dir(module):
            item = getattr(module, item_name)
            if (
                isinstance(item, type)
                and issubclass(item, PluginInterface)
                and item is not PluginInterface
            ):
                plugin_instance = item()
                plugin_instance.initialize()

                is_valid, errors = plugin_instance.validate()
                if not is_valid:
                    self.logger.warning("Plugin %s validation failed: %s", module_name, errors)
                    return None

                self.logger.info(
                    "Loaded plugin: %s v%s",
                    plugin_instance.name,
                    plugin_instance.version,
                )
                return plugin_instance
        return None

    def load_plugin(
        self,
        plugin_path: str,
        module_name: str,
    ) -> PluginInterface | None:
        """Load a single plugin module with security validation.

        SECURITY: Before loading, validates:
        1. Plugin manifest exists and is valid
        2. Plugin implements PluginInterface
        3. Plugin integrity is verified

        Args:
            plugin_path: Path to plugin file or directory
            module_name: Module name

        Returns:
            Loaded plugin instance or None
        """
        try:
            # SECURITY: Validate plugin before loading
            plugin_dir = Path(plugin_path)
            validator = PluginValidator(plugin_dir.parent)
            is_valid, message = validator.validate_plugin(module_name)

            if not is_valid:
                self.logger.error("Plugin validation failed for %s: %s", module_name, message)
                return None

            # SECURITY: Verify manifest integrity
            if not self._validate_plugin_manifest(plugin_dir, module_name):
                return None

            self.logger.debug("Plugin validation passed for %s", module_name)

            # Create a proper module name with namespace
            full_module_name = f"mac_setup_plugins.{module_name}"

            # Load the module
            module = self._load_plugin_module(full_module_name, plugin_path, module_name)
            if module is None:
                return None

            # Find and instantiate plugin class
            return self._find_plugin_class(module, module_name)
        except (ImportError, AttributeError, OSError):
            self.logger.exception("Error loading plugin %s", module_name)
            return None

    def load_all(self, plugin_paths: list[Path] | None = None) -> int:
        """Discover and load all plugins.

        Args:
            plugin_paths: Optional list of paths to search

        Returns:
            Number of successfully loaded plugins
        """
        # Add default paths
        if not plugin_paths:
            plugin_paths = [
                Path.home() / ".devkit" / "plugins",
                Path(__file__).parent.parent / "plugins",
            ]

        for path in plugin_paths:
            self.add_plugin_path(path)

        # Discover plugins
        discovered = self.discover_plugins()

        # Load each plugin
        loaded = 0
        for plugin_path_str, module_name_str in discovered:
            plugin = self.load_plugin(plugin_path_str, module_name_str)
            if plugin:
                self.plugins[plugin.name] = plugin
                loaded += 1

                # Register hooks
                for stage, hooks in plugin.get_hooks().items():
                    if stage not in self.hooks:
                        self.hooks[stage] = []
                    self.hooks[stage].extend(hooks)

        self.logger.info("Successfully loaded %d/%d plugins", loaded, len(discovered))
        return loaded

    def get_plugin(self, name: str) -> PluginInterface | None:
        """Get plugin by name."""
        return self.plugins.get(name)

    def list_plugins(self) -> list[str]:
        """List loaded plugin names."""
        return list(self.plugins.keys())

    def get_plugin_roles(self) -> dict[str, Path]:
        """Get all custom roles from loaded plugins."""
        roles: dict[str, Path] = {}
        for plugin in self.plugins.values():
            roles.update(plugin.get_roles())
        return roles

    def execute_hooks(self, stage: str, context: HookContext | None = None) -> bool:
        """Execute all hooks for a given stage.

        Args:
            stage: Hook stage name
            context: Hook context

        Returns:
            True if all hooks succeeded, False otherwise
        """
        if not context:
            context = HookContext(stage=stage)

        hooks = self.hooks.get(stage, [])
        if not hooks:
            return True

        self.logger.debug("Executing %d hooks for stage: %s", len(hooks), stage)

        for hook in hooks:
            try:
                if not hook.execute(context):
                    self.logger.warning("Hook failed for stage %s", stage)
                    context.status = "failed"
                    return False
            except (OSError, RuntimeError, ValueError) as e:
                self.logger.exception("Hook execution error")
                context.error = str(e)
                context.status = "failed"
                return False

        context.status = "success"
        return True

    def get_plugin_info(self) -> dict[str, dict[str, Any]]:
        """Get information about all loaded plugins."""
        info = {}
        for name, plugin in self.plugins.items():
            info[name] = {
                "version": plugin.version,
                "description": plugin.description,
                "roles": len(plugin.get_roles()),
                "hooks": sum(len(h) for h in plugin.get_hooks().values()),
            }
        return info


class BuiltinHook(HookInterface):  # pylint: disable=too-few-public-methods
    """Base class for builtin hooks."""

    def __init__(self, name: str) -> None:
        """Initialize builtin hook with name."""
        self.name = name

    @staticmethod
    def execute(_context: HookContext) -> bool:  # pylint: disable=arguments-differ
        """Execute hook."""
        return True


class SimplePlugin(PluginInterface):
    """Example simple plugin for reference.

    Users can create their own plugins by extending PluginInterface.
    """

    name = "example"
    version = "1.0.0"
    description = "Example plugin"

    def initialize(self) -> None:
        """Initialize plugin."""

    @staticmethod
    def get_roles() -> dict[str, Path]:  # pylint: disable=arguments-differ
        """Return custom roles."""
        return {}

    @staticmethod
    def get_hooks() -> dict[str, list[HookInterface]]:  # pylint: disable=arguments-differ
        """Return hooks."""
        return {}

    @staticmethod
    def validate() -> tuple[bool, list[str]]:  # pylint: disable=arguments-differ
        """Validate plugin."""
        return True, []


def _display_plugin_list(loader: "PluginLoader") -> None:  # pylint: disable=unused-argument
    """Display list of loaded plugins."""
    plugins = loader.list_plugins()
    print(f'\n{"Loaded Plugins":^50}')  # noqa: T201
    print("=" * 50)  # noqa: T201
    if plugins:
        for plugin in plugins:
            print(f"  • {plugin}")  # noqa: T201
    else:
        print("  (No plugins loaded)")  # noqa: T201
    print()  # noqa: T201


def _display_plugin_info(loader: "PluginLoader") -> None:  # pylint: disable=unused-argument
    """Display detailed plugin information."""
    info = loader.get_plugin_info()
    print(f'\n{"Plugin Information":^50}')  # noqa: T201
    print("=" * 50)  # noqa: T201
    if info:
        for name, details in info.items():
            print(f"\n{name}:")  # noqa: T201
            print(f'  Version:     {details.get("version", "unknown")}')  # noqa: T201
            print(f'  Description: {details.get("description", "N/A")}')  # noqa: T201
            print(f'  Roles:       {details.get("roles", 0)}')  # noqa: T201
            print(f'  Hooks:       {details.get("hooks", 0)}')  # noqa: T201
    else:
        print("  (No plugin information available)")  # noqa: T201
    print()  # noqa: T201


def _display_plugin_validation(loader: "PluginLoader") -> None:  # pylint: disable=unused-argument
    """Display plugin validation status."""
    plugins = loader.list_plugins()
    print(f'\n{"Plugin Validation":^50}')  # noqa: T201
    print("=" * 50)  # noqa: T201
    if plugins:
        print(f"✓ {len(plugins)} plugin(s) validated successfully")  # noqa: T201
        for plugin in plugins:
            print(f"  ✓ {plugin}")  # noqa: T201
    else:
        print("  (No plugins to validate)")  # noqa: T201
    print()  # noqa: T201


def _display_plugin_summary(loader: "PluginLoader") -> None:  # pylint: disable=unused-argument
    """Display plugin system summary."""
    plugins = loader.list_plugins()
    print(f'\n{"Plugin System Status":^50}')  # noqa: T201
    print("=" * 50)  # noqa: T201
    print(f"Plugins loaded: {len(plugins)}")  # noqa: T201
    if plugins:
        print("Installed plugins:")  # noqa: T201
        for plugin in plugins:
            print(f"  • {plugin}")  # noqa: T201
    else:
        print("  (No plugins installed)")  # noqa: T201
    print()  # noqa: T201


def main() -> None:
    """CLI interface for plugin system."""
    parser = argparse.ArgumentParser(description="Mac-Setup Plugin System")
    parser.add_argument("--plugin-path", action="append", help="Add plugin path")
    parser.add_argument("--list", action="store_true", help="List plugins")
    parser.add_argument("--info", action="store_true", help="Show plugin info")
    parser.add_argument("--validate", action="store_true", help="Validate plugins")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Create loader
    loader = PluginLoader()

    # Add custom paths
    if args.plugin_path:
        for path in args.plugin_path:
            loader.add_plugin_path(Path(path))

    # Load plugins
    loader.load_all()

    # Handle commands
    if args.list:
        _display_plugin_list(loader)
    elif args.info:
        _display_plugin_info(loader)
    elif args.validate:
        _display_plugin_validation(loader)
    else:
        _display_plugin_summary(loader)


if __name__ == "__main__":
    main()

# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "BuiltinHook",
    "HookContext",
    "HookInterface",
    "PluginInterface",
    "PluginLoader",
    "SimplePlugin",
]
