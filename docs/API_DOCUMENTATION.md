# API Documentation

## Configuration Engine API

### `ConfigurationEngine(config_dir: Path)`

Main configuration management class for loading, validating, and accessing configuration.

#### Methods

##### `load_file(path: Path | str) -> bool`

Load configuration from a YAML or JSON file.

```python
from cli.config_engine import ConfigurationEngine
from pathlib import Path

engine = ConfigurationEngine(Path("./config"))
engine.load_file("config.yml")
```

**Parameters:**

- `path`: Path to configuration file

**Returns:** `bool` - True if successful

**Raises:**

- `FileNotFoundError`: If file doesn't exist
- `ValueError`: If file format is invalid

---

##### `get(key: str) -> Any`

Retrieve a configuration value by key using dot notation.

```python
value = engine.get("logging.level")
debug = engine.get("debug", default=False)
```

**Parameters:**

- `key`: Configuration key (supports dot notation for nested access)

**Returns:** `Any` - Configuration value or None

---

##### `set(key: str, value: Any) -> None`

Set a configuration value.

```python
engine.set("logging.level", "DEBUG")
```

**Parameters:**

- `key`: Configuration key
- `value`: Value to set

---

##### `validate() -> tuple[bool, list[str]]`

Validate entire configuration against schema.

```python
is_valid, errors = engine.validate()
if not is_valid:
    for error in errors:
        print(f"Validation error: {error}")
```

**Returns:** Tuple of (is_valid, error_list)

---

## Plugin System API

### `PluginLoader(logger: logging.Logger | None = None)`

Plugin discovery, loading, and management system.

#### Methods

##### `add_plugin_path(path: Path) -> None`

Register a directory to search for plugins.

```python
from cli.plugin_system import PluginLoader
from pathlib import Path

loader = PluginLoader()
loader.add_plugin_path(Path("~/.devkit/plugins"))
loader.add_plugin_path(Path("./plugins"))
```

**Parameters:**

- `path`: Directory path containing plugins

---

##### `discover_plugins() -> list[tuple[str, str]]`

Auto-discover plugins in registered paths.

```python
discovered = loader.discover_plugins()
for plugin_path, module_name in discovered:
    print(f"Found plugin: {module_name} at {plugin_path}")
```

**Returns:** List of (path, module_name) tuples

---

##### `load_all(plugin_paths: list[Path] | None = None) -> int`

Discover and load all plugins.

```python
loaded_count = loader.load_all()
print(f"Loaded {loaded_count} plugins")
```

**Parameters:**

- `plugin_paths`: Optional list of paths to search

**Returns:** Number of successfully loaded plugins

---

##### `load_plugin(plugin_path: str, module_name: str) -> PluginInterface | None`

Load a single plugin with security validation.

```python
plugin = loader.load_plugin("./plugins/my_plugin", "my_plugin")
if plugin:
    plugin.initialize()
```

**Parameters:**

- `plugin_path`: Path to plugin file/directory
- `module_name`: Module name

**Returns:** Plugin instance or None if loading failed

---

##### `execute_hooks(stage: str, context: HookContext | None = None) -> bool`

Execute all hooks registered for a given stage.

```python
from cli.plugin_system import HookContext

context = HookContext(stage="pre_setup", role="nginx")
success = loader.execute_hooks("pre_setup", context)
```

**Parameters:**

- `stage`: Hook stage name (e.g., "pre_setup", "post_setup")
- `context`: Hook execution context

**Returns:** True if all hooks succeeded

---

##### `list_plugins() -> list[str]`

List names of all loaded plugins.

```python
plugins = loader.list_plugins()
for name in plugins:
    print(f"Loaded plugin: {name}")
```

**Returns:** List of plugin names

---

### `PluginInterface` (Abstract Base Class)

Base class for creating plugins.

#### Abstract Methods

```python
from cli.plugin_system import PluginInterface, HookInterface

class MyPlugin(PluginInterface):
    name = "my_plugin"
    version = "1.0.0"
    description = "My custom plugin"

    def initialize(self) -> None:
        """Initialize plugin resources."""
        pass

    def get_roles(self) -> dict[str, Path]:
        """Provide custom roles."""
        return {
            "custom_role": Path("./roles/custom_role")
        }

    def get_hooks(self) -> dict[str, list[HookInterface]]:
        """Register hooks for lifecycle events."""
        return {
            "pre_setup": [MyPreSetupHook()],
            "post_setup": [MyPostSetupHook()]
        }

    def validate(self) -> tuple[bool, list[str]]:
        """Validate plugin configuration."""
        return True, []
```

---

### `HookContext`

Context passed to hook execution.

#### Attributes

```python
class HookContext:
    stage: str              # Hook stage name
    role: str | None        # Role name (optional)
    task: str | None        # Task name (optional)
    status: str             # "running", "success", or "failed"
    error: str | None       # Error message if failed
    metadata: dict[str, Any] # Additional context
```

#### Example

```python
context = HookContext(
    stage="pre_setup",
    role="webserver",
    task="configure_nginx",
    status="running",
    metadata={"port": 8080}
)
```

---

## Plugin Validator API

### `PluginValidator(plugins_dir: Path, logger: logging.Logger | None = None)`

Comprehensive plugin validation system.

#### Methods

##### `validate_plugin(plugin_name: str) -> tuple[bool, str]`

Validate a single plugin before loading.

```python
from cli.plugin_validator import PluginValidator
from pathlib import Path

validator = PluginValidator(Path("./plugins"))
is_valid, message = validator.validate_plugin("my_plugin")

if not is_valid:
    print(f"Validation failed: {message}")
```

**Parameters:**

- `plugin_name`: Name of plugin directory

**Returns:** Tuple of (is_valid, message)

---

##### `validate_all_plugins() -> dict[str, tuple[bool, str]]`

Validate all plugins in the registered directory.

```python
results = validator.validate_all_plugins()
for plugin_name, (is_valid, message) in results.items():
    status = "✓" if is_valid else "✗"
    print(f"{status} {plugin_name}: {message}")
```

**Returns:** Dictionary mapping plugin names to validation results

---

##### `get_plugin_info(plugin_name: str) -> dict[str, Any] | None`

Get metadata from a plugin's manifest.

```python
info = validator.get_plugin_info("my_plugin")
if info:
    print(f"Name: {info['name']}")
    print(f"Version: {info['version']}")
    print(f"Author: {info['author']}")
```

**Returns:** Plugin manifest dictionary or None

---

### `PluginManifest(manifest_path: Path)`

Plugin manifest validation and integrity checking.

#### Methods

##### `validate() -> tuple[bool, list[str]]`

Validate manifest against schema.

```python
from cli.plugin_validator import PluginManifest

manifest = PluginManifest(Path("plugins/my_plugin/manifest.json"))
is_valid, errors = manifest.validate()
```

**Returns:** Tuple of (is_valid, error_list)

---

##### `verify_integrity() -> tuple[bool, str]`

Verify manifest integrity using SHA256 checksum.

```python
is_valid, message = manifest.verify_integrity()
print(message)  # "Manifest integrity verified" or error message
```

**Returns:** Tuple of (is_valid, message)

---

##### `generate_checksum() -> str`

Generate and store SHA256 checksum for manifest.

```python
checksum = manifest.generate_checksum()
manifest.data["checksum"] = checksum
# Save updated manifest
```

**Returns:** Computed checksum as hex string

---

## Health Check API

### `health_check() -> dict[str, Any]`

Perform comprehensive system health check.

```python
from cli.health_check import health_check

result = health_check()
print(f"Overall health: {result['status']}")
print(f"Components: {result['components']}")
```

**Returns:** Health check result dictionary

**Result Format:**

```python
{
    "status": "healthy" | "degraded" | "unhealthy",
    "components": {
        "configuration": {"status": "healthy"},
        "plugins": {"status": "healthy", "loaded": 5},
        "git": {"status": "healthy"},
        "performance": {"status": "healthy"}
    },
    "timestamp": "2025-01-01T00:00:00Z"
}
```

---

## Performance API

### `PerformanceMonitor()`

Track and report performance metrics.

```python
from cli.performance import PerformanceMonitor

monitor = PerformanceMonitor()
monitor.start("operation")
# ... perform operation ...
duration = monitor.stop("operation")
print(f"Operation took {duration:.2f}s")
```

---

### `CacheManager(cache_dir: Path)`

Multi-level caching system.

```python
from cli.performance import CacheManager
from pathlib import Path

cache = CacheManager(Path("./cache"))

# Store value
cache.set("key", {"data": "value"}, ttl=3600)

# Retrieve value
value = cache.get("key")

# Clear cache
cache.clear()
```

---

## Git Configuration API

### `GitConfigManager(repo_path: Path, logger: logging.Logger | None = None)`

Git repository management.

```python
from cli.git_config_manager import GitConfigManager
from pathlib import Path

manager = GitConfigManager(Path("."))

# Check if repo is dirty
is_dirty = manager.is_dirty()

# Get current branch
branch = manager.get_current_branch()

# Get commit info
commit = manager.get_commit_info("HEAD")
```

---

## Error Handling

All API methods follow consistent error handling:

```python
from cli.config_engine import ConfigError, ConfigPermissionError

try:
    engine.load_file("config.yml")
except FileNotFoundError as e:
    print(f"Configuration file not found: {e}")
except ConfigPermissionError as e:
    print(f"Permission denied: {e}")
except ConfigError as e:
    print(f"Configuration error: {e}")
```

---

## Common Usage Patterns

### Initialize System

```python
from cli.config_engine import ConfigurationEngine
from cli.plugin_system import PluginLoader
from pathlib import Path

# Load configuration
config = ConfigurationEngine(Path("./config"))
config.load_file("config.yml")

# Load plugins
loader = PluginLoader()
loader.add_plugin_path(Path("./plugins"))
loaded = loader.load_all()
print(f"Loaded {loaded} plugins")
```

### Create Custom Plugin

```python
from cli.plugin_system import PluginInterface, HookInterface, HookContext
from pathlib import Path

class MyHook(HookInterface):
    def execute(self, context: HookContext) -> bool:
        print(f"Hook executed for stage: {context.stage}")
        return True

class MyPlugin(PluginInterface):
    name = "my_plugin"
    version = "1.0.0"
    description = "My custom plugin"

    def initialize(self):
        print("Plugin initialized")

    def get_roles(self):
        return {"my_role": Path("./roles/my_role")}

    def get_hooks(self):
        return {"pre_setup": [MyHook()]}

    def validate(self):
        return True, []
```

### Validate Configuration

```python
from cli.config_engine import ConfigurationEngine

engine = ConfigurationEngine(Path("./config"))
engine.load_file("config.yml")

is_valid, errors = engine.validate()
if not is_valid:
    for error in errors:
        print(f"Error: {error}")
```

---

## References

- [Architecture Documentation](ARCHITECTURE.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [Performance Report](PERFORMANCE_REPORT.md)
