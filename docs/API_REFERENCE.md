# Mac-Setup API Reference

Complete API documentation for devkit v2.0 components.

---

## Configuration Engine API

### ConfigurationEngine Class

```python
from cli.config_engine import ConfigurationEngine

engine = ConfigurationEngine(project_root=None, logger=None)
```

#### Methods

##### load_defaults()

Load default configuration from schema.

```python
engine.load_defaults()
```

##### load_file(file_path, section=None)

Load configuration from YAML file.

```python
config = engine.load_file('~/.devkit/config.yaml')
```

##### load_environment_overrides()

Load configuration from environment variables (MAC_SETUP_*).

```python
overrides = engine.load_environment_overrides()
```

##### load_all(group=None, platform=None, local_config=None)

Load all configuration in priority order.

```python
config = engine.load_all(group="development", platform="macos")
```

##### get(key, default=None)

Get configuration value using dot notation.

```python
level = engine.get("global.logging.level")
roles = engine.get("global.enabled_roles", [])
```

##### set(key, value)

Set configuration value using dot notation.

```python
engine.set("global.logging.level", "debug")
```

##### validate()

Validate configuration against schema.

```python
is_valid, errors = engine.validate()
```

##### export(format_type)

Export configuration in YAML or JSON format.

```python
yaml_str = engine.export("yaml")
json_str = engine.export("json")
```

##### save(file_path)

Save current configuration to file.

```python
engine.save("~/.devkit/config.yaml")
```

##### get_enabled_roles()

Get list of enabled roles based on current configuration.

```python
roles = engine.get_enabled_roles()
```

##### get_role_config(role)

Get configuration for specific role.

```python
config = engine.get_role_config("shell")
```

---

## Plugin System API

### PluginInterface (Abstract Base Class)

```python
from cli.plugin_system import PluginInterface, HookInterface, HookContext

class MyPlugin(PluginInterface):
    name = "my_plugin"
    version = "1.0.0"
    description = "Description"

    def initialize(self) -> None:
        """Called when plugin is loaded."""
        pass

    def get_roles(self) -> Dict[str, Path]:
        """Return custom Ansible roles."""
        return {}

    def get_hooks(self) -> Dict[str, List[HookInterface]]:
        """Return hooks for various stages."""
        return {}

    def validate(self) -> tuple[bool, List[str]]:
        """Validate plugin. Return (is_valid, error_list)."""
        return True, []
```

### HookInterface (Abstract Base Class)

```python
from cli.plugin_system import HookInterface, HookContext

class MyHook(HookInterface):
    def execute(self, context: HookContext) -> bool:
        """Execute hook. Return True if successful."""
        return True
```

### HookContext (Data Class)

```python
@dataclass
class HookContext:
    stage: str                      # Hook stage name
    role: Optional[str] = None      # Role name
    task: Optional[str] = None      # Task name
    status: str = "running"         # Status: running, success, failed
    error: Optional[str] = None     # Error message if failed
    metadata: Dict[str, Any] = None # Additional context
```

### PluginLoader Class

```python
from cli.plugin_system import PluginLoader
from pathlib import Path

loader = PluginLoader(logger=None)
```

#### Methods

##### add_plugin_path(path)

Add directory to plugin search path.

```python
loader.add_plugin_path(Path.home() / ".devkit" / "plugins")
```

##### discover_plugins()

Auto-discover plugins in configured paths.

```python
discovered = loader.discover_plugins()  # Returns list of (path, module_name)
```

##### load_plugin(plugin_path, module_name)

Load a single plugin module.

```python
plugin = loader.load_plugin("/path/to/plugin.py", "plugin_name")
```

##### load_all(plugin_paths=None)

Discover and load all plugins.

```python
count = loader.load_all()
```

##### get_plugin(name)

Get plugin by name.

```python
plugin = loader.get_plugin("docker_dev")
```

##### list_plugins()

Get list of loaded plugin names.

```python
plugins = loader.list_plugins()
```

##### get_plugin_roles()

Get all custom roles from loaded plugins.

```python
roles = loader.get_plugin_roles()
```

##### execute_hooks(stage, context=None)

Execute all hooks for a given stage.

```python
context = HookContext(stage="pre_setup")
success = loader.execute_hooks("pre_setup", context)
```

##### get_plugin_info()

Get information about all loaded plugins.

```python
info = loader.get_plugin_info()
```

---

## Setup Wizard API

### SetupWizard Class

```python
from cli.setup_wizard import SetupWizard

wizard = SetupWizard(project_root=None)
```

#### Methods

##### run()

Run the interactive setup wizard.

```python
config = wizard.run()  # Returns Dict[str, Any]
```

##### save_config(file_path=None)

Save configuration to file.

```python
path = wizard.save_config("~/.devkit/config.yaml")
```

---

## Test Suite API

### TestSuite Class

```python
from tests.test_suite import TestSuite

suite = TestSuite(project_root=None)
```

#### Methods

##### run_all()

Run all test suites.

```python
exit_code = suite.run_all()  # Returns 0 for pass, 1 for fail
```

#### Test Result Class

```python
@dataclass
class TestResult:
    name: str
    status: TestStatus  # PASS, FAIL, SKIP, WARN
    message: str
    duration: float = 0.0
    details: Optional[str] = None
```

---

## Environment Variables

### Configuration Overrides

Configure devkit via environment variables using MAC_SETUP_ prefix:

```bash
# Simple values
MAC_SETUP_LOGGING_LEVEL=debug

# Arrays (comma-separated)
MAC_SETUP_ENABLED_ROLES=core,shell,editors

# Nested keys (double underscore)
MAC_SETUP_GLOBAL__LOGGING__LEVEL=debug
MAC_SETUP_GLOBAL__PERFORMANCE__PARALLEL_TASKS=8
```

---

## Configuration Schema

### Global Settings

```yaml
global:
  setup_name: string              # Friendly name
  setup_environment: string       # development/staging/production
  enabled_roles: [string]         # List of roles to enable
  disabled_roles: [string]        # List of roles to disable

  logging:
    enabled: boolean
    level: string                 # debug/info/warning/error
    file: string
    archive: boolean

  performance:
    parallel_tasks: integer
    timeout: integer              # Seconds
    cache_downloads: boolean

  backup:
    enabled: boolean
    path: string
    max_backups: integer
    compress: boolean

  verification:
    enabled: boolean
    run_after_setup: boolean
    detailed_report: boolean

  security:
    enable_ssh_setup: boolean
    enable_gpg_setup: boolean
    enable_audit_logging: boolean
    require_verification: boolean

  updates:
    check_for_updates: boolean
    auto_update_tools: boolean
    update_interval: string       # daily/weekly/monthly
```

---

## Command-Line Interfaces

### Configuration Engine CLI

```bash
python cli/config_engine.py [OPTIONS]

Options:
  --project-root PATH        Path to project root
  --group GROUP             Machine group
  --platform PLATFORM       Platform (macos/linux)
  --config PATH            Custom config file
  --get KEY                Get config value (dot notation)
  --set KEY VALUE          Set config value
  --validate               Validate configuration
  --export {yaml,json}     Export configuration
  --list-files             List loaded files
  --list-roles             List enabled roles
```

### Plugin System CLI

```bash
python cli/plugin_system.py [OPTIONS]

Options:
  --plugin-path PATH       Add plugin path
  --list                   List plugins
  --info                   Show plugin info
  --validate               Validate plugins
```

### Setup Wizard CLI

```bash
python cli/setup_wizard.py [OPTIONS]

Options:
  --skip-wizard           Skip interactive wizard
  --config PATH           Custom config file
  --project-root PATH     Path to project root
```

### Test Suite CLI

```bash
python tests/test_suite.py [OPTIONS]

Options:
  --project-root PATH     Path to project root
  --verbose, -v           Verbose output
```

---

## Exit Codes

### Configuration Engine

- 0: Success
- 1: Validation failed

### Plugin System

- 0: Success
- 1: Plugin loading failed

### Setup Wizard

- 0: Setup completed
- 1: Setup cancelled

### Test Suite

- 0: All tests passed
- 1: Some tests failed

---

## Error Handling

All components implement consistent error handling:

```python
try:
    result = operation()
except Exception as e:
    logger.error(f"Operation failed: {e}")
    # Graceful degradation or user notification
```

Errors are logged and reported clearly to the user.

---

## Best Practices

1. **Always validate** configurations before applying:

   ```python
   is_valid, errors = engine.validate()
   ```

2. **Use dot notation** for configuration access:

   ```python
   value = engine.get("global.logging.level")
   ```

3. **Load in order** - use load_all() for proper priority:

   ```python
   config = engine.load_all(group="dev", platform="macos")
   ```

4. **Implement error handling** in plugins:

   ```python
   def execute(self, context: HookContext) -> bool:
       try:
           # Your code
       except Exception as e:
           context.error = str(e)
           return False
   ```

5. **Save configuration** after changes:

   ```python
   engine.set("key", "value")
   engine.save("~/.devkit/config.yaml")
   ```

---

---

## Structured Logging API

### Overview

The `cli.log` module provides production-ready structured logging with support for JSON output, colored terminal formatting, and automatic log rotation.

### Modules

#### setup_logging()

Configure and initialize a logger for your application.

```python
from cli.log import setup_logging
import logging

# Basic setup with colored console output
logger = setup_logging(__name__)

# Advanced setup with JSON output and file logging
logger = setup_logging(
    __name__,
    level=logging.DEBUG,
    log_dir=Path.home() / ".devkit" / "logs",
    json_output=True,
    file_output=True,
)

logger.info("Application started")
logger.debug("Debug information")
logger.warning("Warning message")
logger.error("Error occurred")
```

**Parameters:**

- `name` (str): Logger name (typically `__name__`)
- `level` (int, optional): Logging level (default: `logging.INFO`)
- `log_dir` (Path, optional): Directory for log files (default: `~/.devkit/logs`)
- `json_output` (bool, optional): Enable JSON output for structured logging (default: `False`)
- `file_output` (bool, optional): Enable file output in addition to console (default: `True`)

**Returns:** Configured `logging.Logger` instance

**Example - Production Setup:**

```python
from cli.log import setup_logging
import logging

# Console: colored output | File: JSON format with rotation
logger = setup_logging(
    "myapp",
    level=logging.INFO,
    json_output=False,  # Console shows colors
    file_output=True,   # File gets JSON
)

# Logs appear in: ~/.devkit/logs/myapp.log
```

#### get_logger()

Get an existing logger instance by name.

```python
from cli.log import get_logger

logger = get_logger("myapp")
logger.info("Message from existing logger")
```

**Parameters:**

- `name` (str): Logger name

**Returns:** `logging.Logger` instance

**Note:** Returns the same logger instance for the same name (singleton pattern).

#### log_context()

Log a message with additional context data (structured logging).

```python
from cli.log import setup_logging, log_context

logger = setup_logging(__name__, json_output=True)

# Log with context (appears in JSON output)
log_context(logger, {
    "user_id": 12345,
    "action": "deploy",
    "environment": "production",
    "timestamp": "2025-10-31T10:30:00Z"
})
```

**Parameters:**

- `logger` (logging.Logger): Logger instance
- `data` (dict): Context dictionary to include in log

**Output (JSON format):**

```json
{
  "timestamp": "2025-10-31T10:30:00Z",
  "level": "INFO",
  "module": "myapp",
  "message": "Context",
  "line": 42,
  "extra": {
    "user_id": 12345,
    "action": "deploy",
    "environment": "production"
  }
}
```

### Formatters

#### JSONFormatter

Formats log records as JSON for machine parsing and structured logging.

```python
from cli.log import JSONFormatter
import logging

formatter = JSONFormatter()
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(handler)
```

**Output Format:**

```json
{
  "timestamp": "2025-10-31T10:30:45.123456Z",
  "level": "INFO",
  "module": "cli.main",
  "message": "Application started",
  "line": 42
}
```

**Features:**

- ISO 8601 timestamps with UTC timezone
- Structured JSON output for log aggregation
- Exception traceback in `exception` field
- Extra context data in `extra` field

#### ColoredFormatter

Formats log records with ANSI color codes for terminal output.

```python
from cli.log import ColoredFormatter
import logging

formatter = ColoredFormatter()
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(handler)
```

**Color Scheme:**

- `DEBUG`: Cyan (`\033[36m`)
- `INFO`: Green (`\033[32m`)
- `WARNING`: Yellow (`\033[33m`)
- `ERROR`: Red (`\033[31m`)
- `CRITICAL`: Magenta (`\033[35m`)

**Output Example:**

```
[10:30:45] [INFO] cli.main: Application started
[10:30:46] [DEBUG] cli.config: Loading configuration from /etc/devkit/config.yaml
[10:30:47] [ERROR] cli.plugin: Plugin 'example' failed to load
```

### Common Patterns

#### Pattern 1: Development Logging

```python
from cli.log import setup_logging
import logging

# Colored console, no files
logger = setup_logging(
    __name__,
    level=logging.DEBUG,
    file_output=False,
)

logger.debug("Detailed debugging info")
logger.info("Informational message")
```

#### Pattern 2: Production Logging

```python
from cli.log import setup_logging
from pathlib import Path
import logging

# JSON file logging, colored console
logger = setup_logging(
    "myapp",
    level=logging.INFO,
    log_dir=Path("/var/log/myapp"),
    json_output=False,
    file_output=True,
)

logger.info("Application running")

# File output: /var/log/myapp/myapp.log (JSON format)
# Console output: Colored (human-readable)
```

#### Pattern 3: Structured Context Logging

```python
from cli.log import setup_logging, log_context

logger = setup_logging("api", json_output=True)

# Log request with full context
log_context(logger, {
    "request_id": "req-12345",
    "method": "POST",
    "path": "/api/users",
    "status": 201,
    "duration_ms": 45,
})
```

#### Pattern 4: Exception Logging

```python
from cli.log import setup_logging

logger = setup_logging(__name__)

try:
    result = risky_operation()
except Exception as e:
    # Exception details automatically included in log
    logger.exception("Operation failed")
```

**Output includes full traceback.**

### File Rotation

The logging module automatically rotates log files when they exceed 10MB.

**Configuration:**

- Maximum file size: 10 MB
- Backup count: 5 (keeps up to 5 rotated log files)
- Default location: `~/.devkit/logs/<logger_name>.log`

**Example with 5 rotations:**

```
~/.devkit/logs/myapp.log         (current, ≤ 10 MB)
~/.devkit/logs/myapp.log.1       (10 MB)
~/.devkit/logs/myapp.log.2       (10 MB)
~/.devkit/logs/myapp.log.3       (10 MB)
~/.devkit/logs/myapp.log.4       (10 MB)
~/.devkit/logs/myapp.log.5       (oldest, 10 MB)
```

When log file exceeds 10 MB, it's renamed to `.1`, `.1` becomes `.2`, etc., and `.5` is deleted.

### Best Practices

1. **Use module name as logger name:**

   ```python
   logger = setup_logging(__name__)  # ✓ Good
   logger = setup_logging("myapp")   # ✓ OK for single module
   ```

2. **Configure once, reuse:**

   ```python
   # In main module
   logger = setup_logging(__name__)

   # In other modules
   from cli.log import get_logger
   logger = get_logger("myapp")  # Reuse existing logger
   ```

3. **Use appropriate log levels:**

   ```python
   logger.debug("Variable: x = 42")           # Details
   logger.info("User logged in")              # Normal flow
   logger.warning("Cache is 95% full")        # Unusual situation
   logger.error("Failed to connect to DB")    # Error occurred
   logger.critical("System shutting down")    # Critical issue
   ```

4. **Structure context data:**

   ```python
   # Good - structured
   log_context(logger, {"user_id": 123, "action": "login"})

   # Avoid - unstructured
   logger.info(f"User 123 logged in")
   ```

5. **Don't log sensitive data:**

   ```python
   # Bad - exposes password
   logger.info(f"Connecting to {username}:{password}@{host}")

   # Good - sanitize
   logger.info(f"Connecting to {username}@{host}")
   ```

### Testing

See `tests/test_log.py` for comprehensive test examples:

```python
from cli.log import setup_logging
import tempfile
from pathlib import Path

def test_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = setup_logging(
            "test",
            log_dir=Path(tmpdir),
            json_output=True,
        )
        logger.info("Test message")
        # Verify log file created and contains message
```

---

## See Also

- [ARCHITECTURE.md](../ARCHITECTURE.md) - System design
- [PLUGIN_DEVELOPMENT_GUIDE.md](PLUGIN_DEVELOPMENT_GUIDE.md) - Plugin creation
- [README.md](../README.md) - Quick start guide
