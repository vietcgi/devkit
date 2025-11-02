#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
# !/usr/bin/env python3
"""Mac-Setup Configuration Engine.

Handles loading, validating, merging, and managing configuration from multiple sources.
Supports YAML configuration files, environment variables, and runtime overrides.
"""

import argparse
import json
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

import yaml  # pylint: disable=import-error

from cli.exceptions import ConfigError
from cli.utils import setup_logger

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class ConfigPermissionError(PermissionError):
    """Raised when config file has permission issues."""


class ConfigEnvironment(Enum):
    """Configuration environment types."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class RateLimiter:
    """Rate limiter for sensitive configuration operations.

    SECURITY: Prevents abuse and brute-force attacks by limiting
    the number of sensitive operations (like config changes) within
    a time window.

    Default: Max 5 operations per 60 seconds
    """

    def __init__(self, max_operations: int = 5, window_seconds: int = 60) -> None:
        """Initialize rate limiter.

        Args:
            max_operations: Maximum operations allowed in time window
            window_seconds: Time window in seconds
        """
        self.max_operations = max_operations
        self.window_seconds = window_seconds
        self.operations: dict[str, deque[datetime]] = {}

    def is_allowed(self, identifier: str) -> tuple[bool, str]:
        """Check if operation is allowed for given identifier.

        Args:
            identifier: User, IP, or operation identifier

        Returns:
            Tuple of (is_allowed, message)
        """
        now = datetime.now(tz=UTC)

        # Initialize operation list if needed
        if identifier not in self.operations:
            self.operations[identifier] = deque()

        # Remove old operations outside time window
        operations = self.operations[identifier]
        window_start = now - timedelta(seconds=self.window_seconds)

        while operations and operations[0] < window_start:
            operations.popleft()

        # Check if within limit
        if len(operations) < self.max_operations:
            operations.append(now)
            remaining = self.max_operations - len(operations)
            return True, f"Operation allowed ({remaining} remaining)"

        # Rate limit exceeded
        oldest_op = operations[0]
        reset_time = oldest_op + timedelta(seconds=self.window_seconds)
        wait_seconds = (reset_time - now).total_seconds()

        return False, (
            f"Rate limit exceeded: {len(operations)}/{self.max_operations} "
            f"operations in {self.window_seconds}s window. "
            f"Please wait {wait_seconds:.1f} seconds."
        )

    def cleanup_old_identifiers(self) -> None:
        """Clean up empty identifier entries to prevent unbounded memory growth.

        This method removes entries from the operations dictionary that have empty
        deques (all operations have expired from the time window). Call periodically
        in long-running processes or when memory is a concern.
        """
        expired_identifiers = [
            identifier for identifier, operations in self.operations.items() if not operations
        ]
        for identifier in expired_identifiers:
            del self.operations[identifier]

    def reset(self, identifier: str | None = None) -> None:
        """Reset rate limit for identifier or all identifiers.

        Args:
            identifier: Identifier to reset (None resets all)
        """
        if identifier:
            self.operations.pop(identifier, None)
        else:
            self.operations.clear()

    def get_stats(self, identifier: str) -> dict[str, Any]:
        """Get rate limit statistics for identifier.

        Returns:
            Dictionary with operation count and reset time
        """
        if identifier not in self.operations:
            return {
                "identifier": identifier,
                "operations_count": 0,
                "max_operations": self.max_operations,
                "window_seconds": self.window_seconds,
                "next_reset": None,
            }

        operations = self.operations[identifier]

        next_reset = None
        if operations:
            oldest_op = operations[0]
            next_reset = (oldest_op + timedelta(seconds=self.window_seconds)).isoformat()

        return {
            "identifier": identifier,
            "operations_count": len(operations),
            "max_operations": self.max_operations,
            "window_seconds": self.window_seconds,
            "next_reset": next_reset,
        }


@dataclass
class ConfigMetadata:
    """Metadata about a configuration."""

    source: str  # File path or "environment", "cli", "default"
    timestamp: str
    version: str


class ConfigurationEngine:
    """Main configuration engine for devkit.

    Loads configuration from multiple sources in priority order:
    1. CLI arguments (highest priority)
    2. Environment variables
    3. Local config file (~/.devkit/config.yaml)
    4. Group config (config/groups/{group}.yaml)
    5. Role configs (config/roles/{role}.yaml)
    6. Platform config (config/platforms/{platform}.yaml)
    7. Schema defaults (lowest priority)
    """

    def __init__(
        self,
        project_root: str | None = None,
        logger: logging.Logger | None = None,
        *,
        enable_rate_limiting: bool = False,
    ) -> None:
        """Initialize configuration engine.

        Args:
            project_root: Path to devkit project root
            logger: Logger instance
            enable_rate_limiting: Enable rate limiting on sensitive operations
        """
        self.project_root = Path(project_root or Path(__file__).parent.parent)
        self.logger = logger or self._setup_logger()
        self.config: dict[str, Any] = {}
        self.metadata: dict[str, ConfigMetadata] = {}
        self._loaded_files: list[Path] = []

        # Rate limiting for sensitive operations
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limiter = RateLimiter(max_operations=5, window_seconds=60)

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Setup default logger."""
        return setup_logger("devkit.config")

    def validate_and_secure_config_file(self, config_path: Path) -> None:
        """Validate and secure configuration file permissions.

        Config files may contain sensitive data (API keys, tokens, etc.)
        and must have restrictive permissions (0600 - user read/write only).

        Args:
            config_path: Path to configuration file

        Raises:
            PermissionError: If file is owned by different user
            OSError: If unable to fix permissions
        """
        if not config_path.exists():
            # Create with secure permissions (0600)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.touch(mode=0o600)
            self.logger.debug("Created %s with secure permissions (0600)", config_path)
            return

        # Get file stats
        try:
            stat_info = config_path.stat()
        except OSError:
            self.logger.exception("Cannot access config file")
            raise

        # Verify ownership - file must be owned by current user
        current_uid = os.getuid()
        if stat_info.st_uid != current_uid:
            msg = (
                f"Config file {config_path} is owned by different user "
                f"(uid: {stat_info.st_uid}, current: {current_uid}). "
                f"This could be a security risk."
            )
            raise ConfigPermissionError(msg)

        # Check file permissions
        file_mode = stat_info.st_mode & 0o777
        if file_mode != 0o600:
            self.logger.warning(
                "Config file %s has insecure permissions: %#o",
                config_path,
                file_mode,
            )
            self.logger.info("Fixing permissions to 0600 (user read/write only)...")

            try:
                config_path.chmod(0o600)
                self.logger.info("Fixed config permissions for %s", config_path)
            except OSError as e:
                self.logger.exception("Cannot fix file permissions")
                msg = f"Unable to fix permissions on {config_path}: {e}"
                raise ConfigPermissionError(msg) from e

    def load_defaults(self) -> None:
        """Load default configuration from schema."""
        self.logger.debug("Loading default configuration")
        defaults = {
            "global": {
                "setup_name": "Development Environment",
                "setup_environment": "development",
                "enabled_roles": [
                    "core",
                    "shell",
                    "editors",
                    "languages",
                    "development",
                    "containers",
                    "cloud",
                ],
                "disabled_roles": [],
                "logging": {
                    "enabled": True,
                    "level": "info",
                    "file": "~/.devkit/logs/setup.log",
                    "archive": True,
                },
                "performance": {
                    "parallel_tasks": 4,
                    "timeout": 300,
                    "cache_downloads": True,
                },
                "backup": {
                    "enabled": True,
                    "path": "~/.devkit/backups",
                    "max_backups": 10,
                    "compress": True,
                },
                "verification": {
                    "enabled": True,
                    "run_after_setup": True,
                    "detailed_report": True,
                },
                "security": {
                    "enable_ssh_setup": False,
                    "enable_gpg_setup": False,
                    "enable_audit_logging": True,
                    "require_verification": False,
                },
                "updates": {
                    "check_for_updates": True,
                    "auto_update_tools": False,
                    "update_interval": "weekly",
                },
            },
            "roles": {},
            "groups": {},
            "platforms": {},
            "plugins": {
                "enabled": True,
                "load_custom": True,
                "custom_path": "~/.devkit/plugins",
                "hooks": {},
            },
        }
        self.config = defaults
        self.metadata["defaults"] = ConfigMetadata(
            source="schema",
            timestamp=self._get_timestamp(),
            version="1.0",
        )

    def load_file(self, file_path: str | Path, section: str | None = None) -> dict[str, Any]:
        """Load configuration from YAML file.

        Args:
            file_path: Path to configuration file
            section: Optional section to extract (e.g., "global", "shell")

        Returns:
            Loaded configuration dictionary

        Raises:
            ConfigPermissionError: If file cannot be read due to permissions
        """
        path = Path(file_path).expanduser()
        if not path.exists():
            self.logger.warning("Configuration file not found: %s", path)
            return {}

        try:
            with Path(path).open(encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            self._loaded_files.append(path)
            self.logger.debug("Loaded config from %s", path)

            if section and section in config:
                config = config[section]
        except yaml.YAMLError:
            self.logger.exception("Invalid YAML in %s", path)
            return {}
        except PermissionError as e:
            self.logger.exception("Permission denied reading %s", path)
            raise ConfigError(
                message=f"Permission denied reading configuration: {path}",
                cause="File permissions prevent reading",
            ) from e
        except OSError as e:
            self.logger.exception("Error loading %s", path)
            raise ConfigError(
                message=f"Cannot read configuration file: {path}",
                cause=str(e),
            ) from e

        return config

    @staticmethod
    def _parse_config_value(value: str) -> str | bool | list[str]:
        """Parse configuration value from environment variable.

        Handles boolean strings, comma-separated lists, and plain strings.

        Args:
            value: String value from environment variable

        Returns:
            Parsed value as appropriate type
        """
        if value.lower() in {"true", "false"}:
            return value.lower() == "true"
        if "," in value:
            return [v.strip() for v in value.split(",")]
        return value

    @staticmethod
    def set_nested_value(
        target: dict[str, Any],
        key_parts: list[str],
        value: str | bool | list[str],
    ) -> None:
        """Set value in nested dictionary using key parts.

        Args:
            target: Dictionary to update
            key_parts: Nested key parts (e.g., ["logging", "level"])
            value: Value to set
        """
        current = target
        for part in key_parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[key_parts[-1]] = value

    def load_environment_overrides(self) -> dict[str, Any]:
        """Load configuration from environment variables.

        Supports variables like:
        - MAC_SETUP_ENABLED_ROLES=core,shell,editors
        - MAC_SETUP_LOGGING_LEVEL=debug
        """
        overrides: dict[str, Any] = {}
        prefix = "MAC_SETUP_"

        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue

            # Convert MAC_SETUP_ENABLED_ROLES to enabled_roles
            config_key = key[len(prefix) :].lower()
            parsed_value = self._parse_config_value(value)

            # Handle nested keys using double underscore: MAC_SETUP_LOGGING__LEVEL
            if "__" in config_key:
                key_parts = config_key.split("__")
                self.__class__.set_nested_value(overrides, key_parts, parsed_value)
            else:
                overrides[config_key] = parsed_value

        if overrides:
            self.logger.debug("Loaded environment overrides: %s", overrides)
            self.metadata["environment"] = ConfigMetadata(
                source="environment",
                timestamp=self._get_timestamp(),
                version="1.0",
            )

        return overrides

    def load_all(
        self,
        group: str | None = None,
        platform: str | None = None,
        local_config: str | None = None,
    ) -> dict[str, Any]:
        """Load all configuration in priority order.

        Args:
            group: Machine group (development, design, qa, sre)
            platform: Platform (macos, linux)
            local_config: Path to local config file

        Returns:
            Merged configuration dictionary
        """
        self.logger.info("Loading configuration...")

        # 1. Load defaults
        self.load_defaults()

        # 2. Load platform-specific config
        if platform:
            platform_config = self.load_file(
                self.project_root / "config" / "platforms" / f"{platform}.yaml",
            )
            self._deep_merge(self.config, platform_config)
            self.logger.debug("Merged platform config: %s", platform)

        # 3. Load group config
        if group:
            group_config = self.load_file(self.project_root / "config" / "groups" / f"{group}.yaml")
            self._deep_merge(self.config, group_config)
            self.logger.debug("Merged group config: %s", group)

        # 4. Load global config from project
        global_config = self.load_file(self.project_root / "config" / "config.yaml")
        self._deep_merge(self.config, global_config)

        # 5. Load local user config
        if local_config:
            local = self.load_file(local_config)
            self._deep_merge(self.config, local)
        else:
            # Try default local config location
            local = self.load_file(Path.home() / ".devkit" / "config.yaml")
            if local:
                self._deep_merge(self.config, local)

        # 6. Load environment variable overrides
        env_overrides = self.load_environment_overrides()
        self._deep_merge(self.config, {"global": env_overrides})

        self.logger.info("Configuration loaded from %d files", len(self._loaded_files))
        return self.config

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key.

        Examples:
            config.get("global.logging.level")
            config.get("roles.shell.enabled", True)
        """
        keys = key.split(".")
        value = self.config

        try:
            for k in keys:
                value = value[k]
        except (KeyError, TypeError):
            return default

        return value

    def set(self, key: str, value: Any, user_id: str | None = None) -> tuple[bool, str]:
        """Set configuration value by dot-notation key.

        SECURITY: Applies rate limiting to prevent abuse of config changes.

        Examples:
            success, msg = config.set("global.logging.level", "debug")
            success, msg = config.set("roles.shell.enabled", True)

        Args:
            key: Configuration key in dot notation
            value: New value
            user_id: User identifier for rate limiting (default: current user)

        Returns:
            Tuple of (success, message)
        """
        # Check rate limit if enabled
        if self.enable_rate_limiting:
            user = user_id or os.getenv("USER") or "unknown"
            allowed, message = self.rate_limiter.is_allowed(user)

            if not allowed:
                self.logger.warning("Rate limit: %s", message)
                return False, message

        keys = key.split(".")
        target = self.config

        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]

        target[keys[-1]] = value
        self.logger.debug("Set %s = %s", key, value)
        return True, "Configuration updated"

    def _validate_environment(self, errors: list[str]) -> None:
        """Validate setup environment configuration."""
        valid_environments = ["development", "staging", "production"]
        current_env = self.get("global.setup_environment")
        if current_env not in valid_environments:
            errors.append(f"Invalid setup_environment: {current_env}")

    def _validate_roles(self, errors: list[str]) -> None:
        """Validate enabled/disabled roles don't overlap."""
        enabled = set(self.get("global.enabled_roles", []))
        disabled = set(self.get("global.disabled_roles", []))
        overlap = enabled & disabled
        if overlap:
            errors.append(f"Roles in both enabled and disabled: {overlap}")

    def _validate_logging(self, errors: list[str]) -> None:
        """Validate logging configuration."""
        valid_levels = ["debug", "info", "warning", "error"]
        current_level = self.get("global.logging.level")
        if current_level not in valid_levels:
            errors.append(f"Invalid logging level: {current_level}")

    def _validate_performance(self, errors: list[str]) -> None:
        """Validate performance settings."""
        parallel_tasks = self.get("global.performance.parallel_tasks", 1)
        if parallel_tasks < 1:
            errors.append("parallel_tasks must be >= 1")

        timeout = self.get("global.performance.timeout", 30)
        if timeout < 30:
            errors.append("timeout must be >= 30 seconds")

    def validate(self) -> tuple[bool, list[str]]:
        """Validate configuration against schema.

        Returns:
            Tuple of (is_valid, error_list)
        """
        errors: list[str] = []

        # Validate all sections
        self._validate_environment(errors)
        self._validate_roles(errors)
        self._validate_logging(errors)
        self._validate_performance(errors)

        return not errors, errors

    def export(self, format_type: str = "yaml") -> str:
        """Export configuration in specified format.

        Args:
            format_type: "yaml" or "json"

        Returns:
            Formatted configuration string
        """
        if format_type == "json":
            return json.dumps(self.config, indent=2)

        if format_type == "yaml":
            yaml_str = yaml.dump(self.config, default_flow_style=False)
            return yaml_str if yaml_str is not None else ""

        msg = f"Unsupported format: {format_type}"
        raise ValueError(msg)

    def save(self, file_path: str | Path) -> None:
        """Save current configuration to file."""
        path = Path(file_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(self.export("yaml"), encoding="utf-8")

        self.logger.info("Configuration saved to %s", path)

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> None:
        """Deep merge override into base dictionary."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(tz=UTC).isoformat()

    def list_loaded_files(self) -> list[str]:
        """Get list of loaded configuration files."""
        return [str(f) for f in self._loaded_files]

    def get_enabled_roles(self) -> list[str]:
        """Get list of enabled roles based on current configuration."""
        enabled = self.get("global.enabled_roles", [])
        disabled = self.get("global.disabled_roles", [])
        return [r for r in enabled if r not in disabled]

    def get_role_config(self, role: str) -> dict[str, Any]:
        """Get configuration for specific role."""
        role_config: Any = self.get(f"roles.{role}", {})
        if isinstance(role_config, dict):
            config_value: Any = role_config.get("config", {})
            return config_value if isinstance(config_value, dict) else {}
        return {}

    def get_rate_limit_stats(self, user_id: str | None = None) -> dict[str, Any]:
        """Get rate limiting statistics for user.

        Args:
            user_id: User identifier (default: current user)

        Returns:
            Rate limit statistics
        """
        user = user_id or os.getenv("USER") or "unknown"
        return self.rate_limiter.get_stats(user)

    def reset_rate_limit(self, user_id: str | None = None) -> None:
        """Reset rate limit for user or all users.

        Args:
            user_id: User identifier (None resets all)
        """
        self.rate_limiter.reset(user_id)


def main() -> None:
    """CLI interface for configuration engine."""
    parser = argparse.ArgumentParser(description="Mac-Setup Configuration Engine")
    parser.add_argument("--project-root", default=str(Path(__file__).parent.parent))
    parser.add_argument("--group", help="Machine group")
    parser.add_argument("--platform", default="macos", help="Platform (macos/linux)")
    parser.add_argument("--config", help="Custom config file path")
    parser.add_argument("--get", help="Get config value (dot notation)")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Set config value")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    parser.add_argument("--export", choices=["yaml", "json"], help="Export configuration")
    parser.add_argument("--list-files", action="store_true", help="List loaded files")
    parser.add_argument("--list-roles", action="store_true", help="List enabled roles")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    # Create engine and load config
    engine = ConfigurationEngine(args.project_root)
    engine.load_all(group=args.group, platform=args.platform, local_config=args.config)

    # Handle various commands
    if args.validate:
        is_valid, _ = engine.validate()
        sys.exit(0 if is_valid else 1)

    if args.get:
        engine.get(args.get)
        return

    if args.set:
        success, _ = engine.set(args.set[0], args.set[1])
        if not success:
            sys.exit(1)
        engine.save(Path.home() / ".devkit" / "config.yaml")
        return

    if args.list_files:
        engine.list_loaded_files()
        return

    if args.list_roles:
        engine.get_enabled_roles()
        return

    if args.export:
        # Export functionality to be implemented
        return

    # Default: validate configuration
    is_valid, _ = engine.validate()
    if not is_valid:
        sys.exit(1)


if __name__ == "__main__":
    main()

# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "ConfigEnvironment",
    "ConfigurationEngine",
    "RateLimiter",
]
