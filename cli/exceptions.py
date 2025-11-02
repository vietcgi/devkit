#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
"""Enhanced exception classes with helpful error messages and recovery suggestions.

This module provides custom exception types that include:
- Clear, user-friendly error messages
- Root cause explanations
- Actionable recovery steps
- Suggestion for documentation references
"""

from pathlib import Path


def _sanitize_path(path: str | Path) -> str:
    """Sanitize file path for error messages to prevent info disclosure.

    Replaces absolute paths with user-relative paths (~/) for privacy.

    Args:
        path: File or directory path

    Returns:
        Sanitized path string (e.g., ~/.devkit/config.yaml)
    """
    path_str = str(path)

    # If already using ~, return as-is
    if path_str.startswith("~"):
        return path_str

    path_obj = Path(path_str).expanduser()
    home = Path.home()

    try:
        # Try to get relative path from home directory
        rel_path = path_obj.relative_to(home)
        return f"~/{rel_path}"
    except ValueError:
        # If not under home directory, show basename only for privacy
        return f".../{path_obj.name}"


class DevkitError(Exception):
    """Base exception for all Devkit errors."""

    def __init__(
        self,
        message: str,
        cause: str | None = None,
        solutions: list[str] | None = None,
        documentation: str | None = None,
    ) -> None:
        """Initialize enhanced exception.

        Args:
            message: User-friendly error message
            cause: Root cause explanation
            solutions: List of suggested fixes
            documentation: Reference to documentation
        """
        self.message = message
        self.cause = cause
        self.solutions = solutions or []
        self.documentation = documentation
        super().__init__(self.format_message())

    def format_message(self) -> str:
        """Format complete error message with all information."""
        lines = [f"❌ {self.message}"]

        if self.cause:
            lines.append(f"\n📋 Cause: {self.cause}")

        if self.solutions:
            lines.append("\n💡 How to fix:")
            for i, solution in enumerate(self.solutions, 1):
                lines.append(f"   {i}. {solution}")

        if self.documentation:
            lines.append(f"\n📖 See: {self.documentation}")

        return "\n".join(lines)


class BootstrapError(DevkitError):
    """Bootstrap script execution failed."""

    @staticmethod
    def integrity_check_failed() -> "BootstrapError":
        """Create integrity check failure exception."""
        return BootstrapError(
            message="Bootstrap script integrity check failed",
            cause="Downloaded script does not match expected checksum",
            solutions=[
                "Check your internet connection for corruption",
                "Verify you're using the correct installation method",
                "Try downloading again from https://github.com/vietcgi/devkit",
                "Check if your network is filtering downloads",
            ],
            documentation="See TROUBLESHOOTING.md for network issues",
        )

    @staticmethod
    def network_error(error: str) -> "BootstrapError":
        """Create network error exception."""
        return BootstrapError(
            message="Failed to download bootstrap script",
            cause=f"Network error: {error}",
            solutions=[
                "Check your internet connection",
                "Verify GitHub is accessible: curl https://github.com",
                "Try again with: curl -v to see details",
                "Use offline mode with DEVKIT_BOOTSTRAP_CHECKSUM env var",
            ],
            documentation="See TROUBLESHOOTING.md for network issues",
        )

    @staticmethod
    def permission_denied() -> "BootstrapError":
        """Create permission denied exception."""
        return BootstrapError(
            message="Permission denied executing bootstrap script",
            cause="Script is not executable or no write permission to destination",
            solutions=[
                "Make script executable: chmod +x bootstrap.sh",
                "Run with bash explicitly: bash bootstrap.sh",
                "Check if destination directory is writable: ls -ld $(pwd)",
                "Try installing in different directory with write access",
            ],
            documentation="See TROUBLESHOOTING.md > Permission Issues",
        )

    @staticmethod
    def insufficient_space() -> "BootstrapError":
        """Create insufficient disk space exception."""
        return BootstrapError(
            message="Insufficient disk space for installation",
            cause="Need 5-10GB free space for all tools and dependencies",
            solutions=[
                "Check disk usage: df -h",
                "Free up space: brew cleanup --all",
                "Remove cache: rm -rf ~/Library/Caches/*",
                "Remove downloads: rm -rf ~/Downloads/*",
                "Check what's using space: du -sh ~/",
            ],
            documentation="See TROUBLESHOOTING.md > Installation Issues",
        )


class ConfigError(DevkitError):
    """Configuration file handling error."""

    @staticmethod
    def missing_config() -> "ConfigError":
        """Create missing configuration exception."""
        return ConfigError(
            message="Configuration file not found",
            cause="~/.devkit/config.yaml does not exist",
            solutions=[
                "Create config directory: mkdir -p ~/.devkit",
                "Run bootstrap to create default config: ./bootstrap.sh",
                "Or copy example: cp config.example.yaml ~/.devkit/config.yaml",
            ],
            documentation="See TROUBLESHOOTING.md > Configuration Issues",
        )

    @staticmethod
    def invalid_yaml(error: str) -> "ConfigError":
        """Create invalid YAML exception."""
        return ConfigError(
            message="Configuration file has invalid YAML syntax",
            cause=f"YAML parsing error: {error}",
            solutions=[
                'Validate YAML: python3 -c "import yaml; '
                "yaml.safe_load(open('~/.devkit/config.yaml'))\"",
                "Use online validator: https://www.yamllint.com",
                "Check indentation (must be 2 spaces, not tabs)",
                "Check for special characters needing quotes",
            ],
            documentation="See TROUBLESHOOTING.md > Configuration Issues",
        )

    @staticmethod
    def permission_denied(path: str) -> "ConfigError":
        """Create config permission denied exception."""
        safe_path = _sanitize_path(path)
        return ConfigError(
            message=f"Configuration file has insecure permissions: {safe_path}",
            cause="File should only be readable/writable by owner (0600)",
            solutions=[
                f"Fix permissions: chmod 600 {safe_path}",
                f"Verify owner: ls -la {safe_path}",
                "Copy to new file: cp config.yaml config.yaml.new",
                "Delete old: rm config.yaml && mv config.yaml.new config.yaml",
            ],
            documentation="See TROUBLESHOOTING.md > Configuration Issues",
        )

    @staticmethod
    def invalid_ownership(path: str, owner: str) -> "ConfigError":
        """Create invalid ownership exception."""
        safe_path = _sanitize_path(path)
        return ConfigError(
            message=f"Configuration file owned by wrong user: {owner}",
            cause="Config must be owned by current user for security",
            solutions=[
                f"Fix ownership: chown $USER {safe_path}",
                "Or create new config in your home directory",
            ],
            documentation="See TROUBLESHOOTING.md > Configuration Issues",
        )


class PluginError(DevkitError):
    """Plugin system error."""

    @staticmethod
    def validation_failed(plugin: str, reason: str) -> "PluginError":
        """Create plugin validation failure exception."""
        return PluginError(
            message=f"Plugin validation failed: {plugin}",
            cause=reason,
            solutions=[
                f"Check plugin directory: ls -la ~/.devkit/plugins/{plugin}/",
                "Verify manifest.json exists and is valid JSON",
                "Verify __init__.py exists and contains Plugin class",
                (
                    f'Run validator: python3 -c "from cli.plugin_validator import '
                    f"validate_plugin_manifest; "
                    f"validate_plugin_manifest('{plugin}')\""
                ),
                "See PLUGIN_DEVELOPMENT.md for plugin requirements",
            ],
            documentation="See docs/PLUGINS.md for plugin system",
        )

    @staticmethod
    def missing_manifest(plugin: str) -> "PluginError":
        """Create missing manifest exception."""
        return PluginError(
            message=f"Plugin manifest not found: {plugin}",
            cause="manifest.json is required for all plugins",
            solutions=[
                f"Create manifest: ~/.devkit/plugins/{plugin}/manifest.json",
                (
                    '{ "name": "plugin-name", "version": "1.0.0", '
                    '"author": "Your Name", "description": "Plugin description" }'
                ),
                "See docs/PLUGINS.md for complete manifest structure",
            ],
            documentation="See docs/PLUGINS.md > Manifest",
        )

    @staticmethod
    def invalid_version(version: str) -> "PluginError":
        """Create invalid version exception."""
        return PluginError(
            message=f"Plugin version invalid: {version}",
            cause="Version must follow semantic versioning (X.Y.Z)",
            solutions=[
                "Use format: MAJOR.MINOR.PATCH (e.g., 1.0.0)",
                "Examples: 1.0.0, 2.3.5, 0.1.2",
                "Pre-release: 1.0.0-alpha (optional)",
                "Build metadata: 1.0.0+20130313144700 (optional)",
            ],
            documentation="See semver.org for semantic versioning spec",
        )

    @staticmethod
    def missing_class(plugin: str) -> "PluginError":
        """Create missing plugin class exception."""
        return PluginError(
            message=f"Plugin class not found: {plugin}",
            cause="__init__.py must define a 'Plugin' class extending PluginInterface",
            solutions=[
                f"Edit ~/.devkit/plugins/{plugin}/__init__.py",
                "Add import: from cli.plugin_interface import PluginInterface",
                "Add class: class Plugin(PluginInterface):",
                "Implement required methods: initialize, get_roles, get_hooks, validate",
                "See docs/PLUGINS.md for example plugin code",
            ],
            documentation="See docs/PLUGINS.md > Creating Plugins",
        )


class SecurityError(DevkitError):
    """Security-related error."""

    @staticmethod
    def checksum_mismatch(_expected: str, _actual: str) -> "SecurityError":
        """Create checksum mismatch exception."""
        return SecurityError(
            message="Checksum verification failed",
            cause="Downloaded file does not match expected checksum",
            solutions=[
                "Delete corrupted file and try again",
                "Check internet connection for packet loss",
                "Verify you downloaded from official source",
                "Check if file was partially downloaded",
                "Try manual installation: git clone + ./bootstrap.sh",
            ],
            documentation="See SECURITY.md for security practices",
        )

    @staticmethod
    def insecure_permissions(path: str, current: str, expected: str) -> "SecurityError":
        """Create insecure permissions exception."""
        return SecurityError(
            message=f"File has insecure permissions: {path}",
            cause=f"Permissions are {current}, should be {expected}",
            solutions=[
                f'Fix permissions: chmod {expected.replace("0", "")} {path}',
                f"Verify: ls -la {path}",
                "Consider using secure_config() to auto-fix permissions",
            ],
            documentation="See SECURITY.md for file permission requirements",
        )


class DependencyError(DevkitError):
    """Missing or incompatible dependency."""

    @staticmethod
    def tool_not_found(tool: str, install_cmd: str | None = None) -> "DependencyError":
        """Create tool not found exception."""
        install = install_cmd or f"brew install {tool}"
        return DependencyError(
            message=f"Required tool not found: {tool}",
            cause="Tool is not installed or not in PATH",
            solutions=[
                f"Install: {install}",
                f"Verify installation: which {tool}",
                "Update PATH if needed: source ~/.zshrc",
                f"Check if installed in different location: find /opt -name {tool}",
            ],
            documentation="See README.md > Requirements",
        )

    @staticmethod
    def version_incompatible(tool: str, required: str, current: str) -> "DependencyError":
        """Create version incompatibility exception."""
        return DependencyError(
            message=f"Tool version incompatible: {tool}",
            cause=f"Requires {required} but found {current}",
            solutions=[
                f"Upgrade: brew upgrade {tool}",
                f"Check version: {tool} --version",
                f"If already latest, check PATH: which {tool}",
                f"Remove old version: brew uninstall {tool} && brew install {tool}",
            ],
            documentation="See README.md > Requirements",
        )


class VerificationError(DevkitError):
    """Setup verification failed."""

    @staticmethod
    def some_tools_missing(missing_tools: list[str]) -> "VerificationError":
        """Create verification failure exception."""
        install_cmd = " ".join(missing_tools)
        return VerificationError(
            message=f"Setup verification failed: {len(missing_tools)} tool(s) missing",
            cause=f'Missing tools: {", ".join(missing_tools)}',
            solutions=[
                f"Install all missing: brew install {install_cmd}",
                "Verify each installed: which <tool>",
                "Update PATH: source ~/.zshrc",
                "Run verification again: ./verify-setup.sh",
            ],
            documentation="See README.md > Verification",
        )

    @staticmethod
    def setup_incomplete(reason: str) -> "VerificationError":
        """Create setup incomplete exception."""
        return VerificationError(
            message="Setup is incomplete or misconfigured",
            cause=reason,
            solutions=[
                "Re-run bootstrap: ./bootstrap.sh",
                "Check logs: cat ~/.devkit/logs/setup.log",
                "Fix any errors then verify: ./verify-setup.sh",
                "Check specific error in logs: grep ERROR ~/.devkit/logs/setup.log",
            ],
            documentation="See TROUBLESHOOTING.md > Verification Issues",
        )


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "BootstrapError",
    "ConfigError",
    "DependencyError",
    "DevkitError",
    "PluginError",
    "SecurityError",
    "VerificationError",
]
