#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
"""Git Configuration Manager.

Handles dynamic reloading of git configuration without requiring
full Ansible playbook re-runs.

Features:
- Detect configuration changes
- Validate git config syntax
- Reload git hooks
- Apply credential helper updates
- Log all changes to audit trail
"""

import argparse
import logging
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cli.utils import Colors, ValidatorBase, run_command, setup_logger


class GitConfigManager(ValidatorBase):
    """Manage git configuration and reload mechanisms."""

    def __init__(self, home_dir: str | None = None) -> None:
        """Initialize git config manager.

        Args:
            home_dir: Home directory (defaults to $HOME)
        """
        self.home_dir = Path(home_dir or Path.home())
        self.git_config_dir = self.home_dir / ".config" / "git"
        self.git_templates_dir = self.home_dir / ".git-templates"
        self.git_hooks_dir = self.git_templates_dir / "hooks"
        self.git_global_config = self.home_dir / ".gitconfig"
        self.git_local_config = self.home_dir / ".gitconfig.local"
        self.devkit_git_dir = self.home_dir / ".devkit" / "git"
        self.log_dir = self.home_dir / ".devkit" / "logs"

        self.setup_logging()

    def setup_logging(self) -> None:
        """Setup logging for git config changes."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "git_config_reload.log"

        self.logger = setup_logger(
            __name__,
            level=logging.INFO,
            log_file=self.log_file,
        )

    def validate_git_config_syntax(self) -> bool:
        """Validate git config file syntax.

        Returns:
            True if valid, False otherwise
        """
        self.print_status("Validating git config syntax...")

        result = None
        try:
            # Check global config
            if self.git_global_config.exists():
                result = run_command(["git", "config", "--list"], timeout=5)
        except subprocess.TimeoutExpired:
            self.print_status("Config validation timed out", "ERROR")
            return False
        except OSError as e:
            self.print_status(f"Config validation error: {e}", "ERROR")
            return False

        if result and result.returncode:
            self.print_status(f"Git config validation failed: {result.stderr}", "ERROR")
            return False

        self.print_status("Git config syntax valid", "SUCCESS")
        return True

    def get_current_config(self) -> dict[str, str]:
        """Get current git configuration.

        Returns:
            Dictionary of git config key-value pairs
        """
        try:
            result = run_command(["git", "config", "--list", "--null"], timeout=5)
        except OSError as e:
            self.print_status(f"Error reading config: {e}", "ERROR")
            return {}

        config = {}
        if not result.returncode:
            for line in result.stdout.split("\0"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key] = value

        return config

    def detect_config_changes(self) -> dict[str, str]:
        """Detect what git config values have changed.

        Returns:
            Dictionary of changed config keys and their new values
        """
        self.print_status("Detecting configuration changes...")

        current_config = self.get_current_config()

        # Read the gitconfig file to compare
        changed: dict[str, str] = {}

        if not self.git_global_config.exists():
            self.print_status("No gitconfig found", "WARNING")
            return changed

        try:
            result = run_command(
                [
                    "git",
                    "config",
                    "--file",
                    str(self.git_global_config),
                    "--list",
                    "--null",
                ],
                timeout=5,
            )
        except OSError as e:
            self.print_status(f"Error detecting changes: {e}", "ERROR")
            return {}

        if not result.returncode:
            for line in result.stdout.split("\0"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    if current_config.get(key) != value:
                        changed[key] = value

        if changed:
            self.print_status(f"Found {len(changed)} configuration changes", "WARNING")
            for key, value in list(changed.items())[:5]:
                self.logger.info("Changed: %s = %s", key, value)
            if len(changed) > 5:
                self.logger.info("... and %d more changes", len(changed) - 5)
        else:
            self.print_status("No configuration changes detected", "SUCCESS")

        return changed

    def reload_git_config(self) -> bool:
        """Reload git configuration.

        Returns:
            True if successful, False otherwise
        """
        self.print_status("Reloading git configuration...")

        try:
            # Git reads config from files on each invocation
            # We just need to verify it's readable
            result = run_command(["git", "config", "--list"], timeout=5)
        except OSError as e:
            self.print_status(f"Reload error: {e}", "ERROR")
            return False

        if not result.returncode:
            self.print_status("Git configuration reloaded", "SUCCESS")
            self.logger.info("Git configuration reloaded successfully")
            return True

        self.print_status(f"Reload failed: {result.stderr}", "ERROR")
        return False

    def verify_hooks(self) -> bool:
        """Verify and make git hooks executable.

        Returns:
            True if all hooks are valid, False otherwise
        """
        self.print_status("Verifying git hooks...")

        if not self.git_hooks_dir.exists():
            self.print_status("Hooks directory not found", "WARNING")
            return False

        hooks = ["pre-commit", "commit-msg", "post-commit", "prepare-commit-msg"]
        all_valid = True

        for hook in hooks:
            hook_path = self.git_hooks_dir / hook

            if not hook_path.exists():
                self.print_status(f"  Hook not found: {hook}", "WARNING")
                all_valid = False
                continue

            # Make executable
            try:
                hook_path.chmod(0o755)

                # Verify it's executable
                stat_info = hook_path.stat()
                if not (stat_info.st_mode & 0o111):  # pylint: disable=superfluous-parens
                    self.print_status(f"  Hook not executable: {hook}", "ERROR")
                    all_valid = False
                else:
                    self.print_status(f"  Hook valid: {hook}", "SUCCESS")

            except OSError as e:
                self.print_status(f"  Error with hook {hook}: {e}", "ERROR")
                all_valid = False

        return all_valid

    def create_backup(self) -> Path | None:
        """Create backup of git configuration.

        Returns:
            Path to backup file, None if failed
        """
        if not self.git_global_config.exists():
            return None

        try:
            self.devkit_git_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
            backup_path = self.devkit_git_dir / f"gitconfig.backup.{timestamp}"

            # SECURITY FIX: Enforce 0600 permissions on backup file
            # Git config may contain API keys, SSH keys, auth tokens
            backup_path.write_text(
                self.git_global_config.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            backup_path.chmod(0o600)

            # Verify permissions are correctly set
            stat_info = backup_path.stat()
            if stat_info.st_mode & 0o077:  # Check if world/group readable
                msg = f"Backup file has insecure permissions: {oct(stat_info.st_mode)}"
                raise PermissionError(msg)

        except OSError as e:
            self.print_status(f"Backup failed: {e}", "ERROR")
            return None

        self.print_status(f"Configuration backed up: {backup_path.name}", "SUCCESS")
        return backup_path

    def reload_hooks(self) -> bool:
        """Reload git hooks configuration.

        Returns:
            True if successful, False otherwise
        """
        self.print_status("Reloading git hooks...")

        try:
            # Make hooks executable
            if not self.verify_hooks():
                return False

            # Verify hooks can be executed
            test_hook = self.git_hooks_dir / "pre-commit"
            if test_hook.exists():
                result = run_command(["bash", "-n", str(test_hook)], timeout=5)
                if result.returncode != 0:
                    self.print_status("Hook syntax error", "ERROR")
                    return False

        except OSError as e:
            self.print_status(f"Hook reload error: {e}", "ERROR")
            return False

        self.print_status("Hooks reloaded successfully", "SUCCESS")
        self.logger.info("Git hooks reloaded successfully")
        return True

    def reload_credential_helpers(self) -> bool:
        """Reload credential helper configuration.

        Returns:
            True if successful, False otherwise
        """
        self.print_status("Reloading credential helpers...")

        try:
            # Get configured credential helper
            result = run_command(["git", "config", "--get", "credential.helper"], timeout=5)
        except OSError as e:
            self.print_status(f"Credential helper error: {e}", "ERROR")
            return False

        if not result.returncode and result.stdout.strip():
            helper = result.stdout.strip()
            self.print_status(f"Credential helper: {helper}", "INFO")
        else:
            self.print_status("Credential helpers verified", "SUCCESS")

        return True

    def generate_report(self) -> dict[str, Any]:
        """Generate detailed reload report.

        Returns:
            Dictionary with reload status details
        """
        config = self.get_current_config()

        return {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "config_status": {
                "user_name": config.get("user.name", "NOT SET"),
                "user_email": config.get("user.email", "NOT SET"),
                "default_editor": config.get("core.editor", "NOT SET"),
                "pull_rebase": config.get("pull.rebase", "false"),
            },
            "hooks_status": {
                "pre_commit": (self.git_hooks_dir / "pre-commit").exists(),
                "commit_msg": (self.git_hooks_dir / "commit-msg").exists(),
                "post_commit": (self.git_hooks_dir / "post-commit").exists(),
                "prepare_commit_msg": (self.git_hooks_dir / "prepare-commit-msg").exists(),
            },
            "directories": {
                "config_dir": str(self.git_config_dir),
                "templates_dir": str(self.git_templates_dir),
                "hooks_dir": str(self.git_hooks_dir),
            },
        }

    @staticmethod
    def display_report(report: dict[str, Any]) -> None:
        """Display formatted reload report.

        Args:
            report: Report dictionary from generate_report()
        """
        # This method is reserved for future formatting implementation
        # Currently a stub to prevent runtime errors

    def reload_all(self, *, dry_run: bool = False) -> bool:
        """Perform complete git configuration reload.

        Args:
            dry_run: If True, only validate without making changes

        Returns:
            True if reload successful, False otherwise
        """
        success = True

        # Validation
        if not self.validate_git_config_syntax():
            return False

        if dry_run:
            self.detect_config_changes()
            self.verify_hooks()
        else:
            # Backup current config
            self.create_backup()

            # Detect changes
            self.detect_config_changes()

            # Reload components
            if not self.reload_git_config():
                success = False

            if not self.reload_hooks():
                success = False

            if not self.reload_credential_helpers():
                success = False

        # Generate and display report
        report = self.generate_report()
        self.__class__.display_report(report)

        if success:
            self.print_status("Git configuration reload completed successfully", "SUCCESS")
        else:
            self.print_status("Git configuration reload completed with errors", "ERROR")

        return success

    def reload_component(self, component: str) -> bool:
        """Reload specific git component.

        Args:
            component: Component to reload (config, hooks, credentials)

        Returns:
            True if successful, False otherwise
        """
        if component == "config":
            return self.reload_git_config()

        if component == "hooks":
            return self.reload_hooks()

        if component == "credentials":
            return self.reload_credential_helpers()

        self.print_status(f"Unknown component: {component}", "ERROR")
        return False

    def get_current_branch(self) -> str:
        """Get current git branch name.

        Returns:
            Current branch name or "unknown" if not in a git repo
        """
        try:
            result = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return "unknown"

    def is_dirty(self) -> bool:
        """Check if git repository has uncommitted changes.

        Returns:
            True if repository is dirty, False otherwise
        """
        try:
            result = run_command(["git", "status", "--porcelain"], timeout=5)
            if result.returncode == 0:
                return bool(result.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass
        return False

    def get_commit_info(self, ref: str = "HEAD") -> dict[str, str]:
        """Get commit information for a given reference.

        Args:
            ref: Git reference (default: HEAD)

        Returns:
            Dictionary with commit info (hash, author, message, date)
        """
        commit_info: dict[str, str] = {}
        try:
            # Get short hash
            result = run_command(["git", "rev-parse", "--short", ref], timeout=5)
            if result.returncode == 0:
                commit_info["hash"] = result.stdout.strip()

            # Get author
            result = run_command(
                ["git", "log", "-1", "--format=%an", ref],
                timeout=5,
            )
            if result.returncode == 0:
                commit_info["author"] = result.stdout.strip()

            # Get message
            result = run_command(
                ["git", "log", "-1", "--format=%s", ref],
                timeout=5,
            )
            if result.returncode == 0:
                commit_info["message"] = result.stdout.strip()

            # Get date
            result = run_command(
                ["git", "log", "-1", "--format=%ai", ref],
                timeout=5,
            )
            if result.returncode == 0:
                commit_info["date"] = result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

        return commit_info


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Manage git configuration reload")
    parser.add_argument("--dry-run", action="store_true", help="Validate without making changes")
    parser.add_argument(
        "--component",
        choices=["config", "hooks", "credentials"],
        help="Reload specific component",
    )
    parser.add_argument("--home", help="Home directory (defaults to $HOME)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    manager = GitConfigManager(home_dir=args.home)

    if args.component:
        success = manager.reload_component(args.component)
    else:
        success = manager.reload_all(dry_run=args.dry_run)

    return 0 if success else 1


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "Colors",
    "GitConfigManager",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
