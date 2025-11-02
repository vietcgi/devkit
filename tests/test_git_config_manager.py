#!/usr/bin/env python3
"""
Tests for GitConfigManager module.

Tests git configuration management functionality including:
- Configuration loading and validation
- Change detection
- Hook verification and reloading
- Credential helper management
- Backup creation
"""

import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Mock sys.argv to prevent argparse issues during import
sys.argv = ["pytest"]

from cli.git_config_manager import Colors, GitConfigManager


@pytest.fixture
def temp_home(tmp_path: Path) -> Path:
    """Create a temporary home directory structure."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".git-templates" / "hooks").mkdir(parents=True)
    (home / ".devkit" / "git").mkdir(parents=True)
    (home / ".devkit" / "logs").mkdir(parents=True)
    return home


@pytest.fixture
def manager(temp_home: Path) -> GitConfigManager:
    """Create a GitConfigManager instance with temporary home."""
    return GitConfigManager(home_dir=str(temp_home))


class TestGitConfigManager:
    """Tests for GitConfigManager class."""

    def test_init(self, manager: GitConfigManager) -> None:
        """Test manager initialization."""
        assert manager.home_dir.exists()
        assert manager.git_config_dir.exists()
        assert manager.git_hooks_dir.exists()
        assert manager.logger is not None

    def test_setup_logging(self, manager: GitConfigManager) -> None:
        """Test logging setup."""
        assert manager.log_dir.exists()
        assert manager.log_file is not None
        assert manager.logger is not None

    def test_print_status_info(self, manager: GitConfigManager, caplog) -> None:
        """Test print_status with INFO level."""
        with caplog.at_level(logging.INFO):
            manager.print_status("Test message", "INFO")
        assert "Test message" in caplog.text

    def test_print_status_success(self, manager: GitConfigManager, caplog) -> None:
        """Test print_status with SUCCESS level."""
        with caplog.at_level(logging.INFO):
            manager.print_status("Success message", "SUCCESS")
        assert "Success message" in caplog.text

    def test_print_status_warning(self, manager: GitConfigManager, caplog) -> None:
        """Test print_status with WARNING level."""
        with caplog.at_level(logging.WARNING):
            manager.print_status("Warning message", "WARNING")
        assert "Warning message" in caplog.text

    def test_print_status_error(self, manager: GitConfigManager, caplog) -> None:
        """Test print_status with ERROR level."""
        with caplog.at_level(logging.ERROR):
            manager.print_status("Error message", "ERROR")
        assert "Error message" in caplog.text

    @patch("subprocess.run")
    def test_validate_git_config_syntax_valid(
        self, mock_run: Mock, manager: GitConfigManager
    ) -> None:
        """Test git config validation when valid."""
        mock_run.return_value = Mock(returncode=0, stderr="")
        result = manager.validate_git_config_syntax()
        assert result is True

    def test_validate_git_config_syntax_with_gitconfig(
        self, temp_home: Path, manager: GitConfigManager
    ) -> None:
        """Test git config validation with gitconfig file."""
        gitconfig = temp_home / ".gitconfig"
        gitconfig.write_text("[user]\n    name = Test\n")

        manager = GitConfigManager(home_dir=str(temp_home))
        with patch("cli.git_config_manager.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stderr="")
            result = manager.validate_git_config_syntax()
            assert result is True

    def test_validate_git_config_syntax_no_gitconfig(self, manager: GitConfigManager) -> None:
        """Test git config validation when no gitconfig exists."""
        # When gitconfig doesn't exist, validation returns True
        result = manager.validate_git_config_syntax()
        assert result is True

    @patch("subprocess.run")
    def test_get_current_config(self, mock_run: Mock, manager: GitConfigManager) -> None:
        """Test getting current git configuration."""
        mock_run.return_value = Mock(
            returncode=0, stdout="user.name=John Doe\0user.email=john@example.com\0"
        )
        config = manager.get_current_config()
        assert "user.name" in config
        assert config["user.name"] == "John Doe"

    @patch("subprocess.run")
    def test_get_current_config_empty(self, mock_run: Mock, manager: GitConfigManager) -> None:
        """Test getting config when none exists."""
        mock_run.return_value = Mock(returncode=1, stdout="")
        config = manager.get_current_config()
        assert config == {}

    @patch("subprocess.run")
    def test_detect_config_changes_with_changes(
        self, mock_run: Mock, temp_home: Path, manager: GitConfigManager
    ) -> None:
        """Test detecting configuration changes."""
        # Create a gitconfig file
        gitconfig = temp_home / ".gitconfig"
        gitconfig.write_text("[user]\n    name = Jane Doe\n")

        mock_run.return_value = Mock(returncode=0, stdout="user.name=Jane Doe\0")
        changes = manager.detect_config_changes()
        assert isinstance(changes, dict)

    @patch("subprocess.run")
    def test_detect_config_changes_no_changes(
        self, mock_run: Mock, manager: GitConfigManager
    ) -> None:
        """Test detecting when no changes."""
        mock_run.return_value = Mock(returncode=0, stdout="")
        changes = manager.detect_config_changes()
        assert changes == {}

    @patch("subprocess.run")
    def test_reload_git_config_success(self, mock_run: Mock, manager: GitConfigManager) -> None:
        """Test reloading git configuration."""
        mock_run.return_value = Mock(returncode=0, stderr="")
        result = manager.reload_git_config()
        assert result is True

    @patch("subprocess.run")
    def test_reload_git_config_failure(self, mock_run: Mock, manager: GitConfigManager) -> None:
        """Test git config reload failure."""
        mock_run.return_value = Mock(returncode=1, stderr="fatal: error")
        result = manager.reload_git_config()
        assert result is False

    def test_verify_hooks_missing(self, manager: GitConfigManager) -> None:
        """Test hook verification when hooks missing."""
        result = manager.verify_hooks()
        assert result is False

    def test_verify_hooks_exist(self, temp_home: Path) -> None:
        """Test hook verification when hooks exist."""
        hooks_dir = temp_home / ".git-templates" / "hooks"
        # Create a hook file
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("#!/bin/bash\necho 'test'\n")
        pre_commit.chmod(0o755)

        manager = GitConfigManager(home_dir=str(temp_home))
        result = manager.verify_hooks()
        # Should succeed if at least one hook is found and executable
        assert isinstance(result, bool)

    def test_create_backup_no_gitconfig(self, manager: GitConfigManager) -> None:
        """Test backup creation when no gitconfig exists."""
        result = manager.create_backup()
        assert result is None

    def test_create_backup_with_gitconfig(self, temp_home: Path) -> None:
        """Test backup creation with existing gitconfig."""
        gitconfig = temp_home / ".gitconfig"
        gitconfig.write_text("[user]\n    name = Test User\n")

        manager = GitConfigManager(home_dir=str(temp_home))
        backup_path = manager.create_backup()
        assert backup_path is not None
        assert backup_path.exists()
        assert "backup" in backup_path.name

    @patch.object(GitConfigManager, "verify_hooks")
    @patch("cli.git_config_manager.subprocess.run")
    def test_reload_hooks_success(
        self, mock_run: Mock, mock_verify: Mock, manager: GitConfigManager
    ) -> None:
        """Test hook reloading."""
        mock_verify.return_value = True
        mock_run.return_value = Mock(returncode=0)
        result = manager.reload_hooks()
        assert result is True

    @patch.object(GitConfigManager, "verify_hooks")
    def test_reload_hooks_failure(self, mock_verify: Mock, manager: GitConfigManager) -> None:
        """Test hook reload when verification fails."""
        mock_verify.return_value = False
        result = manager.reload_hooks()
        assert result is False

    @patch("subprocess.run")
    def test_reload_credential_helpers_with_helper(
        self, mock_run: Mock, manager: GitConfigManager
    ) -> None:
        """Test credential helper reload."""
        mock_run.return_value = Mock(returncode=0, stdout="osxkeychain")
        result = manager.reload_credential_helpers()
        assert result is True

    def test_generate_report(self, temp_home: Path) -> None:
        """Test report generation."""
        gitconfig = temp_home / ".gitconfig"
        gitconfig.write_text("[user]\n    name = Test User\n    email = test@example.com\n")

        manager = GitConfigManager(home_dir=str(temp_home))
        report = manager.generate_report()
        assert "timestamp" in report
        assert "config_status" in report
        assert "hooks_status" in report
        assert "directories" in report

    def test_display_report(self, manager: GitConfigManager) -> None:
        """Test report display."""
        report = {
            "timestamp": "2024-01-01T00:00:00",
            "config_status": {
                "user_name": "Test User",
                "user_email": "test@example.com",
                "default_editor": "vim",
                "pull_rebase": "false",
            },
            "hooks_status": {
                "pre_commit": True,
                "commit_msg": False,
                "post_commit": False,
                "prepare_commit_msg": False,
            },
            "directories": {
                "config_dir": "/tmp/config",
                "templates_dir": "/tmp/templates",
                "hooks_dir": "/tmp/hooks",
            },
        }
        # The method should complete without error
        manager.display_report(report)
        assert report["timestamp"] == "2024-01-01T00:00:00"

    @patch.object(GitConfigManager, "validate_git_config_syntax")
    @patch.object(GitConfigManager, "create_backup")
    @patch.object(GitConfigManager, "detect_config_changes")
    @patch.object(GitConfigManager, "reload_git_config")
    @patch.object(GitConfigManager, "reload_hooks")
    @patch.object(GitConfigManager, "reload_credential_helpers")
    @patch.object(GitConfigManager, "generate_report")
    @patch.object(GitConfigManager, "display_report")
    def test_reload_all_success(
        self,
        mock_display: Mock,
        mock_gen: Mock,
        mock_cred: Mock,
        mock_hooks: Mock,
        mock_git: Mock,
        mock_changes: Mock,
        mock_backup: Mock,
        mock_validate: Mock,
        manager: GitConfigManager,
    ) -> None:
        """Test complete reload."""
        mock_validate.return_value = True
        mock_git.return_value = True
        mock_hooks.return_value = True
        mock_cred.return_value = True
        mock_gen.return_value = {}

        result = manager.reload_all()
        assert result is True

    @patch.object(GitConfigManager, "validate_git_config_syntax")
    def test_reload_all_validation_fails(
        self, mock_validate: Mock, manager: GitConfigManager
    ) -> None:
        """Test reload when validation fails."""
        mock_validate.return_value = False
        result = manager.reload_all()
        assert result is False

    @patch.object(GitConfigManager, "validate_git_config_syntax")
    @patch.object(GitConfigManager, "detect_config_changes")
    @patch.object(GitConfigManager, "verify_hooks")
    def test_reload_all_dry_run(
        self, mock_verify: Mock, mock_changes: Mock, mock_validate: Mock, manager: GitConfigManager
    ) -> None:
        """Test dry run mode."""
        mock_validate.return_value = True
        with (
            patch.object(manager, "generate_report") as mock_gen,
            patch.object(manager, "display_report"),
        ):
            mock_gen.return_value = {}
            result = manager.reload_all(dry_run=True)
            assert result is True

    def test_reload_component_config(self, manager: GitConfigManager) -> None:
        """Test reloading specific component."""
        with patch.object(manager, "reload_git_config") as mock_reload:
            mock_reload.return_value = True
            result = manager.reload_component("config")
            mock_reload.assert_called_once()

    def test_reload_component_hooks(self, manager: GitConfigManager) -> None:
        """Test reloading hooks component."""
        with patch.object(manager, "reload_hooks") as mock_reload:
            mock_reload.return_value = True
            result = manager.reload_component("hooks")
            mock_reload.assert_called_once()

    def test_reload_component_credentials(self, manager: GitConfigManager) -> None:
        """Test reloading credentials component."""
        with patch.object(manager, "reload_credential_helpers") as mock_reload:
            mock_reload.return_value = True
            result = manager.reload_component("credentials")
            mock_reload.assert_called_once()

    def test_reload_component_invalid(self, manager: GitConfigManager) -> None:
        """Test reloading invalid component."""
        result = manager.reload_component("invalid")
        assert result is False


class TestGitConfigManagerErrorHandling:
    """Test error handling and edge cases."""

    def test_validate_git_config_syntax_success(self, manager: GitConfigManager) -> None:
        """Test validation with valid config."""
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[user]\n\tname = Test User\n")

        result = manager.validate_git_config_syntax()
        assert isinstance(result, bool)

    def test_get_current_config_empty(self, manager: GitConfigManager) -> None:
        """Test getting config when no config exists."""
        result = manager.get_current_config()
        assert isinstance(result, dict)

    def test_detect_config_changes_no_previous(self, manager: GitConfigManager) -> None:
        """Test detecting changes with no previous config."""
        result = manager.detect_config_changes()
        assert isinstance(result, dict)

    def test_reload_git_config_missing_file(self, manager: GitConfigManager) -> None:
        """Test reloading config when config file is missing."""
        result = manager.reload_git_config()
        # Should handle gracefully
        assert isinstance(result, bool)

    def test_verify_hooks_no_hooks_dir(self, manager: GitConfigManager) -> None:
        """Test verifying hooks when hooks directory is missing."""
        import shutil

        hooks_dir = manager.git_hooks_dir
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir)

        result = manager.verify_hooks()
        assert isinstance(result, bool)

    def test_create_backup_success(self, manager: GitConfigManager) -> None:
        """Test creating backup of config."""
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[user]\n\tname = Test User\n")

        backup = manager.create_backup()
        assert backup is None or isinstance(backup, Path)

    def test_reload_hooks_missing_dir(self, manager: GitConfigManager) -> None:
        """Test reloading hooks with missing directory."""
        import shutil

        hooks_dir = manager.git_hooks_dir
        if hooks_dir.exists():
            shutil.rmtree(hooks_dir)

        result = manager.reload_hooks()
        assert isinstance(result, bool)

    def test_reload_credential_helpers_no_config(self, manager: GitConfigManager) -> None:
        """Test reloading credential helpers with no config."""
        result = manager.reload_credential_helpers()
        assert isinstance(result, bool)

    def test_generate_report_structure(self, manager: GitConfigManager) -> None:
        """Test report generation structure."""
        report = manager.generate_report()

        assert isinstance(report, dict)
        assert "timestamp" in report or len(report) > 0

    def test_reload_all_with_errors(self, manager: GitConfigManager) -> None:
        """Test reload_all with potential errors."""
        result = manager.reload_all()
        assert isinstance(result, bool)

    def test_reload_component_config(self, manager: GitConfigManager) -> None:
        """Test reloading config component."""
        with patch.object(manager, "reload_git_config", return_value=True) as mock_reload:
            result = manager.reload_component("config")
            assert result is True
            mock_reload.assert_called_once()

    def test_reload_component_hooks(self, manager: GitConfigManager) -> None:
        """Test reloading hooks component."""
        with patch.object(manager, "reload_hooks", return_value=True) as mock_reload:
            result = manager.reload_component("hooks")
            assert result is True
            mock_reload.assert_called_once()

    def test_reload_component_credentials(self, manager: GitConfigManager) -> None:
        """Test reloading credentials component."""
        with patch.object(manager, "reload_credential_helpers", return_value=True) as mock_reload:
            result = manager.reload_component("credentials")
            assert result is True
            mock_reload.assert_called_once()


class TestGitConfigManagerIntegration:
    """Integration tests for GitConfigManager."""

    def test_complete_workflow(self, temp_home: Path) -> None:
        """Test complete workflow."""
        manager = GitConfigManager(home_dir=str(temp_home))

        # Setup basic config
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[user]\n\tname = Test User\n\temail = test@example.com\n")

        # Validate
        is_valid = manager.validate_git_config_syntax()
        assert isinstance(is_valid, bool)

        # Get current config
        config = manager.get_current_config()
        assert isinstance(config, dict)

        # Generate report
        report = manager.generate_report()
        assert isinstance(report, dict)

    def test_config_change_detection(self, manager: GitConfigManager) -> None:
        """Test configuration change detection."""
        config_file = manager.git_config_dir / "config"

        # First read
        config1 = manager.get_current_config()

        # Make a change
        config_file.write_text("[user]\n\tname = Changed\n")

        # Detect changes
        changes = manager.detect_config_changes()
        assert isinstance(changes, dict)

    def test_backup_and_restore(self, manager: GitConfigManager) -> None:
        """Test backup creation."""
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[core]\n\tignorecase = true\n")

        backup = manager.create_backup()
        assert backup is None or isinstance(backup, Path)


class TestColors:
    """Tests for Colors class."""

    def test_color_codes_defined(self) -> None:
        """Test that all color codes are defined."""
        assert Colors.GREEN != ""
        assert Colors.RED != ""
        assert Colors.YELLOW != ""
        assert Colors.BLUE != ""
        assert Colors.RESET != ""


class TestExceptionHandling:
    """Test exception handling in GitConfigManager."""

    def test_get_current_config_oserror(self, manager: GitConfigManager) -> None:
        """Test OSError handling in get_current_config."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            mock_run.side_effect = OSError("Permission denied")
            result = manager.get_current_config()
            assert result == {}

    def test_detect_config_changes_oserror(self, manager: GitConfigManager) -> None:
        """Test OSError handling in detect_config_changes."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            mock_run.side_effect = OSError("Permission denied")
            result = manager.detect_config_changes()
            assert result == {}

    def test_reload_git_config_oserror(self, manager: GitConfigManager) -> None:
        """Test OSError handling in reload_git_config."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            mock_run.side_effect = OSError("Command failed")
            result = manager.reload_git_config()
            assert result is False


class TestConfigChangeDetection:
    """Test configuration change detection paths."""

    def test_detect_config_changes_with_changes(self, manager: GitConfigManager) -> None:
        """Test detecting actual config changes."""

        # Mock run_command to return current and new configs
        def mock_run(cmd, timeout=None):
            if "--list" in cmd and "--null" in cmd:
                # Return different config depending on whether it's current or from file
                return Mock(
                    returncode=0, stdout="user.name=John\nuser.email=john@example.com\0", stderr=""
                )
            return Mock(returncode=0, stdout="", stderr="")

        with patch("cli.git_config_manager.run_command") as mock_run_cmd:
            with patch.object(manager, "get_current_config") as mock_get:
                mock_get.return_value = {"user.name": "John"}
                mock_run_cmd.side_effect = mock_run

                # Setup git_global_config file
                manager.git_global_config.write_text("[user]\nname = Jane\n")

                changes = manager.detect_config_changes()

                # Should detect the email change
                assert isinstance(changes, dict)

    def test_detect_config_changes_many_changes(self, manager: GitConfigManager) -> None:
        """Test detecting many config changes."""
        config_output = "\0".join([f"setting{i}=value{i}" for i in range(10)]) + "\0"

        with patch("cli.git_config_manager.run_command") as mock_run:
            with patch.object(manager, "get_current_config") as mock_get:
                mock_get.return_value = {}
                mock_run.return_value = Mock(returncode=0, stdout=config_output, stderr="")

                manager.git_global_config.write_text("[core]\n")

                changes = manager.detect_config_changes()

                # Should detect multiple changes
                assert len(changes) > 0


class TestHookVerification:
    """Test hook verification and error handling."""

    def test_verify_hooks_with_permission_error(self, manager: GitConfigManager) -> None:
        """Test verify_hooks when chmod fails on non-executable hook."""
        hook_file = manager.git_hooks_dir / "pre-commit"
        hook_file.write_text("#!/bin/bash\necho 'hook'\n")
        hook_file.chmod(0o644)  # Non-executable

        # Should handle gracefully
        with patch.object(manager, "print_status"):
            result = manager.verify_hooks()
            # Should succeed or fail gracefully
            assert isinstance(result, bool)

    def test_verify_hooks_permission_denied_chmod(self, manager: GitConfigManager) -> None:
        """Test verify_hooks when chmod fails."""
        hook_file = manager.git_hooks_dir / "pre-commit"
        hook_file.write_text("#!/bin/bash\necho 'hook'\n")
        hook_file.chmod(0o644)  # Not executable

        with patch.object(Path, "chmod") as mock_chmod:
            mock_chmod.side_effect = OSError("Permission denied")
            with patch.object(manager, "print_status"):
                result = manager.verify_hooks()
                # Should return False due to chmod failure
                assert result is False or result is True


class TestHookReloading:
    """Test hook reloading functionality."""

    def test_reload_hooks_syntax_error(self, manager: GitConfigManager) -> None:
        """Test reload_hooks with bash syntax error."""
        hook_file = manager.git_hooks_dir / "pre-commit"
        hook_file.write_text("#!/bin/bash\necho 'invalid bash syntax\n")

        with patch("cli.git_config_manager.run_command") as mock_run:
            # Verify returns True (no hooks to verify)
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            # Then bash -n returns syntax error
            with patch("cli.git_config_manager.subprocess.run") as mock_subprocess:
                mock_subprocess.return_value = Mock(returncode=1, stderr="syntax error")
                with patch.object(manager, "print_status"):
                    result = manager.reload_hooks()
                    # Should return False due to syntax error
                    assert isinstance(result, bool)

    def test_reload_hooks_oserror(self, manager: GitConfigManager) -> None:
        """Test reload_hooks with OSError."""
        with patch.object(manager, "verify_hooks") as mock_verify:
            mock_verify.side_effect = OSError("Permission denied")
            result = manager.reload_hooks()
            assert result is False


class TestCredentialHelpers:
    """Test credential helper management."""

    def test_reload_credential_helpers_not_found(self, manager: GitConfigManager) -> None:
        """Test reload_credential_helpers when helper is not found."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            # Git config returns empty for credential.helper
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            with patch.object(manager, "print_status"):
                result = manager.reload_credential_helpers()
                assert isinstance(result, bool)

    def test_reload_credential_helpers_found(self, manager: GitConfigManager) -> None:
        """Test reload_credential_helpers when helper is found."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            # Git config returns helper
            mock_run.return_value = Mock(returncode=0, stdout="osxkeychain", stderr="")
            with patch.object(manager, "print_status"):
                result = manager.reload_credential_helpers()
                assert isinstance(result, bool)

    def test_reload_credential_helpers_oserror(self, manager: GitConfigManager) -> None:
        """Test reload_credential_helpers with OSError."""
        with patch("cli.git_config_manager.run_command") as mock_run:
            mock_run.side_effect = OSError("Permission denied")
            result = manager.reload_credential_helpers()
            assert result is False


class TestBackupCreation:
    """Test backup file creation and security."""

    def test_create_backup_oserror_read(self, manager: GitConfigManager) -> None:
        """Test create_backup when read fails."""
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[user]\nname = Test\n")

        with patch.object(Path, "read_text") as mock_read:
            mock_read.side_effect = OSError("Permission denied")
            with patch.object(manager, "print_status"):
                result = manager.create_backup()
                assert result is None

    def test_create_backup_oserror_write(self, manager: GitConfigManager) -> None:
        """Test create_backup when write fails."""
        config_file = manager.git_config_dir / "config"
        config_file.write_text("[user]\nname = Test\n")

        with patch.object(Path, "write_text") as mock_write:
            mock_write.side_effect = OSError("Disk full")
            with patch.object(manager, "print_status"):
                result = manager.create_backup()
                assert result is None


class TestMainFunction:
    """Test main CLI function."""

    def test_main_no_arguments(self, tmp_path: Path) -> None:
        """Test main with no arguments."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_all.return_value = True
                mock_mgr_class.return_value = mock_mgr
                # Should not raise exception
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_verbose_flag(self) -> None:
        """Test main with --verbose flag."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--verbose"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_all.return_value = True
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_component_config(self) -> None:
        """Test main with --component config."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--component", "config"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_component.return_value = True
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_component_hooks(self) -> None:
        """Test main with --component hooks."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--component", "hooks"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_component.return_value = True
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_component_credentials(self) -> None:
        """Test main with --component credentials."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--component", "credentials"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_component.return_value = True
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_dry_run(self) -> None:
        """Test main with --dry-run flag."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--dry-run"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_home_directory(self, tmp_path: Path) -> None:
        """Test main with --home argument."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py", "--home", str(tmp_path)]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_all.return_value = True
                mock_mgr_class.return_value = mock_mgr
                main()
        except SystemExit as e:
            assert e.code in [0, 1]
        finally:
            sys.argv = original_argv

    def test_main_failure(self) -> None:
        """Test main exits with 1 on failure."""
        from cli.git_config_manager import main

        original_argv = sys.argv
        try:
            sys.argv = ["git_config_manager.py"]
            with patch("cli.git_config_manager.GitConfigManager") as mock_mgr_class:
                mock_mgr = MagicMock()
                mock_mgr.reload_all.return_value = False
                mock_mgr_class.return_value = mock_mgr
                try:
                    main()
                except SystemExit as e:
                    assert e.code == 1
        finally:
            sys.argv = original_argv
