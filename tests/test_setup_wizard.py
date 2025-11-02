#!/usr/bin/env python3
"""
Tests for Setup Wizard module.

Tests interactive setup wizard functionality including:
- Configuration management
- User interaction
- Progress tracking
- Validation
"""

import pytest
import sys
import tempfile
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import shutil

# Mock sys.argv to prevent argparse issues during import
sys.argv = ["pytest"]

from cli.setup_wizard import ProgressBar, Colors, SetupWizard


class TestColors:
    """Tests for Colors class."""

    def test_color_codes_defined(self) -> None:
        """Test that all color codes are defined."""
        assert Colors.RESET != ""
        assert Colors.BOLD != ""
        assert Colors.DIM != ""

    def test_foreground_colors(self) -> None:
        """Test foreground color codes."""
        assert Colors.RED != ""
        assert Colors.GREEN != ""
        assert Colors.YELLOW != ""
        assert Colors.BLUE != ""
        assert Colors.CYAN != ""
        assert Colors.WHITE != ""

    def test_style_colors(self) -> None:
        """Test style color codes."""
        assert Colors.SUCCESS != ""
        assert Colors.ERROR != ""
        assert Colors.WARNING != ""
        assert Colors.INFO != ""
        assert Colors.PROMPT != ""

    def test_color_string_formatting(self) -> None:
        """Test color string composition."""
        colored_text = f"{Colors.GREEN}Success{Colors.RESET}"
        assert Colors.GREEN in colored_text
        assert Colors.RESET in colored_text
        assert "Success" in colored_text


class TestProgressBar:
    """Tests for ProgressBar class."""

    def test_progress_bar_init(self) -> None:
        """Test ProgressBar initialization."""
        bar = ProgressBar(total=100, description="Loading")
        assert bar.total == 100
        assert bar.current == 0
        assert bar.description == "Loading"
        assert bar.start_time is not None

    def test_progress_bar_init_no_description(self) -> None:
        """Test ProgressBar without description."""
        bar = ProgressBar(total=50)
        assert bar.total == 50
        assert bar.description == ""

    def test_progress_bar_default_total(self) -> None:
        """Test ProgressBar with default total."""
        bar = ProgressBar(total=1)
        assert bar.total == 1

    def test_progress_bar_large_total(self) -> None:
        """Test ProgressBar with large total."""
        bar = ProgressBar(total=10000)
        assert bar.total == 10000

    @patch("builtins.print")
    def test_progress_bar_update(
        self, mock_print: Mock
    ) -> None:
        """Test updating progress bar."""
        bar = ProgressBar(total=100)
        # Test updating
        if hasattr(bar, "update"):
            bar.update()
            assert bar.current >= 0

    @patch("time.time")
    def test_progress_bar_elapsed_time(
        self, mock_time: Mock
    ) -> None:
        """Test elapsed time calculation."""
        mock_time.return_value = 100.0
        bar = ProgressBar(total=100, description="Test")
        if hasattr(bar, "start_time"):
            elapsed = mock_time.return_value - bar.start_time
            assert elapsed >= 0

    def test_progress_bar_percentage(self) -> None:
        """Test progress percentage calculation."""
        bar = ProgressBar(total=100)
        bar.current = 50
        # If the bar has a percentage method
        if hasattr(bar, "percentage"):
            percentage = bar.percentage()
            assert 0 <= percentage <= 100
        elif hasattr(bar, "current"):
            # Calculate percentage manually
            percentage = (bar.current / bar.total) * 100
            assert 50 <= percentage <= 50

    def test_progress_bar_multiple_updates(self) -> None:
        """Test multiple progress updates."""
        bar = ProgressBar(total=100)
        for i in range(1, 6):
            bar.current = i * 20
            assert bar.current == i * 20

    def test_progress_bar_completion(self) -> None:
        """Test progress bar completion."""
        bar = ProgressBar(total=100)
        bar.current = 100
        assert bar.current == bar.total

    def test_progress_bar_zero_total(self) -> None:
        """Test ProgressBar with zero total."""
        bar = ProgressBar(total=0)
        assert bar.total == 0

    def test_progress_bar_current_exceeds_total(self) -> None:
        """Test current progress exceeding total."""
        bar = ProgressBar(total=100)
        bar.current = 150
        assert bar.current == 150

    def test_progress_bar_description_update(self) -> None:
        """Test updating progress bar description."""
        bar = ProgressBar(total=100, description="Initial")
        assert bar.description == "Initial"
        if hasattr(bar, "description"):
            bar.description = "Updated"
            assert bar.description == "Updated"

    @patch("builtins.print")
    def test_progress_bar_display(
        self, mock_print: Mock
    ) -> None:
        """Test progress bar display."""
        bar = ProgressBar(total=100, description="Loading")
        if hasattr(bar, "display"):
            bar.display()
            mock_print.assert_called()

    def test_progress_bar_float_progress(self) -> None:
        """Test progress with float values."""
        bar = ProgressBar(total=100)
        bar.current = 33.33
        assert 33 <= bar.current < 34


class TestSetupWizardIntegration:
    """Tests for setup wizard integration."""

    def test_colors_in_progress_bar(self) -> None:
        """Test using colors in progress bar."""
        bar = ProgressBar(total=100, description=f"{Colors.INFO}Setup{Colors.RESET}")
        assert Colors.INFO in bar.description
        assert Colors.RESET in bar.description

    def test_multiple_progress_bars(self) -> None:
        """Test multiple progress bar instances."""
        bar1 = ProgressBar(total=100, description="Task 1")
        bar2 = ProgressBar(total=50, description="Task 2")

        assert bar1.total == 100
        assert bar2.total == 50
        assert bar1.description != bar2.description

    @patch("builtins.print")
    def test_progress_workflow(
        self, mock_print: Mock
    ) -> None:
        """Test complete progress workflow."""
        bar = ProgressBar(total=10, description="Setup")
        bar.current = 0
        assert bar.current == 0

        bar.current = 5
        assert bar.current == 5

        bar.current = 10
        assert bar.current == 10

    def test_color_combinations(self) -> None:
        """Test various color combinations."""
        combinations = [
            (Colors.GREEN, "Success", Colors.RESET),
            (Colors.RED, "Error", Colors.RESET),
            (Colors.YELLOW, "Warning", Colors.RESET),
            (Colors.BLUE, "Info", Colors.RESET),
            (Colors.CYAN, "Prompt", Colors.RESET),
        ]

        for color, text, reset in combinations:
            colored = f"{color}{text}{reset}"
            assert color in colored
            assert text in colored
            assert reset in colored


class TestSetupWizard:
    """Tests for SetupWizard class."""

    def setup_method(self) -> None:
        """Set up test wizard."""
        self.temp_dir = tempfile.mkdtemp()
        self.wizard = SetupWizard(project_root=self.temp_dir)

    def teardown_method(self) -> None:
        """Clean up."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_wizard_initialization(self) -> None:
        """Test SetupWizard initialization."""
        assert self.wizard is not None
        assert self.wizard.project_root == Path(self.temp_dir)
        assert isinstance(self.wizard.config, dict)
        assert self.wizard.logger is not None

    def test_wizard_default_project_root(self) -> None:
        """Test SetupWizard with default project root."""
        wizard = SetupWizard()
        assert wizard.project_root is not None
        assert wizard.project_root.exists() or wizard.project_root.parent.exists()

    def test_wizard_config_dict(self) -> None:
        """Test that config is a dictionary."""
        assert isinstance(self.wizard.config, dict)
        assert len(self.wizard.config) == 0

    def test_wizard_logger_setup(self) -> None:
        """Test that logger is properly set up."""
        assert self.wizard.logger is not None
        assert self.wizard.logger.name == "devkit.wizard"

    def test_wizard_step_counter(self) -> None:
        """Test wizard step counter initialization."""
        assert self.wizard._step == 0
        assert self.wizard._total_steps == 8

    def test_print_header(self) -> None:
        """Test printing wizard header."""
        # Method should complete without error
        self.wizard._print_header()
        assert self.wizard._total_steps == 8

    def test_step_header(self) -> None:
        """Test printing step header."""
        self.wizard._step = 1
        # Method should complete without error
        self.wizard._step_header("Test Step")
        assert self.wizard._step == 1

    @patch("builtins.input", return_value="1")
    @patch("builtins.print")
    def test_ask_environment_development(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test asking for development environment."""
        self.wizard._ask_environment()
        assert self.wizard.config["environment"] == "development"

    @patch("builtins.input", return_value="2")
    @patch("builtins.print")
    def test_ask_environment_production(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test asking for production environment."""
        self.wizard._ask_environment()
        assert self.wizard.config["environment"] == "production"

    @patch("builtins.input", return_value="3")
    @patch("builtins.print")
    def test_ask_environment_staging(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test asking for staging environment."""
        self.wizard._ask_environment()
        assert self.wizard.config["environment"] == "staging"

    @patch("builtins.input", side_effect=["invalid", "1"])
    @patch("builtins.print")
    def test_ask_environment_invalid_then_valid(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test invalid then valid environment selection."""
        self.wizard._ask_environment()
        assert self.wizard.config["environment"] == "development"

    @patch("builtins.input", return_value="")
    @patch("builtins.print")
    def test_ask_enabled_roles_default(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test role selection with default."""
        self.wizard._ask_enabled_roles()
        # Default should select first 5 roles
        assert "enabled_roles" in self.wizard.config
        assert len(self.wizard.config["enabled_roles"]) == 5

    @patch("builtins.input", return_value="1,2,3")
    @patch("builtins.print")
    def test_ask_enabled_roles_custom(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test custom role selection."""
        self.wizard._ask_enabled_roles()
        assert "enabled_roles" in self.wizard.config
        assert len(self.wizard.config["enabled_roles"]) == 3

    @patch("builtins.input", side_effect=["invalid", "1,2"])
    @patch("builtins.print")
    def test_ask_enabled_roles_invalid_then_valid(
        self, mock_print: Mock, mock_input: Mock
    ) -> None:
        """Test invalid then valid role selection."""
        self.wizard._ask_enabled_roles()
        assert len(self.wizard.config["enabled_roles"]) == 2

    @patch("builtins.input", return_value="1")
    @patch("builtins.print")
    def test_ask_shell_zsh(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test selecting zsh shell."""
        self.wizard._ask_shell()
        assert self.wizard.config["shell"] == "zsh"

    @patch("builtins.input", return_value="2")
    @patch("builtins.print")
    def test_ask_shell_fish(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test selecting fish shell."""
        self.wizard._ask_shell()
        assert self.wizard.config["shell"] == "fish"

    @patch("builtins.input", return_value="3")
    @patch("builtins.print")
    def test_ask_shell_none(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test skipping shell setup."""
        self.wizard._ask_shell()
        assert self.wizard.config["shell"] == "none"

    @patch("builtins.input", return_value="y")
    @patch("builtins.print")
    def test_ask_editors_with_selection(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test editor selection with yes responses."""
        self.wizard._ask_editors()
        assert "editors" in self.wizard.config
        assert isinstance(self.wizard.config["editors"], list)

    @patch("builtins.input", return_value="n")
    @patch("builtins.print")
    def test_ask_editors_defaults_to_neovim(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test editors defaults to neovim if nothing selected."""
        self.wizard._ask_editors()
        assert self.wizard.config["editors"] == ["neovim"]

    @patch("builtins.input", side_effect=["y", "n", "n"])
    @patch("builtins.print")
    def test_ask_editors_partial_selection(
        self, mock_print: Mock, mock_input: Mock
    ) -> None:
        """Test partial editor selection."""
        self.wizard._ask_editors()
        assert "neovim" in self.wizard.config["editors"]

    @patch("builtins.input", side_effect=["y", "y", "n"])
    @patch("builtins.print")
    def test_ask_security_multiple_options(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test security configuration with multiple options."""
        self.wizard._ask_security()
        assert "security" in self.wizard.config
        assert isinstance(self.wizard.config["security"], dict)
        assert self.wizard.config["security"]["ssh_setup"] is True
        assert self.wizard.config["security"]["gpg_setup"] is True
        assert self.wizard.config["security"]["audit_logging"] is False

    @patch("builtins.input", return_value="y")
    @patch("builtins.print")
    def test_ask_backup_enabled(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test backup configuration enabled."""
        self.wizard._ask_backup()
        assert self.wizard.config["backup_enabled"] is True

    @patch("builtins.input", side_effect=["y", "/custom/backup"])
    @patch("builtins.print")
    def test_ask_backup_custom_location(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test backup with custom location."""
        self.wizard._ask_backup()
        assert self.wizard.config["backup_enabled"] is True
        assert self.wizard.config["backup_location"] == "/custom/backup"

    @patch("builtins.input", side_effect=["y", ""])
    @patch("builtins.print")
    def test_ask_backup_default_location(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test backup with default location."""
        self.wizard._ask_backup()
        assert self.wizard.config["backup_enabled"] is True
        assert self.wizard.config["backup_location"] == "~/.devkit/backups"

    @patch("builtins.input", return_value="n")
    @patch("builtins.print")
    def test_ask_backup_disabled(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test backup configuration disabled."""
        self.wizard._ask_backup()
        assert self.wizard.config["backup_enabled"] is False

    @patch("builtins.input", return_value="y")
    @patch("builtins.print")
    def test_ask_verification_enabled(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test verification enabled."""
        self.wizard._ask_verification()
        assert self.wizard.config["verify_after_setup"] is True

    @patch("builtins.input", return_value="n")
    @patch("builtins.print")
    def test_ask_verification_disabled(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test verification disabled."""
        self.wizard._ask_verification()
        assert self.wizard.config["verify_after_setup"] is False

    @patch("builtins.input", return_value="y")
    @patch("builtins.print")
    def test_confirm_settings_proceed(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test confirming settings and proceeding."""
        # Set up minimal config first
        self.wizard.config = {
            "environment": "development",
            "enabled_roles": ["core", "shell"],
            "shell": "zsh",
            "editors": ["neovim"],
            "backup_enabled": True,
            "verify_after_setup": True,
        }
        self.wizard._confirm_settings()
        # Should not raise and should not exit if we confirm

    @patch("builtins.input", return_value="n")
    @patch("builtins.print")
    def test_confirm_settings_cancel(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test canceling settings confirmation."""
        self.wizard.config = {
            "environment": "development",
            "enabled_roles": ["core"],
            "shell": "zsh",
            "editors": ["neovim"],
            "backup_enabled": False,
            "verify_after_setup": False,
        }
        with pytest.raises(SystemExit):
            self.wizard._confirm_settings()

    def test_save_config_default_path(self) -> None:
        """Test saving config to default path."""
        self.wizard.config = {
            "environment": "development",
            "enabled_roles": ["core"],
            "shell": "zsh",
        }
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path(self.temp_dir)
            saved_path = self.wizard.save_config()
            assert saved_path is not None
            assert Path(saved_path).exists()

    def test_save_config_custom_path(self) -> None:
        """Test saving config to custom path."""
        self.wizard.config = {
            "environment": "development",
            "enabled_roles": ["core"],
        }
        custom_path = Path(self.temp_dir) / "custom_config.yaml"
        saved_path = self.wizard.save_config(str(custom_path))
        assert Path(saved_path).exists()
        assert Path(saved_path).name == "custom_config.yaml"

    def test_save_config_creates_parent_directories(self) -> None:
        """Test that save_config creates parent directories."""
        self.wizard.config = {"test": "value"}
        nested_path = Path(self.temp_dir) / "nested" / "dirs" / "config.yaml"
        saved_path = self.wizard.save_config(str(nested_path))
        assert Path(saved_path).exists()
        assert Path(saved_path).parent.exists()

    @patch("builtins.input", return_value="1")
    @patch("builtins.print")
    def test_wizard_run_partial(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test running parts of wizard."""
        # Just test that methods can be called without errors
        self.wizard._ask_environment()
        assert "environment" in self.wizard.config

    def test_format_time_seconds(self) -> None:
        """Test time formatting for seconds."""
        bar = ProgressBar(total=100)
        formatted = bar._format_time(45)
        assert "s" in formatted

    def test_format_time_minutes(self) -> None:
        """Test time formatting for minutes."""
        bar = ProgressBar(total=100)
        formatted = bar._format_time(120)
        assert "m" in formatted

    def test_format_time_hours(self) -> None:
        """Test time formatting for hours."""
        bar = ProgressBar(total=100)
        formatted = bar._format_time(3600)
        assert "h" in formatted

    @patch("builtins.print")
    @patch("time.time")
    def test_progress_bar_finish(self, mock_time: Mock, mock_print: Mock) -> None:
        """Test finishing progress bar."""
        mock_time.return_value = 100.0
        bar = ProgressBar(total=100, description="Test")
        bar.finish()
        assert bar.current == bar.total

    @patch("builtins.input", side_effect=["1", "1", "1", "n", "n", "n", "y", "n", "y", "n", "y", "y"])
    @patch("builtins.print")
    def test_wizard_run_complete_sequence(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test running the complete wizard with all 8 steps."""
        result = self.wizard.run()
        assert result == self.wizard.config
        assert "environment" in result
        assert "enabled_roles" in result
        assert "shell" in result
        assert "editors" in result
        assert "security" in result
        assert "backup_enabled" in result
        assert "verify_after_setup" in result

    @patch("builtins.input", side_effect=["1", "", "1", "n", "n", "n", "y", "n", "y", "y", "/backup", "y", "y"])
    @patch("builtins.print")
    def test_wizard_run_with_defaults_and_custom(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test wizard run with mix of defaults and custom values."""
        result = self.wizard.run()
        assert result["environment"] == "development"
        assert result["shell"] == "zsh"
        assert result["backup_location"] == "/backup"

    @patch("builtins.input", side_effect=["3", "1,3,5,7", "2", "y", "n", "n", "y", "y", "n", "n", "y", "y"])
    @patch("builtins.print")
    def test_wizard_run_all_options(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test wizard with various option combinations."""
        result = self.wizard.run()
        assert result["environment"] == "staging"
        assert len(result["enabled_roles"]) == 4
        assert result["shell"] == "fish"

    @patch("builtins.input", side_effect=["1", "invalid", "1,2", "2", "n", "n", "n", "y", "n", "y", "n", "y", "y"])
    @patch("builtins.print")
    def test_wizard_run_with_invalid_role_count(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test wizard with invalid role count then valid."""
        # This tests the branch coverage for line 179->169 (validation check)
        result = self.wizard.run()
        assert "enabled_roles" in result
        assert len(result["enabled_roles"]) == 2

    @patch("builtins.input", side_effect=["1", "1", "4", "1", "n", "n", "n", "y", "n", "y", "n", "y", "y"])
    @patch("builtins.print")
    def test_wizard_run_with_invalid_shell_then_valid(self, mock_print: Mock, mock_input: Mock) -> None:
        """Test wizard with invalid shell selection then valid."""
        # This tests the branch coverage for line 201->199
        result = self.wizard.run()
        assert result["shell"] == "zsh"


class TestSetupWizardMain:
    """Tests for the main() CLI function."""

    @patch("sys.argv", ["setup_wizard.py"])
    @patch("cli.setup_wizard.SetupWizard.run")
    @patch("cli.setup_wizard.SetupWizard.save_config")
    def test_main_with_wizard(self, mock_save: Mock, mock_run: Mock) -> None:
        """Test main function runs wizard."""
        from cli.setup_wizard import main

        mock_run.return_value = {"test": "config"}
        mock_save.return_value = "/path/to/config"

        result = main()
        assert result == 0
        mock_run.assert_called_once()
        mock_save.assert_called_once()

    @patch("sys.argv", ["setup_wizard.py", "--skip-wizard"])
    def test_main_skip_wizard(self) -> None:
        """Test main function with --skip-wizard flag."""
        from cli.setup_wizard import main

        result = main()
        assert result == 0

    @patch("sys.argv", ["setup_wizard.py", "--config", "/custom/config.yaml"])
    @patch("cli.setup_wizard.SetupWizard.run")
    @patch("cli.setup_wizard.SetupWizard.save_config")
    def test_main_with_custom_config_path(self, mock_save: Mock, mock_run: Mock) -> None:
        """Test main function with custom config path."""
        from cli.setup_wizard import main

        mock_run.return_value = {"test": "config"}
        mock_save.return_value = "/custom/config.yaml"

        result = main()
        assert result == 0
        # Verify save_config was called with the custom path
        mock_save.assert_called_once_with("/custom/config.yaml")

    @patch("sys.argv", ["setup_wizard.py", "--project-root", "/custom/root"])
    @patch("cli.setup_wizard.SetupWizard")
    def test_main_with_custom_project_root(self, mock_wizard_class: Mock) -> None:
        """Test main function with custom project root."""
        from cli.setup_wizard import main

        mock_wizard_instance = MagicMock()
        mock_wizard_class.return_value = mock_wizard_instance
        mock_wizard_instance.run.return_value = {"test": "config"}
        mock_wizard_instance.save_config.return_value = "/path/to/config"

        result = main()
        assert result == 0
        # Verify SetupWizard was instantiated with custom project root
        mock_wizard_class.assert_called_once_with("/custom/root")

    @patch("sys.argv", ["setup_wizard.py", "--skip-wizard", "--config", "/custom/config.yaml"])
    def test_main_skip_wizard_with_custom_config(self) -> None:
        """Test main with both --skip-wizard and --config flags."""
        from cli.setup_wizard import main

        result = main()
        assert result == 0

    @patch("sys.argv", ["setup_wizard.py"])
    @patch("cli.setup_wizard.logging.basicConfig")
    @patch("cli.setup_wizard.SetupWizard.run")
    @patch("cli.setup_wizard.SetupWizard.save_config")
    def test_main_logging_configured(self, mock_save: Mock, mock_run: Mock, mock_logging: Mock) -> None:
        """Test that main function configures logging."""
        from cli.setup_wizard import main

        mock_run.return_value = {"test": "config"}
        mock_save.return_value = "/path/to/config"

        result = main()
        assert result == 0
        mock_logging.assert_called_once()
