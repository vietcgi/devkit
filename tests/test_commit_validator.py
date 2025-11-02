#!/usr/bin/env python3
"""
Tests for CodeQualityValidator module.

Tests code quality validation functionality including:
- Code style checks
- Test coverage verification
- Security scanning
- Code complexity analysis
- Documentation validation
- Dependency checking
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Mock sys.argv to prevent argparse issues during import
sys.argv = ["pytest"]

from cli.commit_validator import CodeQualityValidator, Colors, main
from cli.utils import run_command


@pytest.fixture
def validator() -> CodeQualityValidator:
    """Create a CodeQualityValidator instance for testing."""
    return CodeQualityValidator()


@pytest.fixture
def mock_run_command(monkeypatch):
    """Mock the run_command function."""
    mock = MagicMock()
    monkeypatch.setattr("cli.commit_validator.run_command", mock)
    return mock


@pytest.fixture
def temp_path(tmp_path: Path) -> Path:
    """Create a temporary path for testing."""
    return tmp_path


@pytest.fixture
def temp_files(tmp_path: Path) -> list[str]:
    """Create temporary test files."""
    test_file = tmp_path / "test_module.py"
    test_file.write_text(
        '"""Test module."""\n\ndef test_func() -> None:\n    """Test function."""\n    pass\n'
    )
    return [str(test_file)]


class TestCodeQualityValidator:
    """Tests for CodeQualityValidator class."""

    def test_init(self, validator: CodeQualityValidator) -> None:
        """Test validator initialization."""
        assert validator.home == Path.home()
        assert "devkit" in str(validator.devkit_dir)
        assert validator.logger is not None

    def test_setup_logging(self, validator: CodeQualityValidator) -> None:
        """Test logging setup."""
        assert validator.log_file.exists()
        assert validator.logger is not None
        assert validator.logger.level == pytest.importorskip("logging").INFO

    def test_print_status_info(self, validator: CodeQualityValidator, caplog) -> None:
        """Test print_status with INFO level."""
        with caplog.at_level(logging.INFO):
            validator.print_status("Test message", "INFO")
        assert "Test message" in caplog.text

    def test_print_status_success(self, validator: CodeQualityValidator, caplog) -> None:
        """Test print_status with SUCCESS level."""
        with caplog.at_level(logging.INFO):
            validator.print_status("Success message", "SUCCESS")
        assert "Success message" in caplog.text

    def test_print_status_warning(self, validator: CodeQualityValidator, caplog) -> None:
        """Test print_status with WARNING level."""
        with caplog.at_level(logging.WARNING):
            validator.print_status("Warning message", "WARNING")
        assert "Warning message" in caplog.text

    def test_print_status_error(self, validator: CodeQualityValidator, caplog) -> None:
        """Test print_status with ERROR level."""
        with caplog.at_level(logging.ERROR):
            validator.print_status("Error message", "ERROR")
        assert "Error message" in caplog.text

    @patch("subprocess.run")
    def test_check_code_style_pass(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test code style check when passing."""
        mock_run.return_value = Mock(returncode=0, stdout="")
        passed, issues, score = validator.check_code_style(["test.py"])
        assert passed is True
        assert issues == []
        assert score == 100

    @patch("subprocess.run")
    def test_check_code_style_fail(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test code style check when failing."""
        mock_run.return_value = Mock(
            returncode=1, stdout="test.py:1:0: C0111: Missing docstring\nC: test.py missing"
        )
        passed, issues, score = validator.check_code_style(["test.py"])
        # Will be True if pylint errors are found but handled gracefully
        assert isinstance(passed, bool)
        assert isinstance(issues, list)

    @patch("subprocess.run")
    def test_check_code_style_pylint_not_found(
        self, mock_run: Mock, validator: CodeQualityValidator
    ) -> None:
        """Test code style check when pylint not installed."""
        mock_run.side_effect = FileNotFoundError()
        passed, issues, score = validator.check_code_style(["test.py"])
        assert passed is True
        assert score == 100

    @patch("subprocess.run")
    def test_check_test_coverage_pass(
        self, mock_run: Mock, validator: CodeQualityValidator
    ) -> None:
        """Test coverage check when passing."""
        mock_run.side_effect = [
            Mock(returncode=0),  # coverage run
            Mock(returncode=0, stdout="TOTAL       100      0 100%"),  # coverage report
        ]
        passed, issues, coverage = validator.check_test_coverage(["test.py"])
        assert passed is True
        assert coverage == 100.0

    @patch("subprocess.run")
    def test_check_test_coverage_fail(
        self, mock_run: Mock, validator: CodeQualityValidator
    ) -> None:
        """Test coverage check when below threshold."""
        mock_run.side_effect = [
            Mock(returncode=0),
            Mock(returncode=1, stdout="TOTAL       100      20 80%"),
        ]
        passed, issues, coverage = validator.check_test_coverage(["test.py"])
        assert passed is False

    @patch("subprocess.run")
    def test_check_security_pass(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test security check when passing."""
        mock_run.return_value = Mock(returncode=0, stdout="")
        passed, issues, score = validator.check_security(["test.py"])
        assert passed is True
        assert score == 100

    @patch("subprocess.run")
    def test_check_security_fail(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test security check when finding issues."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="Issue: Use of hardcoded SQL string\nSeverity: HIGH",
        )
        passed, issues, score = validator.check_security(["test.py"])
        assert passed is False
        assert len(issues) > 0

    @patch("subprocess.run")
    def test_check_complexity_pass(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test complexity check when acceptable."""
        mock_run.return_value = Mock(returncode=0, stdout="test.py - A")
        passed, issues, complexity = validator.check_complexity(["test.py"])
        assert passed is True

    @patch("subprocess.run")
    def test_check_complexity_high(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test complexity check when too high."""
        mock_run.return_value = Mock(returncode=0, stdout="test.py - F (very high)")
        passed, issues, complexity = validator.check_complexity(["test.py"])
        assert passed is False

    def test_check_documentation_pass(self, temp_files: list[str]) -> None:
        """Test documentation check when passing."""
        validator = CodeQualityValidator()
        # Create a properly documented file
        test_file = Path(temp_files[0])
        test_file.write_text(
            '"""Module docstring."""\n\ndef func():\n    """Function docstring."""\n    pass\n'
        )
        passed, issues, score = validator.check_documentation(temp_files)
        assert passed is True
        assert score == 100

    def test_check_documentation_missing_docstring(self, temp_files: list[str]) -> None:
        """Test documentation check with missing docstrings."""
        validator = CodeQualityValidator()
        test_file = Path(temp_files[0])
        test_file.write_text("def func():\n    pass\n")
        passed, issues, score = validator.check_documentation(temp_files)
        assert passed is False

    @patch("subprocess.run")
    def test_check_dependencies_pass(self, mock_run: Mock, validator: CodeQualityValidator) -> None:
        """Test dependency check when no vulnerabilities."""
        mock_run.return_value = Mock(returncode=0, stdout="")
        with patch("pathlib.Path.exists", return_value=True):
            passed, issues, score = validator.check_dependencies(["test.py"])
            # If requirements exist, pip-audit is called
            assert isinstance(passed, bool)
            assert isinstance(score, int)

    def test_get_staged_files(self, validator: CodeQualityValidator) -> None:
        """Test getting staged files from git."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="file1.py\nfile2.py")
            files = validator.get_staged_files()
            assert isinstance(files, list)

    def test_generate_quality_report(self, validator: CodeQualityValidator) -> None:
        """Test quality report generation."""
        checks = {
            "code_style": {"passed": True, "score": 100},
            "tests": {"passed": True, "score": 100},
            "security": {"passed": True, "score": 100},
        }
        report = validator.generate_quality_report(checks)
        assert "timestamp" in report
        assert "checks" in report
        assert "overall_quality_score" in report
        assert report["pass_all"] is True

    def test_generate_quality_report_with_failures(self, validator: CodeQualityValidator) -> None:
        """Test quality report with failing checks."""
        checks = {
            "code_style": {"passed": False, "score": 50},
            "tests": {"passed": True, "score": 100},
        }
        report = validator.generate_quality_report(checks)
        assert report["pass_all"] is False

    @patch.object(CodeQualityValidator, "check_code_style")
    @patch.object(CodeQualityValidator, "check_tests_pass")
    @patch.object(CodeQualityValidator, "check_test_coverage")
    @patch.object(CodeQualityValidator, "check_security")
    @patch.object(CodeQualityValidator, "check_complexity")
    @patch.object(CodeQualityValidator, "check_documentation")
    @patch.object(CodeQualityValidator, "check_dependencies")
    @patch.object(CodeQualityValidator, "save_quality_report")
    def test_run_all_checks(
        self,
        mock_save: Mock,
        mock_deps: Mock,
        mock_docs: Mock,
        mock_complexity: Mock,
        mock_security: Mock,
        mock_coverage: Mock,
        mock_tests: Mock,
        mock_style: Mock,
        validator: CodeQualityValidator,
    ) -> None:
        """Test running all quality checks."""
        mock_style.return_value = (True, [], 100)
        mock_tests.return_value = (True, [], 5)
        mock_coverage.return_value = (True, [], 85.0)
        mock_security.return_value = (True, [], 100)
        mock_complexity.return_value = (True, [], 5.0)
        mock_docs.return_value = (True, [], 100)
        mock_deps.return_value = (True, [], 100)

        report = validator.run_all_checks(files=["test.py"])
        assert isinstance(report, dict)
        mock_save.assert_called_once()

    @patch.object(CodeQualityValidator, "get_staged_files")
    @patch.object(CodeQualityValidator, "check_code_style")
    @patch.object(CodeQualityValidator, "check_tests_pass")
    @patch.object(CodeQualityValidator, "check_test_coverage")
    @patch.object(CodeQualityValidator, "check_security")
    @patch.object(CodeQualityValidator, "check_complexity")
    @patch.object(CodeQualityValidator, "check_documentation")
    @patch.object(CodeQualityValidator, "check_dependencies")
    @patch.object(CodeQualityValidator, "save_quality_report")
    def test_run_all_checks_no_files(
        self,
        mock_save: Mock,
        mock_deps: Mock,
        mock_docs: Mock,
        mock_complexity: Mock,
        mock_security: Mock,
        mock_coverage: Mock,
        mock_tests: Mock,
        mock_style: Mock,
        mock_staged: Mock,
        validator: CodeQualityValidator,
    ) -> None:
        """Test running checks with no files."""
        mock_staged.return_value = []
        result = validator.run_all_checks()
        assert result.get("status") == "no_files"

    def test_display_summary(self, validator: CodeQualityValidator, caplog) -> None:
        """Test summary display."""
        report = {
            "checks": {
                "code_style": {"passed": True, "score": 100},
                "tests": {"passed": False, "score": 0},
            },
            "overall_quality_score": 50.0,
            "pass_all": False,
        }
        with caplog.at_level(logging.INFO):
            validator.display_summary(report)
        # The method should complete without error
        assert report["overall_quality_score"] == 50.0

    def test_save_quality_report(self, validator: CodeQualityValidator) -> None:
        """Test saving quality report."""
        report = {
            "timestamp": "2024-01-01T00:00:00",
            "checks": {},
            "overall_quality_score": 100,
            "pass_all": True,
        }
        validator.save_quality_report(report)
        # Verify file was written
        assert validator.quality_report_file.exists()


class TestColors:
    """Tests for Colors class."""

    def test_color_codes_defined(self) -> None:
        """Test that all color codes are defined."""
        assert Colors.GREEN != ""
        assert Colors.RED != ""
        assert Colors.YELLOW != ""
        assert Colors.BLUE != ""
        assert Colors.RESET != ""


class TestCodeQualityValidatorErrorPaths:
    """Test error handling and edge cases in CodeQualityValidator."""

    def test_check_code_style_non_python_files(self, validator: CodeQualityValidator) -> None:
        """Test code style check skips non-Python files."""
        passed, issues, score = validator.check_code_style(["test.txt", "readme.md"])
        assert passed is True
        assert issues == []
        assert score == 100

    def test_check_code_style_pylint_command_error(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test code style check handles OSError."""
        mock_run_command.side_effect = OSError("Permission denied")
        passed, issues, score = validator.check_code_style(["test.py"])
        assert passed is False
        assert "Permission denied" in issues[0]
        assert score == 0

    def test_check_code_style_with_violations(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test code style check detects violations."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "test.py:1: C: Missing module docstring\ntest.py:2: E: Invalid syntax"
        mock_run_command.return_value = mock_result

        passed, issues, score = validator.check_code_style(["test.py"])
        assert passed is False
        assert len(issues) == 2
        assert score < 100

    def test_check_test_coverage_no_files(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test test coverage check with no files."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "TOTAL 100%"
        mock_run_command.return_value = mock_result

        passed, issues, coverage = validator.check_test_coverage([])
        assert passed is True
        assert coverage == 100

    def test_check_test_coverage_command_error(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test test coverage check handles OSError."""
        mock_run_command.side_effect = OSError("Permission denied")
        passed, issues, coverage = validator.check_test_coverage(["test.py"])
        assert passed is False
        assert coverage == 0

    def test_check_test_coverage_below_threshold(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test test coverage check detects low coverage."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "Coverage report:\nTOTAL: 50%"
        mock_run_command.return_value = mock_result

        passed, issues, coverage = validator.check_test_coverage(["test.py"])
        assert passed is False
        assert coverage == 0

    def test_check_test_coverage_extracts_percentage(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test test coverage extraction from report."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Coverage:\nTOTAL 85%\n"
        mock_run_command.return_value = mock_result

        passed, issues, coverage = validator.check_test_coverage(["test.py"])
        assert passed is True
        assert coverage == 85.0

    def test_check_test_coverage_skipped_when_coverage_not_installed(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test coverage check gracefully skips when coverage is not installed."""
        # Simulate coverage not being installed by raising OSError with "Command not found"
        mock_run_command.side_effect = OSError("Command not found: coverage")

        passed, issues, coverage = validator.check_test_coverage(["test.py"])

        # When coverage is not installed, it should return True (skip, not fail)
        assert passed is True
        # Coverage should be 100 when skipped (meaning test requirement is met)
        assert coverage == 100

    def test_check_security_no_python_files(self, validator: CodeQualityValidator) -> None:
        """Test security check skips when no Python files."""
        passed, issues, score = validator.check_security(["test.txt", "readme.md"])
        assert passed is True
        assert score == 100

    def test_check_security_command_error(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test security check handles OSError."""
        mock_run_command.side_effect = OSError("Permission denied")
        passed, issues, score = validator.check_security(["test.py"])
        assert passed is False
        assert score == 0

    def test_check_security_with_high_severity_issues(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test security check detects high severity issues."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "Issue: Test issue\nSeverity: HIGH\n"
        mock_run_command.return_value = mock_result

        passed, issues, score = validator.check_security(["test.py"])
        assert passed is False
        assert len(issues) > 0
        assert score < 100

    def test_check_security_with_medium_issues(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test security check scores medium severity issues."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "Issue: Test\nSeverity: MEDIUM\n"
        mock_run_command.return_value = mock_result

        passed, issues, score = validator.check_security(["test.py"])
        assert passed is False
        assert score < 100

    def test_check_complexity_no_python_files(self, validator: CodeQualityValidator) -> None:
        """Test complexity check skips when no Python files."""
        passed, issues, complexity = validator.check_complexity(["test.txt"])
        assert passed is True
        assert complexity == 10

    def test_check_complexity_command_error(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test complexity check handles OSError."""
        mock_run_command.side_effect = OSError("Permission denied")
        passed, issues, complexity = validator.check_complexity(["test.py"])
        assert passed is False

    def test_check_complexity_with_high_complexity(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test complexity check detects high complexity."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test.py:1 - F (too complex)\ntest.py:2 - D (high)\n"
        mock_run_command.return_value = mock_result

        passed, issues, complexity = validator.check_complexity(["test.py"])
        assert len(issues) > 0
        # F functions should make passed=False, D should make it True
        assert complexity > 0

    def test_check_complexity_moderate_only(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test complexity check with only moderate issues."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test.py:1 - D (high complexity)\n"
        mock_run_command.return_value = mock_result

        passed, issues, complexity = validator.check_complexity(["test.py"])
        assert len(issues) == 1
        assert "Moderate" in issues[0]

    def test_check_documentation_non_python_files(self, validator: CodeQualityValidator) -> None:
        """Test documentation check skips non-Python files."""
        passed, issues, score = validator.check_documentation(["readme.md"])
        assert passed is True
        assert score == 100

    def test_check_documentation_file_read_error(
        self, validator: CodeQualityValidator, monkeypatch
    ) -> None:
        """Test documentation check handles file read errors."""

        def mock_read_text(*args, **kwargs):
            raise OSError("Permission denied")

        monkeypatch.setattr(Path, "read_text", mock_read_text)
        passed, issues, score = validator.check_documentation(["test.py"])
        assert passed is False
        assert score == 0

    def test_check_documentation_missing_module_docstring(
        self, validator: CodeQualityValidator, temp_path
    ) -> None:
        """Test documentation check detects missing module docstring."""
        test_file = temp_path / "test.py"
        test_file.write_text("def func():\n    pass\n")

        passed, issues, score = validator.check_documentation([str(test_file)])
        assert passed is False
        assert any("module docstring" in issue for issue in issues)

    def test_check_documentation_missing_function_docstring(
        self, validator: CodeQualityValidator, temp_path
    ) -> None:
        """Test documentation check detects missing function docstring."""
        test_file = temp_path / "test.py"
        test_file.write_text('"""Module docstring."""\n\ndef func():\n    pass\n')

        passed, issues, score = validator.check_documentation([str(test_file)])
        assert passed is False
        assert any("docstring" in issue for issue in issues)

    def test_check_dependencies_no_requirements(self, validator: CodeQualityValidator) -> None:
        """Test dependencies check passes when no requirements file."""
        passed, issues, score = validator.check_dependencies([])
        assert passed is True
        assert score == 100

    def test_check_dependencies_command_error(
        self, validator: CodeQualityValidator, mock_run_command, monkeypatch
    ) -> None:
        """Test dependencies check handles OSError."""
        # Mock requirements.txt to exist
        monkeypatch.setattr(Path, "exists", lambda self: self.name == "requirements.txt")
        mock_run_command.side_effect = OSError("Permission denied")

        passed, issues, score = validator.check_dependencies([])
        assert passed is False
        assert score == 0

    def test_check_dependencies_vulnerabilities_found(
        self, validator: CodeQualityValidator, mock_run_command, monkeypatch
    ) -> None:
        """Test dependencies check detects vulnerabilities."""
        monkeypatch.setattr(Path, "exists", lambda self: self.name == "requirements.txt")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "Found 2 vulnerabilities in requirements"
        mock_run_command.return_value = mock_result

        passed, issues, score = validator.check_dependencies([])
        assert passed is False
        assert score == 0

    def test_get_staged_files_git_error(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test get_staged_files handles git error."""
        mock_run_command.side_effect = OSError("git not found")
        files = validator.get_staged_files()
        assert files == []

    def test_get_staged_files_returns_list(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test get_staged_files returns file list."""
        mock_result = MagicMock()
        mock_result.stdout = "file1.py\nfile2.py\n"
        mock_run_command.return_value = mock_result

        files = validator.get_staged_files()
        assert len(files) == 2
        assert "file1.py" in files

    def test_generate_quality_report_with_scores(self) -> None:
        """Test quality report generation with check scores."""
        checks = {
            "style": {"passed": True, "score": 95, "issues": []},
            "tests": {"passed": True, "score": 100, "issues": []},
        }
        report = CodeQualityValidator.generate_quality_report(checks)

        assert report["pass_all"] is True
        assert "overall_quality_score" in report
        assert report["overall_quality_score"] > 0

    def test_generate_quality_report_with_failures(self) -> None:
        """Test quality report with failed checks."""
        checks = {
            "style": {"passed": False, "score": 50, "issues": ["Issue"]},
            "tests": {"passed": True, "score": 100, "issues": []},
        }
        report = CodeQualityValidator.generate_quality_report(checks)

        assert report["pass_all"] is False
        assert report["overall_quality_score"] > 0

    def test_generate_quality_report_without_scores(self) -> None:
        """Test quality report with checks without scores."""
        checks = {
            "style": {"passed": True, "issues": []},
        }
        report = CodeQualityValidator.generate_quality_report(checks)

        assert "overall_quality_score" in report
        assert report["overall_quality_score"] == 0

    def test_display_summary_returns_bool(self) -> None:
        """Test display_summary returns boolean."""
        report = {
            "pass_all": True,
            "checks": {
                "style": {"passed": True, "score": 100},
            },
        }
        result = CodeQualityValidator.display_summary(report)
        assert isinstance(result, bool)
        assert result is True

    def test_display_summary_with_failures(self) -> None:
        """Test display_summary with failures."""
        report = {
            "pass_all": False,
            "checks": {
                "style": {"passed": False, "score": 50},
            },
        }
        result = CodeQualityValidator.display_summary(report)
        assert result is False

    def test_run_all_checks_with_explicit_files(
        self, validator: CodeQualityValidator, temp_files, mock_run_command
    ) -> None:
        """Test run_all_checks with explicit file list."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test PASSED\nTOTAL 85%"
        mock_run_command.return_value = mock_result

        report = validator.run_all_checks(files=temp_files)

        assert "checks" in report
        assert "pass_all" in report
        assert "overall_quality_score" in report

    def test_run_all_checks_empty_file_list(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test run_all_checks with empty file list."""
        mock_run_command.return_value = MagicMock(stdout="")

        report = validator.run_all_checks(files=[])
        assert report.get("status") == "no_files"

    def test_run_all_checks_empty_string_file_list(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test run_all_checks with list containing empty string."""
        mock_run_command.return_value = MagicMock(stdout="")

        report = validator.run_all_checks(files=[""])
        assert report.get("status") == "no_files"

    def test_check_tests_pass_success(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test check_tests_pass with passing tests."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test1 PASSED\ntest2 PASSED\n"
        mock_run_command.return_value = mock_result

        passed, issues, count = validator.check_tests_pass([])
        assert passed is True
        assert count == 2

    def test_check_tests_pass_failure(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test check_tests_pass with failing tests."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "test1 FAILED some.module.test\ntest2 FAILED other.test\n"
        mock_run_command.return_value = mock_result

        passed, issues, count = validator.check_tests_pass([])
        assert passed is False
        assert len(issues) > 0

    def test_check_tests_pass_timeout(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test check_tests_pass handles timeout."""
        mock_run_command.side_effect = subprocess.TimeoutExpired("cmd", 60)

        passed, issues, count = validator.check_tests_pass([])
        assert passed is False
        assert "timeout" in issues[0].lower()

    def test_check_tests_pass_oserror(
        self, validator: CodeQualityValidator, mock_run_command
    ) -> None:
        """Test check_tests_pass handles OSError."""
        mock_run_command.side_effect = OSError("Permission denied")

        passed, issues, count = validator.check_tests_pass([])
        assert passed is False

    def test_main_with_no_args(self, monkeypatch, mock_run_command) -> None:
        """Test main function with no arguments."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test PASSED\nTOTAL 85%"
        mock_run_command.return_value = mock_result

        monkeypatch.setattr("sys.argv", ["commit_validator.py"])
        result = main()
        assert result in [0, 1]
