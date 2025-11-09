"""
Tests for health checks and monitoring system.

Validates:
- Health check execution
- Status reporting
- Log monitoring
- Configuration verification
- System health assessment
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.health_check import (  # noqa: E402
    ConfigurationCheck,
    DependencyCheck,
    DiskSpaceCheck,
    HealthMonitor,
    HealthStatus,
    LogCheck,
    SystemCheck,
    create_default_monitor,
)


@pytest.mark.unit
class TestHealthStatus(unittest.TestCase):
    """Test HealthStatus constants."""

    def test_health_status_constants(self):
        """Test health status values."""
        self.assertEqual(HealthStatus.HEALTHY, "healthy")
        self.assertEqual(HealthStatus.WARNING, "warning")
        self.assertEqual(HealthStatus.CRITICAL, "critical")
        self.assertEqual(HealthStatus.UNKNOWN, "unknown")

    def test_all_statuses(self):
        """Test all statuses list."""
        self.assertEqual(len(HealthStatus.ALL_STATUSES), 4)
        self.assertIn(HealthStatus.HEALTHY, HealthStatus.ALL_STATUSES)
        self.assertIn(HealthStatus.WARNING, HealthStatus.ALL_STATUSES)
        self.assertIn(HealthStatus.CRITICAL, HealthStatus.ALL_STATUSES)
        self.assertIn(HealthStatus.UNKNOWN, HealthStatus.ALL_STATUSES)


@pytest.mark.unit
class TestDependencyCheck(unittest.TestCase):
    """Test DependencyCheck."""

    def test_dependency_check_creation(self):
        """Test creating dependency check."""
        check = DependencyCheck(["bash", "git"])
        self.assertEqual(check.name, "Dependencies")
        self.assertEqual(check.tools, ["bash", "git"])

    def test_check_existing_dependencies(self):
        """Test checking for commonly available tools."""
        check = DependencyCheck(["bash", "ls", "echo"])
        status, message, details = check.run()

        # bash should exist on most systems
        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIn("installed", details)
        self.assertIn("missing", details)

    def test_check_nonexistent_dependencies(self):
        """Test checking for tools that probably don't exist."""
        check = DependencyCheck(["this_tool_definitely_does_not_exist_xyz"])
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.CRITICAL)
        self.assertIn("missing", details)
        self.assertEqual(len(details["missing"]), 1)

    def test_check_mixed_dependencies(self):
        """Test with mix of existing and missing tools."""
        check = DependencyCheck(["bash", "nonexistent_tool_xyz"])
        status, message, details = check.run()

        # Status should be warning since some are missing but some exist
        self.assertIn(status, [HealthStatus.WARNING, HealthStatus.CRITICAL])
        self.assertTrue(len(details["installed"]) > 0)
        self.assertTrue(len(details["missing"]) > 0)


@pytest.mark.unit
class TestDiskSpaceCheck(unittest.TestCase):
    """Test DiskSpaceCheck."""

    def test_disk_space_check_creation(self):
        """Test creating disk space check."""
        check = DiskSpaceCheck(min_gb=5)
        self.assertEqual(check.name, "Disk Space")
        self.assertEqual(check.min_gb, 5)

    def test_disk_space_check_default(self):
        """Test disk space check with default parameters."""
        check = DiskSpaceCheck()
        self.assertEqual(check.min_gb, 5)

    def test_disk_space_check_run(self):
        """Test running disk space check."""
        check = DiskSpaceCheck(min_gb=1)
        status, message, details = check.run()

        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        # Most systems should have at least 1GB
        self.assertIn(status, [HealthStatus.HEALTHY, HealthStatus.CRITICAL])

    def test_disk_space_high_requirement(self):
        """Test disk space check with high requirement."""
        check = DiskSpaceCheck(min_gb=1000000)
        status, message, details = check.run()

        # Should fail if asking for unrealistic amount
        self.assertNotEqual(status, HealthStatus.UNKNOWN)
        self.assertIn("available_gb", details)


@pytest.mark.unit
class TestConfigurationCheck(unittest.TestCase):
    """Test ConfigurationCheck."""

    def setUp(self):
        """Set up temporary config file."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.yaml"

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_config_check_creation(self):
        """Test creating configuration check."""
        check = ConfigurationCheck(self.config_path)
        self.assertEqual(check.name, "Configuration")
        self.assertEqual(check.config_path, self.config_path)

    def test_config_missing(self):
        """Test check when config doesn't exist."""
        check = ConfigurationCheck(self.config_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.WARNING)
        self.assertFalse(details["exists"])

    def test_config_with_insecure_permissions(self):
        """Test check with insecure permissions."""
        # Create config with insecure permissions
        with open(self.config_path, "w") as f:
            f.write("global:\n  name: test\n")

        self.config_path.chmod(0o644)

        check = ConfigurationCheck(self.config_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.WARNING)
        self.assertIn("permission", message.lower())

    def test_config_healthy(self):
        """Test check with healthy config."""
        # Create config with secure permissions
        with open(self.config_path, "w") as f:
            f.write("global:\n  name: test\n")

        self.config_path.chmod(0o600)

        check = ConfigurationCheck(self.config_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.HEALTHY)
        self.assertEqual(details["permissions"], "600")


@pytest.mark.unit
class TestLogCheck(unittest.TestCase):
    """Test LogCheck."""

    def setUp(self):
        """Set up temporary log file."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.temp_dir) / "setup.log"

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_log_check_creation(self):
        """Test creating log check."""
        check = LogCheck(self.log_path)
        self.assertEqual(check.name, "Logs")
        self.assertEqual(check.log_file, self.log_path)

    def test_log_missing(self):
        """Test check when log doesn't exist."""
        check = LogCheck(self.log_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.UNKNOWN)
        self.assertFalse(details["exists"])

    def test_log_healthy(self):
        """Test check with healthy log."""
        with open(self.log_path, "w") as f:
            f.write("INFO: Setup started\n")
            f.write("INFO: Installation complete\n")

        check = LogCheck(self.log_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.HEALTHY)
        self.assertIn("lines", details)

    def test_log_with_warnings(self):
        """Test check with warnings in log."""
        with open(self.log_path, "w") as f:
            f.write("INFO: Setup started\n")
            f.write("WARNING: Package already installed\n")

        check = LogCheck(self.log_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.WARNING)
        self.assertIn("warning", message.lower())

    def test_log_with_errors(self):
        """Test check with errors in log."""
        with open(self.log_path, "w") as f:
            f.write("INFO: Setup started\n")
            f.write("ERROR: Installation failed\n")
            f.write("ERROR: Rollback initiated\n")

        check = LogCheck(self.log_path)
        status, message, details = check.run()

        self.assertEqual(status, HealthStatus.CRITICAL)
        self.assertIn("error", message.lower())


@pytest.mark.unit
class TestSystemCheck(unittest.TestCase):
    """Test SystemCheck."""

    def test_system_check_creation(self):
        """Test creating system check."""
        check = SystemCheck()
        self.assertEqual(check.name, "System")

    def test_system_check_run(self):
        """Test running system check."""
        check = SystemCheck()
        status, message, details = check.run()

        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIn("load_average", details)
        self.assertIn("cpu_count", details)


@pytest.mark.unit
class TestHealthMonitor(unittest.TestCase):
    """Test HealthMonitor."""

    def setUp(self):
        """Set up test monitor."""
        self.monitor = HealthMonitor()

    def test_monitor_creation(self):
        """Test creating health monitor."""
        self.assertEqual(len(self.monitor.checks), 0)
        self.assertEqual(len(self.monitor.results), 0)

    def test_add_check(self):
        """Test adding health checks."""
        check1 = DependencyCheck(["bash"])
        check2 = SystemCheck()

        self.monitor.add_check(check1)
        self.monitor.add_check(check2)

        self.assertEqual(len(self.monitor.checks), 2)

    def test_run_all_checks(self):
        """Test running all checks."""
        self.monitor.add_check(DependencyCheck(["bash"]))
        self.monitor.add_check(SystemCheck())

        results = self.monitor.run_all()

        self.assertEqual(len(results), 2)
        self.assertIn("Dependencies", results)
        self.assertIn("System", results)

        for status, message, details in results.values():
            self.assertIn(status, HealthStatus.ALL_STATUSES)
            self.assertIsNotNone(message)
            self.assertIsInstance(details, dict)

    def test_overall_status_all_healthy(self):
        """Test overall status when all checks are healthy."""
        # Create checks that will be healthy
        check = SystemCheck()
        self.monitor.add_check(check)
        self.monitor.run_all()

        overall = self.monitor.get_overall_status()
        self.assertIn(overall, HealthStatus.ALL_STATUSES)

    def test_overall_status_with_critical(self):
        """Test overall status with critical failure."""
        self.monitor.add_check(DependencyCheck(["nonexistent_xyz"]))
        self.monitor.run_all()

        overall = self.monitor.get_overall_status()
        self.assertEqual(overall, HealthStatus.CRITICAL)

    def test_json_report(self):
        """Test JSON report generation."""
        self.monitor.add_check(SystemCheck())
        self.monitor.run_all()

        json_report = self.monitor.get_json_report()
        report = json.loads(json_report)

        self.assertIn("timestamp", report)
        self.assertIn("overall_status", report)
        self.assertIn("checks", report)
        self.assertTrue(len(report["checks"]) > 0)


@pytest.mark.unit
class TestCreateDefaultMonitor(unittest.TestCase):
    """Test default monitor factory."""

    def test_create_default_monitor(self):
        """Test creating default monitor."""
        monitor = create_default_monitor()

        self.assertIsInstance(monitor, HealthMonitor)
        self.assertEqual(len(monitor.checks), 5)

        check_names = [check.name for check in monitor.checks]
        self.assertIn("Dependencies", check_names)
        self.assertIn("Disk Space", check_names)
        self.assertIn("Configuration", check_names)
        self.assertIn("Logs", check_names)
        self.assertIn("System", check_names)

    def test_default_monitor_runs(self):
        """Test running default monitor."""
        monitor = create_default_monitor()
        results = monitor.run_all()

        self.assertEqual(len(results), 5)

        overall = monitor.get_overall_status()
        self.assertIn(overall, HealthStatus.ALL_STATUSES)


@pytest.mark.unit
class TestHealthStatusMethods(unittest.TestCase):
    """Test HealthStatus utility methods."""

    def test_is_valid_healthy(self):
        """Test is_valid for healthy status."""
        self.assertTrue(HealthStatus.is_valid(HealthStatus.HEALTHY))

    def test_is_valid_warning(self):
        """Test is_valid for warning status."""
        self.assertTrue(HealthStatus.is_valid(HealthStatus.WARNING))

    def test_is_valid_critical(self):
        """Test is_valid for critical status."""
        self.assertTrue(HealthStatus.is_valid(HealthStatus.CRITICAL))

    def test_is_valid_unknown(self):
        """Test is_valid for unknown status."""
        self.assertTrue(HealthStatus.is_valid(HealthStatus.UNKNOWN))

    def test_is_valid_invalid_status(self):
        """Test is_valid for invalid status."""
        self.assertFalse(HealthStatus.is_valid("invalid"))
        self.assertFalse(HealthStatus.is_valid(""))
        self.assertFalse(HealthStatus.is_valid("error"))

    def test_get_severity_healthy(self):
        """Test severity for healthy status."""
        severity = HealthStatus.get_severity(HealthStatus.HEALTHY)
        self.assertEqual(severity, 0)

    def test_get_severity_warning(self):
        """Test severity for warning status."""
        severity = HealthStatus.get_severity(HealthStatus.WARNING)
        self.assertEqual(severity, 1)

    def test_get_severity_critical(self):
        """Test severity for critical status."""
        severity = HealthStatus.get_severity(HealthStatus.CRITICAL)
        self.assertEqual(severity, 2)

    def test_get_severity_unknown(self):
        """Test severity for unknown status."""
        severity = HealthStatus.get_severity(HealthStatus.UNKNOWN)
        self.assertEqual(severity, 3)

    def test_get_severity_invalid(self):
        """Test severity for invalid status returns unknown."""
        severity = HealthStatus.get_severity("invalid")
        self.assertEqual(severity, 3)

    def test_get_severity_comparison(self):
        """Test severity ordering."""
        healthy_sev = HealthStatus.get_severity(HealthStatus.HEALTHY)
        warning_sev = HealthStatus.get_severity(HealthStatus.WARNING)
        critical_sev = HealthStatus.get_severity(HealthStatus.CRITICAL)
        unknown_sev = HealthStatus.get_severity(HealthStatus.UNKNOWN)

        self.assertLess(healthy_sev, warning_sev)
        self.assertLess(warning_sev, critical_sev)
        self.assertLess(critical_sev, unknown_sev)


@pytest.mark.unit
class TestHealthCheckBaseMethods(unittest.TestCase):
    """Test HealthCheck base class methods."""

    def setUp(self):
        """Set up test health check."""
        from cli.health_check import HealthCheck

        self.check = HealthCheck("TestCheck", "Test description")

    def test_health_check_init(self):
        """Test HealthCheck initialization."""
        self.assertEqual(self.check.name, "TestCheck")
        self.assertEqual(self.check.description, "Test description")

    def test_health_check_run_not_implemented(self):
        """Test HealthCheck run is abstract."""
        with self.assertRaises(NotImplementedError):
            self.check.run()

    def test_get_result_summary_healthy(self):
        """Test result summary for healthy status."""
        result = (HealthStatus.HEALTHY, "All systems operational", {})
        summary = self.check.get_result_summary(result)
        self.assertIn("HEALTHY", summary)
        self.assertIn("TestCheck", summary)
        self.assertIn("All systems operational", summary)

    def test_get_result_summary_warning(self):
        """Test result summary for warning status."""
        result = (HealthStatus.WARNING, "Minor issues detected", {})
        summary = self.check.get_result_summary(result)
        self.assertIn("WARNING", summary)
        self.assertIn("TestCheck", summary)

    def test_get_result_summary_critical(self):
        """Test result summary for critical status."""
        result = (HealthStatus.CRITICAL, "Critical error", {})
        summary = self.check.get_result_summary(result)
        self.assertIn("CRITICAL", summary)
        self.assertIn("Critical error", summary)


@pytest.mark.unit
class TestDependencyCheckStaticMethod(unittest.TestCase):
    """Test DependencyCheck static method."""

    def test_check_tool_existing(self):
        """Test checking for existing tool."""
        # bash should exist on most systems
        result = DependencyCheck.check_tool("bash")
        self.assertTrue(result)

    def test_check_tool_nonexistent(self):
        """Test checking for nonexistent tool."""
        result = DependencyCheck.check_tool("nonexistent_tool_xyz_123")
        self.assertFalse(result)

    def test_check_tool_system_command(self):
        """Test checking for common system command."""
        # ls should exist on Unix systems
        result = DependencyCheck.check_tool("ls")
        self.assertTrue(result)


@pytest.mark.unit
class TestDiskSpaceCheckResults(unittest.TestCase):
    """Test DiskSpaceCheck result details."""

    def setUp(self):
        """Set up test disk space check."""
        self.check = DiskSpaceCheck(min_gb=1)

    def test_disk_space_check_run(self):
        """Test disk space check execution."""
        status, message, details = self.check.run()

        # Verify result structure
        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIsInstance(details, dict)

    def test_disk_space_check_init(self):
        """Test DiskSpaceCheck initialization."""
        check = DiskSpaceCheck(min_gb=10)
        self.assertEqual(check.min_gb, 10)
        self.assertEqual(check.name, "Disk Space")


@pytest.mark.unit
class TestConfigurationCheckValidation(unittest.TestCase):
    """Test ConfigurationCheck validation."""

    def setUp(self):
        """Set up test configuration check."""
        self.check = ConfigurationCheck()

    def test_configuration_check_run(self):
        """Test configuration check execution."""
        status, message, details = self.check.run()

        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIsInstance(details, dict)

    def test_configuration_check_init(self):
        """Test ConfigurationCheck initialization."""
        self.assertEqual(self.check.name, "Configuration")


@pytest.mark.unit
class TestLogCheckParsing(unittest.TestCase):
    """Test LogCheck log file parsing."""

    def setUp(self):
        """Set up test log check."""
        self.check = LogCheck()

    def test_log_check_run(self):
        """Test log check execution."""
        status, message, details = self.check.run()

        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIsInstance(details, dict)

    def test_log_check_init(self):
        """Test LogCheck initialization."""
        self.assertEqual(self.check.name, "Logs")

    def test_log_check_count_errors_and_warnings(self):
        """Test log check error/warning counting."""
        errors, warnings = self.check.count_errors_and_warnings()
        self.assertIsInstance(errors, int)
        self.assertIsInstance(warnings, int)
        self.assertGreaterEqual(errors, 0)
        self.assertGreaterEqual(warnings, 0)


@pytest.mark.unit
class TestSystemCheckComprehensive(unittest.TestCase):
    """Test SystemCheck comprehensive results."""

    def setUp(self):
        """Set up test system check."""
        self.check = SystemCheck()

    def test_system_check_run_complete(self):
        """Test system check returns complete information."""
        status, message, details = self.check.run()

        self.assertIn(status, HealthStatus.ALL_STATUSES)
        self.assertIsNotNone(message)
        self.assertIsInstance(details, dict)

    def test_system_check_init(self):
        """Test SystemCheck initialization."""
        self.assertEqual(self.check.name, "System")

    def test_system_check_get_load_average(self):
        """Test get_load_average method."""
        load = SystemCheck.get_load_average()
        # Should return either None or a tuple of 3 floats
        if load is not None:
            self.assertEqual(len(load), 3)
            for val in load:
                self.assertIsInstance(val, (int, float))


@pytest.mark.unit
class TestHealthMonitorComprehensive(unittest.TestCase):
    """Test HealthMonitor comprehensive functionality."""

    def setUp(self):
        """Set up test monitor."""
        self.monitor = HealthMonitor()

    def test_monitor_multiple_checks(self):
        """Test monitor with multiple checks."""
        self.monitor.add_check(SystemCheck())
        self.monitor.add_check(DependencyCheck(["bash"]))

        self.assertEqual(len(self.monitor.checks), 2)

    def test_monitor_run_returns_dict(self):
        """Test monitor run_all returns dictionary."""
        self.monitor.add_check(SystemCheck())
        results = self.monitor.run_all()

        self.assertIsInstance(results, dict)
        self.assertIn("System", results)

    def test_monitor_has_results(self):
        """Test monitor stores results after running."""
        self.monitor.add_check(SystemCheck())
        self.monitor.run_all()

        self.assertIn("System", self.monitor.results)

    def test_monitor_severity_comparison(self):
        """Test that critical status has higher severity."""
        dep_check = DependencyCheck(["nonexistent_xyz"])
        self.monitor.add_check(dep_check)
        self.monitor.run_all()

        overall = self.monitor.get_overall_status()
        self.assertEqual(overall, HealthStatus.CRITICAL)

    def test_monitor_json_report_format(self):
        """Test JSON report formatting."""
        self.monitor.add_check(SystemCheck())
        self.monitor.run_all()

        report = self.monitor.get_json_report()
        self.assertIsInstance(report, str)
        self.assertIn("System", report)
        self.assertTrue(len(report) > 0)

    def test_monitor_print_report(self):
        """Test print_report method."""
        self.monitor.add_check(SystemCheck())
        self.monitor.run_all()

        # print_report() doesn't return anything, just verify it doesn't crash
        self.monitor.print_report()

    def test_monitor_overall_status_unknown(self):
        """Test overall status when no checks have run."""
        monitor = HealthMonitor()
        overall = monitor.get_overall_status()
        self.assertEqual(overall, HealthStatus.UNKNOWN)


class TestHealthCheckErrorPaths:
    """Tests for error handling paths in health checks."""

    @patch("cli.health_check.run_command")
    def test_dependency_check_tool_timeout(self, mock_run: MagicMock) -> None:
        """Test check_tool with timeout exception."""
        mock_run.side_effect = subprocess.TimeoutExpired("which", 2)
        result = DependencyCheck.check_tool("python")
        assert result is False

    @patch("cli.health_check.run_command")
    def test_dependency_check_tool_oserror(self, mock_run: MagicMock) -> None:
        """Test check_tool with OSError."""
        mock_run.side_effect = OSError("Command not found")
        result = DependencyCheck.check_tool("python")
        assert result is False

    @patch("cli.health_check.run_command")
    def test_dependency_run_with_timeout(self, mock_run: MagicMock) -> None:
        """Test DependencyCheck.run with timeout during check."""
        mock_run.side_effect = subprocess.TimeoutExpired("which", 2)
        check = DependencyCheck(["python"])
        status, message, details = check.run()
        assert status == HealthStatus.CRITICAL
        assert "python" in details["missing"]

    @patch("cli.health_check.run_command")
    def test_dependency_run_with_oserror(self, mock_run: MagicMock) -> None:
        """Test DependencyCheck.run with OSError during check."""
        mock_run.side_effect = OSError("Permission denied")
        check = DependencyCheck(["git"])
        status, message, details = check.run()
        assert status == HealthStatus.CRITICAL
        assert "git" in details["missing"]

    @patch("cli.health_check.run_command")
    def test_disk_space_check_get_available_space_timeout(self, mock_run: MagicMock) -> None:
        """Test get_available_space with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("df", 2)
        result = DiskSpaceCheck.get_available_space()
        assert result is None

    @patch("cli.health_check.run_command")
    def test_disk_space_check_get_available_space_value_error(self, mock_run: MagicMock) -> None:
        """Test get_available_space with ValueError in parsing."""
        mock_result = MagicMock()
        mock_result.stdout = "invalid output"
        mock_run.return_value = mock_result
        result = DiskSpaceCheck.get_available_space()
        assert result is None

    @patch("cli.health_check.run_command")
    def test_disk_space_check_run_with_oserror(self, mock_run: MagicMock) -> None:
        """Test DiskSpaceCheck.run with OSError."""
        mock_run.side_effect = OSError("Permission denied")
        check = DiskSpaceCheck()
        status, message, details = check.run()
        assert status == HealthStatus.UNKNOWN
        assert "error" in details

    @patch("cli.health_check.run_command")
    def test_disk_space_check_parse_error(self, mock_run: MagicMock) -> None:
        """Test DiskSpaceCheck.run with malformed output."""
        mock_result = MagicMock()
        mock_result.stdout = "single_line_only"
        mock_run.return_value = mock_result
        check = DiskSpaceCheck()
        status, message, details = check.run()
        assert status == HealthStatus.UNKNOWN

    @patch("builtins.open", side_effect=OSError("Permission denied"))
    def test_configuration_check_run_file_error(self, mock_file: MagicMock) -> None:
        """Test ConfigurationCheck.run when config file is unreadable."""
        check = ConfigurationCheck()
        status, message, details = check.run()
        assert status == HealthStatus.WARNING

    @patch("builtins.open", side_effect=FileNotFoundError("Config not found"))
    def test_configuration_check_run_file_not_found(self, mock_file: MagicMock) -> None:
        """Test ConfigurationCheck.run when config file is missing."""
        check = ConfigurationCheck()
        status, message, details = check.run()
        assert status == HealthStatus.WARNING

    @patch("cli.health_check.os.getloadavg")
    def test_system_check_get_load_average_error(self, mock_loadavg: MagicMock) -> None:
        """Test SystemCheck.get_load_average with error."""
        mock_loadavg.side_effect = OSError("System error")
        result = SystemCheck.get_load_average()
        assert result is None

    def test_health_status_invalid_status(self) -> None:
        """Test HealthStatus with invalid status string."""
        result = HealthStatus.get_severity("invalid_status")
        # Should return default (3 for unknown)
        assert result == 3

    def test_monitor_add_check_valid(self) -> None:
        """Test adding checks to monitor."""
        monitor = HealthMonitor()
        monitor.add_check(SystemCheck())
        assert len(monitor.checks) >= 1

    def test_monitor_get_json_report(self) -> None:
        """Test JSON report generation."""
        monitor = HealthMonitor()
        check = SystemCheck()
        monitor.add_check(check)
        monitor.run_all()
        report = monitor.get_json_report()
        assert "checks" in report
        assert isinstance(report, str)
        json.loads(report)  # Verify it's valid JSON


if __name__ == "__main__":
    unittest.main()
