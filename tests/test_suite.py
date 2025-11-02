#!/usr/bin/env python3
"""
Mac-Setup Comprehensive Test Suite

Tests all components of devkit including:
- Configuration validation
- Ansible playbook syntax
- Installation verification
- Health checks
- Integration tests
"""

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional

import yaml


class TestStatus(Enum):
    """Test result status."""

    PASS = "✓ PASS"
    FAIL = "✗ FAIL"
    SKIP = "⊘ SKIP"
    WARN = "⚠ WARN"


@dataclass
class TestResult:
    """Single test result."""

    name: str
    status: TestStatus
    message: str
    duration: float = 0.0
    details: Optional[str] = None


class TestSuite:
    """Main test suite runner."""

    def __init__(self, project_root: Optional[str] = None):
        """
        Initialize test suite.

        Args:
            project_root: Path to devkit project root
        """
        self.project_root = Path(project_root or Path(__file__).parent.parent)
        self.logger = self._setup_logger()
        self.results: List[TestResult] = []
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def _setup_logger(self) -> logging.Logger:
        """Setup logger."""
        logger = logging.getLogger("devkit.tests")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(levelname)s: %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        return logger

    def run_all(self) -> int:
        """
        Run all test suites.

        Returns:
            Exit code (0 = all passed, 1 = some failed)
        """
        print("\n" + "=" * 60)
        print("MAC-SETUP COMPREHENSIVE TEST SUITE")
        print("=" * 60 + "\n")

        # Configuration Tests
        print("Running configuration tests...")
        self._test_configuration()

        # Ansible Tests
        print("\nRunning Ansible validation tests...")
        self._test_ansible()

        # Role Tests
        print("\nRunning role structure tests...")
        self._test_roles()

        # Plugin System Tests
        print("\nRunning plugin system tests...")
        self._test_plugins()

        # Verification Tests
        print("\nRunning verification tests...")
        self._test_verification()

        # Print results
        self._print_results()

        return 0 if self.failed == 0 else 1

    def _test_configuration(self) -> None:
        """Test configuration engine and files."""
        print("\n--- Configuration Tests ---")

        # Test schema exists
        schema_path = self.project_root / "config" / "schema.yaml"
        result = self._check_file_exists("Schema file exists", schema_path)
        self._record_result(result)

        # Test schema is valid YAML
        if schema_path.exists():
            result = self._check_yaml_valid("Schema is valid YAML", schema_path)
            self._record_result(result)

        # Test configuration engine
        try:
            sys.path.insert(0, str(self.project_root / "cli"))
            from config_engine import ConfigurationEngine

            engine = ConfigurationEngine(str(self.project_root))
            engine.load_defaults()

            is_valid, errors = engine.validate()
            status = TestStatus.PASS if is_valid else TestStatus.FAIL
            result = TestResult(
                name="Configuration engine loads defaults",
                status=status,
                message="Default configuration loaded and validated",
                details=f"Errors: {errors}" if errors else None,
            )
            self._record_result(result)
        except Exception as e:
            result = TestResult(
                name="Configuration engine loads defaults",
                status=TestStatus.FAIL,
                message=f"Failed to load configuration engine: {e}",
            )
            self._record_result(result)

    def _test_ansible(self) -> None:
        """Test Ansible playbooks and roles."""
        print("\n--- Ansible Tests ---")

        # Test main playbook syntax
        playbook_path = self.project_root / "setup.yml"
        if playbook_path.exists():
            result = self._check_ansible_syntax("Main playbook syntax is valid", playbook_path)
            self._record_result(result)

        # Test Ansible lint
        result = self._check_ansible_lint()
        self._record_result(result)

        # Test role directories exist
        roles_path = self.project_root / "ansible" / "roles"
        if roles_path.exists():
            roles = [d for d in roles_path.iterdir() if d.is_dir()]
            result = TestResult(
                name="Role directories found",
                status=TestStatus.PASS if roles else TestStatus.WARN,
                message=f"Found {len(roles)} role directories",
                details=", ".join(r.name for r in roles),
            )
            self._record_result(result)

    def _test_roles(self) -> None:
        """Test individual role structure."""
        print("\n--- Role Structure Tests ---")

        roles_path = self.project_root / "ansible" / "roles"
        required_roles = ["core", "shell", "editors"]

        for role in required_roles:
            role_path = roles_path / role
            if role_path.exists():
                tasks_path = role_path / "tasks" / "main.yml"
                if tasks_path.exists():
                    result = self._check_yaml_valid(
                        f"Role '{role}' tasks are valid YAML", tasks_path
                    )
                else:
                    result = TestResult(
                        name=f"Role '{role}' has tasks/main.yml",
                        status=TestStatus.FAIL,
                        message=f"Missing tasks/main.yml in {role_path}",
                    )
                self._record_result(result)
            else:
                result = TestResult(
                    name=f"Role '{role}' directory exists",
                    status=TestStatus.FAIL,
                    message=f"Role directory not found: {role_path}",
                )
                self._record_result(result)

    def _test_plugins(self) -> None:
        """Test plugin system."""
        print("\n--- Plugin System Tests ---")

        try:
            sys.path.insert(0, str(self.project_root / "cli"))
            from plugin_system import PluginLoader

            loader = PluginLoader()
            plugins = loader.discover_plugins()

            result = TestResult(
                name="Plugin loader initializes",
                status=TestStatus.PASS,
                message="Plugin system loaded successfully",
                details=f"Can discover {len(plugins)} plugins",
            )
            self._record_result(result)
        except Exception as e:
            result = TestResult(
                name="Plugin loader initializes",
                status=TestStatus.FAIL,
                message=f"Failed to initialize plugin loader: {e}",
            )
            self._record_result(result)

        # Check plugin directory structure
        plugin_dirs = [
            self.project_root / "plugins",
            Path.home() / ".devkit" / "plugins",
        ]

        for plugin_dir in plugin_dirs:
            if plugin_dir.exists():
                result = TestResult(
                    name="Plugin directory exists",
                    status=TestStatus.PASS,
                    message=f"Plugin directory found at {plugin_dir}",
                )
                self._record_result(result)

    def _test_verification(self) -> None:
        """Test verification scripts."""
        print("\n--- Verification Tests ---")

        verify_script = self.project_root / "verify-setup.sh"
        if verify_script.exists():
            result = TestResult(
                name="Verification script exists",
                status=TestStatus.PASS,
                message=f"Found {verify_script.name}",
            )
            self._record_result(result)

            # Check if executable
            if os.access(verify_script, os.X_OK):
                result = TestResult(
                    name="Verification script is executable",
                    status=TestStatus.PASS,
                    message="Script has execute permissions",
                )
            else:
                result = TestResult(
                    name="Verification script is executable",
                    status=TestStatus.WARN,
                    message="Script needs executable permissions",
                )
            self._record_result(result)

        # Check for required tools
        required_tools = ["git", "curl", "brew"]
        for tool in required_tools:
            try:
                subprocess.run([tool, "--version"], capture_output=True, timeout=5)
                result = TestResult(
                    name=f"Required tool '{tool}' available",
                    status=TestStatus.PASS,
                    message=f"{tool} is installed and in PATH",
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                result = TestResult(
                    name=f"Required tool '{tool}' available",
                    status=TestStatus.WARN,
                    message=f"{tool} not found in PATH",
                )
            self._record_result(result)

    def _check_file_exists(self, name: str, path: Path) -> TestResult:
        """Check if file exists."""
        if path.exists():
            return TestResult(
                name=name,
                status=TestStatus.PASS,
                message=f"File found at {path}",
            )
        else:
            return TestResult(
                name=name,
                status=TestStatus.FAIL,
                message=f"File not found at {path}",
            )

    def _check_yaml_valid(self, name: str, path: Path) -> TestResult:
        """Check if YAML file is valid."""
        try:
            with open(path, "r") as f:
                yaml.safe_load(f)
            return TestResult(
                name=name,
                status=TestStatus.PASS,
                message="Valid YAML syntax",
            )
        except yaml.YAMLError as e:
            return TestResult(
                name=name,
                status=TestStatus.FAIL,
                message=f"Invalid YAML: {e}",
            )
        except Exception as e:
            return TestResult(
                name=name,
                status=TestStatus.FAIL,
                message=f"Error reading file: {e}",
            )

    def _check_ansible_syntax(self, name: str, path: Path) -> TestResult:
        """Check Ansible playbook syntax."""
        try:
            result = subprocess.run(
                ["ansible-playbook", "--syntax-check", str(path)],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                return TestResult(
                    name=name,
                    status=TestStatus.PASS,
                    message="Playbook syntax is valid",
                )
            else:
                return TestResult(
                    name=name,
                    status=TestStatus.FAIL,
                    message=f"Syntax error: {result.stderr.decode()}",
                )
        except FileNotFoundError:
            return TestResult(
                name=name,
                status=TestStatus.SKIP,
                message="ansible-playbook not found",
            )
        except Exception as e:
            return TestResult(
                name=name,
                status=TestStatus.FAIL,
                message=f"Error checking syntax: {e}",
            )

    def _check_ansible_lint(self) -> TestResult:
        """Run ansible-lint on playbooks."""
        try:
            result = subprocess.run(
                ["ansible-lint", str(self.project_root / "setup.yml")],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                return TestResult(
                    name="ansible-lint passes",
                    status=TestStatus.PASS,
                    message="No ansible-lint errors found",
                )
            else:
                errors = result.stdout.decode()
                return TestResult(
                    name="ansible-lint passes",
                    status=TestStatus.WARN,
                    message="Some ansible-lint warnings found",
                    details=errors[:200],
                )
        except FileNotFoundError:
            return TestResult(
                name="ansible-lint passes",
                status=TestStatus.SKIP,
                message="ansible-lint not found",
            )
        except Exception as e:
            return TestResult(
                name="ansible-lint passes",
                status=TestStatus.FAIL,
                message=f"Error running ansible-lint: {e}",
            )

    def _record_result(self, result: TestResult) -> None:
        """Record test result."""
        self.results.append(result)

        if result.status == TestStatus.PASS:
            self.passed += 1
            symbol = "✓"
        elif result.status == TestStatus.FAIL:
            self.failed += 1
            symbol = "✗"
        elif result.status == TestStatus.SKIP:
            self.skipped += 1
            symbol = "⊘"
        else:
            symbol = "⚠"

        print(f"  {symbol} {result.name}: {result.message}")
        if result.details:
            print(f"     {result.details}")

    def _print_results(self) -> None:
        """Print test summary."""
        total = len(self.results)
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"\nTotal Tests:  {total}")
        print(f"Passed:       {self.passed} ✓")
        print(f"Failed:       {self.failed} ✗")
        print(f"Skipped:      {self.skipped} ⊘")

        if self.failed == 0:
            print("\n✓ All tests passed!")
        else:
            print(f"\n✗ {self.failed} test(s) failed")

        print("=" * 60 + "\n")


def main():
    """Run test suite."""
    import argparse

    parser = argparse.ArgumentParser(description="Mac-Setup Test Suite")
    parser.add_argument("--project-root", default=str(Path(__file__).parent.parent))
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    suite = TestSuite(args.project_root)
    return suite.run_all()


if __name__ == "__main__":
    sys.exit(main())
