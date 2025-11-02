#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
"""AI Commit Validator - Quality-First Validation System.

Ensures AI-generated code meets quality standards before commits are made.
Focuses on code quality over speed.
"""

import argparse
import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cli.utils import Colors, ValidatorBase, run_command, setup_logger


class CodeQualityValidator(ValidatorBase):
    """Validates code quality for AI-generated commits."""

    def __init__(self) -> None:
        """Initialize code quality validator."""
        self.home = Path.home()
        self.devkit_dir = self.home / ".devkit/git"
        self.devkit_dir.mkdir(parents=True, exist_ok=True)
        self.quality_report_file = self.devkit_dir / "quality_reports.jsonl"
        self.setup_logging()

    def setup_logging(self) -> None:
        """Setup logging for quality checks."""
        self.log_file = self.devkit_dir / "quality_checks.log"
        self.logger = setup_logger(
            __name__,
            level=logging.INFO,
            log_file=self.log_file,
        )

    # ========== QUALITY CHECK METHODS ==========

    def check_code_style(self, _files: list[str]) -> tuple[bool, list[str], int]:
        """Check Python code style (PEP 8, pylint)."""
        self.print_status("Checking code style (PEP 8)...", "INFO")
        issues = []
        score = 100

        for filepath in _files:
            if not filepath.endswith(".py"):
                continue

            # Check with pylint
            try:
                result = run_command(
                    ["pylint", "--disable=all", "--enable=C,E", filepath],
                    timeout=10,
                )
            except OSError as e:
                if "Command not found" in str(e):
                    self.print_status("pylint not installed, skipping style check", "WARNING")
                    return True, [], 100
                self.print_status(f"Style check error: {e}", "ERROR")
                return False, [str(e)], 0

            if result.returncode != 0:
                for line in result.stdout.split("\n"):
                    if "C:" in line or "E:" in line:
                        issues.append(f"{filepath}: {line}")
                        score -= 5

        if issues:
            self.print_status(f"Found {len(issues)} style issues", "WARNING")
            return False, issues, max(0, score)

        self.print_status("Code style check passed", "SUCCESS")
        return True, [], 100

    def check_test_coverage(self, _files: list[str]) -> tuple[bool, list[str], float]:
        """Check test coverage (minimum 80%)."""
        self.print_status("Checking test coverage...", "INFO")

        try:
            run_command(
                ["coverage", "run", "-m", "pytest", "--tb=short"],
                timeout=30,
            )

            # Get coverage report
            cov_result = run_command(
                ["coverage", "report", "--fail-under=80"],
                timeout=10,
            )
        except OSError as e:
            if "Command not found" in str(e):
                self.print_status("coverage/pytest not installed, skipping", "WARNING")
                return True, [], 100
            self.print_status(f"Coverage check error: {e}", "ERROR")
            return False, [str(e)], 0

        if not cov_result.returncode:
            # Extract coverage percentage
            for line in cov_result.stdout.split("\n"):
                if "TOTAL" in line:
                    match = re.search(r"(\d+)%", line)
                    if match:
                        coverage = float(match.group(1))
                        self.print_status(f"Test coverage: {coverage}%", "SUCCESS")
                        return True, [], coverage

        self.print_status("Test coverage below 80%", "ERROR")
        return False, [cov_result.stdout], 0

    def check_security(self, files: list[str]) -> tuple[bool, list[str], int]:
        """Check for security issues using bandit."""
        self.print_status("Checking security...", "INFO")
        issues = []
        score = 100

        try:
            python_files = [f for f in files if f.endswith(".py")]
            if not python_files:
                return True, [], 100

            result = run_command(["bandit", "-r", "-ll", *python_files], timeout=30)
        except OSError as e:
            if "Command not found" in str(e):
                self.print_status("bandit not installed, skipping security check", "WARNING")
                return True, [], 100
            self.print_status(f"Security check error: {e}", "ERROR")
            return False, [str(e)], 0

        if "Issue: " in result.stdout:
            for line in result.stdout.split("\n"):
                if "Issue: " in line or "Severity: " in line:
                    issues.append(line)
                    if "HIGH" in line:
                        score -= 20
                    elif "MEDIUM" in line:
                        score -= 10

        if issues:
            self.print_status(f"Found {len(issues)} security issues", "ERROR")
            return False, issues, max(0, score)

        self.print_status("Security check passed", "SUCCESS")
        return True, [], 100

    def check_complexity(self, files: list[str]) -> tuple[bool, list[str], float]:
        """Check code complexity using radon."""
        self.print_status("Checking code complexity...", "INFO")
        issues = []
        avg_complexity: float = 0

        try:
            python_files = [f for f in files if f.endswith(".py")]
            if not python_files:
                return True, [], 10  # Best complexity score

            result = run_command(["radon", "cc", "-a", *python_files], timeout=30)
        except OSError as e:
            if "Command not found" in str(e):
                self.print_status("radon not installed, skipping complexity check", "WARNING")
                return True, [], 5
            self.print_status(f"Complexity check error: {e}", "ERROR")
            return False, [str(e)], 10

        complexities = []
        for line in result.stdout.split("\n"):
            if " - " in line and any(c in line for c in ["A", "B", "C", "D", "F"]):
                complexities.append(line)
                # F = too complex, D = high, C = moderate
                if "F" in line:
                    issues.append(f"HIGH COMPLEXITY: {line}")
                    avg_complexity += 10
                elif "D" in line:
                    issues.append(f"Moderate complexity: {line}")
                    avg_complexity += 3

        if complexities:
            avg_complexity = float(avg_complexity / len(complexities)) if complexities else 5.0

        if issues:
            self.print_status(f"Found {len(issues)} complexity issues", "WARNING")
            return (
                not [i for i in issues if "HIGH" in i],
                issues,
                avg_complexity,
            )

        self.print_status("Code complexity acceptable", "SUCCESS")
        return True, [], avg_complexity

    def check_tests_pass(self, _files: list[str]) -> tuple[bool, list[str], int]:
        """Run tests to ensure they pass."""
        self.print_status("Running tests...", "INFO")

        try:
            result = run_command(["pytest", "-v", "--tb=short"], timeout=60)
        except subprocess.TimeoutExpired:
            self.print_status("Tests timeout (>60s)", "ERROR")
            return False, ["Test execution timeout"], 0
        except OSError as e:
            if "Command not found" in str(e):
                self.print_status("pytest not installed, skipping tests", "WARNING")
                return True, [], 0
            self.print_status(f"Test error: {e}", "ERROR")
            return False, [str(e)], 0

        if not result.returncode:
            # Count passed tests
            passed = len(re.findall(r"PASSED", result.stdout))
            self.print_status(f"All tests passed ({passed} tests)", "SUCCESS")
            return True, [], passed

        # Extract failed tests
        failed = re.findall(r"FAILED.*", result.stdout)
        self.print_status(f"Tests failed ({len(failed)} failures)", "ERROR")
        return False, failed, 0

    def check_documentation(self, files: list[str]) -> tuple[bool, list[str], int]:
        """Check for code documentation and docstrings."""
        self.print_status("Checking documentation...", "INFO")
        issues = []
        score = 100

        for filepath in files:
            if not filepath.endswith(".py"):
                continue

            try:
                content = Path(filepath).read_text(encoding="utf-8")

                # Check for module docstring
                if not content.startswith(('"""', "'''")):
                    issues.append(f"{filepath}: Missing module docstring")
                    score -= 10

                # Check for function docstrings
                functions = re.findall(r"def \w+\(.*?\):", content)
                for func in functions:
                    if f'{func}\n    """' not in content and f"{func}\n    '''" not in content:
                        issues.append(f"{filepath}: Function missing docstring: {func}")
                        score -= 5

            except OSError as e:
                self.print_status(f"Documentation check error: {e}", "ERROR")
                return False, [str(e)], 0

        if issues:
            self.print_status(f"Found {len(issues)} documentation issues", "WARNING")
            return False, issues, max(0, score)
        self.print_status("Documentation check passed", "SUCCESS")
        return True, [], 100

    def check_dependencies(self, _files: list[str]) -> tuple[bool, list[str], int]:
        """Check for dependency issues."""
        self.print_status("Checking dependencies...", "INFO")
        issues = []

        # Check for requirements.txt or setup.py
        if not (Path("requirements.txt").exists() or Path("setup.py").exists()):
            return True, [], 100

        try:
            result = run_command(["pip-audit"], timeout=30)
        except OSError as e:
            if "Command not found" in str(e):
                self.print_status("pip-audit not installed, skipping", "WARNING")
                return True, [], 100
            self.print_status(f"Dependency check error: {e}", "ERROR")
            return False, [str(e)], 0

        if "found" in result.stdout.lower():
            issues = result.stdout.split("\n")
            self.print_status("Found dependency vulnerabilities", "ERROR")
            return False, issues, 0

        self.print_status("Dependency check passed", "SUCCESS")
        return True, [], 100

    # ========== INTEGRATION METHODS ==========

    @staticmethod
    def get_staged_files() -> list[str]:
        """Get list of staged files."""
        try:
            result = run_command(["git", "diff", "--cached", "--name-only"])
        except OSError:
            return []
        # result.stdout is str since text=True (run_command default)
        if result.stdout:
            return result.stdout.strip().split("\n")
        return []

    @staticmethod
    def generate_quality_report(checks: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive quality report."""
        report = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "checks": checks,
            "overall_quality_score": 0,
            "pass_all": True,
        }

        # Calculate scores
        scores = []
        for check_result in checks.values():
            if isinstance(check_result, dict):
                if "score" in check_result:
                    scores.append(check_result["score"])
                if not check_result.get("passed", True):
                    report["pass_all"] = False

        if scores:
            report["overall_quality_score"] = sum(scores) / len(scores)

        return report

    def run_all_checks(self, files: list[str] | None = None) -> dict[str, Any]:
        """Run all quality checks."""
        if not files:
            files = self.get_staged_files()

        if not files or files == [""]:
            self.print_status("No files to check", "WARNING")
            return {"status": "no_files"}

        checks = {}

        # Run all checks

        # 1. Code Style
        passed, issues, score = self.check_code_style(files)
        checks["code_style"] = {"passed": passed, "score": score, "issues": issues}

        # 2. Tests
        passed, issues, count = self.check_tests_pass(files)
        checks["tests"] = {
            "passed": passed,
            "score": 100 if passed else 0,
            "test_count": count,
            "issues": issues,
        }

        # 3. Test Coverage
        passed, issues, coverage = self.check_test_coverage(files)
        checks["coverage"] = {"passed": passed, "score": coverage, "issues": issues}

        # 4. Security
        passed, issues, score = self.check_security(files)
        checks["security"] = {"passed": passed, "score": score, "issues": issues}

        # 5. Complexity
        passed, issues, complexity = self.check_complexity(files)
        checks["complexity"] = {
            "passed": passed,
            "score": min(10, max(0, 10 - complexity)),
            "complexity_score": complexity,
            "issues": issues,
        }

        # 6. Documentation
        passed, issues, score = self.check_documentation(files)
        checks["documentation"] = {"passed": passed, "score": score, "issues": issues}

        # 7. Dependencies
        passed, issues, score = self.check_dependencies(files)
        checks["dependencies"] = {"passed": passed, "score": score, "issues": issues}

        # Generate report
        report = self.__class__.generate_quality_report(checks)
        self.save_quality_report(report)

        # Display summary
        self.__class__.display_summary(report)

        return report

    @staticmethod
    def display_summary(report: dict[str, Any]) -> bool:
        """Display quality check summary."""
        for check_result in report["checks"].values():
            if isinstance(check_result, dict):
                _status = " PASS" if check_result.get("passed", False) else " FAIL"
                _color = Colors.GREEN if check_result.get("passed") else Colors.RED
                _score = check_result.get("score", 0)

        return bool(report["pass_all"])

    def save_quality_report(self, report: dict[str, Any]) -> None:
        """Save quality report to file."""
        self.quality_report_file.write_text(
            json.dumps(report) + "\n",
            encoding="utf-8",
        )


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Validate AI-generated code quality")
    parser.add_argument("--files", nargs="+", help="Specific files to check")
    parser.add_argument(
        "--check",
        choices=[
            "style",
            "tests",
            "coverage",
            "security",
            "complexity",
            "docs",
            "deps",
            "all",
        ],
        default="all",
        help="Specific check to run",
    )

    args = parser.parse_args()

    validator = CodeQualityValidator()
    report = validator.run_all_checks(files=args.files)

    # Exit with appropriate code
    return 0 if report.get("pass_all", True) else 1


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "CodeQualityValidator",
    "Colors",
    "main",
]


if __name__ == "__main__":
    import sys

    sys.exit(main())
