#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
# !/usr/bin/env python3
"""Mutation Testing Framework for Devkit CLI.

Validates test quality by introducing controlled mutations (bugs) into source code
and verifying that tests catch them (kill the mutations).

Key Concepts:
- Mutation: A controlled modification to source code (e.g., change == to !=)
- Killed: Mutation caught by tests (test fails) - GOOD
- Survived: Mutation not caught by tests (test passes) - BAD (weak test)
- Mutation Score: (Killed / Total) * 100 - Goal: 80%+

This implementation:
1. Scans CLI source files
2. Identifies mutation points (operators, literals, comparisons)
3. Introduces mutations one at a time
4. Runs pytest for each mutation
5. Tracks kill/survive statistics
6. Reports weaknesses in test coverage
"""

import ast
import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

# ============================================================================
# MUTATION DEFINITIONS
# ============================================================================


class MutationType(Enum):
    """Types of mutations to introduce."""

    COMPARISON_OPERATOR = "comparison_operator"  # == -> !=, > -> >=, etc.
    BOOLEAN_LITERAL = "boolean_literal"  # True -> False
    ARITHMETIC_OPERATOR = "arithmetic_operator"  # + -> -, * -> /
    LOGICAL_OPERATOR = "logical_operator"  # and -> or
    RETURN_VALUE = "return_value"  # return x -> return not x
    CONSTANT_REPLACEMENT = "constant_replacement"  # 1 -> 0, "" -> "mutant"


@dataclass
class Mutation:
    """Represents a single mutation point in source code."""

    file_path: Path
    line_number: int
    mutation_type: MutationType
    original_code: str
    mutated_code: str
    description: str

    def __hash__(self) -> int:
        """Make mutation hashable."""
        return hash((str(self.file_path), self.line_number, self.mutation_type.value))


@dataclass
class MutationResult:
    """Result of running tests against a mutation."""

    mutation: Mutation
    test_result: str  # "killed" or "survived"
    details: str = ""

    @property
    def killed(self) -> bool:
        """Check if mutation was killed by tests."""
        return self.test_result == "killed"


@dataclass
class MutationReport:
    """Comprehensive mutation testing report."""

    total_mutations: int = 0
    killed_mutations: int = 0
    survived_mutations: int = 0
    mutation_score: float = 0.0
    results: list[MutationResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def update(self) -> None:
        """Calculate metrics from results."""
        self.total_mutations = len(self.results)
        self.killed_mutations = sum(1 for r in self.results if r.killed)
        self.survived_mutations = self.total_mutations - self.killed_mutations

        if self.total_mutations > 0:
            self.mutation_score = (self.killed_mutations / self.total_mutations) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "total_mutations": self.total_mutations,
            "killed_mutations": self.killed_mutations,
            "survived_mutations": self.survived_mutations,
            "mutation_score": round(self.mutation_score, 2),
            "survived_mutations_details": [
                {
                    "file": str(r.mutation.file_path),
                    "line": r.mutation.line_number,
                    "type": r.mutation.mutation_type.value,
                    "original": r.mutation.original_code,
                    "mutated": r.mutation.mutated_code,
                    "description": r.mutation.description,
                }
                for r in self.results
                if not r.killed
            ],
        }


# ============================================================================
# MUTATION DETECTOR
# ============================================================================


class MutationDetector(ast.NodeVisitor):
    """Detects potential mutation points in Python AST."""

    def __init__(self, source_code: str, file_path: Path) -> None:
        """Initialize detector."""
        self.source_code = source_code
        self.file_path = file_path
        self.lines = source_code.split("\n")
        self.mutations: list[Mutation] = []

    def detect(self) -> list[Mutation]:
        """Detect all mutation points in source code."""
        try:
            tree = ast.parse(self.source_code)
            self.visit(tree)
        except SyntaxError:
            pass
        return self.mutations

    def visit_Compare(self, node: ast.Compare) -> None:  # pylint: disable=invalid-name
        """Detect comparison operator mutations."""
        for op in node.ops:
            line_num = node.lineno
            line_code = self.lines[line_num - 1] if line_num <= len(self.lines) else ""

            mutations_for_op = self._get_comparison_mutations(op, line_code, line_num)
            self.mutations.extend(mutations_for_op)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:  # pylint: disable=invalid-name
        """Detect logical operator mutations (and/or)."""
        line_num = node.lineno
        line_code = self.lines[line_num - 1] if line_num <= len(self.lines) else ""

        if isinstance(node.op, ast.And):
            self.mutations.append(
                Mutation(
                    file_path=self.file_path,
                    line_number=line_num,
                    mutation_type=MutationType.LOGICAL_OPERATOR,
                    original_code=line_code.strip(),
                    mutated_code=line_code.strip().replace(" and ", " or ", 1),
                    description=f"Changed 'and' to 'or' on line {line_num}",
                ),
            )
        elif isinstance(node.op, ast.Or):
            self.mutations.append(
                Mutation(
                    file_path=self.file_path,
                    line_number=line_num,
                    mutation_type=MutationType.LOGICAL_OPERATOR,
                    original_code=line_code.strip(),
                    mutated_code=line_code.strip().replace(" or ", " and ", 1),
                    description=f"Changed 'or' to 'and' on line {line_num}",
                ),
            )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:  # pylint: disable=invalid-name
        """Detect boolean literal mutations."""
        if isinstance(node.value, bool):
            line_num = node.lineno
            line_code = self.lines[line_num - 1] if line_num <= len(self.lines) else ""

            original = "True" if node.value else "False"
            mutated = "False" if node.value else "True"

            self.mutations.append(
                Mutation(
                    file_path=self.file_path,
                    line_number=line_num,
                    mutation_type=MutationType.BOOLEAN_LITERAL,
                    original_code=line_code.strip(),
                    mutated_code=line_code.strip().replace(original, mutated, 1),
                    description=f"Changed {original} to {mutated} on line {line_num}",
                ),
            )

        self.generic_visit(node)

    def _get_comparison_mutations(
        self,
        op: ast.cmpop,
        line_code: str,
        line_num: int,
    ) -> list[Mutation]:
        """Generate comparison operator mutations."""
        mutations: list[Mutation] = []

        op_map = {
            ast.Eq: ("==", "!="),
            ast.NotEq: ("!=", "=="),
            ast.Lt: ("<", "<="),
            ast.LtE: ("<=", "<"),
            ast.Gt: (">", ">="),
            ast.GtE: (">=", ">"),
        }

        if type(op) in op_map:
            original_op, mutated_op = op_map[type(op)]
            if original_op in line_code:
                mutations.append(
                    Mutation(
                        file_path=self.file_path,
                        line_number=line_num,
                        mutation_type=MutationType.COMPARISON_OPERATOR,
                        original_code=line_code.strip(),
                        mutated_code=line_code.strip().replace(original_op, mutated_op, 1),
                        description=f"Changed '{original_op}' to '{mutated_op}' on line {line_num}",
                    ),
                )

        return mutations


# ============================================================================
# MUTATION TESTER
# ============================================================================


class MutationTester:
    """Executes mutation testing against test suite."""

    def __init__(self, cli_dir: Path, tests_dir: Path) -> None:
        """Initialize tester."""
        self.cli_dir = cli_dir
        self.tests_dir = tests_dir
        self.logger = self._setup_logging()
        self.report = MutationReport()

    @staticmethod
    def _setup_logging() -> logging.Logger:
        """Set up logging."""
        logger = logging.getLogger("mutation_test")
        logger.setLevel(logging.INFO)
        return logger

    def get_mutation_count(self) -> int:
        """Get total number of detected mutations."""
        return len(self.report.results)

    def run(self) -> MutationReport:
        """Execute mutation testing."""
        self.logger.info("Starting Mutation Testing")
        self.logger.info("   CLI directory: %s", self.cli_dir)
        self.logger.info("   Tests directory: %s", self.tests_dir)

        # Step 1: Detect mutations
        mutations = self._detect_all_mutations()
        self.logger.info("   Detected %d potential mutation points", len(mutations))

        # Step 2: Run tests against each mutation
        for i, mutation in enumerate(mutations, 1):
            self.logger.info("   Testing mutation %d/%d...", i, len(mutations))
            result = self._test_mutation(mutation)
            self.report.results.append(result)

        # Step 3: Calculate final metrics
        self.report.update()
        self.logger.info("   Mutation testing complete")

        return self.report

    def _detect_all_mutations(self) -> list[Mutation]:
        """Detect all mutations in CLI source code."""
        mutations: list[Mutation] = []

        for py_file in self.cli_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                source = py_file.read_text()
                detector = MutationDetector(source, py_file)
                file_mutations = detector.detect()
                mutations.extend(file_mutations)
            except (OSError, SyntaxError) as e:
                self.logger.warning("Error detecting mutations in %s: %s", py_file, e)

        return mutations

    def _test_mutation(self, mutation: Mutation) -> MutationResult:
        """Test a single mutation."""
        # Create temporary mutated file
        original_code = mutation.file_path.read_text()
        lines = original_code.split("\n")

        # Apply mutation
        if mutation.line_number - 1 < len(lines):
            lines[mutation.line_number - 1] = mutation.mutated_code

        mutated_code = "\n".join(lines)

        # Write mutated file
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".py",
                delete=False,
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(mutated_code)
                Path(tmp_file.name)

            # Copy mutated file back
            backup_path = mutation.file_path.with_suffix(".py.backup")
            backup_path.write_text(original_code)
            mutation.file_path.write_text(mutated_code)

            # Run tests
            result = subprocess.run(
                ["pytest", str(self.tests_dir), "-q", "--tb=no"],
                capture_output=True,
                timeout=30,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            mutation.file_path.write_text(original_code)
            return MutationResult(
                mutation=mutation,
                test_result="survived",
                details="Test timeout (mutation not caught)",
            )
        except OSError as e:
            mutation.file_path.write_text(original_code)
            return MutationResult(
                mutation=mutation,
                test_result="survived",
                details=f"Error during testing: {e}",
            )

        # Restore original
        mutation.file_path.write_text(original_code)
        if backup_path.exists():
            backup_path.unlink()

        # Determine if mutation was killed
        if result.returncode:
            return MutationResult(
                mutation=mutation,
                test_result="killed",
                details="Tests failed (mutation caught)",
            )

        return MutationResult(
            mutation=mutation,
            test_result="survived",
            details="Tests passed (mutation not caught)",
        )


# ============================================================================
# REPORTING
# ============================================================================


def print_mutation_report(report: MutationReport) -> None:
    """Print formatted mutation testing report."""
    # Score interpretation
    if report.mutation_score >= 80:
        pass  # Green
    elif report.mutation_score >= 70 or report.mutation_score >= 60:
        pass  # Yellow
    else:
        pass  # Red

    # Show survived mutations (weak tests)
    if report.survived_mutations > 0:
        for _i, result in enumerate(report.results, 1):
            if not result.killed:
                pass


def save_mutation_report(report: MutationReport, output_path: Path) -> None:
    """Save mutation report as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


# ============================================================================
# CLI INTERFACE
# ============================================================================


def main() -> int:
    """Run mutation testing."""
    devkit_root = Path(__file__).parent.parent
    cli_dir = devkit_root / "cli"
    tests_dir = devkit_root / "tests"
    report_dir = devkit_root / ".mutation_test"

    # Run mutation testing
    tester = MutationTester(cli_dir, tests_dir)
    report = tester.run()

    # Print and save results
    print_mutation_report(report)
    save_mutation_report(report, report_dir / "report.json")

    # Exit with success if score is good
    return 0 if report.mutation_score >= 70 else 1


if __name__ == "__main__":
    sys.exit(main())

# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "MutationDetector",
    "MutationReport",
    "MutationTester",
    "MutationType",
]
