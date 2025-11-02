#!/usr/bin/env python3
"""
Tests for mutation testing framework.

Validates:
- Mutation type definitions
- Mutation detection in AST
- Mutation result tracking
- Report generation
"""

import ast
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

# Mock sys.argv to prevent argparse issues during import
sys.argv = ["pytest"]

from cli.mutation_test import (  # noqa: E402
    Mutation,
    MutationDetector,
    MutationReport,
    MutationResult,
    MutationTester,
    MutationType,
)


class TestMutationType:
    """Test MutationType enum."""

    def test_comparison_operator_enum(self) -> None:
        """Test comparison operator mutation type."""
        assert MutationType.COMPARISON_OPERATOR.value == "comparison_operator"

    def test_boolean_literal_enum(self) -> None:
        """Test boolean literal mutation type."""
        assert MutationType.BOOLEAN_LITERAL.value == "boolean_literal"

    def test_arithmetic_operator_enum(self) -> None:
        """Test arithmetic operator mutation type."""
        assert MutationType.ARITHMETIC_OPERATOR.value == "arithmetic_operator"

    def test_logical_operator_enum(self) -> None:
        """Test logical operator mutation type."""
        assert MutationType.LOGICAL_OPERATOR.value == "logical_operator"

    def test_return_value_enum(self) -> None:
        """Test return value mutation type."""
        assert MutationType.RETURN_VALUE.value == "return_value"

    def test_constant_replacement_enum(self) -> None:
        """Test constant replacement mutation type."""
        assert MutationType.CONSTANT_REPLACEMENT.value == "constant_replacement"


class TestMutation:
    """Test Mutation dataclass."""

    def test_mutation_creation(self) -> None:
        """Test creating a mutation."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        assert mutation.file_path == Path("test.py")
        assert mutation.line_number == 10
        assert mutation.mutation_type == MutationType.COMPARISON_OPERATOR
        assert mutation.original_code == "x == y"
        assert mutation.mutated_code == "x != y"

    def test_mutation_hash(self) -> None:
        """Test mutation hashing."""
        mutation1 = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        mutation2 = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="a == b",
            mutated_code="a != b",
            description="Changed == to !=",
        )

        # Same file, line, and type should hash the same
        assert hash(mutation1) == hash(mutation2)

    def test_mutation_hash_different_file(self) -> None:
        """Test mutation hashing with different file."""
        mutation1 = Mutation(
            file_path=Path("test1.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        mutation2 = Mutation(
            file_path=Path("test2.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        assert hash(mutation1) != hash(mutation2)


class TestMutationResult:
    """Test MutationResult dataclass."""

    def test_mutation_result_killed(self) -> None:
        """Test mutation result marked as killed."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        result = MutationResult(mutation=mutation, test_result="killed")

        assert result.killed is True
        assert result.test_result == "killed"

    def test_mutation_result_survived(self) -> None:
        """Test mutation result marked as survived."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        result = MutationResult(mutation=mutation, test_result="survived")

        assert result.killed is False
        assert result.test_result == "survived"

    def test_mutation_result_with_details(self) -> None:
        """Test mutation result with details."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        result = MutationResult(
            mutation=mutation, test_result="killed", details="Test caught the mutation"
        )

        assert result.details == "Test caught the mutation"


class TestMutationReport:
    """Test MutationReport dataclass."""

    def test_mutation_report_creation(self) -> None:
        """Test creating a mutation report."""
        report = MutationReport()

        assert report.total_mutations == 0
        assert report.killed_mutations == 0
        assert report.survived_mutations == 0
        assert report.mutation_score == 0.0
        assert len(report.results) == 0

    def test_mutation_report_update_no_mutations(self) -> None:
        """Test updating report with no mutations."""
        report = MutationReport()
        report.update()

        assert report.total_mutations == 0
        assert report.mutation_score == 0.0

    def test_mutation_report_update_all_killed(self) -> None:
        """Test updating report with all mutations killed."""
        mutation1 = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        mutation2 = Mutation(
            file_path=Path("test.py"),
            line_number=20,
            mutation_type=MutationType.BOOLEAN_LITERAL,
            original_code="True",
            mutated_code="False",
            description="Changed True to False",
        )

        report = MutationReport(
            results=[
                MutationResult(mutation=mutation1, test_result="killed"),
                MutationResult(mutation=mutation2, test_result="killed"),
            ]
        )
        report.update()

        assert report.total_mutations == 2
        assert report.killed_mutations == 2
        assert report.survived_mutations == 0
        assert report.mutation_score == 100.0

    def test_mutation_report_update_some_survived(self) -> None:
        """Test updating report with some mutations survived."""
        mutation1 = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        mutation2 = Mutation(
            file_path=Path("test.py"),
            line_number=20,
            mutation_type=MutationType.BOOLEAN_LITERAL,
            original_code="True",
            mutated_code="False",
            description="Changed True to False",
        )

        report = MutationReport(
            results=[
                MutationResult(mutation=mutation1, test_result="killed"),
                MutationResult(mutation=mutation2, test_result="survived"),
            ]
        )
        report.update()

        assert report.total_mutations == 2
        assert report.killed_mutations == 1
        assert report.survived_mutations == 1
        assert report.mutation_score == 50.0

    def test_mutation_report_to_dict(self) -> None:
        """Test converting report to dictionary."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=10,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Changed == to !=",
        )

        report = MutationReport(results=[MutationResult(mutation=mutation, test_result="survived")])
        report.update()

        result_dict = report.to_dict()

        assert result_dict["total_mutations"] == 1
        assert result_dict["killed_mutations"] == 0
        assert result_dict["survived_mutations"] == 1
        assert "timestamp" in result_dict
        assert "mutation_score" in result_dict
        assert "survived_mutations_details" in result_dict


class TestMutationDetector:
    """Test MutationDetector class."""

    def test_detector_creation(self) -> None:
        """Test creating mutation detector."""
        source = "x = 1\ny = 2"
        detector = MutationDetector(source, Path("test.py"))

        assert detector.source_code == source
        assert detector.file_path == Path("test.py")
        assert len(detector.lines) >= 2
        assert len(detector.mutations) == 0

    def test_detector_detect_comparison(self) -> None:
        """Test detecting comparison operator mutations."""
        source = "if x == y:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        assert len(mutations) > 0
        # Should detect == -> != mutation
        assert any(m.mutation_type == MutationType.COMPARISON_OPERATOR for m in mutations)

    def test_detector_detect_boolean(self) -> None:
        """Test detecting boolean literal mutations."""
        source = "enabled = True\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        assert len(mutations) > 0
        # Should detect True -> False mutation
        assert any(m.mutation_type == MutationType.BOOLEAN_LITERAL for m in mutations)

    def test_detector_detect_logical_and(self) -> None:
        """Test detecting logical AND mutations."""
        source = "if a and b:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        assert len(mutations) > 0
        # Should detect and -> or mutation
        assert any(m.mutation_type == MutationType.LOGICAL_OPERATOR for m in mutations)

    def test_detector_detect_logical_or(self) -> None:
        """Test detecting logical OR mutations."""
        source = "if a or b:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        assert len(mutations) > 0
        # Should detect or -> and mutation
        assert any(m.mutation_type == MutationType.LOGICAL_OPERATOR for m in mutations)

    def test_detector_handle_syntax_error(self) -> None:
        """Test handling syntax errors in source code."""
        source = "if x == y\n    pass\n"  # Missing colon
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        # Should not raise, just return empty or partial results
        assert isinstance(mutations, list)

    def test_detector_multiple_mutations_in_line(self) -> None:
        """Test detecting multiple mutation types in same line."""
        source = "if x == y and True:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        # Should find multiple mutation types
        assert len(mutations) > 1


class TestMutationTester:
    """Test MutationTester class."""

    def test_tester_creation(self) -> None:
        """Test creating mutation tester."""
        tester = MutationTester(
            cli_dir=Path("cli"),
            tests_dir=Path("tests"),
        )

        assert tester.cli_dir == Path("cli")
        assert tester.tests_dir == Path("tests")
        assert tester.logger is not None
        assert tester.report is not None

    def test_tester_setup_logging(self) -> None:
        """Test mutation tester logging setup."""
        tester = MutationTester(
            cli_dir=Path("cli"),
            tests_dir=Path("tests"),
        )

        assert tester.logger is not None
        assert tester.logger.name == "mutation_test"

    def test_tester_report_initialization(self) -> None:
        """Test that tester initializes report."""
        tester = MutationTester(
            cli_dir=Path("cli"),
            tests_dir=Path("tests"),
        )

        assert tester.report is not None
        assert isinstance(tester.report, MutationReport)
        assert len(tester.report.results) == 0

    @patch("cli.mutation_test.MutationDetector.detect")
    def test_tester_detect_all_mutations(self, mock_detect: Mock) -> None:
        """Test detecting all mutations in directory."""
        mock_detect.return_value = [
            Mutation(
                file_path=Path("cli/test.py"),
                line_number=10,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x == y",
                mutated_code="x != y",
                description="Changed == to !=",
            )
        ]

        temp_dir = tempfile.mkdtemp()
        cli_dir = Path(temp_dir) / "cli"
        cli_dir.mkdir()
        try:
            # Create a test Python file
            test_file = cli_dir / "test.py"
            test_file.write_text("x = 1\n")

            tester = MutationTester(cli_dir=cli_dir, tests_dir=Path("tests"))

            # Test private method would normally be called by run()
            assert tester.cli_dir == cli_dir
        finally:
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)


class TestMutationIntegration:
    """Integration tests for mutation testing."""

    def test_full_mutation_workflow(self) -> None:
        """Test complete mutation detection workflow."""
        source_code = """
def is_valid(x):
    if x > 0 and x < 100:
        return True
    return False
"""

        detector = MutationDetector(source_code, Path("test.py"))
        mutations = detector.detect()

        # Should detect mutations
        assert len(mutations) > 0

        # Should have different mutation types
        mutation_types = {m.mutation_type for m in mutations}
        assert len(mutation_types) > 0

    def test_mutation_report_statistics(self) -> None:
        """Test mutation report statistics."""
        mutations = [
            Mutation(
                file_path=Path("test.py"),
                line_number=i,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x == y",
                mutated_code="x != y",
                description="Changed == to !=",
            )
            for i in range(10)
        ]

        # Create results: 7 killed, 3 survived
        results = [
            MutationResult(mutation=mutations[i], test_result="killed" if i < 7 else "survived")
            for i in range(10)
        ]

        report = MutationReport(results=results)
        report.update()

        assert report.total_mutations == 10
        assert report.killed_mutations == 7
        assert report.survived_mutations == 3
        assert report.mutation_score == 70.0

    def test_mutation_score_calculation(self) -> None:
        """Test mutation score calculation."""
        for total in [5, 10, 20]:
            killed = total // 2
            mutations = [
                Mutation(
                    file_path=Path("test.py"),
                    line_number=i,
                    mutation_type=MutationType.COMPARISON_OPERATOR,
                    original_code="x == y",
                    mutated_code="x != y",
                    description="Changed == to !=",
                )
                for i in range(total)
            ]

            results = [
                MutationResult(
                    mutation=mutations[i],
                    test_result="killed" if i < killed else "survived",
                )
                for i in range(total)
            ]

            report = MutationReport(results=results)
            report.update()

            expected_score = (killed / total) * 100
            assert abs(report.mutation_score - expected_score) < 0.01

    def test_comparison_mutations_coverage(self) -> None:
        """Test all comparison operator mutations."""
        comparisons = [
            ("x == y", "x != y"),
            ("x != y", "x == y"),
            ("x < y", "x <= y"),
            ("x <= y", "x < y"),
            ("x > y", "x >= y"),
            ("x >= y", "x > y"),
        ]

        for original, expected_mutation in comparisons:
            source = f"if {original}:\n    pass\n"
            detector = MutationDetector(source, Path("test.py"))
            mutations = detector.detect()

            # Filter for comparison mutations in this source
            comp_mutations = [
                m for m in mutations if m.mutation_type == MutationType.COMPARISON_OPERATOR
            ]
            if comp_mutations:
                assert any(expected_mutation in m.mutated_code for m in comp_mutations)


class TestMutationDetectorLogicalOperators:
    """Test detection of logical operator mutations."""

    def test_logical_and_to_or_mutation(self) -> None:
        """Test detecting 'and' to 'or' mutations."""
        source = "if x and y:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        # Should detect and -> or mutation
        logical_mutations = [
            m for m in mutations if m.mutation_type == MutationType.LOGICAL_OPERATOR
        ]
        assert len(logical_mutations) > 0
        assert any("or" in m.mutated_code for m in logical_mutations)

    def test_logical_or_to_and_mutation(self) -> None:
        """Test detecting 'or' to 'and' mutations."""
        source = "if x or y:\n    pass\n"
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        # Should detect or -> and mutation
        logical_mutations = [
            m for m in mutations if m.mutation_type == MutationType.LOGICAL_OPERATOR
        ]
        assert len(logical_mutations) > 0
        assert any("and" in m.mutated_code for m in logical_mutations)


class TestMutationTesterDetection:
    """Test mutation detection in MutationTester."""

    def test_detect_all_mutations(self) -> None:
        """Test detecting mutations from CLI directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            # Create a simple Python file with detectable mutations
            test_file = cli_dir / "example.py"
            test_file.write_text("def check(x, y):\n    return x == y\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutations = tester._detect_all_mutations()

            # Should detect at least one mutation
            assert len(mutations) > 0

    def test_get_mutation_count(self) -> None:
        """Test getting mutation count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            tester = MutationTester(cli_dir, tests_dir)

            # Initially should have 0 mutations
            assert tester.get_mutation_count() == 0


class TestMutationTesterExecution:
    """Test mutation testing execution."""

    def test_test_mutation_with_syntax_error_handling(self) -> None:
        """Test _test_mutation handles errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            # Create test file
            test_file = cli_dir / "test_code.py"
            test_file.write_text("x = 1\ny = 2\n")

            tester = MutationTester(cli_dir, tests_dir)

            # Create mutation with out-of-range line number
            mutation = Mutation(
                file_path=test_file,
                line_number=999,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x == y",
                mutated_code="x != y",
                description="Test mutation",
            )

            result = tester._test_mutation(mutation)

            # Should handle gracefully
            assert isinstance(result, MutationResult)
            assert result.mutation == mutation

    def test_test_mutation_returns_survived_on_timeout(self) -> None:
        """Test _test_mutation handles timeout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            test_file = cli_dir / "example.py"
            test_file.write_text("x = 1\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutation = Mutation(
                file_path=test_file,
                line_number=1,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x = 1",
                mutated_code="x = 2",
                description="Test mutation",
            )

            # Mock run_command to raise TimeoutExpired
            with patch("cli.mutation_test.run_command") as mock_run:
                import subprocess

                mock_run.side_effect = subprocess.TimeoutExpired("pytest", 30)
                result = tester._test_mutation(mutation)

                assert result.test_result == "survived"
                assert "Test timeout" in result.details


class TestMutationTesterRun:
    """Test MutationTester.run() method."""

    def test_run_with_no_mutations(self) -> None:
        """Test run() with empty CLI directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            tester = MutationTester(cli_dir, tests_dir)

            with patch.object(tester, "_detect_all_mutations", return_value=[]):
                report = tester.run()

                assert report.total_mutations == 0
                assert report.killed_mutations == 0
                assert report.mutation_score == 0.0

    def test_run_updates_report(self) -> None:
        """Test run() updates the report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            tester = MutationTester(cli_dir, tests_dir)

            # Create mock mutations and results
            mutation1 = Mutation(
                file_path=Path("test.py"),
                line_number=1,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x == y",
                mutated_code="x != y",
                description="Test",
            )

            result1 = MutationResult(mutation=mutation1, test_result="killed")

            with patch.object(tester, "_detect_all_mutations", return_value=[mutation1]):
                with patch.object(tester, "_test_mutation", return_value=result1):
                    report = tester.run()

                    assert report.total_mutations == 1
                    assert report.killed_mutations == 1


class TestMutationReporting:
    """Test mutation reporting functions."""

    def test_print_mutation_report_high_score(self) -> None:
        """Test print_mutation_report with high mutation score."""
        from cli.mutation_test import print_mutation_report

        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=1,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Test",
        )
        result = MutationResult(mutation=mutation, test_result="killed")
        report = MutationReport(results=[result])
        report.update()

        # Should not raise
        print_mutation_report(report)

    def test_print_mutation_report_low_score(self) -> None:
        """Test print_mutation_report with low mutation score."""
        from cli.mutation_test import print_mutation_report

        mutation1 = Mutation(
            file_path=Path("test.py"),
            line_number=1,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Test",
        )
        mutation2 = Mutation(
            file_path=Path("test.py"),
            line_number=2,
            mutation_type=MutationType.BOOLEAN_LITERAL,
            original_code="True",
            mutated_code="False",
            description="Test",
        )
        result1 = MutationResult(mutation=mutation1, test_result="killed")
        result2 = MutationResult(mutation=mutation2, test_result="survived")
        report = MutationReport(results=[result1, result2])
        report.update()

        # Should not raise
        print_mutation_report(report)

    def test_print_mutation_report_with_survived(self) -> None:
        """Test print_mutation_report with survived mutations."""
        from cli.mutation_test import print_mutation_report

        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=1,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Test",
        )
        result = MutationResult(mutation=mutation, test_result="survived")
        report = MutationReport(results=[result])
        report.update()

        # Should not raise
        print_mutation_report(report)

    def test_save_mutation_report(self) -> None:
        """Test save_mutation_report creates JSON file."""
        from cli.mutation_test import save_mutation_report

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "reports" / "mutation_report.json"

            mutation = Mutation(
                file_path=Path("test.py"),
                line_number=1,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x == y",
                mutated_code="x != y",
                description="Test",
            )
            result = MutationResult(mutation=mutation, test_result="killed")
            report = MutationReport(results=[result])
            report.update()

            save_mutation_report(report, output_path)

            # Should create file
            assert output_path.exists()

            # Should contain valid JSON
            import json

            data = json.loads(output_path.read_text())
            assert data["total_mutations"] == 1
            assert data["killed_mutations"] == 1


class TestMutationDetectorErrorHandling:
    """Test error handling in MutationDetector."""

    def test_detector_handles_syntax_error(self) -> None:
        """Test detector handles syntax errors gracefully."""
        source = "if x == y\n    pass\n"  # Missing colon - syntax error
        detector = MutationDetector(source, Path("test.py"))
        mutations = detector.detect()

        # Should return empty list on syntax error
        assert isinstance(mutations, list)

    def test_detector_init_with_multiline_code(self) -> None:
        """Test detector initialization with multiline code."""
        source = "def func():\n    x = 1\n    y = 2\n    return x == y"
        detector = MutationDetector(source, Path("test.py"))

        assert detector.source_code == source
        assert len(detector.lines) == 4
        assert detector.file_path == Path("test.py")


class TestMutationTesterDetectionErrors:
    """Test error handling in mutation detection."""

    def test_detect_all_mutations_with_syntax_error_in_file(self) -> None:
        """Test _detect_all_mutations skips files with syntax errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            # Create a file with syntax error
            bad_file = cli_dir / "bad.py"
            bad_file.write_text("if x == y\n    pass\n")  # Missing colon

            # Create a good file
            good_file = cli_dir / "good.py"
            good_file.write_text("def func():\n    return x == y\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutations = tester._detect_all_mutations()

            # Should still work, skipping the bad file
            assert isinstance(mutations, list)

    def test_detect_all_mutations_skips_init_file(self) -> None:
        """Test _detect_all_mutations skips __init__.py."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            # Create __init__.py
            init_file = cli_dir / "__init__.py"
            init_file.write_text("x = 1 == 2\n")

            # Create normal file
            normal_file = cli_dir / "module.py"
            normal_file.write_text("y = 3 == 4\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutations = tester._detect_all_mutations()

            # __init__.py should be skipped
            init_mutations = [m for m in mutations if "__init__" in str(m.file_path)]
            assert len(init_mutations) == 0


class TestMutationResultKilled:
    """Test MutationResult.killed property."""

    def test_mutation_result_killed_property(self) -> None:
        """Test killed property returns correct value."""
        mutation = Mutation(
            file_path=Path("test.py"),
            line_number=1,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Test",
        )

        killed_result = MutationResult(mutation=mutation, test_result="killed")
        survived_result = MutationResult(mutation=mutation, test_result="survived")

        assert killed_result.killed is True
        assert survived_result.killed is False


class TestMutationReportToDictWithSurvived:
    """Test MutationReport.to_dict() with survived mutations."""

    def test_to_dict_includes_survived_mutations(self) -> None:
        """Test to_dict includes survived mutation details."""
        mutation1 = Mutation(
            file_path=Path("test.py"),
            line_number=1,
            mutation_type=MutationType.COMPARISON_OPERATOR,
            original_code="x == y",
            mutated_code="x != y",
            description="Test mutation",
        )
        mutation2 = Mutation(
            file_path=Path("test.py"),
            line_number=2,
            mutation_type=MutationType.BOOLEAN_LITERAL,
            original_code="True",
            mutated_code="False",
            description="Test boolean",
        )

        result1 = MutationResult(mutation=mutation1, test_result="killed")
        result2 = MutationResult(mutation=mutation2, test_result="survived")

        report = MutationReport(results=[result1, result2])
        report.update()

        report_dict = report.to_dict()

        assert report_dict["total_mutations"] == 2
        assert report_dict["killed_mutations"] == 1
        assert report_dict["survived_mutations"] == 1
        assert len(report_dict["survived_mutations_details"]) == 1
        assert report_dict["survived_mutations_details"][0]["type"] == "boolean_literal"


class TestMutationTesterTestMutationKilled:
    """Test _test_mutation when mutation is killed."""

    def test_test_mutation_killed(self) -> None:
        """Test _test_mutation returns killed result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            test_file = cli_dir / "example.py"
            test_file.write_text("x = 1\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutation = Mutation(
                file_path=test_file,
                line_number=1,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x = 1",
                mutated_code="x = 2",
                description="Test mutation",
            )

            # Mock run_command to return non-zero (failure - mutation caught)
            with patch("cli.mutation_test.run_command") as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 1
                mock_run.return_value = mock_result

                result = tester._test_mutation(mutation)

                assert result.test_result == "killed"
                assert "Tests failed" in result.details

    def test_test_mutation_survived(self) -> None:
        """Test _test_mutation returns survived result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_dir = Path(tmpdir) / "cli"
            tests_dir = Path(tmpdir) / "tests"
            cli_dir.mkdir()
            tests_dir.mkdir()

            test_file = cli_dir / "example.py"
            test_file.write_text("x = 1\n")

            tester = MutationTester(cli_dir, tests_dir)
            mutation = Mutation(
                file_path=test_file,
                line_number=1,
                mutation_type=MutationType.COMPARISON_OPERATOR,
                original_code="x = 1",
                mutated_code="x = 2",
                description="Test mutation",
            )

            # Mock run_command to return zero (success - mutation not caught)
            with patch("cli.mutation_test.run_command") as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_run.return_value = mock_result

                result = tester._test_mutation(mutation)

                assert result.test_result == "survived"
                assert "Tests passed" in result.details


class TestMainFunction:
    """Test main CLI function."""

    def test_main_returns_zero_on_good_score(self) -> None:
        """Test main returns 0 for mutation score >= 70."""
        from cli.mutation_test import main

        with patch("cli.mutation_test.MutationTester") as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            mock_report = MagicMock()
            mock_report.mutation_score = 80.0
            mock_tester.run.return_value = mock_report

            with patch("cli.mutation_test.print_mutation_report"):
                with patch("cli.mutation_test.save_mutation_report"):
                    result = main()

                    assert result == 0

    def test_main_returns_one_on_bad_score(self) -> None:
        """Test main returns 1 for mutation score < 70."""
        from cli.mutation_test import main

        with patch("cli.mutation_test.MutationTester") as mock_tester_class:
            mock_tester = MagicMock()
            mock_tester_class.return_value = mock_tester

            mock_report = MagicMock()
            mock_report.mutation_score = 50.0
            mock_tester.run.return_value = mock_report

            with patch("cli.mutation_test.print_mutation_report"):
                with patch("cli.mutation_test.save_mutation_report"):
                    result = main()

                    assert result == 1


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
