"""
Tests for performance optimization and caching system.

Validates:
- Cache storage and retrieval
- Performance metrics collection
- Installation optimization
- Parallel installation ordering
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.performance import (  # noqa: E402
    CacheManager,
    PerformanceMonitor,
    InstallationOptimizer,
    ParallelInstaller,
)


class TestCacheManager(unittest.TestCase):
    """Test CacheManager class."""

    def setUp(self):
        """Set up test cache manager with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache = CacheManager(Path(self.temp_dir))

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_set_and_get(self):
        """Test storing and retrieving cache."""
        key = "test_key"
        value = {"foo": "bar", "count": 42}

        self.cache.set(key, value)
        result = self.cache.get(key)

        self.assertIsNotNone(result)
        self.assertEqual(result["foo"], "bar")
        self.assertEqual(result["count"], 42)

    def test_cache_expiration(self):
        """Test that cache expires after TTL."""
        key = "expiring_key"
        value = {"data": "test"}

        # Set cache with very short TTL
        self.cache.set(key, value, ttl_hours=0)
        time.sleep(0.1)

        # Should be expired
        result = self.cache.get(key)
        self.assertIsNone(result)

    def test_cache_invalidation(self):
        """Test cache invalidation."""
        key = "invalidate_key"
        value = {"data": "test"}

        self.cache.set(key, value)
        self.assertIsNotNone(self.cache.get(key))

        self.cache.invalidate(key)
        self.assertIsNone(self.cache.get(key))

    def test_cache_clear(self):
        """Test clearing all cache entries."""
        for i in range(5):
            self.cache.set(f"key_{i}", {"value": i})

        stats_before = self.cache.get_cache_stats()
        self.assertGreater(stats_before["entries"], 0)

        self.cache.clear()

        stats_after = self.cache.get_cache_stats()
        self.assertEqual(stats_after["entries"], 0)

    def test_cache_stats(self):
        """Test cache statistics."""
        for i in range(3):
            self.cache.set(f"key_{i}", {"value": f"data_{i}"})

        stats = self.cache.get_cache_stats()

        self.assertEqual(stats["entries"], 3)
        self.assertGreater(stats["size_bytes"], 0)
        self.assertGreaterEqual(stats["size_mb"], 0)
        self.assertIn("cache_dir", stats)

    def test_cache_file_hashing(self):
        """Test that cache files use hashed keys."""
        key = "test_key_with_special_chars_!@#$%"
        value = {"data": "test"}

        self.cache.set(key, value)

        cache_files = list(Path(self.temp_dir).glob("*.cache"))
        self.assertEqual(len(cache_files), 1)

        # Filename should be SHA256 hash + .cache extension
        filename = cache_files[0].name
        self.assertTrue(filename.endswith(".cache"))
        # SHA256 hash is 64 hex chars, plus ".cache" (6 chars) = 70
        self.assertEqual(len(filename), 70)

    def test_cache_with_complex_data(self):
        """Test caching complex nested data."""
        value = {
            "list": [1, 2, 3],
            "nested": {"deep": {"data": "value"}},
            "boolean": True,
            "null": None,
        }

        self.cache.set("complex_key", value)
        result = self.cache.get("complex_key")

        self.assertEqual(result["list"], [1, 2, 3])
        self.assertEqual(result["nested"]["deep"]["data"], "value")
        self.assertTrue(result["boolean"])
        self.assertIsNone(result["null"])


class TestPerformanceMonitor(unittest.TestCase):
    """Test PerformanceMonitor class."""

    def setUp(self):
        """Set up test performance monitor."""
        self.monitor = PerformanceMonitor()

    def test_record_metric(self):
        """Test recording a metric."""
        self.monitor.record_metric("test_operation", 1.5, "seconds")

        summary = self.monitor.get_summary()
        self.assertIn("test_operation", summary)
        self.assertEqual(summary["test_operation"]["count"], 1)
        self.assertEqual(summary["test_operation"]["min"], 1.5)
        self.assertEqual(summary["test_operation"]["max"], 1.5)

    def test_timer_methods(self):
        """Test start and end timer."""
        start = self.monitor.start_timer("timed_operation")
        time.sleep(0.1)
        duration = self.monitor.end_timer("timed_operation", start)

        self.assertGreaterEqual(duration, 0.1)

        summary = self.monitor.get_summary()
        self.assertIn("timed_operation", summary)

    def test_multiple_measurements(self):
        """Test recording multiple measurements."""
        for i in range(5):
            self.monitor.record_metric("operation", float(i + 1))

        summary = self.monitor.get_summary()
        stats = summary["operation"]

        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["min"], 1.0)
        self.assertEqual(stats["max"], 5.0)
        self.assertEqual(stats["avg"], 3.0)
        self.assertEqual(stats["total"], 15.0)

    def test_summary_with_no_metrics(self):
        """Test summary when no metrics recorded."""
        summary = self.monitor.get_summary()
        self.assertEqual(summary, {})

    def test_multiple_labels(self):
        """Test tracking multiple different metrics."""
        self.monitor.record_metric("install", 5.0)
        self.monitor.record_metric("config", 2.0)
        self.monitor.record_metric("verify", 1.5)

        summary = self.monitor.get_summary()
        self.assertEqual(len(summary), 3)
        self.assertIn("install", summary)
        self.assertIn("config", summary)
        self.assertIn("verify", summary)


class TestInstallationOptimizer(unittest.TestCase):
    """Test InstallationOptimizer class."""

    def setUp(self):
        """Set up test optimizer with temporary cache."""
        self.temp_dir = tempfile.mkdtemp()
        self.optimizer = InstallationOptimizer()
        self.optimizer.cache = CacheManager(Path(self.temp_dir))

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_should_reinstall_no_cache(self):
        """Test reinstall when no cache exists."""
        result = self.optimizer.should_reinstall("python", "3.12")
        self.assertTrue(result)

    def test_should_reinstall_with_cache(self):
        """Test skip reinstall when cache exists."""
        self.optimizer.mark_installed("python", "3.12")
        result = self.optimizer.should_reinstall("python", "3.12")
        self.assertFalse(result)

    def test_should_reinstall_failed(self):
        """Test reinstall when previous installation failed."""
        self.optimizer.mark_installed("ansible", "2.14", success=False)
        result = self.optimizer.should_reinstall("ansible", "2.14")
        self.assertTrue(result)

    def test_mark_installed_success(self):
        """Test marking successful installation."""
        self.optimizer.mark_installed("python", "3.11", success=True)
        result = self.optimizer.should_reinstall("python", "3.11")
        self.assertFalse(result)

    def test_optimization_suggestions_no_issues(self):
        """Test suggestions when no issues."""
        suggestions = self.optimizer.get_optimization_suggestions()
        self.assertEqual(suggestions, [])

    def test_optimization_suggestions_many_cache_entries(self):
        """Test suggestions when cache is large."""
        # Add many cache entries
        for i in range(150):
            self.optimizer.cache.set(f"install:package_{i}:1.0", {"success": True})

        suggestions = self.optimizer.get_optimization_suggestions()
        self.assertTrue(any("cache" in s.lower() for s in suggestions))


class TestParallelInstaller(unittest.TestCase):
    """Test ParallelInstaller class."""

    def setUp(self):
        """Set up test installer."""
        self.installer = ParallelInstaller(max_parallel=4)

    def test_simple_installation_order(self):
        """Test installation order without dependencies."""
        packages = [
            {"name": "pkg1", "version": "1.0"},
            {"name": "pkg2", "version": "2.0"},
            {"name": "pkg3", "version": "3.0"},
        ]

        waves = self.installer.get_install_order(packages)

        # All packages can be installed in parallel
        self.assertEqual(len(waves), 1)
        self.assertEqual(len(waves[0]), 3)

    def test_installation_with_dependencies(self):
        """Test installation order with dependencies."""
        packages = [
            {"name": "python", "version": "3.12"},
            {"name": "ansible", "version": "2.14", "depends_on": ["python"]},
            {"name": "homebrew", "version": "latest"},
        ]

        waves = self.installer.get_install_order(packages)

        # First wave: homebrew and python
        # Second wave: ansible (depends on python)
        self.assertEqual(len(waves), 2)
        self.assertEqual(len(waves[0]), 2)
        self.assertEqual(len(waves[1]), 1)

    def test_complex_dependency_chain(self):
        """Test complex dependency chain."""
        packages = [
            {"name": "A", "version": "1.0"},
            {"name": "B", "version": "1.0", "depends_on": ["A"]},
            {"name": "C", "version": "1.0", "depends_on": ["B"]},
            {"name": "D", "version": "1.0", "depends_on": ["B"]},
            {"name": "E", "version": "1.0"},
        ]

        waves = self.installer.get_install_order(packages)

        # Wave 1: A, E
        # Wave 2: B
        # Wave 3: C, D
        self.assertEqual(len(waves), 3)
        self.assertEqual(len(waves[0]), 2)
        self.assertEqual(len(waves[1]), 1)
        self.assertEqual(len(waves[2]), 2)

    def test_duration_estimation(self):
        """Test installation duration estimation."""
        packages = [
            {"name": "pkg1", "version": "1.0"},
            {"name": "pkg2", "version": "2.0"},
            {"name": "pkg3", "version": "3.0"},
        ]

        duration = self.installer.estimate_duration(packages)

        # Should be reasonable positive number
        self.assertGreater(duration, 0)
        self.assertLess(duration, 100)

    def test_max_parallel_constraint(self):
        """Test max parallel limit is respected."""
        installer = ParallelInstaller(max_parallel=2)

        packages = [{"name": f"pkg{i}", "version": "1.0"} for i in range(10)]

        waves = installer.get_install_order(packages)

        # With 2 parallel max, should be in 1 wave (no dependencies)
        self.assertEqual(len(waves), 1)
        # But duration should consider parallel limit
        duration = installer.estimate_duration(packages)
        self.assertGreater(duration, 0)

    def test_single_package(self):
        """Test with single package."""
        packages = [{"name": "python", "version": "3.12"}]

        waves = self.installer.get_install_order(packages)

        self.assertEqual(len(waves), 1)
        self.assertEqual(len(waves[0]), 1)
        self.assertEqual(waves[0][0]["name"], "python")

    def test_empty_packages(self):
        """Test with empty package list."""
        packages = []

        waves = self.installer.get_install_order(packages)

        self.assertEqual(len(waves), 0)


class TestCacheManagerErrorHandling:
    """Test error handling in CacheManager."""

    @patch("pathlib.Path.open")
    def test_cache_set_write_error(self, mock_open: MagicMock) -> None:
        """Test cache set with write error."""
        from unittest.mock import MagicMock, patch
        import tempfile
        from pathlib import Path
        from cli.performance import CacheManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CacheManager(cache_dir=Path(tmpdir))
            mock_open.side_effect = OSError("Permission denied")

            # Should handle gracefully
            manager.set("key1", {"data": "value"})
            # No exception should be raised

    @patch("pathlib.Path.open")
    def test_cache_get_read_error(self, mock_open: MagicMock) -> None:
        """Test cache get with read error."""
        from unittest.mock import MagicMock, patch
        import tempfile
        from pathlib import Path
        from cli.performance import CacheManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CacheManager(cache_dir=Path(tmpdir))
            mock_open.side_effect = OSError("Permission denied")

            result = manager.get("key1")
            assert result is None

    @patch("pathlib.Path.unlink")
    def test_cache_invalidate_error(self, mock_unlink: MagicMock) -> None:
        """Test cache invalidate with error."""
        from unittest.mock import MagicMock, patch
        import tempfile
        from pathlib import Path
        from cli.performance import CacheManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CacheManager(cache_dir=Path(tmpdir))
            manager.set("key1", {"data": "value"})

            # Mock the unlink to raise an error
            manager.cache_dir = Path(tmpdir)

            # This should handle the error gracefully
            with patch.object(Path, "unlink", side_effect=OSError("Permission denied")):
                manager.invalidate("key1")
            # No exception should be raised

    @patch("pathlib.Path.glob")
    def test_cache_clear_error(self, mock_glob: MagicMock) -> None:
        """Test cache clear with error."""
        from unittest.mock import MagicMock, patch
        import tempfile
        from pathlib import Path
        from cli.performance import CacheManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CacheManager(cache_dir=Path(tmpdir))

            # Mock glob to raise an error
            mock_glob.side_effect = OSError("Permission denied")

            # This should handle the error gracefully
            manager.clear()
            # No exception should be raised


class TestPerformanceMonitorEdgeCases:
    """Test edge cases in PerformanceMonitor."""

    def test_print_report_empty_metrics(self) -> None:
        """Test print_report with no metrics."""
        from cli.performance import PerformanceMonitor

        monitor = PerformanceMonitor()
        # Should not raise any exception
        monitor.print_report()

    def test_get_summary_empty_label_metrics(self) -> None:
        """Test get_summary skips empty metric lists."""
        from cli.performance import PerformanceMonitor

        monitor = PerformanceMonitor()
        monitor.metrics["empty"] = []
        monitor.metrics["filled"] = [1.0, 2.0, 3.0]

        summary = monitor.get_summary()

        # Empty label should be skipped
        assert "empty" not in summary
        assert "filled" in summary
        assert summary["filled"]["count"] == 3


class TestInstallationOptimizerEdgeCases:
    """Test edge cases in InstallationOptimizer."""

    def test_mark_installed_creates_cache(self) -> None:
        """Test that mark_installed stores in cache."""
        from cli.performance import InstallationOptimizer

        optimizer = InstallationOptimizer()
        optimizer.mark_installed("test-pkg", "1.0")

        # Verify it was cached
        cache_key = "install:test-pkg:1.0"
        assert optimizer.cache.get(cache_key) is not None

    def test_should_reinstall_with_failed_status(self) -> None:
        """Test should_reinstall with failed status in cache."""
        from cli.performance import InstallationOptimizer

        optimizer = InstallationOptimizer()
        cache_key = "install:pkg:1.0"
        optimizer.cache.set(cache_key, {"status": "failed"})

        # Failed installations should require reinstall
        result = optimizer.should_reinstall("pkg", "1.0")
        assert result is True


if __name__ == "__main__":
    unittest.main()
