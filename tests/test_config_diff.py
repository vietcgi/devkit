"""Tests for configuration diff/comparison feature.

Tests the ConfigDiff class that compares configurations
and reports differences in a structured format.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
import pytest

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.config_engine import ConfigDiff


@pytest.mark.unit
@pytest.mark.edge_case
class TestConfigDiff(unittest.TestCase):
    """Test ConfigDiff functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.differ = ConfigDiff()

    def test_diff_identical_configs(self):
        """Test that identical configs have no differences."""
        config1 = {"version": "1.0", "name": "test"}
        config2 = {"version": "1.0", "name": "test"}

        diff = self.differ.compare(config1, config2)

        self.assertEqual(len(diff["added"]), 0)
        self.assertEqual(len(diff["removed"]), 0)
        self.assertEqual(len(diff["modified"]), 0)

    def test_diff_added_keys(self):
        """Test detection of added keys."""
        config1 = {"version": "1.0"}
        config2 = {"version": "1.0", "debug": True}

        diff = self.differ.compare(config1, config2)

        self.assertIn("debug", diff["added"])
        self.assertEqual(diff["added"]["debug"], True)

    def test_diff_removed_keys(self):
        """Test detection of removed keys."""
        config1 = {"version": "1.0", "debug": True}
        config2 = {"version": "1.0"}

        diff = self.differ.compare(config1, config2)

        self.assertIn("debug", diff["removed"])
        self.assertEqual(diff["removed"]["debug"], True)

    def test_diff_modified_values(self):
        """Test detection of modified values."""
        config1 = {"version": "1.0", "level": "DEBUG"}
        config2 = {"version": "1.0", "level": "INFO"}

        diff = self.differ.compare(config1, config2)

        self.assertIn("level", diff["modified"])
        self.assertEqual(diff["modified"]["level"]["old"], "DEBUG")
        self.assertEqual(diff["modified"]["level"]["new"], "INFO")

    def test_diff_nested_configs(self):
        """Test comparison of nested configurations."""
        config1 = {
            "database": {"host": "localhost", "port": 5432},
            "cache": {"enabled": True}
        }
        config2 = {
            "database": {"host": "localhost", "port": 3306},
            "cache": {"enabled": False}
        }

        diff = self.differ.compare(config1, config2)

        # Should have modifications
        self.assertIn("database", diff["modified"])
        self.assertIn("cache", diff["modified"])

    def test_diff_deeply_nested(self):
        """Test comparison of deeply nested structures."""
        config1 = {
            "app": {
                "server": {
                    "port": 8080,
                    "ssl": True
                }
            }
        }
        config2 = {
            "app": {
                "server": {
                    "port": 9000,
                    "ssl": False
                }
            }
        }

        diff = self.differ.compare(config1, config2)

        # Flatten and check differences
        self.assertTrue(len(diff["modified"]) > 0)

    def test_diff_list_values(self):
        """Test comparison of list values."""
        config1 = {"items": [1, 2, 3]}
        config2 = {"items": [1, 2, 3, 4]}

        diff = self.differ.compare(config1, config2)

        self.assertIn("items", diff["modified"])

    def test_diff_summary(self):
        """Test that summary includes correct counts."""
        config1 = {"a": 1, "b": 2}
        config2 = {"a": 1, "b": 3, "c": 4}

        diff = self.differ.compare(config1, config2)
        summary = diff["summary"]

        self.assertEqual(summary["added"], 1)  # c
        self.assertEqual(summary["removed"], 0)
        self.assertEqual(summary["modified"], 1)  # b
        self.assertEqual(summary["unchanged"], 1)  # a

    def test_diff_empty_configs(self):
        """Test comparison of empty configs."""
        config1 = {}
        config2 = {}

        diff = self.differ.compare(config1, config2)

        self.assertEqual(len(diff["added"]), 0)
        self.assertEqual(len(diff["removed"]), 0)
        self.assertEqual(len(diff["modified"]), 0)

    def test_diff_none_values(self):
        """Test comparison with None values."""
        config1 = {"key": None}
        config2 = {"key": "value"}

        diff = self.differ.compare(config1, config2)

        self.assertIn("key", diff["modified"])

    def test_diff_format_json(self):
        """Test formatting diff as JSON."""
        config1 = {"version": "1.0"}
        config2 = {"version": "1.0", "debug": True}

        diff = self.differ.compare(config1, config2)
        json_str = self.differ.format_json(diff)

        # Should be valid JSON
        parsed = json.loads(json_str)
        self.assertIn("added", parsed)
        self.assertIn("summary", parsed)

    def test_diff_format_text(self):
        """Test formatting diff as human-readable text."""
        config1 = {"version": "1.0", "level": "DEBUG"}
        config2 = {"version": "1.0", "level": "INFO", "debug": True}

        diff = self.differ.compare(config1, config2)
        text = self.differ.format_text(diff)

        # Should contain descriptive text
        self.assertIn("Modified", text)
        self.assertIn("Added", text)

    def test_diff_multiple_levels_of_nesting(self):
        """Test deeply nested configuration comparison."""
        config1 = {
            "services": {
                "api": {
                    "handlers": {
                        "logging": {
                            "level": "INFO"
                        }
                    }
                }
            }
        }
        config2 = {
            "services": {
                "api": {
                    "handlers": {
                        "logging": {
                            "level": "DEBUG"
                        }
                    }
                }
            }
        }

        diff = self.differ.compare(config1, config2)

        # Should detect modification
        self.assertTrue(len(diff["modified"]) > 0)

    def test_diff_preserves_types(self):
        """Test that diff preserves original types."""
        config1 = {
            "count": 42,
            "enabled": True,
            "name": "test",
            "tags": ["a", "b"]
        }
        config2 = {
            "count": 42,
            "enabled": True,
            "name": "test",
            "tags": ["a", "b"]
        }

        diff = self.differ.compare(config1, config2)

        # All should be unchanged
        self.assertEqual(diff["summary"]["unchanged"], 4)


if __name__ == "__main__":
    unittest.main()
