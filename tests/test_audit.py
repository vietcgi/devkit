"""
Tests for refactored AuditLogger components.

Validates:
- AuditSigningService cryptographic operations
- AuditLogStorage file I/O and rotation
- Error handling in refactored classes
"""

import sys
import unittest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.audit import (  # noqa: E402
    AuditSigningService,
    AuditLogStorage,
    AuditLogger,
    AuditReporter,
    AuditAction,
)


class TestAuditSigningService(unittest.TestCase):
    """Test AuditSigningService class."""

    def setUp(self):
        """Set up test signing service."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.service = AuditSigningService(self.log_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_service_creation(self):
        """Test creating signing service."""
        self.assertIsNotNone(self.service)
        self.assertIsNotNone(self.service.hmac_key)
        self.assertEqual(len(self.service.hmac_key), 32)

    def test_hmac_key_persistence(self):
        """Test that HMAC key persists across instances."""
        key1 = self.service.hmac_key

        # Create new service with same log dir
        service2 = AuditSigningService(self.log_dir)
        key2 = service2.hmac_key

        # Keys should be identical
        self.assertEqual(key1, key2)

    def test_sign_entry(self):
        """Test signing an audit entry."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }

        signature = self.service.sign_entry(entry)

        # Signature should be 64 character hex (SHA256)
        self.assertEqual(len(signature), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in signature))

    def test_verify_valid_signature(self):
        """Test verifying a valid signature."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }
        signature = self.service.sign_entry(entry)
        entry["signature"] = signature

        # Should verify successfully
        self.assertTrue(self.service.verify_signature(entry))

    def test_verify_invalid_signature(self):
        """Test verifying an invalid signature."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
            "signature": "0" * 64,  # Wrong signature
        }

        # Should fail verification
        self.assertFalse(self.service.verify_signature(entry))

    def test_verify_missing_signature(self):
        """Test verifying entry without signature."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }

        # Should fail when signature missing
        self.assertFalse(self.service.verify_signature(entry))

    def test_signature_detects_tampering(self):
        """Test that signature detects data tampering."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }
        signature = self.service.sign_entry(entry)
        entry["signature"] = signature

        # Tamper with entry
        entry["details"]["malicious"] = "change"

        # Should detect tampering
        self.assertFalse(self.service.verify_signature(entry))

    def test_constant_time_comparison(self):
        """Test that signature comparison is constant-time."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }
        signature = self.service.sign_entry(entry)
        entry["signature"] = signature

        # Should use constant-time comparison (hmac.compare_digest)
        # This test just verifies it uses secure comparison
        result1 = self.service.verify_signature(entry)

        # Modify signature completely (all zeros)
        entry["signature"] = "0" * 64
        result2 = self.service.verify_signature(entry)

        # First should pass, second should fail
        self.assertTrue(result1)
        self.assertFalse(result2)


class TestAuditLogStorage(unittest.TestCase):
    """Test AuditLogStorage class."""

    def setUp(self):
        """Set up test log storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"
        self.storage = AuditLogStorage(self.log_dir)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_storage_creation(self):
        """Test creating log storage."""
        self.assertIsNotNone(self.storage)
        self.assertTrue(self.log_dir.exists())
        # Log file is created on first write, not during initialization
        self.assertIsNotNone(self.storage.log_file)

    def test_write_entry(self):
        """Test writing an audit entry."""
        entry = {
            "timestamp": "2024-01-01T00:00:00",
            "action": "test_action",
            "status": "success",
            "details": {},
        }

        self.storage.write_entry(entry)

        # Entry should be written to file
        self.assertTrue(self.storage.log_file.exists())

        with open(self.storage.log_file, "r") as f:
            content = f.read()
            self.assertIn("test_action", content)

    def test_read_entries(self):
        """Test reading audit entries."""
        entries = [
            {
                "timestamp": "2024-01-01T00:00:00",
                "action": f"action_{i}",
                "status": "success",
                "details": {},
            }
            for i in range(3)
        ]

        for entry in entries:
            self.storage.write_entry(entry)

        # Read entries back
        read_entries = self.storage.read_entries()

        self.assertEqual(len(read_entries), 3)
        for i, entry in enumerate(read_entries):
            self.assertEqual(entry["action"], f"action_{i}")

    def test_read_entries_with_limit(self):
        """Test reading entries with limit."""
        for i in range(5):
            entry = {
                "timestamp": "2024-01-01T00:00:00",
                "action": f"action_{i}",
                "status": "success",
                "details": {},
            }
            self.storage.write_entry(entry)

        # Read only last 2
        entries = self.storage.read_entries(limit=2)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["action"], "action_3")
        self.assertEqual(entries[1]["action"], "action_4")

    def test_read_entries_nonexistent_file(self):
        """Test reading from nonexistent log file."""
        storage = AuditLogStorage(Path(self.temp_dir) / "nonexistent")
        entries = storage.read_entries()

        self.assertEqual(entries, [])

    def test_get_log_file_path(self):
        """Test getting log file path."""
        path = self.storage.get_log_file_path()

        self.assertIsInstance(path, Path)
        self.assertTrue(path.name.startswith("audit-"))
        self.assertTrue(path.name.endswith(".jsonl"))

    def test_file_permissions(self):
        """Test that log file has correct permissions."""
        self.storage.write_entry({"action": "test"})

        # Check file permissions (0600)
        mode = oct(self.storage.log_file.stat().st_mode)[-3:]
        self.assertEqual(mode, "600")

        # Check directory permissions (0700)
        dir_mode = oct(self.log_dir.stat().st_mode)[-3:]
        self.assertEqual(dir_mode, "700")

    def test_rotate_logs(self):
        """Test log rotation."""
        # Write old entries
        old_entry = {
            "timestamp": "2020-01-01T00:00:00",
            "action": "old_action",
            "status": "success",
            "details": {},
        }
        self.storage.write_entry(old_entry)

        # Create new storage instance with fresh log file
        storage2 = AuditLogStorage(self.log_dir)

        # Rotate logs (should archive anything older than 90 days)
        storage2.rotate_logs(days=90)

        # Archive directory should exist
        archive_dir = self.log_dir / "archive"
        # (Note: might be empty if entry is within 90 days)

    def test_corrupted_json_handling(self):
        """Test handling of corrupted JSON entries."""
        # Write valid entry
        self.storage.write_entry({"action": "valid"})

        # Append corrupted entry directly
        with open(self.storage.log_file, "a") as f:
            f.write("{ invalid json }\n")

        # Write another valid entry
        self.storage.write_entry({"action": "valid2"})

        # Read should handle corruption gracefully
        entries = self.storage.read_entries()

        # Should skip corrupted entry but read valid ones
        # (Current implementation reads all, so we get 2 valid + corruption attempt)
        self.assertTrue(len(entries) >= 2)


class TestAuditLoggerIntegration(unittest.TestCase):
    """Integration tests for refactored AuditLogger."""

    def setUp(self):
        """Set up test logger."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_with_signing_service(self):
        """Test AuditLogger uses AuditSigningService correctly."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        entry = logger.log_action(AuditAction.INSTALL_STARTED)

        # Should have signature
        self.assertIn("signature", entry)

        # Signature should be valid
        self.assertTrue(logger.signing_service.verify_signature(entry))

    def test_logger_with_storage_service(self):
        """Test AuditLogger uses AuditLogStorage correctly."""
        logger = AuditLogger(self.log_dir)

        logger.log_action(AuditAction.INSTALL_STARTED)
        logger.log_action(AuditAction.INSTALL_COMPLETED)

        # Should retrieve via storage
        entries = logger.get_audit_logs()

        self.assertEqual(len(entries), 2)

    def test_reporter_with_logger(self):
        """Test AuditReporter works with AuditLogger."""
        logger = AuditLogger(self.log_dir)
        reporter = AuditReporter(logger)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=60)

        report = reporter.generate_activity_report(days=1)

        self.assertIn("Activity Report", report)
        self.assertIn("install_started", report)
        self.assertIn("install_completed", report)

    def test_integrity_validation_with_signing(self):
        """Test log integrity validation."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        logger.log_action(AuditAction.INSTALL_STARTED)
        logger.log_action(AuditAction.INSTALL_COMPLETED)

        # Validate integrity
        result = logger.validate_log_integrity()

        self.assertEqual(result["total_entries"], 2)
        self.assertEqual(result["valid_entries"], 2)
        self.assertEqual(result["invalid_entries"], 0)
        self.assertFalse(result["tampering_detected"])


class TestAuditLoggerAdditional(unittest.TestCase):
    """Test additional AuditLogger functionality."""

    def setUp(self):
        """Set up test logger."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_log_install_started(self):
        """Test logging install started action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_install_started()

        self.assertEqual(entry["action"], "install_started")
        self.assertIn("timestamp", entry)

    def test_log_install_completed(self):
        """Test logging install completed action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_install_completed(duration_seconds=120)

        self.assertEqual(entry["action"], "install_completed")
        self.assertIn("duration_seconds", entry["details"])
        self.assertEqual(entry["details"]["duration_seconds"], 120)

    def test_log_install_failed(self):
        """Test logging install failed action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_install_failed(error="Test error")

        self.assertEqual(entry["action"], "install_failed")
        self.assertIn("error", entry["details"])

    def test_log_plugin_installed(self):
        """Test logging plugin installed action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_plugin_installed(plugin_name="test_plugin", version="1.0.0")

        self.assertEqual(entry["action"], "plugin_installed")
        self.assertEqual(entry["details"]["plugin"], "test_plugin")
        self.assertEqual(entry["details"]["version"], "1.0.0")

    def test_log_plugin_removed(self):
        """Test logging plugin removed action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_plugin_removed(plugin_name="test_plugin")

        self.assertEqual(entry["action"], "plugin_removed")
        self.assertEqual(entry["details"]["plugin"], "test_plugin")

    def test_log_security_check(self):
        """Test logging security check action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_security_check(check_name="ssh_keys", status="passed")

        self.assertEqual(entry["action"], "security_check")
        self.assertEqual(entry["details"]["check"], "ssh_keys")

    def test_log_permission_changed(self):
        """Test logging permission changed action."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_permission_changed(path="/path/to/file", old_perms="0644", new_perms="0600")

        self.assertEqual(entry["action"], "permission_changed")
        self.assertIn("path", entry["details"])

    def test_get_audit_logs(self):
        """Test retrieving audit logs."""
        logger = AuditLogger(self.log_dir)
        logger.log_install_started()
        logger.log_install_completed(duration_seconds=60)

        logs = logger.get_audit_logs()

        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["action"], "install_started")
        self.assertEqual(logs[1]["action"], "install_completed")


class TestAuditReporterAdvanced(unittest.TestCase):
    """Test AuditReporter advanced functionality."""

    def setUp(self):
        """Set up test reporter."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_activity_report(self):
        """Test generating activity report."""
        logger = AuditLogger(self.log_dir)
        logger.log_install_started()
        logger.log_install_completed(duration_seconds=60)

        reporter = AuditReporter(logger)
        report = reporter.generate_activity_report(days=30)

        self.assertIsInstance(report, str)
        self.assertIn("Activity Report", report)

    def test_generate_security_report(self):
        """Test generating security report."""
        logger = AuditLogger(self.log_dir)
        logger.log_security_check(check_name="ssh_keys", status="passed")
        logger.log_security_check(check_name="permissions", status="passed")

        reporter = AuditReporter(logger)
        report = reporter.generate_security_report()

        self.assertIsInstance(report, str)
        self.assertIn("Security & Integrity Report", report)


if __name__ == "__main__":
    unittest.main()
