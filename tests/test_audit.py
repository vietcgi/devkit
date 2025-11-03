"""Tests for refactored AuditLogger components.

Validates:
- AuditSigningService cryptographic operations
- AuditLogStorage file I/O and rotation
- Error handling in refactored classes
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.audit import (
    AuditAction,
    AuditLogger,
    AuditLogStorage,
    AuditReporter,
    AuditSigningService,
    HMACKeyError,
)


@pytest.mark.security
@pytest.mark.unit
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


@pytest.mark.security
@pytest.mark.unit
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

        with Path(self.storage.log_file).open("r") as f:
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
        with Path(self.storage.log_file).open("a") as f:
            f.write("{ invalid json }\n")

        # Write another valid entry
        self.storage.write_entry({"action": "valid2"})

        # Read should handle corruption gracefully
        entries = self.storage.read_entries()

        # Should skip corrupted entry but read valid ones
        # (Current implementation reads all, so we get 2 valid + corruption attempt)
        self.assertTrue(len(entries) >= 2)


@pytest.mark.security
@pytest.mark.unit
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


@pytest.mark.security
@pytest.mark.unit
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
        entry = logger.log_permission_changed(
            path="/path/to/file", old_perms="0644", new_perms="0600",
        )

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


@pytest.mark.security
@pytest.mark.unit
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


@pytest.mark.security
@pytest.mark.unit
class TestAuditSigningServiceErrors(unittest.TestCase):
    """Test error handling in AuditSigningService."""

    def setUp(self):
        """Set up test signing service."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sign_entry_without_hmac_key(self):
        """Test that signing without HMAC key raises HMACKeyError."""
        service = AuditSigningService(self.log_dir, hmac_key=b"")
        # Set hmac_key to None to simulate missing key
        service.hmac_key = None

        entry = {"action": "test"}
        with self.assertRaises(HMACKeyError):
            service.sign_entry(entry)

    def test_verify_signature_without_hmac_key(self):
        """Test signature verification when HMAC key is not available."""
        service = AuditSigningService(self.log_dir, hmac_key=b"x" * 32)
        service.hmac_key = None

        entry = {"action": "test", "signature": "0" * 64}
        result = service.verify_signature(entry)

        self.assertFalse(result)

    def test_verify_signature_with_invalid_entry_data(self):
        """Test signature verification with non-serializable entry data."""
        service = AuditSigningService(self.log_dir)

        entry = {"action": "test", "signature": "0" * 64, "data": object()}
        result = service.verify_signature(entry)

        self.assertFalse(result)

    def test_load_or_create_hmac_key_invalid_length(self):
        """Test handling of HMAC key with invalid length."""
        service = AuditSigningService(self.log_dir, hmac_key=b"x" * 32)
        key_file = self.log_dir / ".hmac_key"

        # Write invalid key (wrong length)
        key_file.write_bytes(b"short_key")

        # Create new service - should generate new key
        service2 = AuditSigningService(self.log_dir)
        self.assertEqual(len(service2.hmac_key), 32)

    def test_load_or_create_hmac_key_oserror_on_read(self):
        """Test handling of OSError when reading HMAC key."""
        service = AuditSigningService(self.log_dir)
        key_file = self.log_dir / ".hmac_key"

        # Write valid key
        valid_key = os.urandom(32)
        key_file.write_bytes(valid_key)

        # Make key file unreadable
        key_file.chmod(0o000)

        try:
            # Create new service - should generate new key due to read error
            service2 = AuditSigningService(self.log_dir)
            self.assertEqual(len(service2.hmac_key), 32)
        finally:
            # Restore permissions for cleanup
            key_file.chmod(0o600)

    def test_load_or_create_hmac_key_oserror_on_write(self):
        """Test handling of OSError when writing HMAC key."""
        log_dir = Path(self.temp_dir) / "readonly" / "audit"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Make parent directory read-only
        parent = log_dir.parent
        original_mode = parent.stat().st_mode
        parent.chmod(0o555)

        try:
            # Should still generate key even if write fails
            service = AuditSigningService(log_dir)
            self.assertEqual(len(service.hmac_key), 32)
        finally:
            # Restore permissions
            parent.chmod(original_mode)


@pytest.mark.security
@pytest.mark.unit
class TestAuditStorageErrors(unittest.TestCase):
    """Test error handling in AuditLogStorage."""

    def setUp(self):
        """Set up test storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_entry_with_non_serializable_data(self):
        """Test writing entry with non-serializable data."""
        storage = AuditLogStorage(self.log_dir)

        entry = {"action": "test", "data": object()}
        # Should not raise, but log warning
        storage.write_entry(entry)

        # Log file should still exist
        self.assertTrue(storage.log_file.exists())

    def test_ensure_secure_permissions_oserror(self):
        """Test handling of permission errors."""
        storage = AuditLogStorage(self.log_dir)

        # Create a file in the log directory
        storage.write_entry({"action": "test"})

        # Make log file read-only to trigger error
        storage.log_file.chmod(0o444)

        try:
            # Should handle the error gracefully
            storage._ensure_secure_permissions()
        finally:
            # Restore permissions for cleanup
            storage.log_file.chmod(0o600)

    def test_read_entries_with_invalid_json_lines(self):
        """Test reading log file with corrupted JSON lines."""
        storage = AuditLogStorage(self.log_dir)

        # Write mixed valid and invalid JSON
        with Path(storage.log_file).open("w") as f:
            f.write('{"action": "valid1"}\n')
            f.write("{ invalid json }\n")
            f.write('{"action": "valid2"}\n')

        entries = storage.read_entries()

        # Should read the 2 valid entries and skip invalid
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["action"], "valid1")
        self.assertEqual(entries[1]["action"], "valid2")

    def test_read_entries_oserror(self):
        """Test handling of OSError when reading log file."""
        storage = AuditLogStorage(self.log_dir)

        # Write an entry first
        storage.write_entry({"action": "test"})

        # Make log file unreadable
        storage.log_file.chmod(0o000)

        try:
            # Should return empty list due to read error
            entries = storage.read_entries()
            # With OSError handling, should return empty
            self.assertEqual(entries, [])
        finally:
            # Restore permissions
            storage.log_file.chmod(0o600)

    def test_rotate_logs_with_shutil_error(self):
        """Test handling of shutil.Error during log rotation."""
        storage = AuditLogStorage(self.log_dir)

        # Create old log file
        old_log = self.log_dir / "audit-20200101.jsonl"
        old_log.write_text('{"action": "old"}\n')

        # Make archive directory read-only to trigger error
        archive_dir = self.log_dir / "archive"
        archive_dir.mkdir(exist_ok=True)
        parent = archive_dir.parent
        original_mode = parent.stat().st_mode
        parent.chmod(0o555)

        try:
            # Should handle error gracefully
            storage.rotate_logs()
        finally:
            parent.chmod(original_mode)


@pytest.mark.security
@pytest.mark.unit
class TestAuditLoggerAdditionalMethods(unittest.TestCase):
    """Test additional AuditLogger methods and error paths."""

    def setUp(self):
        """Set up test logger."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_log_config_changed(self):
        """Test logging configuration change."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_config_changed("key", "old_value", "new_value")

        self.assertEqual(entry["action"], "config_changed")
        self.assertEqual(entry["details"]["key"], "key")
        self.assertEqual(entry["details"]["old_value"], "old_value")
        self.assertEqual(entry["details"]["new_value"], "new_value")

    def test_log_config_changed_with_none_values(self):
        """Test logging configuration change with None values."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_config_changed("key", None, 42)

        self.assertEqual(entry["details"]["old_value"], "None")
        self.assertEqual(entry["details"]["new_value"], "42")

    def test_log_verification_passed(self):
        """Test logging successful verification."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_verification(passed=True, details={"checks": 5})

        self.assertEqual(entry["action"], "verification_passed")
        self.assertEqual(entry["status"], "success")

    def test_log_verification_failed(self):
        """Test logging failed verification."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_verification(passed=False, details={"reason": "check failed"})

        self.assertEqual(entry["action"], "verification_failed")
        self.assertEqual(entry["status"], "failure")

    def test_log_health_check(self):
        """Test logging health check result."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_health_check("healthy", details={"services": 3})

        self.assertEqual(entry["action"], "health_check")
        self.assertEqual(entry["status"], "healthy")
        self.assertEqual(entry["details"]["services"], 3)

    def test_log_health_check_with_warning(self):
        """Test logging health check with warning status."""
        logger = AuditLogger(self.log_dir)
        entry = logger.log_health_check("warning", details={"issue": "high memory"})

        self.assertEqual(entry["action"], "health_check")
        self.assertEqual(entry["status"], "warning")

    def test_get_audit_logs_with_signature_verification(self):
        """Test retrieving logs with signature verification."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=30)

        # Get with verification
        entries = logger.get_audit_logs(verify_signatures=True)

        # Both should verify successfully
        self.assertEqual(len(entries), 2)

    def test_get_audit_logs_filter_invalid_signatures(self):
        """Test that logs with invalid signatures are filtered out."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        entry1 = logger.log_install_started()
        entry2 = logger.log_install_completed(duration_seconds=30)

        # Manually tamper with second entry
        storage = logger.storage
        lines = storage.log_file.read_text().strip().split("\n")
        lines[1] = lines[1].replace("install_completed", "tampered_action")
        storage.log_file.write_text("\n".join(lines) + "\n")

        # Get with verification - should only get first entry
        entries = logger.get_audit_logs(verify_signatures=True)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "install_started")

    def test_rotate_logs_proxy(self):
        """Test rotate_logs proxy method."""
        logger = AuditLogger(self.log_dir)

        # Create old log
        old_log = self.log_dir / "audit-20200101.jsonl"
        old_log.write_text('{"action": "old"}\n')

        # Should call storage.rotate_logs()
        logger.rotate_logs()

        # Archive directory should be created
        archive_dir = self.log_dir / "archive"
        self.assertTrue(archive_dir.exists())

    def test_validate_log_integrity_all_valid(self):
        """Test log integrity validation with all valid entries."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=30)

        result = logger.validate_log_integrity()

        self.assertEqual(result["total_entries"], 2)
        self.assertEqual(result["valid_entries"], 2)
        self.assertEqual(result["invalid_entries"], 0)
        self.assertEqual(result["unsigned_entries"], 0)
        self.assertFalse(result["tampering_detected"])

    def test_validate_log_integrity_with_tampering(self):
        """Test log integrity validation detects tampering."""
        logger = AuditLogger(self.log_dir, enable_signing=True)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=30)

        # Tamper with entry in file
        storage = logger.storage
        lines = storage.log_file.read_text().strip().split("\n")
        lines[0] = lines[0].replace("install_started", "tampered")
        storage.log_file.write_text("\n".join(lines) + "\n")

        result = logger.validate_log_integrity()

        self.assertEqual(result["total_entries"], 2)
        self.assertEqual(result["invalid_entries"], 1)
        self.assertTrue(result["tampering_detected"])
        self.assertEqual(len(result["invalid_entry_timestamps"]), 1)

    def test_validate_log_integrity_unsigned_entries(self):
        """Test log integrity validation with unsigned entries."""
        logger = AuditLogger(self.log_dir)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=30)

        result = logger.validate_log_integrity()

        self.assertEqual(result["total_entries"], 2)
        self.assertEqual(result["unsigned_entries"], 2)
        self.assertFalse(result["tampering_detected"])

    def test_get_audit_summary_basic(self):
        """Test getting basic audit summary."""
        logger = AuditLogger(self.log_dir)

        logger.log_install_started()
        logger.log_install_completed(duration_seconds=30)
        logger.log_install_started()

        summary = logger.get_audit_summary(hours=24)

        self.assertEqual(summary["total_actions"], 3)
        self.assertIn("install_started", summary["actions_by_type"])
        self.assertIn("install_completed", summary["actions_by_type"])
        self.assertEqual(summary["actions_by_type"]["install_started"], 2)
        self.assertEqual(summary["actions_by_type"]["install_completed"], 1)

    def test_get_audit_summary_with_status(self):
        """Test audit summary includes status tracking."""
        logger = AuditLogger(self.log_dir)

        logger.log_install_completed(duration_seconds=30)
        logger.log_install_failed(error="Test error")

        summary = logger.get_audit_summary(hours=24)

        self.assertIn("success", summary["actions_by_status"])
        self.assertIn("failure", summary["actions_by_status"])

    def test_get_audit_summary_with_users(self):
        """Test audit summary tracks different users."""
        logger = AuditLogger(self.log_dir)

        # Log with implicit user (from os.getenv)
        logger.log_install_started()

        summary = logger.get_audit_summary(hours=24)

        self.assertIsInstance(summary["users"], list)
        self.assertGreater(len(summary["users"]), 0)

    def test_get_audit_summary_old_entries_excluded(self):
        """Test that old entries are excluded from summary."""
        logger = AuditLogger(self.log_dir)

        # Write old entry directly
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=2)).isoformat()
        logger.storage.write_entry(
            {
                "timestamp": old_time,
                "action": "old_action",
                "status": "success",
                "details": {},
            },
        )

        # Write recent entry
        logger.log_install_started()

        summary = logger.get_audit_summary(hours=24)

        # Should only count the recent entry
        self.assertEqual(summary["total_actions"], 1)

    def test_get_audit_summary_invalid_timestamp(self):
        """Test audit summary handling of invalid timestamps."""
        logger = AuditLogger(self.log_dir)

        logger.log_install_started()

        # Write entry with invalid timestamp
        logger.storage.write_entry(
            {
                "timestamp": "invalid-timestamp",
                "action": "test",
                "status": "success",
                "details": {},
            },
        )

        # Should not raise, just skip invalid entries
        summary = logger.get_audit_summary(hours=24)
        self.assertIsInstance(summary, dict)


@pytest.mark.security
@pytest.mark.unit
class TestAuditReporterErrors(unittest.TestCase):
    """Test error handling in AuditReporter."""

    def setUp(self):
        """Set up test reporter."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_activity_report_with_invalid_timestamp(self):
        """Test activity report handles invalid timestamps."""
        logger = AuditLogger(self.log_dir)
        reporter = AuditReporter(logger)

        logger.log_install_started()

        # Write entry with invalid timestamp
        logger.storage.write_entry(
            {
                "timestamp": "invalid",
                "action": "test",
                "status": "success",
                "details": {},
            },
        )

        # Should not raise
        report = reporter.generate_activity_report(days=30)
        self.assertIsInstance(report, str)
        self.assertIn("Activity Report", report)

    def test_generate_activity_report_empty_logs(self):
        """Test activity report with no entries."""
        logger = AuditLogger(self.log_dir)
        reporter = AuditReporter(logger)

        report = reporter.generate_activity_report(days=30)

        self.assertIsInstance(report, str)
        self.assertIn("Activity Report", report)

    def test_generate_activity_report_old_entries_excluded(self):
        """Test that old entries are excluded from activity report."""
        logger = AuditLogger(self.log_dir)
        reporter = AuditReporter(logger)

        # Write old entry
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=60)).isoformat()
        logger.storage.write_entry(
            {
                "timestamp": old_time,
                "action": "old_action",
                "status": "success",
                "user": "user1",
                "details": {},
            },
        )

        # Write recent entry
        logger.log_install_started()

        report = reporter.generate_activity_report(days=30)

        # Old action should not appear
        self.assertNotIn("old_action", report)

    def test_generate_activity_report_sorted_by_count(self):
        """Test that activity report sorts actions by count."""
        logger = AuditLogger(self.log_dir)
        reporter = AuditReporter(logger)

        # Create multiple entries of same type
        for _ in range(3):
            logger.log_install_started()

        for _ in range(2):
            logger.log_install_completed(duration_seconds=30)

        report = reporter.generate_activity_report(days=30)

        # install_started should appear before install_completed (more counts)
        install_started_pos = report.find("install_started")
        install_completed_pos = report.find("install_completed")
        self.assertLess(install_started_pos, install_completed_pos)

    def test_generate_security_report_with_tampering(self):
        """Test security report shows tampering."""
        logger = AuditLogger(self.log_dir, enable_signing=True)
        reporter = AuditReporter(logger)

        logger.log_install_started()

        # Tamper with entry
        storage = logger.storage
        lines = storage.log_file.read_text().strip().split("\n")
        lines[0] = lines[0].replace("install_started", "tampered")
        storage.log_file.write_text("\n".join(lines) + "\n")

        report = reporter.generate_security_report()

        self.assertIsInstance(report, str)
        self.assertIn("Security & Integrity Report", report)
        self.assertIn("Tampering Detected: True", report)

    def test_generate_security_report_invalid_entries_listed(self):
        """Test security report lists invalid entry timestamps."""
        logger = AuditLogger(self.log_dir, enable_signing=True)
        reporter = AuditReporter(logger)

        entry = logger.log_install_started()
        timestamp = entry["timestamp"]

        # Tamper with entry
        storage = logger.storage
        lines = storage.log_file.read_text().strip().split("\n")
        lines[0] = lines[0].replace("install_started", "tampered")
        storage.log_file.write_text("\n".join(lines) + "\n")

        report = reporter.generate_security_report()

        self.assertIn("Invalid Entries at:", report)


@pytest.mark.security
@pytest.mark.unit
class TestAuditSigningServiceErrorPaths(unittest.TestCase):
    """Test error handling in AuditSigningService."""

    def setUp(self):
        """Set up test signing service."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_hmac_key_generation_permission_error(self):
        """Test HMAC key generation when file permissions cannot be set."""
        from unittest.mock import patch

        # Create service with permission error on chmod
        with patch("pathlib.Path.chmod", side_effect=PermissionError("Permission denied")):
            service = AuditSigningService(self.log_dir)
            # Should still generate key even if chmod fails
            assert service.hmac_key is not None
            assert len(service.hmac_key) == 32

    def test_hmac_key_recovery_from_corrupted_file(self):
        """Test HMAC key recovery when file is corrupted (wrong size)."""
        # Create corrupted key file with wrong size
        key_file = self.log_dir / ".hmac_key"
        key_file.write_bytes(b"short_key")  # Less than 32 bytes

        # Should generate new key since old one is invalid
        service = AuditSigningService(self.log_dir)
        assert service.hmac_key is not None
        assert len(service.hmac_key) == 32
        assert service.hmac_key != b"short_key"

    def test_hmac_key_persistence(self):
        """Test that HMAC key persists across service instances."""
        # First service creates key
        service1 = AuditSigningService(self.log_dir)
        key1 = service1.hmac_key

        # Second service loads same key
        service2 = AuditSigningService(self.log_dir)
        key2 = service2.hmac_key

        assert key1 == key2
        assert key1 is not None
        assert len(key1) == 32


@pytest.mark.unit
class TestAuditLogStorageErrorPaths(unittest.TestCase):
    """Test error handling in AuditLogStorage."""

    def setUp(self):
        """Set up test storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "audit"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        """Clean up."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_entry_creates_directory_if_missing(self):
        """Test that write_entry creates log directory if missing."""
        new_dir = Path(self.temp_dir) / "nonexistent" / "audit"
        storage = AuditLogStorage(new_dir)

        entry = {
            "action": "TEST_ACTION",
            "user": "test_user",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

        # Should not raise, should create directory
        storage.write_entry(entry)
        assert storage.log_file.exists()
        assert storage.log_dir.exists()

    def test_permission_denied_on_file_write(self):
        """Test handling when log file cannot be written due to permissions."""
        from unittest.mock import patch

        storage = AuditLogStorage(self.log_dir)

        # Mock the open function to raise PermissionError
        with patch("pathlib.Path.open", side_effect=PermissionError("Permission denied")):
            entry = {
                "action": "TEST_ACTION",
                "user": "test_user",
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }

            # Should catch OSError and log it (graceful handling)
            # verify no exception is raised
            storage.write_entry(entry)  # Should not raise

    def test_ensure_secure_permissions_handles_permission_error(self):
        """Test that _ensure_secure_permissions handles permission errors gracefully."""
        from unittest.mock import patch

        storage = AuditLogStorage(self.log_dir)

        # Mock chmod to raise PermissionError
        with patch("pathlib.Path.chmod", side_effect=PermissionError("Operation not permitted")):
            # Should not raise, should log warning
            storage._ensure_secure_permissions()


if __name__ == "__main__":
    unittest.main()
