# Copyright (c) 2025 devkit contributors
# Licensed under the Apache License, Version 2.0

"""Unit tests for the structured logging module.

Tests cover:
- JSON formatter output and structure
- Colored formatter output
- Logger configuration and setup
- File handler rotation
- Context logging
"""

import json
import logging as log
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from cli.log import ColoredFormatter, JSONFormatter, get_logger, log_context, setup_logging


class TestJSONFormatter:
    """Test JSON formatted log output."""

    def test_json_formatter_basic_log(self) -> None:
        """Test basic log record formatting as JSON."""
        formatter = JSONFormatter()
        record = log.LogRecord(
            name="test_logger",
            level=log.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["module"] == "test_logger"
        assert data["line"] == 42
        assert "timestamp" in data
        # ISO format with timezone
        assert "T" in data["timestamp"]
        assert "+00:00" in data["timestamp"] or "Z" in data["timestamp"]

    def test_json_formatter_with_exception(self) -> None:
        """Test JSON formatter includes exception information."""
        formatter = JSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
            record = log.LogRecord(
                name="test",
                level=log.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error occurred",
                args=(),
                exc_info=exc_info,
            )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "ERROR"
        assert "exception" in data
        assert "ValueError: Test error" in data["exception"]

    def test_json_formatter_with_extra_data(self) -> None:
        """Test JSON formatter includes extra context data."""
        formatter = JSONFormatter()
        record = log.LogRecord(
            name="test",
            level=log.INFO,
            pathname="test.py",
            lineno=1,
            msg="Context message",
            args=(),
            exc_info=None,
        )
        record.extra_data = {"user": "john", "action": "deploy"}  # type: ignore[attr-defined]

        result = formatter.format(record)
        data = json.loads(result)

        assert data["extra"] == {"user": "john", "action": "deploy"}

    def test_json_formatter_handles_complex_args(self) -> None:
        """Test JSON formatter with message formatting arguments."""
        formatter = JSONFormatter()
        record = log.LogRecord(
            name="test",
            level=log.INFO,
            pathname="test.py",
            lineno=1,
            msg="User %s performed %s",
            args=("alice", "login"),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["message"] == "User alice performed login"


class TestColoredFormatter:
    """Test colored log formatter."""

    def test_colored_formatter_info_level(self) -> None:
        """Test info level has correct color code."""
        formatter = ColoredFormatter()
        record = log.LogRecord(
            name="test",
            level=log.INFO,
            pathname="test.py",
            lineno=1,
            msg="Info message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "\033[32m" in result  # Green color for INFO
        assert "Info message" in result
        assert "test" in result

    def test_colored_formatter_error_level(self) -> None:
        """Test error level has correct color code."""
        formatter = ColoredFormatter()
        record = log.LogRecord(
            name="test",
            level=log.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "\033[31m" in result  # Red color for ERROR
        assert "Error message" in result

    def test_colored_formatter_debug_level(self) -> None:
        """Test debug level has correct color code."""
        formatter = ColoredFormatter()
        record = log.LogRecord(
            name="test",
            level=log.DEBUG,
            pathname="test.py",
            lineno=1,
            msg="Debug message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "\033[36m" in result  # Cyan color for DEBUG
        assert "Debug message" in result

    def test_colored_formatter_reset_code(self) -> None:
        """Test that reset code is present in output."""
        formatter = ColoredFormatter()
        record = log.LogRecord(
            name="test",
            level=log.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "\033[0m" in result  # Reset code

    def test_colored_formatter_with_exception(self) -> None:
        """Test colored formatter includes exception traceback."""
        formatter = ColoredFormatter()

        try:
            raise RuntimeError("Test error")
        except RuntimeError:
            import sys

            exc_info = sys.exc_info()
            record = log.LogRecord(
                name="test",
                level=log.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Error",
                args=(),
                exc_info=exc_info,
            )

        result = formatter.format(record)

        assert "RuntimeError: Test error" in result
        assert "Traceback" in result


class TestSetupLogging:
    """Test logger configuration and setup."""

    def test_setup_logging_creates_logger(self) -> None:
        """Test that setup_logging creates a configured logger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(
                "test_module",
                log_dir=Path(tmpdir),
                file_output=False,
            )

            assert logger.name == "test_module"
            assert logger.level == log.INFO
            assert len(logger.handlers) > 0

    def test_setup_logging_with_custom_level(self) -> None:
        """Test setup_logging respects custom log level."""
        logger = setup_logging(
            "test_module",
            level=log.DEBUG,
            file_output=False,
        )

        assert logger.level == log.DEBUG

    def test_setup_logging_console_handler(self) -> None:
        """Test that console handler is added."""
        logger = setup_logging(
            "test_module",
            file_output=False,
        )

        console_handlers = [h for h in logger.handlers if isinstance(h, log.StreamHandler)]
        assert len(console_handlers) > 0

    def test_setup_logging_with_colored_output(self) -> None:
        """Test setup_logging uses ColoredFormatter by default."""
        logger = setup_logging(
            "test_module",
            json_output=False,
            file_output=False,
        )

        console_handler = [h for h in logger.handlers if isinstance(h, log.StreamHandler)][0]
        assert isinstance(console_handler.formatter, ColoredFormatter)

    def test_setup_logging_with_json_output(self) -> None:
        """Test setup_logging uses JSONFormatter when requested."""
        logger = setup_logging(
            "test_json_module",
            json_output=True,
            file_output=False,
        )

        # Check console handler has JSON formatter
        stream_handlers = [h for h in logger.handlers if isinstance(h, log.StreamHandler)]
        assert len(stream_handlers) > 0
        assert isinstance(stream_handlers[0].formatter, JSONFormatter)

    def test_setup_logging_json_output_default_is_false(self) -> None:
        """Test that json_output defaults to False (ColoredFormatter)."""
        logger = setup_logging(
            "test_default_json_false",
            file_output=False,
            # Note: json_output not specified, should default to False
        )

        # Check console handler uses ColoredFormatter by default
        stream_handlers = [h for h in logger.handlers if isinstance(h, log.StreamHandler)]
        assert len(stream_handlers) > 0
        assert isinstance(stream_handlers[0].formatter, ColoredFormatter)
        assert not isinstance(stream_handlers[0].formatter, JSONFormatter)

    def test_setup_logging_with_file_handler(self) -> None:
        """Test that file handler is created when file_output=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            logger = setup_logging(
                "test_file_handler",
                log_dir=log_dir,
                file_output=True,
            )

            file_handlers = [
                h for h in logger.handlers if isinstance(h, log.handlers.RotatingFileHandler)
            ]
            assert len(file_handlers) >= 1, f"Found handlers: {logger.handlers}"
            assert "test_file_handler.log" in file_handlers[0].baseFilename

    def test_setup_logging_creates_log_directory(self) -> None:
        """Test that log directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "nested" / "logs"
            assert not log_dir.exists()

            logger = setup_logging(
                "test_nested_dir",
                log_dir=log_dir,
                file_output=True,
            )

            # Directory should be created
            assert log_dir.exists(), f"Log dir {log_dir} was not created"
            # And should have a log file
            log_file = log_dir / "test_nested_dir.log"
            assert log_file.exists(), f"Log file {log_file} was not created"

    def test_setup_logging_uses_default_log_dir(self) -> None:
        """Test that default log directory is used when not specified."""
        logger = setup_logging(
            "test_default_dir",
            log_dir=None,
            file_output=True,
        )

        file_handlers = [
            h for h in logger.handlers if isinstance(h, log.handlers.RotatingFileHandler)
        ]
        assert len(file_handlers) >= 1, f"No file handlers found: {logger.handlers}"
        default_path = Path.home() / ".devkit" / "logs"
        # Check that the log file is in the default directory
        log_file_path = Path(file_handlers[0].baseFilename)
        assert (
            default_path == log_file_path.parent
        ), f"Expected {default_path}, got {log_file_path.parent}"

    def test_setup_logging_avoids_duplicate_handlers(self) -> None:
        """Test that calling setup_logging twice doesn't add duplicate handlers."""
        logger = setup_logging(
            "test_module_dup",
            file_output=False,
        )
        handler_count_first = len(logger.handlers)

        logger = setup_logging(
            "test_module_dup",
            file_output=False,
        )
        handler_count_second = len(logger.handlers)

        assert handler_count_first == handler_count_second

    def test_setup_logging_file_rotation_configured(self) -> None:
        """Test that rotating file handler is configured for log rotation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(
                "test_rotation_config",
                log_dir=Path(tmpdir),
                file_output=True,
            )

            file_handlers = [
                h for h in logger.handlers if isinstance(h, log.handlers.RotatingFileHandler)
            ]
            assert len(file_handlers) >= 1, f"No rotation handlers: {logger.handlers}"
            handler = file_handlers[0]
            assert handler.maxBytes == 10 * 1024 * 1024, f"Max bytes: {handler.maxBytes}"
            assert handler.backupCount == 5, f"Backup count: {handler.backupCount}"


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger_returns_logger(self) -> None:
        """Test that get_logger returns a logger instance."""
        logger = get_logger("test_module")

        assert isinstance(logger, log.Logger)
        assert logger.name == "test_module"

    def test_get_logger_same_name_returns_same_logger(self) -> None:
        """Test that same logger name returns same instance."""
        logger1 = get_logger("test_module")
        logger2 = get_logger("test_module")

        assert logger1 is logger2

    def test_get_logger_different_name_returns_different_logger(self) -> None:
        """Test that different logger names return different instances."""
        logger1 = get_logger("test_module_1")
        logger2 = get_logger("test_module_2")

        assert logger1 is not logger2
        assert logger1.name == "test_module_1"
        assert logger2.name == "test_module_2"


class TestLogContext:
    """Test context logging function."""

    def test_log_context_adds_context_data(self) -> None:
        """Test that log_context adds context data to log record."""
        logger = setup_logging("test", file_output=False)

        with mock.patch.object(logger.handlers[0], "emit") as mock_emit:
            log_context(logger, {"user": "john", "action": "deploy"})

            mock_emit.assert_called_once()
            record = mock_emit.call_args[0][0]
            assert record.extra_data == {"user": "john", "action": "deploy"}  # type: ignore[attr-defined]

    def test_log_context_with_empty_data(self) -> None:
        """Test log_context works with empty context data."""
        logger = setup_logging("test", file_output=False)

        with mock.patch.object(logger.handlers[0], "emit") as mock_emit:
            log_context(logger, {})

            mock_emit.assert_called_once()
            record = mock_emit.call_args[0][0]
            assert record.extra_data == {}  # type: ignore[attr-defined]

    def test_log_context_with_complex_data(self) -> None:
        """Test log_context with nested and complex data structures."""
        logger = setup_logging("test", file_output=False)

        context = {
            "user": {"id": 123, "name": "alice"},
            "metrics": [1, 2, 3],
            "nested": {"level": {"deep": "value"}},
        }

        with mock.patch.object(logger.handlers[0], "emit") as mock_emit:
            log_context(logger, context)

            mock_emit.assert_called_once()
            record = mock_emit.call_args[0][0]
            assert record.extra_data == context  # type: ignore[attr-defined]


class TestLoggingIntegration:
    """Integration tests for logging system."""

    def test_json_logging_produces_valid_json(self) -> None:
        """Test that JSON logging produces valid JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            logger = setup_logging(
                "integration_test",
                log_dir=log_dir,
                json_output=False,
                file_output=True,
            )

            logger.info("Test message", extra={"key": "value"})

            log_file = log_dir / "integration_test.log"
            assert log_file.exists()

            with open(log_file) as f:
                lines = f.readlines()
                assert len(lines) > 0
                # Last line should be valid JSON
                data = json.loads(lines[-1])
                assert data["level"] == "INFO"

    def test_logging_to_file_with_rotation(self) -> None:
        """Test that logs are written to file with rotation configured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            logger = setup_logging(
                "rotation_test",
                log_dir=log_dir,
                file_output=True,
            )

            log_file = log_dir / "rotation_test.log"
            assert log_file.exists()

            # Log multiple times
            for i in range(5):
                logger.info(f"Message {i}")

            assert log_file.exists()
            with open(log_file) as f:
                content = f.read()
                assert "Message 0" in content
                assert "Message 4" in content

    def test_colored_and_json_output_compatibility(self) -> None:
        """Test that different formatters can coexist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logging(
                "multi_format",
                log_dir=Path(tmpdir),
                json_output=False,
                file_output=True,
            )

            # Console has colored formatter, file has JSON formatter
            console_handler = [h for h in logger.handlers if isinstance(h, log.StreamHandler)][0]
            file_handler = [
                h for h in logger.handlers if isinstance(h, log.handlers.RotatingFileHandler)
            ][0]

            assert isinstance(console_handler.formatter, ColoredFormatter)
            assert isinstance(file_handler.formatter, JSONFormatter)
