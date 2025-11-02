# Copyright (c) 2025 devkit contributors
# Licensed under the Apache License, Version 2.0

"""Structured logging module for devkit CLI.

Provides production-ready logging with:
- JSON output for machine parsing
- Contextual information (timestamps, levels, modules)
- Color-coded output for terminal
- Log rotation and file persistence
- Configurable log levels and handlers
"""

import json
import logging as log
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Optional


class JSONFormatter(log.Formatter):
    """Format logs as JSON for structured logging."""

    def format(self, record: log.LogRecord) -> str:
        """Format a log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": (
                datetime.fromtimestamp(
                    record.created,
                    tz=UTC,
                ).isoformat()
            ),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data

        return json.dumps(log_data)


class ColoredFormatter(log.Formatter):
    """Format logs with colors for terminal output."""

    COLORS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: log.LogRecord) -> str:
        """Format a log record with colors."""
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).strftime(
            "%H:%M:%S",
        )

        formatted = (
            f"{color}[{timestamp}]{self.RESET} "
            f"{color}[{record.levelname}]{self.RESET} "
            f"{record.name}: {record.getMessage()}"
        )

        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"

        return formatted


def setup_logging(
    name: str,
    *,
    level: int = log.INFO,
    log_dir: Optional[Path] = None,
    json_output: bool = False,
    file_output: bool = True,
) -> log.Logger:
    """Configure logging for the application.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (default: ~/.devkit/logs)
        json_output: Enable JSON output for structured logging
        file_output: Enable file output in addition to console

    Returns:
        Configured logger instance

    Example:
        logger = setup_logging(__name__, level=log.DEBUG)
        logger.info("Application started")
    """
    logger = log.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Console handler (stdout)
    console_handler = log.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if json_output:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ColoredFormatter())

    logger.addHandler(console_handler)

    # File handler (optional)
    if file_output:
        if log_dir is None:
            log_dir = Path.home() / ".devkit" / "logs"

        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{name}.log"

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,  # 10MB per file
        )
        file_handler.setLevel(log.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> log.Logger:
    """Get a logger instance by name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return log.getLogger(name)


def log_context(logger: log.Logger, data: dict[str, Any]) -> None:
    """Log with additional context data.

    Args:
        logger: Logger instance
        data: Additional context to include in log

    Example:
        log_context(logger, {"user": "john", "action": "deploy"})
    """
    record = log.LogRecord(
        name=logger.name,
        level=log.INFO,
        pathname="",
        lineno=0,
        msg="Context",
        args=(),
        exc_info=None,
    )
    record.extra_data = data
    for handler in logger.handlers:
        handler.emit(record)
