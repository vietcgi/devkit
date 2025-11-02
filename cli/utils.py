#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
"""Shared utilities for Devkit CLI.

Provides common functionality used across multiple modules:
- ANSI color codes for terminal output
- Logger setup and configuration
- Shared constants and enumerations
"""

import logging
import subprocess
from typing import ClassVar

# ============================================================================
# ANSI COLOR CODES
# ============================================================================


class Colors:  # pylint: disable=too-few-public-methods
    """ANSI color codes for terminal output.

    Provides a centralized definition of color codes used throughout the CLI
    for consistent terminal styling and better maintainability.

    Examples:
        >>> from cli.utils import Colors
        >>> print(f"{Colors.SUCCESS}Installation complete{Colors.RESET}")
        >>> print(f"{Colors.ERROR}Error occurred{Colors.RESET}")
        >>> print(f"{Colors.WARNING}Please review this{Colors.RESET}")
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Styles (combinations of color + bold)
    SUCCESS = f"{GREEN}{BOLD}"
    ERROR = f"{RED}{BOLD}"
    WARNING = f"{YELLOW}{BOLD}"
    INFO = f"{BLUE}{BOLD}"
    PROMPT = f"{CYAN}{BOLD}"


# ============================================================================
# LOGGER SETUP
# ============================================================================


def setup_logger(
    name: str,
    level: int = logging.INFO,
    format_string: str | None = None,
) -> logging.Logger:
    r"""Set up a logger with consistent formatting.

    Creates a logger with the specified name and configuration. Uses a
    standard format that includes log level and message. Only adds handlers
    if the logger doesn't already have them (prevents duplicate logging).

    Args:
        name: Logger name (typically module name or component name)
        level: Logging level (default: INFO)
        format_string: Custom format string (default: "%(levelname)s: %(message)s")

    Returns:
        Configured logger instance ready for use

    Examples:
        >>> logger = setup_logger("my_module")
        >>> logger.info("Starting process")
        >>> logger.error("An error occurred")
        >>>\n        >>> # Custom format
        >>> logger = setup_logger(
        ...     "app",
        ...     format_string="[%(name)s] %(levelname)s: %(message)s"
        ... )
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            format_string or "%(levelname)s: %(message)s",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)

    return logger


# ============================================================================
# SUBPROCESS EXECUTION
# ============================================================================


def run_command(
    cmd: list[str],
    timeout: int = 10,
    *,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a command with unified error handling.

    Executes a subprocess command with consistent configuration across the
    codebase. Handles timeouts and OS errors consistently.

    Args:
        cmd: Command and arguments as list (e.g., ["git", "config", "--list"])
        timeout: Command timeout in seconds (default: 10)
        text: Return stdout/stderr as strings (default: True)
        check: Raise CalledProcessError if returncode != 0 (default: False)

    Returns:
        CompletedProcess with returncode, stdout, stderr

    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout
        OSError: If command execution fails (e.g., command not found)

    Examples:
        >>> result = run_command(["git", "status"])
        >>> if not result.returncode:
        ...     print("Success:", result.stdout)
        >>> result = run_command(["python3", "-m", "pytest"], timeout=60)
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
            check=check,
            shell=False,
        )
    except FileNotFoundError as e:
        msg = f"Command not found: {cmd[0]}"
        raise OSError(msg) from e


# ============================================================================
# SHARED CONSTANTS
# ============================================================================


class ConfigEnvironments:  # pylint: disable=too-few-public-methods
    """Valid configuration environments."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    ALL: ClassVar[list[str]] = [DEVELOPMENT, STAGING, PRODUCTION]


class LogLevels:  # pylint: disable=too-few-public-methods
    """Valid logging levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    ALL: ClassVar[list[str]] = [DEBUG, INFO, WARNING, ERROR, CRITICAL]


class PluginPermissions:  # pylint: disable=too-few-public-methods
    """Valid plugin permission levels."""

    RESTRICTED = "restricted"
    STANDARD = "standard"
    ELEVATED = "elevated"

    ALL: ClassVar[list[str]] = [RESTRICTED, STANDARD, ELEVATED]


class FilePermissions:  # pylint: disable=too-few-public-methods
    """Standard file permission modes."""

    PRIVATE_FILE = 0o600  # Owner read/write only
    PRIVATE_DIR = 0o700  # Owner rwx only
    SHARED_FILE = 0o644  # Owner rw, others r
    SHARED_DIR = 0o755  # Owner rwx, others rx


# ============================================================================
# VALIDATOR BASE CLASS
# ============================================================================


class ValidatorBase:  # pylint: disable=too-few-public-methods
    """Base class for validators with common status printing."""

    logger: logging.Logger

    def print_status(self, message: str, level: str = "INFO") -> None:
        """Print colored status message.

        Args:
            message: Status message
            level: Log level (INFO, SUCCESS, WARNING, ERROR)
        """
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
        }
        symbol = {
            "INFO": "[i]",
            "SUCCESS": "[✓]",
            "WARNING": "[!]",
            "ERROR": "[E]",
        }
        color = colors.get(level, Colors.RESET)
        _symbol = symbol.get(level, "•")

        self.logger.log(
            getattr(logging, level, logging.INFO),
            message.replace(Colors.RESET, "").replace(color, ""),
        )


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "Colors",
    "ConfigEnvironments",
    "FilePermissions",
    "LogLevels",
    "PluginPermissions",
    "ValidatorBase",
    "run_command",
    "setup_logger",
]
