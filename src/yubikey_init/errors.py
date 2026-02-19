"""Structured error types with recovery hints for YubiKey initialization.

This module provides a hierarchy of error types that include:
- Error categorization for different failure modes
- Recovery hints that guide users to fix issues
- Error logging capabilities
- Graceful interrupt handling
"""

from __future__ import annotations

import contextlib
import logging
import signal
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from pathlib import Path
from types import FrameType
from typing import NoReturn


class ErrorCategory(Enum):
    """Categories of errors for routing recovery strategies."""

    ENVIRONMENT = auto()  # Missing tools, wrong versions
    HARDWARE = auto()  # YubiKey not found, device errors
    GPG = auto()  # GPG operation failures
    STORAGE = auto()  # Backup drive, file system errors
    USER_INPUT = auto()  # Invalid input, cancelled operations
    STATE = auto()  # Invalid state transitions
    PERMISSION = auto()  # Permission denied, sudo required
    NETWORK = auto()  # Network-related (for future keyserver ops)
    INTERNAL = auto()  # Unexpected errors, bugs


@dataclass
class RecoveryHint:
    """A suggested recovery action for an error."""

    action: str
    command: str | None = None
    documentation_url: str | None = None

    def __str__(self) -> str:
        result = self.action
        if self.command:
            result += f"\n  Command: {self.command}"
        if self.documentation_url:
            result += f"\n  See: {self.documentation_url}"
        return result


@dataclass
class YubiKeyInitError(Exception):
    """Base error type with recovery hints."""

    message: str
    category: ErrorCategory
    recovery_hints: list[RecoveryHint] = field(default_factory=list)
    cause: Exception | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __str__(self) -> str:
        return self.message

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def format_full(self) -> str:
        """Format error with all recovery hints."""
        lines = [f"Error: {self.message}"]

        if self.cause:
            lines.append(f"Caused by: {self.cause}")

        if self.recovery_hints:
            lines.append("\nRecovery options:")
            for i, hint in enumerate(self.recovery_hints, 1):
                lines.append(f"  {i}. {hint}")

        return "\n".join(lines)


# Specific error types with pre-defined recovery hints


class EnvironmentError(YubiKeyInitError):
    """Error related to missing tools or wrong environment."""

    def __init__(
        self,
        message: str,
        missing_tool: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        hints = []
        if missing_tool:
            install_commands = {
                "gpg": RecoveryHint(
                    f"Install {missing_tool}",
                    command="brew install gnupg"
                    if sys.platform == "darwin"
                    else "apt install gnupg2",
                ),
                "ykman": RecoveryHint(
                    f"Install {missing_tool}",
                    command="brew install ykman"
                    if sys.platform == "darwin"
                    else "pip install yubikey-manager",
                ),
                "paperkey": RecoveryHint(
                    f"Install {missing_tool}",
                    command="brew install paperkey"
                    if sys.platform == "darwin"
                    else "apt install paperkey",
                ),
            }
            if missing_tool in install_commands:
                hints.append(install_commands[missing_tool])

        super().__init__(
            message=message,
            category=ErrorCategory.ENVIRONMENT,
            recovery_hints=hints,
            cause=cause,
        )


class HardwareError(YubiKeyInitError):
    """Error related to YubiKey or storage device hardware."""

    def __init__(
        self,
        message: str,
        device_type: str = "YubiKey",
        cause: Exception | None = None,
    ) -> None:
        hints = []
        if device_type == "YubiKey":
            hints.extend(
                [
                    RecoveryHint("Ensure YubiKey is properly inserted"),
                    RecoveryHint("Try a different USB port"),
                    RecoveryHint("Run diagnostics", command="yubikey-init doctor"),
                    RecoveryHint(
                        "Check YubiKey is detected",
                        command="ykman info",
                    ),
                ]
            )
        else:
            hints.extend(
                [
                    RecoveryHint("Ensure device is properly connected"),
                    RecoveryHint("Check device permissions"),
                    RecoveryHint("Try unmounting and reconnecting"),
                ]
            )

        super().__init__(
            message=message,
            category=ErrorCategory.HARDWARE,
            recovery_hints=hints,
            cause=cause,
        )


class GPGOperationError(YubiKeyInitError):
    """Error during GPG operations."""

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        gpg_output: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        hints = []

        # Common GPG error patterns and their fixes
        if gpg_output:
            if "permission denied" in gpg_output.lower():
                hints.append(RecoveryHint("Check GNUPGHOME directory permissions"))
            if "no such file" in gpg_output.lower():
                hints.append(RecoveryHint("Ensure GPG is properly initialized"))
            if "agent" in gpg_output.lower():
                hints.append(
                    RecoveryHint(
                        "Restart GPG agent",
                        command="gpgconf --kill gpg-agent && gpg-agent --daemon",
                    )
                )
            if "card error" in gpg_output.lower():
                hints.append(
                    RecoveryHint(
                        "Reset card connection",
                        command="gpg --card-status",
                    )
                )

        # Add general GPG recovery hints
        hints.append(
            RecoveryHint(
                "Check GPG agent status",
                command="gpg-connect-agent 'getinfo version' /bye",
            )
        )

        super().__init__(
            message=message,
            category=ErrorCategory.GPG,
            recovery_hints=hints,
            cause=cause,
        )
        self.operation = operation
        self.gpg_output = gpg_output


class StorageError(YubiKeyInitError):
    """Error during storage/backup operations."""

    def __init__(
        self,
        message: str,
        device_path: Path | str | None = None,
        cause: Exception | None = None,
    ) -> None:
        hints = []

        if device_path:
            hints.append(RecoveryHint(f"Check device at {device_path} is accessible"))

        hints.extend(
            [
                RecoveryHint("Verify device has enough free space"),
                RecoveryHint("Check file system is not corrupted"),
                RecoveryHint("Ensure device is not mounted read-only"),
            ]
        )

        super().__init__(
            message=message,
            category=ErrorCategory.STORAGE,
            recovery_hints=hints,
            cause=cause,
        )
        self.device_path = device_path


class PermissionError(YubiKeyInitError):
    """Error due to insufficient permissions."""

    def __init__(
        self,
        message: str,
        requires_sudo: bool = False,
        resource_path: Path | str | None = None,
        cause: Exception | None = None,
    ) -> None:
        hints = []

        if requires_sudo:
            hints.append(RecoveryHint("Run with sudo", command="sudo yubikey-init ..."))
        if resource_path:
            hints.append(RecoveryHint(f"Check permissions on {resource_path}"))

        hints.append(RecoveryHint("Check current user groups", command="groups"))

        super().__init__(
            message=message,
            category=ErrorCategory.PERMISSION,
            recovery_hints=hints,
            cause=cause,
        )
        self.requires_sudo = requires_sudo
        self.resource_path = resource_path


class UserCancelledError(YubiKeyInitError):
    """Error when user cancels an operation."""

    def __init__(
        self,
        message: str = "Operation cancelled by user",
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message=message,
            category=ErrorCategory.USER_INPUT,
            recovery_hints=[
                RecoveryHint("Run 'yubikey-init continue' to resume from last checkpoint"),
            ],
            cause=cause,
        )


class StateError(YubiKeyInitError):
    """Error related to invalid workflow state."""

    def __init__(
        self,
        message: str,
        current_state: str | None = None,
        expected_state: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        hints = []

        if current_state:
            hints.append(
                RecoveryHint(
                    f"Current state: {current_state}",
                )
            )
        hints.extend(
            [
                RecoveryHint("Check workflow status", command="yubikey-init status"),
                RecoveryHint("Reset workflow if needed", command="yubikey-init reset"),
            ]
        )

        super().__init__(
            message=message,
            category=ErrorCategory.STATE,
            recovery_hints=hints,
            cause=cause,
        )
        self.current_state = current_state
        self.expected_state = expected_state


# Error logging


class ErrorLogger:
    """Logger for structured error tracking."""

    def __init__(self, log_path: Path | None = None) -> None:
        self._log_path = log_path or Path.home() / ".yubikey-init" / "errors.log"
        self._logger = logging.getLogger("yubikey-init.errors")
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure file logging."""
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        handler = logging.FileHandler(self._log_path)
        handler.setLevel(logging.WARNING)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
        handler.setFormatter(formatter)

        self._logger.addHandler(handler)
        self._logger.setLevel(logging.WARNING)

    def log_error(self, error: YubiKeyInitError) -> None:
        """Log an error with full context."""
        context = {
            "category": error.category.name,
            "error_message": error.message,
            "timestamp": error.timestamp.isoformat(),
        }
        if error.cause:
            context["cause"] = str(error.cause)

        self._logger.error(
            f"[{error.category.name}] {error.message}",
            extra=context,
        )

    def log_warning(self, message: str, category: ErrorCategory) -> None:
        """Log a warning."""
        self._logger.warning(f"[{category.name}] {message}")

    def get_recent_errors(self, count: int = 10) -> list[str]:
        """Get recent error log entries."""
        if not self._log_path.exists():
            return []

        with open(self._log_path) as f:
            lines = f.readlines()

        return lines[-count:]


# Interrupt handling


class InterruptHandler:
    """Graceful handling of user interrupts (Ctrl+C)."""

    def __init__(self) -> None:
        self._original_handler: Callable[[int, FrameType | None], None] | int | None = None
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._interrupted = False

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        """Register a cleanup callback to run on interrupt."""
        self._cleanup_callbacks.append(callback)

    def unregister_cleanup(self, callback: Callable[[], None]) -> None:
        """Unregister a cleanup callback."""
        if callback in self._cleanup_callbacks:
            self._cleanup_callbacks.remove(callback)

    def _handle_interrupt(self, _signum: int, _frame: FrameType | None) -> NoReturn:
        """Handle SIGINT (Ctrl+C)."""
        self._interrupted = True

        # Run cleanup callbacks in reverse order
        for callback in reversed(self._cleanup_callbacks):
            with contextlib.suppress(Exception):
                callback()  # Best effort cleanup

        raise UserCancelledError("Interrupted by user (Ctrl+C)")

    def __enter__(self) -> InterruptHandler:
        """Install interrupt handler."""
        self._original_handler = signal.signal(signal.SIGINT, self._handle_interrupt)
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: object) -> None:
        """Restore original handler."""
        if self._original_handler is not None:
            signal.signal(signal.SIGINT, self._original_handler)

    @property
    def was_interrupted(self) -> bool:
        """Check if an interrupt occurred."""
        return self._interrupted


# Common error patterns and their solutions

COMMON_ERROR_PATTERNS: dict[str, list[RecoveryHint]] = {
    "no yubikey found": [
        RecoveryHint("Ensure YubiKey is inserted"),
        RecoveryHint("Check USB connection"),
        RecoveryHint("Run 'ykman list' to see connected devices"),
    ],
    "card error": [
        RecoveryHint("Restart pcscd service", command="sudo systemctl restart pcscd"),
        RecoveryHint("Remove and reinsert YubiKey"),
        RecoveryHint("Check for multiple card readers"),
    ],
    "permission denied": [
        RecoveryHint("Check file permissions"),
        RecoveryHint("Add user to plugdev group", command="sudo usermod -aG plugdev $USER"),
        RecoveryHint("Ensure udev rules are installed"),
    ],
    "gpg agent": [
        RecoveryHint("Kill and restart GPG agent", command="gpgconf --kill all"),
        RecoveryHint("Check socket permissions in ~/.gnupg"),
    ],
    "pinentry": [
        RecoveryHint("Install pinentry", command="apt install pinentry-curses"),
        RecoveryHint("Set pinentry program in gpg-agent.conf"),
    ],
}


def get_recovery_hints_for_message(error_message: str) -> list[RecoveryHint]:
    """Get recovery hints based on error message patterns."""
    hints = []
    lower_message = error_message.lower()

    for pattern, pattern_hints in COMMON_ERROR_PATTERNS.items():
        if pattern in lower_message:
            hints.extend(pattern_hints)

    return hints


def wrap_exception(
    exception: Exception,
    category: ErrorCategory = ErrorCategory.INTERNAL,
) -> YubiKeyInitError:
    """Wrap a generic exception in a YubiKeyInitError with recovery hints."""
    message = str(exception)
    hints = get_recovery_hints_for_message(message)

    return YubiKeyInitError(
        message=message,
        category=category,
        recovery_hints=hints,
        cause=exception,
    )
