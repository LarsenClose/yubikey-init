"""Tests for structured error handling module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from yubikey_init.errors import (
    EnvironmentError,
    ErrorCategory,
    ErrorLogger,
    GPGOperationError,
    HardwareError,
    InterruptHandler,
    PermissionError,
    RecoveryHint,
    StateError,
    StorageError,
    UserCancelledError,
    YubiKeyInitError,
    get_recovery_hints_for_message,
    wrap_exception,
)


class TestRecoveryHint:
    """Test RecoveryHint dataclass."""

    def test_basic_hint(self) -> None:
        """Test basic recovery hint."""
        hint = RecoveryHint(action="Try again")
        assert str(hint) == "Try again"

    def test_hint_with_command(self) -> None:
        """Test hint with command."""
        hint = RecoveryHint(action="Restart service", command="sudo systemctl restart pcscd")
        result = str(hint)
        assert "Restart service" in result
        assert "sudo systemctl restart pcscd" in result

    def test_hint_with_url(self) -> None:
        """Test hint with documentation URL."""
        hint = RecoveryHint(
            action="Read docs",
            documentation_url="https://example.com/docs",
        )
        result = str(hint)
        assert "Read docs" in result
        assert "https://example.com/docs" in result


class TestYubiKeyInitError:
    """Test base error class."""

    def test_basic_error(self) -> None:
        """Test basic error creation."""
        error = YubiKeyInitError(
            message="Something went wrong",
            category=ErrorCategory.INTERNAL,
        )
        assert str(error) == "Something went wrong"
        assert error.category == ErrorCategory.INTERNAL

    def test_error_with_hints(self) -> None:
        """Test error with recovery hints."""
        hints = [
            RecoveryHint("Try this"),
            RecoveryHint("Or try that"),
        ]
        error = YubiKeyInitError(
            message="Failed",
            category=ErrorCategory.GPG,
            recovery_hints=hints,
        )
        assert len(error.recovery_hints) == 2

    def test_error_with_cause(self) -> None:
        """Test error with cause."""
        original = ValueError("Original error")
        error = YubiKeyInitError(
            message="Wrapped error",
            category=ErrorCategory.INTERNAL,
            cause=original,
        )
        assert error.cause == original

    def test_format_full(self) -> None:
        """Test full error formatting."""
        error = YubiKeyInitError(
            message="Failed operation",
            category=ErrorCategory.HARDWARE,
            recovery_hints=[RecoveryHint("Check connection")],
            cause=OSError("Device not found"),
        )
        formatted = error.format_full()
        assert "Failed operation" in formatted
        assert "Device not found" in formatted
        assert "Check connection" in formatted

    def test_timestamp_set(self) -> None:
        """Test timestamp is automatically set."""
        error = YubiKeyInitError(
            message="Test",
            category=ErrorCategory.INTERNAL,
        )
        assert error.timestamp is not None


class TestEnvironmentError:
    """Test environment-specific errors."""

    def test_missing_gpg(self) -> None:
        """Test error for missing GPG."""
        error = EnvironmentError("GPG not found", missing_tool="gpg")
        assert len(error.recovery_hints) > 0
        assert error.category == ErrorCategory.ENVIRONMENT

    def test_missing_ykman(self) -> None:
        """Test error for missing ykman."""
        error = EnvironmentError("ykman not found", missing_tool="ykman")
        assert any("ykman" in str(h) for h in error.recovery_hints)

    def test_unknown_tool(self) -> None:
        """Test error for unknown missing tool."""
        error = EnvironmentError("Tool not found", missing_tool="unknown")
        # Should still work, just no specific hints
        assert error.category == ErrorCategory.ENVIRONMENT


class TestHardwareError:
    """Test hardware-specific errors."""

    def test_yubikey_error(self) -> None:
        """Test YubiKey hardware error."""
        error = HardwareError("YubiKey not responding", device_type="YubiKey")
        assert error.category == ErrorCategory.HARDWARE
        assert any(
            "ykman" in str(h).lower() or "yubikey" in str(h).lower() for h in error.recovery_hints
        )

    def test_storage_device_error(self) -> None:
        """Test storage device hardware error."""
        error = HardwareError("Device not found", device_type="storage")
        assert error.category == ErrorCategory.HARDWARE
        assert any("connect" in str(h).lower() for h in error.recovery_hints)


class TestGPGOperationError:
    """Test GPG-specific errors."""

    def test_basic_gpg_error(self) -> None:
        """Test basic GPG operation error."""
        error = GPGOperationError("Key generation failed", operation="generate")
        assert error.category == ErrorCategory.GPG
        assert error.operation == "generate"

    def test_gpg_error_with_output(self) -> None:
        """Test GPG error with output parsing."""
        error = GPGOperationError(
            "Failed",
            gpg_output="gpg: agent error: connection failed",
        )
        # Should add agent-specific hints
        assert any("agent" in str(h).lower() for h in error.recovery_hints)

    def test_gpg_error_permission(self) -> None:
        """Test GPG error with permission message."""
        error = GPGOperationError(
            "Failed",
            gpg_output="permission denied",
        )
        assert any("permission" in str(h).lower() for h in error.recovery_hints)


class TestStorageError:
    """Test storage-specific errors."""

    def test_storage_error_with_path(self) -> None:
        """Test storage error with device path."""
        error = StorageError("Cannot write", device_path=Path("/dev/sdb"))
        assert error.category == ErrorCategory.STORAGE
        assert error.device_path == Path("/dev/sdb")
        assert any("/dev/sdb" in str(h) for h in error.recovery_hints)

    def test_storage_error_without_path(self) -> None:
        """Test storage error without device path."""
        error = StorageError("Backup failed")
        assert len(error.recovery_hints) > 0


class TestPermissionError:
    """Test permission-specific errors."""

    def test_requires_sudo(self) -> None:
        """Test error requiring sudo."""
        error = PermissionError("Access denied", requires_sudo=True)
        assert error.category == ErrorCategory.PERMISSION
        assert error.requires_sudo is True
        assert any("sudo" in str(h).lower() for h in error.recovery_hints)

    def test_resource_path(self) -> None:
        """Test error with resource path."""
        error = PermissionError(
            "Cannot access",
            resource_path="/dev/bus/usb/001/002",
        )
        assert error.resource_path == "/dev/bus/usb/001/002"


class TestUserCancelledError:
    """Test user cancellation errors."""

    def test_default_message(self) -> None:
        """Test default cancellation message."""
        error = UserCancelledError()
        assert "cancelled" in str(error).lower()
        assert error.category == ErrorCategory.USER_INPUT

    def test_custom_message(self) -> None:
        """Test custom cancellation message."""
        error = UserCancelledError("User pressed Ctrl+C")
        assert "Ctrl+C" in str(error)

    def test_has_continue_hint(self) -> None:
        """Test has hint to continue."""
        error = UserCancelledError()
        assert any("continue" in str(h).lower() for h in error.recovery_hints)


class TestStateError:
    """Test state-specific errors."""

    def test_state_error(self) -> None:
        """Test state transition error."""
        error = StateError(
            "Invalid transition",
            current_state="BACKUP_CREATED",
            expected_state="YUBIKEY_PROVISIONED",
        )
        assert error.category == ErrorCategory.STATE
        assert error.current_state == "BACKUP_CREATED"
        assert error.expected_state == "YUBIKEY_PROVISIONED"

    def test_state_error_hints(self) -> None:
        """Test state error has status/reset hints."""
        error = StateError("Invalid state")
        assert any("status" in str(h).lower() for h in error.recovery_hints)


class TestErrorLogger:
    """Test error logging functionality."""

    def test_logger_creates_directory(self) -> None:
        """Test logger creates log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "subdir" / "errors.log"
            ErrorLogger(log_path=log_path)
            assert log_path.parent.exists()

    def test_log_error(self) -> None:
        """Test logging an error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "errors.log"
            logger = ErrorLogger(log_path=log_path)

            error = YubiKeyInitError(
                message="Test error",
                category=ErrorCategory.GPG,
            )
            logger.log_error(error)

            # Check log file was created
            assert log_path.exists()

    def test_log_warning(self) -> None:
        """Test logging a warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "errors.log"
            logger = ErrorLogger(log_path=log_path)

            logger.log_warning("Test warning", ErrorCategory.ENVIRONMENT)
            assert log_path.exists()

    def test_get_recent_errors_empty(self) -> None:
        """Test getting recent errors from empty log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "errors.log"
            logger = ErrorLogger(log_path=log_path)

            errors = logger.get_recent_errors()
            assert errors == []


class TestInterruptHandler:
    """Test interrupt handler functionality."""

    def test_cleanup_registration(self) -> None:
        """Test cleanup callback registration."""
        handler = InterruptHandler()
        cleanup_called = []

        def cleanup() -> None:
            cleanup_called.append(True)

        handler.register_cleanup(cleanup)
        assert len(handler._cleanup_callbacks) == 1

        handler.unregister_cleanup(cleanup)
        assert len(handler._cleanup_callbacks) == 0

    def test_context_manager(self) -> None:
        """Test handler as context manager."""
        with InterruptHandler() as handler:
            assert handler is not None
        # Should not raise

    def test_was_interrupted_initial_false(self) -> None:
        """Test interrupted flag is initially false."""
        handler = InterruptHandler()
        assert handler.was_interrupted is False


class TestGetRecoveryHints:
    """Test recovery hint lookup function."""

    def test_yubikey_not_found(self) -> None:
        """Test hints for YubiKey not found error."""
        hints = get_recovery_hints_for_message("No YubiKey found")
        assert len(hints) > 0

    def test_card_error(self) -> None:
        """Test hints for card error."""
        hints = get_recovery_hints_for_message("Card error occurred")
        assert len(hints) > 0

    def test_permission_denied(self) -> None:
        """Test hints for permission denied."""
        hints = get_recovery_hints_for_message("Permission denied")
        assert len(hints) > 0

    def test_unknown_error(self) -> None:
        """Test empty hints for unknown error."""
        hints = get_recovery_hints_for_message("Some random error xyz123")
        assert hints == []


class TestWrapException:
    """Test exception wrapping function."""

    def test_wrap_basic_exception(self) -> None:
        """Test wrapping a basic exception."""
        original = ValueError("Something went wrong")
        wrapped = wrap_exception(original)

        assert isinstance(wrapped, YubiKeyInitError)
        assert wrapped.cause == original
        assert "Something went wrong" in str(wrapped)

    def test_wrap_with_category(self) -> None:
        """Test wrapping with specific category."""
        original = OSError("File not found")
        wrapped = wrap_exception(original, category=ErrorCategory.STORAGE)

        assert wrapped.category == ErrorCategory.STORAGE

    def test_wrap_adds_hints(self) -> None:
        """Test wrapping adds recovery hints based on message."""
        original = Exception("permission denied to access device")
        wrapped = wrap_exception(original)

        # Should pick up permission hints
        assert len(wrapped.recovery_hints) > 0
