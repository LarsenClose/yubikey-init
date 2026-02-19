"""Tests for prompts module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from yubikey_init.prompts import (
    MockPrompts,
    PassphraseStrength,
    PINRequirements,
    Prompts,
    analyze_passphrase,
    calculate_entropy,
)
from yubikey_init.types import DeviceInfo, KeySlot, SecureString, TouchPolicy, YubiKeyInfo


class TestMockPrompts:
    """Test MockPrompts class."""

    def test_init_with_defaults(self) -> None:
        """Test MockPrompts initialization with default values."""
        mock = MockPrompts()
        assert mock._passphrase == "test-passphrase"
        assert mock._pin == "123456"
        assert mock._admin_pin == "12345678"
        assert mock._confirmations is True

    def test_init_with_custom_values(self) -> None:
        """Test MockPrompts initialization with custom values."""
        mock = MockPrompts(
            passphrase="custom-pass",
            pin="654321",
            admin_pin="87654321",
            confirmations=False,
        )
        assert mock._passphrase == "custom-pass"
        assert mock._pin == "654321"
        assert mock._admin_pin == "87654321"
        assert mock._confirmations is False

    def test_get_passphrase_returns_configured_value(self) -> None:
        """Test get_passphrase returns configured passphrase."""
        mock = MockPrompts(passphrase="my-secret")
        result = mock.get_passphrase("Enter passphrase:", confirm=True, min_length=8)
        assert isinstance(result, SecureString)
        assert result.get() == "my-secret"

    def test_get_pin_returns_regular_pin(self) -> None:
        """Test get_pin returns regular PIN for non-admin prompts."""
        mock = MockPrompts(pin="111111", admin_pin="222222")
        result = mock.get_pin("Enter PIN:", min_length=6, max_length=8)
        assert result.get() == "111111"

    def test_get_pin_returns_admin_pin_for_admin_prompt(self) -> None:
        """Test get_pin returns admin PIN for admin prompts."""
        mock = MockPrompts(pin="111111", admin_pin="222222")
        result = mock.get_pin("Enter Admin PIN:", min_length=8)
        assert result.get() == "222222"

    def test_confirm_returns_configured_value_true(self) -> None:
        """Test confirm returns True when confirmations=True."""
        mock = MockPrompts(confirmations=True)
        result = mock.confirm("Are you sure?", default=False, dangerous=True)
        assert result is True

    def test_confirm_returns_configured_value_false(self) -> None:
        """Test confirm returns False when confirmations=False."""
        mock = MockPrompts(confirmations=False)
        result = mock.confirm("Are you sure?", default=True, dangerous=False)
        assert result is False

    def test_select_device_returns_first_device(self) -> None:
        """Test select_device returns first device from list."""
        from pathlib import Path

        mock = MockPrompts()
        devices = [
            DeviceInfo(
                path=Path("/dev/sda"),
                name="USB Drive",
                size_bytes=8000000000,
                removable=True,
                mounted=False,
                mount_point=None,
            ),
            DeviceInfo(
                path=Path("/dev/sdb"),
                name="Another Drive",
                size_bytes=16000000000,
                removable=True,
                mounted=True,
                mount_point=Path("/media/usb"),
            ),
        ]
        result = mock.select_device(devices, "Select device:")
        assert result == devices[0]

    def test_select_device_returns_none_for_empty_list(self) -> None:
        """Test select_device returns None for empty list."""
        mock = MockPrompts()
        result = mock.select_device([], "Select device:")
        assert result is None

    def test_select_yubikey_returns_first_device(self) -> None:
        """Test select_yubikey returns first YubiKey from list."""
        mock = MockPrompts()
        devices = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-A",
                has_openpgp=True,
                openpgp_version=None,
            ),
            YubiKeyInfo(
                serial="87654321",
                version="5.2.4",
                form_factor="USB-C",
                has_openpgp=False,
                openpgp_version=None,
            ),
        ]
        result = mock.select_yubikey(devices, "Select YubiKey:")
        assert result == devices[0]

    def test_select_yubikey_returns_none_for_empty_list(self) -> None:
        """Test select_yubikey returns None for empty list."""
        mock = MockPrompts()
        result = mock.select_yubikey([], "Select YubiKey:")
        assert result is None

    def test_wait_for_yubikey_does_nothing(self) -> None:
        """Test wait_for_yubikey is a no-op."""
        mock = MockPrompts()
        # Should not raise
        mock.wait_for_yubikey("12345678")
        mock.wait_for_yubikey()


class TestPromptsInit:
    """Test Prompts class initialization."""

    def test_prompts_init(self) -> None:
        """Test Prompts initialization creates console."""
        with patch("yubikey_init.prompts.Console") as mock_console:
            prompts = Prompts()
            mock_console.assert_called_once()
            assert prompts._console is not None

    def test_prompts_init_with_custom_console(self) -> None:
        """Test Prompts initialization with custom console."""
        from rich.console import Console

        custom_console = Console(quiet=True)
        prompts = Prompts(console=custom_console)
        assert prompts._console is custom_console


class TestPromptsGetPassphrase:
    """Test Prompts get_passphrase method."""

    def test_get_passphrase_valid(self) -> None:
        """Test get_passphrase with valid input."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch("yubikey_init.prompts.getpass.getpass", return_value="validpassphrase123"):
            result = prompts.get_passphrase("Enter passphrase")
            assert isinstance(result, SecureString)
            assert result.get() == "validpassphrase123"

    def test_get_passphrase_too_short_then_valid(self) -> None:
        """Test get_passphrase rejects short input then accepts valid."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch(
            "yubikey_init.prompts.getpass.getpass", side_effect=["short", "validpassphrase123"]
        ):
            result = prompts.get_passphrase("Enter passphrase", min_length=12)
            assert result.get() == "validpassphrase123"

    def test_get_passphrase_confirm_mismatch_then_match(self) -> None:
        """Test get_passphrase with confirm that doesn't match then matches."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch(
            "yubikey_init.prompts.getpass.getpass",
            side_effect=[
                "validpassphrase123",
                "mismatch",  # First attempt - mismatch
                "validpassphrase123",
                "validpassphrase123",  # Second attempt - match
            ],
        ):
            result = prompts.get_passphrase("Enter passphrase", confirm=True)
            assert result.get() == "validpassphrase123"


class TestPromptsGetPin:
    """Test Prompts get_pin method."""

    def test_get_pin_valid(self) -> None:
        """Test get_pin with valid input."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch("yubikey_init.prompts.getpass.getpass", return_value="123456"):
            result = prompts.get_pin("Enter PIN")
            assert isinstance(result, SecureString)
            assert result.get() == "123456"

    def test_get_pin_too_short_then_valid(self) -> None:
        """Test get_pin rejects short input then accepts valid."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch("yubikey_init.prompts.getpass.getpass", side_effect=["123", "123456"]):
            result = prompts.get_pin("Enter PIN", min_length=6)
            assert result.get() == "123456"

    def test_get_pin_too_long_then_valid(self) -> None:
        """Test get_pin rejects long input then accepts valid."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        long_pin = "1" * 130
        with patch("yubikey_init.prompts.getpass.getpass", side_effect=[long_pin, "123456"]):
            result = prompts.get_pin("Enter PIN", max_length=127)
            assert result.get() == "123456"


class TestPromptsSelectDevice:
    """Test Prompts select_device method."""

    def test_select_device_empty_list(self) -> None:
        """Test select_device with empty list returns None."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        result = prompts.select_device([], "Select device")
        assert result is None

    def test_select_device_valid_selection(self) -> None:
        """Test select_device with valid selection."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))
        devices = [
            DeviceInfo(
                path=Path("/dev/sda"),
                name="USB Drive",
                size_bytes=8000000000,
                removable=True,
                mounted=False,
            ),
            DeviceInfo(
                path=Path("/dev/sdb"),
                name="Another Drive",
                size_bytes=16000000000,
                removable=True,
                mounted=True,
                mount_point=Path("/media/usb"),
            ),
        ]
        with patch.object(Prompt, "ask", return_value="2"):
            result = prompts.select_device(devices, "Select device")
            assert result is not None
            assert result.path == Path("/dev/sdb")


class TestPromptsSelectYubikey:
    """Test Prompts select_yubikey method."""

    def test_select_yubikey_empty_list(self) -> None:
        """Test select_yubikey with empty list returns None."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        result = prompts.select_yubikey([], "Select YubiKey")
        assert result is None

    def test_select_yubikey_valid_selection(self) -> None:
        """Test select_yubikey with valid selection."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))
        devices = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-A",
                has_openpgp=True,
                openpgp_version=None,
            ),
            YubiKeyInfo(
                serial="87654321",
                version="5.2.4",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version=None,
            ),
        ]
        with patch.object(Prompt, "ask", return_value="1"):
            result = prompts.select_yubikey(devices, "Select YubiKey")
            assert result is not None
            assert result.serial == "12345678"


class TestPromptsConfirm:
    """Test Prompts confirm method."""

    def test_confirm_normal(self) -> None:
        """Test confirm without dangerous flag."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))
        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.confirm("Are you sure?")
            assert result is True

    def test_confirm_dangerous(self) -> None:
        """Test confirm with dangerous flag shows warning."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))
        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.confirm("Delete everything?", dangerous=True)
            assert result is True


class TestPromptsDisplay:
    """Test Prompts display methods."""

    def test_show_progress_with_total(self) -> None:
        """Test show_progress returns Progress with bar column."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        progress = prompts.show_progress("Processing", total=100)
        assert progress is not None

    def test_show_progress_without_total(self) -> None:
        """Test show_progress returns Progress with spinner only."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        progress = prompts.show_progress("Processing")
        assert progress is not None

    def test_show_step(self) -> None:
        """Test show_step displays step info."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_step(1, 5, "Installing", "This installs the software")

    def test_show_step_without_explanation(self) -> None:
        """Test show_step without explanation."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_step(2, 5, "Configuring")

    def test_show_success(self) -> None:
        """Test show_success displays message."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_success("Operation completed")

    def test_show_error(self) -> None:
        """Test show_error displays error."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_error(Exception("Something went wrong"))

    def test_show_error_with_recovery(self) -> None:
        """Test show_error with recovery hint."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_error(Exception("Failed"), recovery_hint="Try again")

    def test_show_key_info(self) -> None:
        """Test show_key_info displays key info."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        # Should not raise
        prompts.show_key_info(
            "ABCDEF1234567890",
            "1234567890ABCDEF1234567890ABCDEF12345678",
            "Test User <test@example.com>",
            expiry="2026-01-01",
        )

    def test_wait_for_yubikey(self) -> None:
        """Test wait_for_yubikey prompts user."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        with patch("builtins.input", return_value=""):
            # Should not raise
            prompts.wait_for_yubikey(serial="12345678")


class TestCalculateEntropy:
    """Test entropy calculation function."""

    def test_empty_password(self) -> None:
        """Test entropy for empty password."""
        assert calculate_entropy("") == 0.0

    def test_lowercase_only(self) -> None:
        """Test entropy for lowercase letters."""
        entropy = calculate_entropy("password")
        # 8 chars * log2(26) = 8 * 4.7 = ~37.6 bits
        assert 37 < entropy < 38

    def test_mixed_case(self) -> None:
        """Test entropy for mixed case."""
        entropy = calculate_entropy("Password")
        # 8 chars * log2(52) = 8 * 5.7 = ~45.6 bits
        assert 45 < entropy < 46

    def test_alphanumeric(self) -> None:
        """Test entropy for alphanumeric."""
        entropy = calculate_entropy("Pass1234")
        # 8 chars * log2(62) = 8 * 5.95 = ~47.6 bits
        assert 47 < entropy < 48

    def test_with_special(self) -> None:
        """Test entropy with special characters."""
        entropy = calculate_entropy("Pass1234!")
        # 9 chars * log2(94) = 9 * 6.55 = ~59 bits
        assert 58 < entropy < 60


class TestAnalyzePassphrase:
    """Test passphrase analysis function."""

    def test_weak_passphrase(self) -> None:
        """Test weak passphrase analysis."""
        analysis = analyze_passphrase("short")
        assert analysis.strength == PassphraseStrength.WEAK
        assert not analysis.meets_minimum
        assert len(analysis.feedback) > 0

    def test_fair_passphrase(self) -> None:
        """Test fair passphrase analysis."""
        analysis = analyze_passphrase("longpassphrase")
        assert analysis.strength in (PassphraseStrength.WEAK, PassphraseStrength.FAIR)
        assert analysis.meets_minimum

    def test_strong_passphrase(self) -> None:
        """Test strong passphrase analysis."""
        analysis = analyze_passphrase("MyStr0ng!Pass#2024")
        assert analysis.strength in (PassphraseStrength.STRONG, PassphraseStrength.EXCELLENT)
        assert analysis.meets_minimum
        assert analysis.entropy_bits > 60

    def test_excellent_passphrase(self) -> None:
        """Test excellent passphrase analysis."""
        analysis = analyze_passphrase("This Is A Very L0ng & Str0ng Passphrase!")
        assert analysis.strength == PassphraseStrength.EXCELLENT
        assert analysis.meets_minimum
        assert analysis.entropy_bits > 100

    def test_custom_min_length(self) -> None:
        """Test with custom minimum length."""
        analysis = analyze_passphrase("12345678", min_length=8)
        assert analysis.meets_minimum

    def test_common_pattern_penalty(self) -> None:
        """Test that common patterns reduce score."""
        all_lower = analyze_passphrase("abcdefghijklmnop", min_length=12)
        mixed = analyze_passphrase("AbCdEfGhIjKlMnOp", min_length=12)
        # Mixed should have higher score
        assert mixed.score > all_lower.score


class TestPINRequirements:
    """Test PIN requirements dataclass."""

    def test_default_requirements(self) -> None:
        """Test default PIN requirements."""
        req = PINRequirements()
        assert req.min_length == 6
        assert req.max_length == 127
        assert req.require_digits is False
        assert req.require_no_sequential is False
        assert req.require_no_repeated is False

    def test_custom_requirements(self) -> None:
        """Test custom PIN requirements."""
        req = PINRequirements(
            min_length=8,
            max_length=16,
            require_digits=True,
            require_no_sequential=True,
            require_no_repeated=True,
        )
        assert req.min_length == 8
        assert req.max_length == 16
        assert req.require_digits is True


class TestPromptsValidatePin:
    """Test Prompts._validate_pin method."""

    def test_valid_pin(self) -> None:
        """Test valid PIN passes validation."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(min_length=6, max_length=8)
        errors = prompts._validate_pin("123456", req)
        assert errors == []

    def test_too_short(self) -> None:
        """Test too short PIN fails validation."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(min_length=6)
        errors = prompts._validate_pin("123", req)
        assert any("at least 6" in e for e in errors)

    def test_too_long(self) -> None:
        """Test too long PIN fails validation."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(max_length=8)
        errors = prompts._validate_pin("123456789", req)
        assert any("at most 8" in e for e in errors)

    def test_require_digits(self) -> None:
        """Test digits-only requirement."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(min_length=6, require_digits=True)
        errors = prompts._validate_pin("abc123", req)
        assert any("only digits" in e for e in errors)

    def test_require_no_sequential(self) -> None:
        """Test no-sequential requirement."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(min_length=6, require_no_sequential=True)
        errors = prompts._validate_pin("112345", req)
        assert any("sequential" in e for e in errors)

    def test_require_no_repeated(self) -> None:
        """Test no-repeated requirement."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        req = PINRequirements(min_length=6, require_no_repeated=True)
        errors = prompts._validate_pin("111456", req)
        assert any("repeated" in e for e in errors)


class TestPromptsDeviceSafetyWarning:
    """Test Prompts._get_device_safety_warning method."""

    def test_no_warning_for_removable(self) -> None:
        """Test no warning for small removable device."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        device = DeviceInfo(
            path=Path("/dev/sdb"),
            name="USB Drive",
            size_bytes=8 * 1024**3,  # 8 GB
            removable=True,
            mounted=False,
        )
        warning = prompts._get_device_safety_warning(device)
        assert warning is None

    def test_warning_for_system_drive(self) -> None:
        """Test warning for non-removable system drive."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        device = DeviceInfo(
            path=Path("/dev/sda"),
            name="System",
            size_bytes=500 * 1024**3,
            removable=False,
            mounted=True,
            mount_point=Path("/"),
        )
        warning = prompts._get_device_safety_warning(device)
        assert warning is not None
        assert "system" in warning.lower()

    def test_warning_for_mounted(self) -> None:
        """Test warning for mounted device."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        device = DeviceInfo(
            path=Path("/dev/sdc"),
            name="External",
            size_bytes=100 * 1024**3,
            removable=True,
            mounted=True,
            mount_point=Path("/media/external"),
        )
        warning = prompts._get_device_safety_warning(device)
        assert warning is not None
        assert "mounted" in warning.lower()

    def test_warning_for_large_drive(self) -> None:
        """Test warning for large drive."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        device = DeviceInfo(
            path=Path("/dev/sdc"),
            name="Large Drive",
            size_bytes=1000 * 1024**3,  # 1 TB
            removable=True,
            mounted=False,
        )
        warning = prompts._get_device_safety_warning(device)
        assert warning is not None
        assert "large" in warning.lower()


class TestMockPromptsNewMethods:
    """Test MockPrompts new methods."""

    def test_confirm_destructive_returns_configured(self) -> None:
        """Test confirm_destructive returns configured value."""
        mock = MockPrompts(confirmations=True)
        result = mock.confirm_destructive("/dev/sdb", "format")
        assert result is True

        mock = MockPrompts(confirmations=False)
        result = mock.confirm_destructive("/dev/sdb", "format")
        assert result is False

    def test_select_touch_policy_returns_default(self) -> None:
        """Test select_touch_policy returns default."""
        mock = MockPrompts()
        result = mock.select_touch_policy(KeySlot.SIGNATURE, default=TouchPolicy.CACHED)
        assert result == TouchPolicy.CACHED

    def test_checkpoint_backup_verification(self) -> None:
        """Test checkpoint_backup_verification behavior."""
        mock = MockPrompts(confirmations=True)
        # With files found and none missing - should return True
        result = mock.checkpoint_backup_verification(
            "/backup",
            files_found=["file1.gpg", "file2.gpg"],
            files_missing=[],
        )
        assert result is True

        # With files missing - should return False (confirmations AND no missing)
        result = mock.checkpoint_backup_verification(
            "/backup",
            files_found=["file1.gpg"],
            files_missing=["file2.gpg"],
        )
        assert result is False

    def test_checkpoint_before_destructive(self) -> None:
        """Test checkpoint_before_destructive returns configured."""
        mock = MockPrompts(confirmations=True)
        result = mock.checkpoint_before_destructive("Remove files", ["file1", "file2"])
        assert result is True

    def test_checkpoint_resume(self) -> None:
        """Test checkpoint_resume returns configured."""
        mock = MockPrompts(confirmations=True)
        result = mock.checkpoint_resume(
            "GPG_MASTER_GENERATED",
            ["Storage setup", "Key generation"],
            "Create subkeys",
        )
        assert result is True


class TestPromptsGetIdentity:
    """Test Prompts get_identity method."""

    def test_get_identity_with_default(self) -> None:
        """Test get_identity uses default name."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", side_effect=["John Doe", "john@example.com"]):
            result = prompts.get_identity(default="Jane Smith <jane@old.com>")
            assert result == "John Doe <john@example.com>"

    def test_get_identity_without_default(self) -> None:
        """Test get_identity without default."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", side_effect=["Alice", "alice@example.com"]):
            result = prompts.get_identity()
            assert result == "Alice <alice@example.com>"


class TestPromptsShowStrengthBar:
    """Test Prompts _show_strength_bar method."""

    def test_show_strength_bar_weak(self) -> None:
        """Test strength bar display for weak passphrase."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        analysis = analyze_passphrase("weak", min_length=12)
        # Should not raise
        prompts._show_strength_bar(analysis)

    def test_show_strength_bar_excellent(self) -> None:
        """Test strength bar display for excellent passphrase."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        analysis = analyze_passphrase("This Is A Very L0ng & Str0ng Passphrase!", min_length=12)
        # Should not raise
        prompts._show_strength_bar(analysis)


class TestPromptsConfirmDestructive:
    """Test Prompts confirm_destructive method."""

    def test_confirm_destructive_with_device_info(self) -> None:
        """Test confirm_destructive with DeviceInfo object."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))
        device = DeviceInfo(
            path=Path("/dev/sdb"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
        )

        with patch.object(Prompt, "ask", return_value="sdb"):
            result = prompts.confirm_destructive(device, "format")
            assert result is True

    def test_confirm_destructive_with_string(self) -> None:
        """Test confirm_destructive with string device path."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", return_value="sdc"):
            result = prompts.confirm_destructive("/dev/sdc", "erase")
            assert result is True

    def test_confirm_destructive_wrong_input(self) -> None:
        """Test confirm_destructive with wrong device name."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", return_value="wrong"):
            result = prompts.confirm_destructive("/dev/sdb", "format")
            assert result is False


class TestPromptsShowPinRequirements:
    """Test Prompts _show_pin_requirements method."""

    def test_show_pin_requirements_basic(self) -> None:
        """Test PIN requirements display."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        requirements = PINRequirements(min_length=6, max_length=8)
        # Should not raise
        prompts._show_pin_requirements(requirements)

    def test_show_pin_requirements_with_all_flags(self) -> None:
        """Test PIN requirements with all validation flags."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        requirements = PINRequirements(
            min_length=8,
            max_length=16,
            require_digits=True,
            require_no_sequential=True,
            require_no_repeated=True,
        )
        # Should not raise
        prompts._show_pin_requirements(requirements)


class TestPromptsGetPassphraseShowStrength:
    """Test get_passphrase with show_strength flag."""

    def test_get_passphrase_weak_strength_rejected(self) -> None:
        """Test get_passphrase warns on weak passphrase and user rejects."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        with (
            patch(
                "yubikey_init.prompts.getpass.getpass",
                side_effect=["weakpass123", "StrongP@ssw0rd123"],
            ),
            patch.object(Confirm, "ask", return_value=False),
        ):
            result = prompts.get_passphrase("Enter passphrase", show_strength=True)
            # Should retry and get strong password
            assert result.get() == "StrongP@ssw0rd123"

    def test_get_passphrase_no_strength_display(self) -> None:
        """Test get_passphrase without strength display."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))

        with patch("yubikey_init.prompts.getpass.getpass", return_value="simplepassword"):
            result = prompts.get_passphrase("Enter passphrase", show_strength=False)
            assert result.get() == "simplepassword"


class TestPromptsSelectTouchPolicy:
    """Test Prompts select_touch_policy method."""

    def test_select_touch_policy_default(self) -> None:
        """Test select_touch_policy with default choice."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", return_value="2"):
            result = prompts.select_touch_policy(KeySlot.SIGNATURE, default=TouchPolicy.ON)
            assert result == TouchPolicy.ON

    def test_select_touch_policy_invalid_then_valid(self) -> None:
        """Test select_touch_policy with invalid then valid input."""
        from rich.console import Console
        from rich.prompt import Prompt

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Prompt, "ask", side_effect=["invalid", "99", "1"]):
            result = prompts.select_touch_policy(KeySlot.ENCRYPTION)
            assert result == TouchPolicy.OFF


class TestPromptsLongOperationProgress:
    """Test Prompts long_operation_progress context manager."""

    def test_long_operation_progress_with_total(self) -> None:
        """Test long operation progress with known total."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))

        with prompts.long_operation_progress("Processing", total=100) as progress:
            assert progress is not None
            # Check that task_id is stored
            assert hasattr(progress, "_yubikey_init_task_id")

    def test_long_operation_progress_indeterminate(self) -> None:
        """Test long operation progress without total."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))

        with prompts.long_operation_progress("Processing") as progress:
            assert progress is not None

    def test_long_operation_progress_no_time(self) -> None:
        """Test long operation progress without time display."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))

        with prompts.long_operation_progress("Processing", total=50, show_time=False) as progress:
            assert progress is not None


class TestPromptsShowOperationPhases:
    """Test Prompts show_operation_phases method."""

    def test_show_operation_phases_in_progress(self) -> None:
        """Test showing operation phases with current phase."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        phases = ["Setup", "Processing", "Cleanup"]
        # Should not raise
        prompts.show_operation_phases(phases, current_phase=1)

    def test_show_operation_phases_first_phase(self) -> None:
        """Test showing first phase."""
        from rich.console import Console

        prompts = Prompts(console=Console(quiet=True))
        phases = ["Initialize", "Execute", "Finalize"]
        prompts.show_operation_phases(phases, current_phase=0)


class TestPromptsCheckpoints:
    """Test Prompts checkpoint methods."""

    def test_checkpoint_backup_verification_with_missing_files(self) -> None:
        """Test backup verification checkpoint with missing files."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Confirm, "ask", return_value=False):
            result = prompts.checkpoint_backup_verification(
                "/backup/path",
                files_found=["key1.gpg"],
                files_missing=["key2.gpg", "key3.gpg"],
            )
            assert result is False

    def test_checkpoint_backup_verification_all_found(self) -> None:
        """Test backup verification with all files found."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.checkpoint_backup_verification(
                "/backup/path",
                files_found=["key1.gpg", "key2.gpg", "key3.gpg"],
                files_missing=[],
            )
            assert result is True

    def test_checkpoint_backup_verification_many_files(self) -> None:
        """Test backup verification displays truncated file list."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        many_files = [f"file{i}.gpg" for i in range(20)]
        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.checkpoint_backup_verification(
                "/backup/path",
                files_found=many_files,
                files_missing=[],
            )
            assert result is True

    def test_checkpoint_before_destructive_many_items(self) -> None:
        """Test destructive checkpoint with many items."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        many_items = [f"item{i}" for i in range(30)]
        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.checkpoint_before_destructive("Remove all items", many_items)
            assert result is True

    def test_checkpoint_resume_with_steps(self) -> None:
        """Test resume checkpoint displays completed steps."""
        from rich.console import Console
        from rich.prompt import Confirm

        prompts = Prompts(console=Console(quiet=True))

        completed = ["Step 1", "Step 2", "Step 3", "Step 4", "Step 5", "Step 6"]
        with patch.object(Confirm, "ask", return_value=True):
            result = prompts.checkpoint_resume(
                "IN_PROGRESS",
                completed,
                "Step 7",
            )
            assert result is True
