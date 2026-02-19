"""Comprehensive tests for safety.py module.

Tests the safety mechanisms that protect YubiKeys from accidental destructive operations:
- SafetyCheckResult dataclass and properties
- SafetyGuard device checks and confirmation flows
- Protected device handling
- Multi-card warnings
- PIN state warnings
- Device display functions
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from yubikey_init.inventory import (
    DeviceEntry,
    Inventory,
    KeySlotInfo,
    OpenPGPState,
)
from yubikey_init.safety import (
    DeviceVerificationError,
    MultiCardWarningError,
    ProtectedDeviceError,
    SafetyCheckResult,
    SafetyError,
    SafetyGuard,
    SafetyLevel,
    display_device_table,
    list_connected_devices_safely,
)
from yubikey_init.types import YubiKeyInfo


class TestSafetyLevel:
    """Test SafetyLevel enum."""

    def test_safety_level_values(self) -> None:
        """Test that safety levels have expected values."""
        assert SafetyLevel.READ_ONLY.value == "read_only"
        assert SafetyLevel.MODERATE.value == "moderate"
        assert SafetyLevel.DESTRUCTIVE.value == "destructive"


class TestSafetyErrors:
    """Test safety error classes."""

    def test_safety_error_is_exception(self) -> None:
        """Test SafetyError is an Exception."""
        err = SafetyError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"

    def test_protected_device_error_inherits(self) -> None:
        """Test ProtectedDeviceError inherits from SafetyError."""
        err = ProtectedDeviceError("protected device")
        assert isinstance(err, SafetyError)
        assert isinstance(err, Exception)

    def test_multi_card_warning_inherits(self) -> None:
        """Test MultiCardWarning inherits from SafetyError."""
        err = MultiCardWarningError("multiple cards")
        assert isinstance(err, SafetyError)

    def test_device_verification_error_inherits(self) -> None:
        """Test DeviceVerificationError inherits from SafetyError."""
        err = DeviceVerificationError("verification failed")
        assert isinstance(err, SafetyError)


class TestSafetyCheckResult:
    """Test SafetyCheckResult dataclass."""

    def test_creation_with_defaults(self) -> None:
        """Test creating SafetyCheckResult with minimal args."""
        result = SafetyCheckResult(
            passed=True,
            warnings=[],
            errors=[],
        )
        assert result.passed is True
        assert result.warnings == []
        assert result.errors == []
        assert result.device_entry is None
        assert result.openpgp_state is None

    def test_creation_with_all_fields(self) -> None:
        """Test creating SafetyCheckResult with all fields."""
        entry = DeviceEntry(serial="12345678")
        state = OpenPGPState()

        result = SafetyCheckResult(
            passed=False,
            warnings=["Warning 1", "Warning 2"],
            errors=["Error 1"],
            device_entry=entry,
            openpgp_state=state,
        )

        assert result.passed is False
        assert len(result.warnings) == 2
        assert len(result.errors) == 1
        assert result.device_entry == entry
        assert result.openpgp_state == state

    def test_can_proceed_no_errors(self) -> None:
        """Test can_proceed returns True when no errors."""
        result = SafetyCheckResult(
            passed=True,
            warnings=["Some warning"],
            errors=[],
        )
        assert result.can_proceed is True

    def test_can_proceed_with_errors(self) -> None:
        """Test can_proceed returns False when errors exist."""
        result = SafetyCheckResult(
            passed=False,
            warnings=[],
            errors=["Critical error"],
        )
        assert result.can_proceed is False

    def test_can_proceed_multiple_errors(self) -> None:
        """Test can_proceed with multiple errors."""
        result = SafetyCheckResult(
            passed=False,
            warnings=["Warning"],
            errors=["Error 1", "Error 2", "Error 3"],
        )
        assert result.can_proceed is False


class TestSafetyGuard:
    """Test SafetyGuard class."""

    @pytest.fixture
    def mock_inventory(self) -> MagicMock:
        """Create mock inventory."""
        inventory = MagicMock(spec=Inventory)
        inventory.get.return_value = None
        return inventory

    @pytest.fixture
    def mock_yubikey_ops(self) -> MagicMock:
        """Create mock YubiKeyOperations."""
        ops = MagicMock()
        ops.list_devices.return_value = []
        ops._run_ykman.return_value = MagicMock(returncode=1, stdout="")
        return ops

    @pytest.fixture
    def safety_guard(self, mock_inventory: MagicMock, mock_yubikey_ops: MagicMock) -> SafetyGuard:
        """Create SafetyGuard with mocks."""
        return SafetyGuard(mock_inventory, mock_yubikey_ops)

    def test_init_with_defaults(
        self, mock_inventory: MagicMock, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test SafetyGuard initialization with default console."""
        guard = SafetyGuard(mock_inventory, mock_yubikey_ops)
        assert guard._inventory == mock_inventory
        assert guard._yubikey_ops == mock_yubikey_ops
        assert guard._single_card_mode is False

    def test_init_with_custom_console(
        self, mock_inventory: MagicMock, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test SafetyGuard initialization with custom console."""
        mock_console = MagicMock()
        guard = SafetyGuard(mock_inventory, mock_yubikey_ops, console=mock_console)
        assert guard._console == mock_console

    def test_enable_single_card_mode(self, safety_guard: SafetyGuard) -> None:
        """Test enabling single-card mode."""
        assert safety_guard._single_card_mode is False
        safety_guard.enable_single_card_mode()
        assert safety_guard._single_card_mode is True

    def test_disable_single_card_mode(self, safety_guard: SafetyGuard) -> None:
        """Test disabling single-card mode."""
        safety_guard._single_card_mode = True
        safety_guard.disable_single_card_mode()
        assert safety_guard._single_card_mode is False

    def test_check_device_read_only_no_warnings(self, safety_guard: SafetyGuard) -> None:
        """Test check_device for read-only operation with no issues."""
        result = safety_guard.check_device("12345678", SafetyLevel.READ_ONLY, "List devices")

        assert result.passed is True
        assert result.can_proceed is True
        # Read-only doesn't add errors for protected devices or multi-card

    def test_check_device_protected_device_moderate(
        self, safety_guard: SafetyGuard, mock_inventory: MagicMock
    ) -> None:
        """Test check_device blocks moderate operations on protected device."""
        protected_entry = DeviceEntry(serial="12345678", protected=True, label="My Protected Key")
        mock_inventory.get.return_value = protected_entry

        result = safety_guard.check_device("12345678", SafetyLevel.MODERATE, "Change PIN")

        assert result.passed is False
        assert len(result.errors) == 1
        assert "PROTECTED" in result.errors[0]
        assert "My Protected Key" in result.errors[0]

    def test_check_device_protected_device_destructive(
        self, safety_guard: SafetyGuard, mock_inventory: MagicMock
    ) -> None:
        """Test check_device blocks destructive operations on protected device."""
        protected_entry = DeviceEntry(serial="12345678", protected=True)
        mock_inventory.get.return_value = protected_entry

        result = safety_guard.check_device("12345678", SafetyLevel.DESTRUCTIVE, "Reset device")

        assert result.passed is False
        assert any("PROTECTED" in e for e in result.errors)

    def test_check_device_protected_device_read_only_allowed(
        self, safety_guard: SafetyGuard, mock_inventory: MagicMock
    ) -> None:
        """Test check_device allows read-only operations on protected device."""
        protected_entry = DeviceEntry(serial="12345678", protected=True)
        mock_inventory.get.return_value = protected_entry

        result = safety_guard.check_device("12345678", SafetyLevel.READ_ONLY, "Show info")

        # Read-only should be allowed even on protected devices
        assert result.passed is True
        assert len(result.errors) == 0

    def test_check_device_multi_card_warning_destructive(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device warns about multiple cards for destructive ops."""
        # Multiple devices connected
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
            YubiKeyInfo(
                serial="87654321",
                version="5.4.3",
                form_factor="USB-A",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]

        result = safety_guard.check_device("12345678", SafetyLevel.DESTRUCTIVE, "Reset device")

        # Should add warning (not error) about multiple cards
        assert len(result.warnings) >= 1
        assert any("2 YubiKeys connected" in w for w in result.warnings)
        assert "87654321" in result.warnings[0]  # Lists other device

    def test_check_device_multi_card_single_card_mode_error(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device errors in single-card mode with multiple cards."""
        safety_guard.enable_single_card_mode()
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
            YubiKeyInfo(
                serial="87654321",
                version="5.4.3",
                form_factor="USB-A",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]

        result = safety_guard.check_device("12345678", SafetyLevel.DESTRUCTIVE, "Reset device")

        # Should be an error, not just warning
        assert len(result.errors) >= 1
        assert any("Single-card mode" in e for e in result.errors)

    def test_check_device_existing_keys_warning(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device warns about existing keys for destructive ops."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]
        # Simulate successful openpgp info with keys
        mock_yubikey_ops._run_ykman.return_value = MagicMock(
            returncode=0,
            stdout="""
OpenPGP version: 3.4
Signature key:
  Fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
Decryption key:
  Fingerprint: FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000
Authentication key:
  Fingerprint: Not set
PIN tries remaining: 3
Admin PIN tries remaining: 3
""",
        )

        result = safety_guard.check_device("12345678", SafetyLevel.DESTRUCTIVE, "Reset device")

        # Should warn about existing keys
        assert len(result.warnings) >= 1
        assert any("DESTROYED" in w for w in result.warnings)

    def test_check_device_pin_blocked_warning(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device warns when PIN is blocked."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]
        mock_yubikey_ops._run_ykman.return_value = MagicMock(
            returncode=0,
            stdout="""
PIN tries remaining: 0
Admin PIN tries remaining: 3
""",
        )

        result = safety_guard.check_device("12345678", SafetyLevel.MODERATE, "Some operation")

        assert len(result.warnings) >= 1
        assert any("BLOCKED" in w for w in result.warnings)

    def test_check_device_low_pin_tries_warning(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device warns when PIN tries are low."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]
        mock_yubikey_ops._run_ykman.return_value = MagicMock(
            returncode=0,
            stdout="""
PIN tries remaining: 1
Admin PIN tries remaining: 3
""",
        )

        result = safety_guard.check_device("12345678", SafetyLevel.MODERATE, "Some operation")

        assert len(result.warnings) >= 1
        assert any("1 try remaining" in w for w in result.warnings)

    def test_check_device_low_admin_pin_tries_warning(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device warns when admin PIN tries are low."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]
        mock_yubikey_ops._run_ykman.return_value = MagicMock(
            returncode=0,
            stdout="""
PIN tries remaining: 3
Admin PIN tries remaining: 1
""",
        )

        result = safety_guard.check_device("12345678", SafetyLevel.MODERATE, "Some operation")

        assert len(result.warnings) >= 1
        assert any("Admin PIN has only 1" in w for w in result.warnings)

    def test_check_device_openpgp_query_fails_adds_warning(
        self, safety_guard: SafetyGuard, mock_yubikey_ops: MagicMock
    ) -> None:
        """Test check_device adds warning when openpgp query fails."""
        mock_yubikey_ops._run_ykman.side_effect = Exception("Connection error")

        result = safety_guard.check_device("12345678", SafetyLevel.READ_ONLY, "List info")

        assert any("Could not query OpenPGP state" in w for w in result.warnings)


class TestSafetyGuardDisplayCheckResult:
    """Test SafetyGuard.display_check_result method."""

    @pytest.fixture
    def safety_guard_with_mock_console(self) -> tuple[SafetyGuard, MagicMock]:
        """Create SafetyGuard with mock console."""
        mock_console = MagicMock()
        mock_inventory = MagicMock(spec=Inventory)
        mock_yubikey_ops = MagicMock()
        guard = SafetyGuard(mock_inventory, mock_yubikey_ops, console=mock_console)
        return guard, mock_console

    def test_display_with_device_entry(
        self, safety_guard_with_mock_console: tuple[SafetyGuard, MagicMock]
    ) -> None:
        """Test display uses device entry display name."""
        guard, mock_console = safety_guard_with_mock_console
        entry = DeviceEntry(serial="12345678", label="My Work Key")
        result = SafetyCheckResult(passed=True, warnings=[], errors=[], device_entry=entry)

        guard.display_check_result(result, "12345678", "Test operation")

        # Should have printed something
        assert mock_console.print.called

    def test_display_without_device_entry(
        self, safety_guard_with_mock_console: tuple[SafetyGuard, MagicMock]
    ) -> None:
        """Test display uses serial when no device entry."""
        guard, mock_console = safety_guard_with_mock_console
        result = SafetyCheckResult(passed=True, warnings=[], errors=[])

        guard.display_check_result(result, "12345678", "Test operation")

        assert mock_console.print.called

    def test_display_with_warnings(
        self, safety_guard_with_mock_console: tuple[SafetyGuard, MagicMock]
    ) -> None:
        """Test display shows warnings."""
        guard, mock_console = safety_guard_with_mock_console
        result = SafetyCheckResult(passed=True, warnings=["Warning 1", "Warning 2"], errors=[])

        guard.display_check_result(result, "12345678", "Test operation")

        # Should print warnings
        assert mock_console.print.call_count >= 2

    def test_display_with_errors(
        self, safety_guard_with_mock_console: tuple[SafetyGuard, MagicMock]
    ) -> None:
        """Test display shows errors."""
        guard, mock_console = safety_guard_with_mock_console
        result = SafetyCheckResult(passed=False, warnings=[], errors=["Critical error"])

        guard.display_check_result(result, "12345678", "Test operation")

        # Should print errors
        assert mock_console.print.called

    def test_display_with_openpgp_state(
        self, safety_guard_with_mock_console: tuple[SafetyGuard, MagicMock]
    ) -> None:
        """Test display shows OpenPGP state info."""
        guard, mock_console = safety_guard_with_mock_console
        state = OpenPGPState(pin_tries_remaining=2)
        result = SafetyCheckResult(passed=True, warnings=[], errors=[], openpgp_state=state)

        guard.display_check_result(result, "12345678", "Test operation")

        assert mock_console.print.called


class TestSafetyGuardRequireConfirmation:
    """Test SafetyGuard.require_confirmation method."""

    @pytest.fixture
    def safety_guard_for_confirmation(self) -> tuple[SafetyGuard, MagicMock, MagicMock]:
        """Create SafetyGuard for confirmation tests."""
        mock_console = MagicMock()
        mock_inventory = MagicMock(spec=Inventory)
        mock_inventory.get.return_value = None
        mock_yubikey_ops = MagicMock()
        mock_yubikey_ops.list_devices.return_value = []
        mock_yubikey_ops._run_ykman.return_value = MagicMock(returncode=1)
        guard = SafetyGuard(mock_inventory, mock_yubikey_ops, console=mock_console)
        return guard, mock_inventory, mock_yubikey_ops

    def test_require_confirmation_fails_on_safety_check_error(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation returns error when safety check fails."""
        guard, mock_inventory, _ = safety_guard_for_confirmation
        # Set up protected device
        mock_inventory.get.return_value = DeviceEntry(serial="12345678", protected=True)

        result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_err()
        assert "Safety checks failed" in str(result.unwrap_err())

    def test_require_confirmation_destructive_user_confirms(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation succeeds when user confirms destructive op."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("builtins.input", return_value="5678"):  # Last 4 digits
            result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_ok()
        assert result.unwrap() is True

    def test_require_confirmation_destructive_user_declines(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation returns False when user gives wrong input."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("builtins.input", return_value="wrong"):
            result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_ok()
        assert result.unwrap() is False

    def test_require_confirmation_destructive_eof_error(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation handles EOF during input."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("builtins.input", side_effect=EOFError):
            result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_ok()
        assert result.unwrap() is False

    def test_require_confirmation_destructive_keyboard_interrupt(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation handles keyboard interrupt."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_ok()
        assert result.unwrap() is False

    def test_require_confirmation_moderate_user_confirms(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation for moderate operation with Confirm.ask."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("rich.prompt.Confirm.ask", return_value=True):
            result = guard.require_confirmation("12345678", "Change PIN", SafetyLevel.MODERATE)

        assert result.is_ok()
        assert result.unwrap() is True

    def test_require_confirmation_moderate_user_declines(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation for moderate operation when user declines."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("rich.prompt.Confirm.ask", return_value=False):
            result = guard.require_confirmation("12345678", "Change PIN", SafetyLevel.MODERATE)

        assert result.is_ok()
        assert result.unwrap() is False

    def test_require_confirmation_with_extra_message(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation displays extra message."""
        guard, _, _ = safety_guard_for_confirmation

        with patch("builtins.input", return_value="5678"):
            result = guard.require_confirmation(
                "12345678",
                "Reset device",
                SafetyLevel.DESTRUCTIVE,
                extra_message="All data will be lost!",
            )

        assert result.is_ok()

    def test_require_confirmation_uses_device_entry_name(
        self, safety_guard_for_confirmation: tuple[SafetyGuard, MagicMock, MagicMock]
    ) -> None:
        """Test require_confirmation uses device entry display name."""
        guard, mock_inventory, _ = safety_guard_for_confirmation
        mock_inventory.get.return_value = DeviceEntry(
            serial="12345678", label="My Work Key", protected=False
        )

        with patch("builtins.input", return_value="5678"):
            result = guard.require_confirmation("12345678", "Reset device", SafetyLevel.DESTRUCTIVE)

        assert result.is_ok()


class TestListConnectedDevicesSafely:
    """Test list_connected_devices_safely function."""

    def test_list_empty_devices(self) -> None:
        """Test listing when no devices connected."""
        mock_yubikey_ops = MagicMock()
        mock_yubikey_ops.list_devices.return_value = []
        mock_inventory = MagicMock(spec=Inventory)

        result = list_connected_devices_safely(mock_yubikey_ops, mock_inventory)

        assert result == []
        mock_inventory.save.assert_called_once()

    def test_list_single_device(self) -> None:
        """Test listing a single connected device."""
        mock_yubikey_ops = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        mock_yubikey_ops.list_devices.return_value = [device]
        mock_yubikey_ops._run_ykman.return_value = MagicMock(returncode=1)

        mock_inventory = MagicMock(spec=Inventory)
        mock_entry = DeviceEntry(serial="12345678")
        mock_inventory.get_or_create.return_value = mock_entry

        result = list_connected_devices_safely(mock_yubikey_ops, mock_inventory)

        assert len(result) == 1
        assert result[0][0] == device
        assert result[0][1] == mock_entry
        mock_inventory.save.assert_called_once()

    def test_list_multiple_devices(self) -> None:
        """Test listing multiple connected devices."""
        mock_yubikey_ops = MagicMock()
        devices = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
            YubiKeyInfo(
                serial="87654321",
                version="5.4.3",
                form_factor="USB-A",
                has_openpgp=True,
                openpgp_version="3.4",
            ),
        ]
        mock_yubikey_ops.list_devices.return_value = devices
        mock_yubikey_ops._run_ykman.return_value = MagicMock(returncode=1)

        mock_inventory = MagicMock(spec=Inventory)
        mock_inventory.get_or_create.side_effect = [
            DeviceEntry(serial="12345678"),
            DeviceEntry(serial="87654321"),
        ]

        result = list_connected_devices_safely(mock_yubikey_ops, mock_inventory)

        assert len(result) == 2
        mock_inventory.save.assert_called_once()

    def test_list_device_with_openpgp_state(self) -> None:
        """Test listing device with OpenPGP state."""
        mock_yubikey_ops = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        mock_yubikey_ops.list_devices.return_value = [device]
        mock_yubikey_ops._run_ykman.return_value = MagicMock(
            returncode=0,
            stdout="""
PIN tries remaining: 3
Admin PIN tries remaining: 3
""",
        )

        mock_inventory = MagicMock(spec=Inventory)
        mock_entry = DeviceEntry(serial="12345678")
        mock_inventory.get_or_create.return_value = mock_entry

        result = list_connected_devices_safely(mock_yubikey_ops, mock_inventory)

        assert len(result) == 1
        # Should have parsed OpenPGP state
        assert result[0][2] is not None

    def test_list_device_openpgp_query_fails(self) -> None:
        """Test listing continues when OpenPGP query fails."""
        mock_yubikey_ops = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        mock_yubikey_ops.list_devices.return_value = [device]
        mock_yubikey_ops._run_ykman.side_effect = Exception("Connection error")

        mock_inventory = MagicMock(spec=Inventory)
        mock_entry = DeviceEntry(serial="12345678")
        mock_inventory.get_or_create.return_value = mock_entry

        result = list_connected_devices_safely(mock_yubikey_ops, mock_inventory)

        assert len(result) == 1
        assert result[0][2] is None  # No OpenPGP state

    def test_list_with_custom_console(self) -> None:
        """Test listing with custom console."""
        mock_yubikey_ops = MagicMock()
        mock_yubikey_ops.list_devices.return_value = []
        mock_inventory = MagicMock(spec=Inventory)
        mock_console = MagicMock()

        result = list_connected_devices_safely(
            mock_yubikey_ops, mock_inventory, console=mock_console
        )

        assert result == []


class TestDisplayDeviceTable:
    """Test display_device_table function."""

    def test_display_empty_list(self) -> None:
        """Test displaying empty device list."""
        mock_console = MagicMock()
        display_device_table([], console=mock_console)
        mock_console.print.assert_called()

    def test_display_single_device(self) -> None:
        """Test displaying single device."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678", label="My Key")
        state = OpenPGPState(pin_tries_remaining=3)

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_device_with_keys(self) -> None:
        """Test displaying device with keys loaded."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678")
        state = OpenPGPState(
            signature_key=KeySlotInfo(fingerprint="AAAA1111BBBB2222"),
        )

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_device_with_blocked_pin(self) -> None:
        """Test displaying device with blocked PIN."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678")
        state = OpenPGPState(pin_tries_remaining=0)

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_device_with_low_pin_tries(self) -> None:
        """Test displaying device with low PIN tries."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678")
        state = OpenPGPState(pin_tries_remaining=1)

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_protected_device(self) -> None:
        """Test displaying protected device."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678", protected=True)
        state = OpenPGPState()

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_device_no_entry(self) -> None:
        """Test displaying device without inventory entry."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        devices = [(device, None, None)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_device_no_state(self) -> None:
        """Test displaying device without OpenPGP state."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678")

        devices = [(device, entry, None)]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_multiple_devices(self) -> None:
        """Test displaying multiple devices."""
        mock_console = MagicMock()
        devices = [
            (
                YubiKeyInfo(
                    serial="12345678",
                    version="5.4.3",
                    form_factor="USB-C",
                    has_openpgp=True,
                    openpgp_version="3.4",
                ),
                DeviceEntry(serial="12345678", label="Key 1"),
                OpenPGPState(),
            ),
            (
                YubiKeyInfo(
                    serial="87654321",
                    version="5.4.3",
                    form_factor="USB-A",
                    has_openpgp=True,
                    openpgp_version="3.4",
                ),
                DeviceEntry(serial="87654321", label="Key 2"),
                OpenPGPState(),
            ),
        ]
        display_device_table(devices, console=mock_console)

        mock_console.print.assert_called()

    def test_display_with_fingerprints(self) -> None:
        """Test displaying with fingerprints enabled."""
        mock_console = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        entry = DeviceEntry(serial="12345678")
        state = OpenPGPState(
            signature_key=KeySlotInfo(fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"),
            encryption_key=KeySlotInfo(fingerprint="FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000"),
            authentication_key=KeySlotInfo(fingerprint="KKKK1111LLLL2222MMMM3333NNNN4444OOOO5555"),
        )

        devices = [(device, entry, state)]
        display_device_table(devices, console=mock_console, show_fingerprints=True)

        mock_console.print.assert_called()
