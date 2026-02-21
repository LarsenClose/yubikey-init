"""Tests for the TUI controller module."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from yubikey_init.inventory import Inventory
from yubikey_init.tui.controller import (
    DeviceDisplayInfo,
    KeyDisplayInfo,
    TUIController,
    TUIState,
)
from yubikey_init.types import CardStatus, KeyInfo, KeyType, Result, YubiKeyInfo


class TestTUIState:
    """Tests for the TUIState dataclass."""

    def test_init_defaults(self) -> None:
        """Test TUIState initializes with correct defaults."""
        state = TUIState()
        assert state.screen_stack == []
        assert state.selected_device is None
        assert state.selected_key is None
        assert state.last_refresh is not None

    def test_push_screen(self) -> None:
        """Test pushing screens onto the navigation stack."""
        state = TUIState()
        state.push_screen("main_menu")
        state.push_screen("device_list")

        assert state.screen_stack == ["main_menu", "device_list"]
        assert state.current_screen == "device_list"

    def test_pop_screen(self) -> None:
        """Test popping screens from the navigation stack."""
        state = TUIState()
        state.push_screen("main_menu")
        state.push_screen("device_list")

        result = state.pop_screen()
        assert result == "device_list"
        assert state.screen_stack == ["main_menu"]
        assert state.current_screen == "main_menu"

    def test_pop_empty_stack(self) -> None:
        """Test popping from empty stack returns None."""
        state = TUIState()
        result = state.pop_screen()
        assert result is None

    def test_current_screen_empty_stack(self) -> None:
        """Test current_screen returns None for empty stack."""
        state = TUIState()
        assert state.current_screen is None


class TestDeviceDisplayInfo:
    """Tests for the DeviceDisplayInfo dataclass."""

    def test_display_name_with_label(self) -> None:
        """Test display_name returns label when set."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label="Work Key",
            device_type="YubiKey 5C",
            firmware_version="5.4.3",
            form_factor="USB-C",
            has_keys=True,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.display_name == "Work Key (12345678)"

    def test_display_name_with_device_type(self) -> None:
        """Test display_name returns device type when no label."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type="YubiKey 5C",
            firmware_version="5.4.3",
            form_factor="USB-C",
            has_keys=True,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.display_name == "YubiKey 5C (12345678)"

    def test_display_name_fallback(self) -> None:
        """Test display_name falls back to generic name."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.display_name == "YubiKey (12345678)"

    def test_status_text_blocked(self) -> None:
        """Test status_text shows BLOCKED when device is blocked."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=0,
            admin_pin_tries_remaining=3,
            is_blocked=True,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.status_text == "BLOCKED"

    def test_status_text_ready(self) -> None:
        """Test status_text shows Ready when device has keys."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=True,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.status_text == "Ready"

    def test_status_text_empty(self) -> None:
        """Test status_text shows Empty when device has no keys."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.status_text == "Empty"

    def test_status_indicator_blocked(self) -> None:
        """Test status_indicator shows ! for blocked device."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=0,
            admin_pin_tries_remaining=3,
            is_blocked=True,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.status_indicator == "!"

    def test_status_indicator_normal(self) -> None:
        """Test status_indicator shows + for normal device."""
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        assert device.status_indicator == "+"


class TestKeyDisplayInfo:
    """Tests for the KeyDisplayInfo dataclass."""

    def test_short_key_id(self) -> None:
        """Test short_key_id returns last 8 characters."""
        key = KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            is_expired=False,
            days_until_expiry=None,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.short_key_id == "34567890"

    def test_short_key_id_short_input(self) -> None:
        """Test short_key_id handles short key IDs."""
        key = KeyDisplayInfo(
            key_id="ABCD",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            is_expired=False,
            days_until_expiry=None,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.short_key_id == "ABCD"

    def test_expiry_status_never(self) -> None:
        """Test expiry_status shows Never for no expiry."""
        key = KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            is_expired=False,
            days_until_expiry=None,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.expiry_status == "Never"

    def test_expiry_status_expired(self) -> None:
        """Test expiry_status shows EXPIRED for expired keys."""
        key = KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=datetime(2020, 1, 1, tzinfo=UTC),
            is_expired=True,
            days_until_expiry=None,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.expiry_status == "EXPIRED"

    def test_expiry_status_soon(self) -> None:
        """Test expiry_status shows days when expiring soon."""
        key = KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=datetime(2030, 1, 1, tzinfo=UTC),
            is_expired=False,
            days_until_expiry=15,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.expiry_status == "15 days"

    def test_expiry_status_date(self) -> None:
        """Test expiry_status shows date when not soon."""
        expiry = datetime(2030, 6, 15, tzinfo=UTC)
        key = KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123",
            identity="Test User <test@example.com>",
            creation_date=datetime.now(UTC),
            expiry_date=expiry,
            is_expired=False,
            days_until_expiry=100,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        )
        assert key.expiry_status == "2030-06-15"


class TestTUIController:
    """Tests for the TUIController class."""

    @pytest.fixture
    def mock_yubikey_ops(self) -> MagicMock:
        """Create a mock YubiKey operations instance."""
        mock = MagicMock()
        mock.list_devices.return_value = []
        mock.get_card_status.return_value = Result.ok(
            CardStatus(
                serial="12345678",
                signature_key=None,
                encryption_key=None,
                authentication_key=None,
                signature_count=0,
                pin_retries=3,
                admin_pin_retries=3,
            )
        )
        return mock

    @pytest.fixture
    def mock_gpg_ops(self) -> MagicMock:
        """Create a mock GPG operations instance."""
        mock = MagicMock()
        mock.list_secret_keys.return_value = Result.ok([])
        return mock

    @pytest.fixture
    def mock_inventory(self, tmp_path) -> Inventory:
        """Create a mock inventory."""
        inventory = Inventory(path=tmp_path / "inventory.json")
        return inventory

    @pytest.fixture
    def controller(self, mock_yubikey_ops, mock_gpg_ops, mock_inventory) -> TUIController:
        """Create a TUI controller with mocked dependencies."""
        return TUIController(
            yubikey_ops=mock_yubikey_ops,
            gpg_ops=mock_gpg_ops,
            inventory=mock_inventory,
        )

    def test_init(self, controller: TUIController) -> None:
        """Test controller initialization."""
        assert controller.yubikey_ops is not None
        assert controller.gpg_ops is not None
        assert controller.inventory is not None
        assert isinstance(controller.state, TUIState)

    def test_get_devices_empty(self, controller: TUIController) -> None:
        """Test get_devices with no connected devices."""
        devices = controller.get_devices()
        assert devices == []

    def test_get_devices_with_device(self, controller: TUIController, mock_yubikey_ops) -> None:
        """Test get_devices with connected device."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            )
        ]

        devices = controller.get_devices()
        assert len(devices) == 1
        assert devices[0].serial == "12345678"

    def test_get_device_detail_found(self, controller: TUIController, mock_yubikey_ops) -> None:
        """Test get_device_detail finds a device."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            )
        ]

        device = controller.get_device_detail("12345678")
        assert device is not None
        assert device.serial == "12345678"

    def test_get_device_detail_not_found(self, controller: TUIController) -> None:
        """Test get_device_detail returns None for unknown device."""
        device = controller.get_device_detail("99999999")
        assert device is None

    def test_get_keys_empty(self, controller: TUIController) -> None:
        """Test get_keys with no keys."""
        keys = controller.get_keys()
        assert keys == []

    def test_get_keys_with_key(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_keys with keys in keyring."""
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        keys = controller.get_keys()
        assert len(keys) == 1
        assert keys[0].key_id == "ABCDEF1234567890"
        assert keys[0].identity == "Test User <test@example.com>"

    def test_get_key_detail_found(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_key_detail finds a key."""
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        key = controller.get_key_detail("ABCDEF1234567890")
        assert key is not None
        assert key.key_id == "ABCDEF1234567890"

    def test_get_key_detail_partial_match(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_key_detail finds key by partial ID."""
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        key = controller.get_key_detail("34567890")
        assert key is not None
        assert key.key_id == "ABCDEF1234567890"

    def test_get_key_detail_not_found(self, controller: TUIController) -> None:
        """Test get_key_detail returns None for unknown key."""
        key = controller.get_key_detail("UNKNOWN")
        assert key is None

    def test_reset_device_protected(self, controller: TUIController, mock_inventory) -> None:
        """Test reset_device fails for protected device."""
        # Create the entry and set it as protected
        mock_inventory.get_or_create("12345678")
        mock_inventory.set_protected("12345678", True)

        result = controller.reset_device("12345678")
        assert result.is_err()
        assert "protected" in str(result.unwrap_err()).lower()

    def test_label_device(self, controller: TUIController, mock_inventory) -> None:
        """Test label_device sets device label."""
        # First create the entry
        mock_inventory.get_or_create("12345678")

        result = controller.label_device("12345678", "Work Key")
        assert result.is_ok()

        entry = mock_inventory.get("12345678")
        assert entry is not None
        assert entry.label == "Work Key"

    def test_protect_device(self, controller: TUIController, mock_inventory) -> None:
        """Test protect_device sets protection status."""
        # First create the entry
        mock_inventory.get_or_create("12345678")

        result = controller.protect_device("12345678", True)
        assert result.is_ok()
        assert mock_inventory.is_protected("12345678")

    def test_set_device_notes(self, controller: TUIController, mock_inventory) -> None:
        """Test set_device_notes sets device notes."""
        # First create the entry
        mock_inventory.get_or_create("12345678")

        result = controller.set_device_notes("12345678", "Test notes")
        assert result.is_ok()

        entry = mock_inventory.get("12345678")
        assert entry is not None
        assert entry.notes == "Test notes"

    def test_refresh(self, controller: TUIController) -> None:
        """Test refresh updates the last_refresh timestamp."""
        old_refresh = controller.state.last_refresh
        controller.refresh()
        assert controller.state.last_refresh >= old_refresh

    def test_run_diagnostics(self, controller: TUIController) -> None:
        """Test run_diagnostics returns diagnostic results."""
        with patch("yubikey_init.diagnostics.run_diagnostics") as mock_diag:
            mock_result = MagicMock()
            mock_result.gpg_info = {"installed": True, "version": "2.4.0"}
            mock_result.yubikey_info = {"devices": []}
            mock_result.issues = []
            mock_diag.return_value = mock_result

            results = controller.run_diagnostics()
            assert "gpg" in results
            assert results["gpg"] == (True, "GPG 2.4.0")

    def test_alias_methods(self, controller: TUIController) -> None:
        """Test alias methods for screen compatibility."""
        # get_device is alias for get_device_detail
        assert controller.get_device("12345678") is None

        # First create the entry for label and protect tests
        controller.inventory.get_or_create("12345678")

        # set_device_label is alias for label_device
        result = controller.set_device_label("12345678", "Test")
        assert result.is_ok()

        # set_device_protected is alias for protect_device
        result = controller.set_device_protected("12345678", True)
        assert result.is_ok()

        # get_key_info is alias for get_key_detail
        assert controller.get_key_info("UNKNOWN") is None

    def test_export_ssh_key_no_key_selected(self, controller: TUIController) -> None:
        """Test export_ssh_key fails when no key is selected."""
        result = controller.export_ssh_key()
        assert result.is_err()
        assert "No key selected" in str(result.unwrap_err())

    def test_export_ssh_key_with_key_id(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test export_ssh_key with explicit key ID."""
        mock_gpg_ops.export_ssh_key.return_value = Result.ok("ssh-rsa AAAA...")

        result = controller.export_ssh_key(key_id="ABCDEF1234567890")
        assert result.is_ok()
        assert result.unwrap() == "ssh-rsa AAAA..."
        mock_gpg_ops.export_ssh_key.assert_called_once_with("ABCDEF1234567890")

    def test_export_ssh_key_with_selected_key(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test export_ssh_key uses selected key from state."""
        controller.state.selected_key = "ABCDEF1234567890"
        mock_gpg_ops.export_ssh_key.return_value = Result.ok("ssh-rsa AAAA...")

        result = controller.export_ssh_key()
        assert result.is_ok()
        mock_gpg_ops.export_ssh_key.assert_called_once_with("ABCDEF1234567890")

    def test_get_key_fingerprint_no_key_selected(self, controller: TUIController) -> None:
        """Test get_key_fingerprint fails when no key is selected."""
        result = controller.get_key_fingerprint()
        assert result.is_err()
        assert "No key selected" in str(result.unwrap_err())

    def test_get_key_fingerprint_with_key_id(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_key_fingerprint with explicit key ID."""
        mock_gpg_ops.get_key_fingerprint.return_value = Result.ok("ABCDEF1234567890ABCDEF1234567890")

        result = controller.get_key_fingerprint(key_id="ABCDEF1234567890")
        assert result.is_ok()
        mock_gpg_ops.get_key_fingerprint.assert_called_once_with("ABCDEF1234567890")

    def test_get_key_fingerprint_with_selected_key(
        self, controller: TUIController, mock_gpg_ops
    ) -> None:
        """Test get_key_fingerprint uses selected key from state."""
        controller.state.selected_key = "ABCDEF1234567890"
        mock_gpg_ops.get_key_fingerprint.return_value = Result.ok("FP1234567890")

        result = controller.get_key_fingerprint()
        assert result.is_ok()
        mock_gpg_ops.get_key_fingerprint.assert_called_once_with("ABCDEF1234567890")

    def test_get_subkeys_no_keys(self, controller: TUIController) -> None:
        """Test get_subkeys returns empty list when no keys."""
        subkeys = controller.get_subkeys("ABCDEF1234567890")
        assert subkeys == []

    def test_get_subkeys_key_not_found(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_subkeys returns empty list when key not found."""
        mock_gpg_ops.list_secret_keys.return_value = Result.ok([])

        subkeys = controller.get_subkeys("NONEXISTENT")
        assert subkeys == []

    def test_get_subkeys_with_key(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_subkeys returns empty list when key has no subkeys attr."""
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        subkeys = controller.get_subkeys("ABCDEF1234567890")
        assert subkeys == []

    def test_get_subkeys_gpg_error(self, controller: TUIController, mock_gpg_ops) -> None:
        """Test get_subkeys returns empty list on GPG error."""
        mock_gpg_ops.list_secret_keys.return_value = Result.err(Exception("GPG failure"))

        subkeys = controller.get_subkeys("ABCDEF1234567890")
        assert subkeys == []

    def test_get_key_device_mapping_empty(self, controller: TUIController) -> None:
        """Test get_key_device_mapping with no keys returns empty dict."""
        mapping = controller.get_key_device_mapping()
        assert mapping == {}

    def test_get_key_device_mapping_with_key_on_yubikey(
        self, controller: TUIController, mock_gpg_ops, mock_inventory
    ) -> None:
        """Test get_key_device_mapping maps key to device."""
        # Create inventory entry with provisioned identity
        entry = mock_inventory.get_or_create("12345678")
        entry.provisioned_identity = "Test User <test@example.com>"
        mock_inventory.save()

        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        mapping = controller.get_key_device_mapping()
        assert "ABCDEF1234567890" in mapping
        assert mapping["ABCDEF1234567890"] == "12345678"

    def test_run_diagnostics_error_path(self, controller: TUIController) -> None:
        """Test run_diagnostics handles exceptions gracefully."""
        with patch("yubikey_init.diagnostics.run_diagnostics") as mock_diag:
            mock_diag.side_effect = Exception("Diagnostics failed")

            results = controller.run_diagnostics()
            assert "diagnostics" in results
            assert results["diagnostics"][0] is False

    def test_run_diagnostics_no_yubikeys(self, controller: TUIController) -> None:
        """Test run_diagnostics when no YubiKeys detected."""
        with patch("yubikey_init.diagnostics.run_diagnostics") as mock_diag:
            mock_result = MagicMock()
            mock_result.gpg_info = {"installed": False, "version": None}
            mock_result.yubikey_info = {"devices": []}
            mock_result.issues = ["Some issue"]
            mock_diag.return_value = mock_result

            results = controller.run_diagnostics()
            assert results["gpg"][0] is False
            assert results["yubikey"][0] is False
            assert results["issues"][0] is False

    def test_reset_device_success(
        self, controller: TUIController, mock_yubikey_ops, mock_inventory
    ) -> None:
        """Test reset_device succeeds for non-protected device."""
        mock_inventory.get_or_create("12345678")
        mock_yubikey_ops.reset_openpgp.return_value = Result.ok(None)

        result = controller.reset_device("12345678")
        assert result.is_ok()
        mock_yubikey_ops.reset_openpgp.assert_called_once_with("12345678")

    def test_reset_device_not_in_inventory(
        self, controller: TUIController, mock_yubikey_ops
    ) -> None:
        """Test reset_device works even when device not in inventory."""
        mock_yubikey_ops.reset_openpgp.return_value = Result.ok(None)

        result = controller.reset_device("99999999")
        assert result.is_ok()

    def test_label_device_with_empty_string(
        self, controller: TUIController, mock_inventory
    ) -> None:
        """Test label_device with empty string clears label."""
        mock_inventory.get_or_create("12345678")
        mock_inventory.set_label("12345678", "Old Label")

        result = controller.label_device("12345678", "")
        assert result.is_ok()

    def test_set_device_notes_with_empty_string(
        self, controller: TUIController, mock_inventory
    ) -> None:
        """Test set_device_notes with empty string clears notes."""
        mock_inventory.get_or_create("12345678")
        mock_inventory.set_notes("12345678", "Old notes")

        result = controller.set_device_notes("12345678", "")
        assert result.is_ok()

    def test_get_keys_with_expired_key(
        self, controller: TUIController, mock_gpg_ops
    ) -> None:
        """Test get_keys correctly identifies expired keys."""
        past_date = datetime(2020, 1, 1, tzinfo=UTC)
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime(2019, 1, 1, tzinfo=UTC),
                    expiry_date=past_date,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        keys = controller.get_keys()
        assert len(keys) == 1
        assert keys[0].is_expired is True

    def test_get_keys_expiring_soon(
        self, controller: TUIController, mock_gpg_ops
    ) -> None:
        """Test get_keys correctly calculates days until expiry."""
        from datetime import timedelta

        future_date = datetime.now(UTC) + timedelta(days=15)
        mock_gpg_ops.list_secret_keys.return_value = Result.ok(
            [
                KeyInfo(
                    key_id="ABCDEF1234567890",
                    fingerprint="ABC123DEF456",
                    identity="Test User <test@example.com>",
                    creation_date=datetime(2024, 1, 1, tzinfo=UTC),
                    expiry_date=future_date,
                    key_type=KeyType.RSA4096,
                )
            ]
        )

        keys = controller.get_keys()
        assert len(keys) == 1
        assert keys[0].is_expired is False
        assert keys[0].days_until_expiry is not None
        assert keys[0].days_until_expiry <= 16

    def test_get_devices_card_status_error(
        self, controller: TUIController, mock_yubikey_ops
    ) -> None:
        """Test get_devices when card status fails uses defaults."""
        mock_yubikey_ops.list_devices.return_value = [
            YubiKeyInfo(
                serial="12345678",
                version="5.4.3",
                form_factor="USB-C",
                has_openpgp=True,
                openpgp_version="3.4",
            )
        ]
        mock_yubikey_ops.get_card_status.return_value = Result.err(Exception("Card error"))

        devices = controller.get_devices()
        assert len(devices) == 1
        # Defaults: pin_tries=3, admin_tries=3, no keys
        assert devices[0].pin_tries_remaining == 3
        assert devices[0].has_keys is False

    def test_controller_default_inventory(self) -> None:
        """Test controller creates default inventory when none provided."""
        mock_yk = MagicMock()
        mock_yk.list_devices.return_value = []
        mock_gpg = MagicMock()
        mock_gpg.list_secret_keys.return_value = Result.ok([])

        with patch("yubikey_init.inventory.Inventory.load", return_value=Result.ok(None)):
            ctrl = TUIController(yubikey_ops=mock_yk, gpg_ops=mock_gpg)
            assert ctrl.inventory is not None
