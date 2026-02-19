"""Tests for DeviceDetailScreen."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.widgets import Static

from yubikey_init.inventory import KeySlotInfo, OpenPGPState
from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import DeviceDisplayInfo, TUIController
from yubikey_init.tui.screens.device_detail import DeviceDetailScreen
from yubikey_init.types import Result


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_device.return_value = None
    controller.reset_device.return_value = Result.ok(None)
    controller.set_device_label.return_value = Result.ok(None)
    controller.set_device_protected.return_value = Result.ok(None)
    controller.set_device_notes.return_value = Result.ok(None)
    return controller


@pytest.fixture
def sample_device() -> DeviceDisplayInfo:
    """Create a sample device for testing."""
    return DeviceDisplayInfo(
        serial="12345678",
        label="Test Device",
        device_type="YubiKey 5C",
        firmware_version="5.4.3",
        form_factor="USB-C",
        has_keys=True,
        pin_tries_remaining=3,
        admin_pin_tries_remaining=3,
        is_blocked=False,
        protected=False,
        notes="Test notes",
        openpgp_state=OpenPGPState(
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            signature_key=KeySlotInfo(
                fingerprint="ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
                touch_policy="cached",
            ),
            encryption_key=KeySlotInfo(fingerprint=None, touch_policy=None),
            authentication_key=KeySlotInfo(
                fingerprint="1234ABCD5678EFGH9012IJKL3456MNOP7890QRST",
                touch_policy="on",
            ),
        ),
        provisioned_identity="Test User <test@example.com>",
    )


class TestDeviceDetailScreenInit:
    """Tests for DeviceDetailScreen initialization."""

    def test_init_with_serial(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with device serial."""
        screen = DeviceDetailScreen(
            device_serial="12345678",
            controller=mock_controller,
        )
        assert screen._serial == "12345678"
        assert screen._controller is mock_controller

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = DeviceDetailScreen(device_serial="12345678")
        assert screen._serial == "12345678"
        assert screen._controller is None

    def test_init_with_name_and_id(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with name and id."""
        screen = DeviceDetailScreen(
            device_serial="12345678",
            controller=mock_controller,
            name="test_screen",
            id="test_id",
        )
        assert screen._serial == "12345678"
        assert screen.name == "test_screen"
        assert screen.id == "test_id"


class TestDeviceDetailScreenCompose:
    """Tests for DeviceDetailScreen composition."""

    @pytest.mark.asyncio
    async def test_screen_composes(self, mock_controller: MagicMock) -> None:
        """Test that screen composes without errors."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            assert pilot.app.screen is screen

    @pytest.mark.asyncio
    async def test_screen_has_title(self, mock_controller: MagicMock) -> None:
        """Test that screen has a title."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            title = screen.query_one("#screen-title", Static)
            assert title is not None


class TestDeviceDetailScreenDisplay:
    """Tests for DeviceDetailScreen display logic."""

    def test_format_key_slot_no_key(self) -> None:
        """Test formatting a key slot with no key."""
        screen = DeviceDetailScreen("12345678")
        result = screen._format_key_slot(None, None)
        assert result == "[No key]"

    def test_format_key_slot_with_fingerprint_no_policy(self) -> None:
        """Test formatting a key slot with fingerprint but no touch policy."""
        screen = DeviceDetailScreen("12345678")
        fingerprint = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
        result = screen._format_key_slot(fingerprint, None)
        # Should show last 16 chars formatted
        assert "MNOP 3456 QRST 7890" in result
        assert "[Touch:" not in result

    def test_format_key_slot_with_fingerprint_and_policy(self) -> None:
        """Test formatting a key slot with fingerprint and touch policy."""
        screen = DeviceDetailScreen("12345678")
        fingerprint = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
        result = screen._format_key_slot(fingerprint, "cached")
        assert "MNOP 3456 QRST 7890" in result
        assert "[Touch: cached]" in result

    def test_format_key_slot_short_fingerprint(self) -> None:
        """Test formatting a key slot with short fingerprint."""
        screen = DeviceDetailScreen("12345678")
        fingerprint = "ABCD1234"
        result = screen._format_key_slot(fingerprint, None)
        assert "ABCD 1234" in result

    def test_get_device_status_blocked(self, sample_device: DeviceDisplayInfo) -> None:
        """Test device status when PIN is blocked."""
        screen = DeviceDetailScreen("12345678")
        sample_device.openpgp_state.pin_tries_remaining = 0
        screen._device = sample_device
        status = screen._get_device_status()
        assert "BLOCKED" in status.upper()

    def test_get_device_status_low_tries(self, sample_device: DeviceDisplayInfo) -> None:
        """Test device status when PIN tries are low."""
        screen = DeviceDetailScreen("12345678")
        sample_device.openpgp_state.pin_tries_remaining = 1
        screen._device = sample_device
        status = screen._get_device_status()
        assert "low" in status.lower()

    def test_get_device_status_ready(self, sample_device: DeviceDisplayInfo) -> None:
        """Test device status when device is ready."""
        screen = DeviceDetailScreen("12345678")
        screen._device = sample_device
        status = screen._get_device_status()
        assert "Ready" in status

    def test_get_device_status_no_state(self) -> None:
        """Test device status when no OpenPGP state available."""
        screen = DeviceDetailScreen("12345678")
        device = DeviceDisplayInfo(
            serial="12345678",
            label=None,
            device_type=None,
            firmware_version=None,
            form_factor=None,
            has_keys=False,
            pin_tries_remaining=0,
            admin_pin_tries_remaining=0,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=None,
            provisioned_identity=None,
        )
        screen._device = device
        status = screen._get_device_status()
        assert "Unknown" in status


class TestDeviceDetailScreenActions:
    """Tests for DeviceDetailScreen actions."""

    @pytest.mark.asyncio
    async def test_action_go_back(self, mock_controller: MagicMock) -> None:
        """Test go back action pops the screen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            assert pilot.app.screen is screen

            screen.action_go_back()
            await pilot.pause()
            assert pilot.app.screen is not screen

    @pytest.mark.asyncio
    async def test_action_unblock_pin_no_device(self, mock_controller: MagicMock) -> None:
        """Test unblock PIN action when no device available."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            screen._device = None
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_unblock_pin()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_unblock_pin_not_blocked(
        self, mock_controller: MagicMock, sample_device: DeviceDisplayInfo
    ) -> None:
        """Test unblock PIN action when PIN is not blocked."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            screen._device = sample_device
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_unblock_pin()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_reset_device_protected(
        self, mock_controller: MagicMock, sample_device: DeviceDisplayInfo
    ) -> None:
        """Test reset device action when device is protected."""
        sample_device.protected = True
        mock_controller.get_device.return_value = sample_device

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            screen._device = sample_device
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_reset_device()
            await pilot.pause()

            # Should not call reset_device when protected
            mock_controller.reset_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_action_set_label_no_controller(self) -> None:
        """Test set label action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_set_label()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_toggle_protect_no_device(self, mock_controller: MagicMock) -> None:
        """Test toggle protect action when no device available."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=mock_controller)
            screen._device = None
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_toggle_protect()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_edit_notes_no_controller(self) -> None:
        """Test edit notes action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = DeviceDetailScreen("12345678", controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_edit_notes()
            await pilot.pause()


class TestDeviceDetailScreenBindings:
    """Tests for DeviceDetailScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = DeviceDetailScreen("12345678")
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "u" in binding_keys
        assert "r" in binding_keys
        assert "l" in binding_keys
        assert "p" in binding_keys
        assert "n" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = DeviceDetailScreen("12345678")
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0
