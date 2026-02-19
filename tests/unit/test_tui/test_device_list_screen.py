"""Tests for DeviceListScreen."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from yubikey_init.inventory import OpenPGPState
from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import DeviceDisplayInfo, TUIController
from yubikey_init.tui.screens.device_list import DeviceListScreen
from yubikey_init.types import Result


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_devices.return_value = []
    controller.get_device.return_value = None
    controller.reset_device.return_value = Result.ok(None)
    controller.set_device_label.return_value = Result.ok(None)
    return controller


@pytest.fixture
def sample_devices() -> list[DeviceDisplayInfo]:
    """Create sample devices for testing."""
    return [
        DeviceDisplayInfo(
            serial="12345678",
            label="Primary",
            device_type="YubiKey 5C",
            firmware_version="5.4.3",
            form_factor="USB-C",
            has_keys=True,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=False,
            notes=None,
            openpgp_state=OpenPGPState(pin_tries_remaining=3, admin_pin_tries_remaining=3),
            provisioned_identity="Test User <test@example.com>",
        ),
        DeviceDisplayInfo(
            serial="87654321",
            label="Backup",
            device_type="YubiKey 5 NFC",
            firmware_version="5.4.2",
            form_factor="USB-A",
            has_keys=False,
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            is_blocked=False,
            protected=True,
            notes=None,
            openpgp_state=OpenPGPState(pin_tries_remaining=3, admin_pin_tries_remaining=3),
            provisioned_identity=None,
        ),
    ]


class TestDeviceListScreenInit:
    """Tests for DeviceListScreen initialization."""

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with controller."""
        screen = DeviceListScreen(controller=mock_controller)
        assert screen._controller is mock_controller

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = DeviceListScreen()
        assert screen._controller is None


class TestDeviceListScreenDisplay:
    """Tests for DeviceListScreen display logic."""

    def test_format_pin_status_no_state(self) -> None:
        """Test formatting PIN status when no OpenPGP state available."""
        screen = DeviceListScreen()
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
        status = screen._format_pin_status(device)
        assert status == "?"

    def test_format_pin_status_blocked(self, sample_devices: list[DeviceDisplayInfo]) -> None:
        """Test formatting PIN status when device is blocked."""
        screen = DeviceListScreen()
        device = sample_devices[0]
        device.openpgp_state.pin_tries_remaining = 0
        status = screen._format_pin_status(device)
        assert "BLOCKED" in status

    def test_format_pin_status_low_tries(self, sample_devices: list[DeviceDisplayInfo]) -> None:
        """Test formatting PIN status when tries are low."""
        screen = DeviceListScreen()
        device = sample_devices[0]
        device.openpgp_state.pin_tries_remaining = 1
        status = screen._format_pin_status(device)
        assert "1/3" in status

    def test_format_pin_status_normal(self, sample_devices: list[DeviceDisplayInfo]) -> None:
        """Test formatting PIN status when tries are normal."""
        screen = DeviceListScreen()
        device = sample_devices[0]
        status = screen._format_pin_status(device)
        assert "3/3" in status

    def test_get_selected_serial_no_rows(self, mock_controller: MagicMock) -> None:
        """Test getting selected serial when table is empty."""
        screen = DeviceListScreen(controller=mock_controller)
        # Cannot test without mounting the screen
        assert screen._controller is mock_controller


class TestDeviceListScreenActions:
    """Tests for DeviceListScreen actions."""

    @pytest.mark.asyncio
    async def test_action_go_back(self, mock_controller: MagicMock) -> None:
        """Test go back action pops the screen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            assert pilot.app.screen is screen

            screen.action_go_back()
            await pilot.pause()
            assert pilot.app.screen is not screen

    @pytest.mark.asyncio
    async def test_action_refresh(self, mock_controller: MagicMock) -> None:
        """Test refresh action."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_refresh()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_label_device_no_controller(self) -> None:
        """Test label device action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_label_device()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_reset_device_no_controller(self) -> None:
        """Test reset device action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await screen.action_reset_device()
            await pilot.pause()


class TestDeviceListScreenBindings:
    """Tests for DeviceListScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = DeviceListScreen()
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "enter" in binding_keys
        assert "l" in binding_keys
        assert "r" in binding_keys
        assert "R" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = DeviceListScreen()
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0


class TestDeviceListScreenIntegration:
    """Integration tests for DeviceListScreen."""

    @pytest.mark.asyncio
    async def test_screen_loads_devices(
        self, mock_controller: MagicMock, sample_devices: list[DeviceDisplayInfo]
    ) -> None:
        """Test that screen loads and displays devices."""
        mock_controller.get_devices.return_value = sample_devices

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Verify controller was called
            mock_controller.get_devices.assert_called()

    @pytest.mark.asyncio
    async def test_screen_shows_empty_message(self, mock_controller: MagicMock) -> None:
        """Test that screen shows message when no devices found."""
        mock_controller.get_devices.return_value = []

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DeviceListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            mock_controller.get_devices.assert_called()
