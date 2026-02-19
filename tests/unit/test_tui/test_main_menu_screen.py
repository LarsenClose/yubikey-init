"""Tests for MainMenuScreen."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from yubikey_init.inventory import OpenPGPState
from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import DeviceDisplayInfo, KeyDisplayInfo, TUIController
from yubikey_init.tui.screens.device_list import DeviceListScreen
from yubikey_init.tui.screens.diagnostics import DiagnosticsScreen
from yubikey_init.tui.screens.key_list import KeyListScreen
from yubikey_init.tui.screens.main_menu import MainMenuScreen


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_devices.return_value = []
    controller.get_keys.return_value = []
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
    ]


@pytest.fixture
def sample_keys() -> list[KeyDisplayInfo]:
    """Create sample keys for testing."""
    return [
        KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123DEF456789012345678901234567890ABCD",
            identity="Test User <test@example.com>",
            creation_date=datetime(2024, 1, 1, tzinfo=UTC),
            expiry_date=None,
            is_expired=False,
            days_until_expiry=None,
            on_yubikey_serial="12345678",
            on_yubikey_label="Test Device",
        ),
    ]


class TestMainMenuScreenInit:
    """Tests for MainMenuScreen initialization."""

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with controller."""
        screen = MainMenuScreen(controller=mock_controller)
        assert screen._controller is mock_controller
        assert screen._device_summary == "..."
        assert screen._key_summary == "..."

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = MainMenuScreen()
        assert screen._controller is None


class TestMainMenuScreenActions:
    """Tests for MainMenuScreen actions."""

    @pytest.mark.asyncio
    async def test_action_goto_devices(self, mock_controller: MagicMock) -> None:
        """Test goto devices action pushes DeviceListScreen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_goto_devices()
            await pilot.pause()
            assert isinstance(pilot.app.screen, DeviceListScreen)

    @pytest.mark.asyncio
    async def test_action_goto_keys(self, mock_controller: MagicMock) -> None:
        """Test goto keys action pushes KeyListScreen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_goto_keys()
            await pilot.pause()
            assert isinstance(pilot.app.screen, KeyListScreen)

    @pytest.mark.asyncio
    async def test_action_goto_diagnostics(self, mock_controller: MagicMock) -> None:
        """Test goto diagnostics action pushes DiagnosticsScreen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_goto_diagnostics()
            await pilot.pause()
            assert isinstance(pilot.app.screen, DiagnosticsScreen)

    @pytest.mark.asyncio
    async def test_action_quit(self, mock_controller: MagicMock) -> None:
        """Test quit action exits the app."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_quit()
            # App should be exiting
            assert pilot.app._exit


class TestMainMenuScreenBindings:
    """Tests for MainMenuScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = MainMenuScreen()
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "d" in binding_keys
        assert "k" in binding_keys
        assert "x" in binding_keys
        assert "q" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = MainMenuScreen()
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0


class TestMainMenuScreenSummaries:
    """Tests for MainMenuScreen summary generation."""

    @pytest.mark.asyncio
    async def test_summary_no_devices(self, mock_controller: MagicMock) -> None:
        """Test summary when no devices are connected."""
        mock_controller.get_devices.return_value = []
        mock_controller.get_keys.return_value = []

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            assert mock_controller.get_devices.called
            assert mock_controller.get_keys.called

    @pytest.mark.asyncio
    async def test_summary_with_devices(
        self, mock_controller: MagicMock, sample_devices: list[DeviceDisplayInfo]
    ) -> None:
        """Test summary with connected devices."""
        mock_controller.get_devices.return_value = sample_devices
        mock_controller.get_keys.return_value = []

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            assert mock_controller.get_devices.called

    @pytest.mark.asyncio
    async def test_summary_with_keys(
        self, mock_controller: MagicMock, sample_keys: list[KeyDisplayInfo]
    ) -> None:
        """Test summary with keys in keyring."""
        mock_controller.get_devices.return_value = []
        mock_controller.get_keys.return_value = sample_keys

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            assert mock_controller.get_keys.called

    @pytest.mark.asyncio
    async def test_summary_device_needs_attention(self, mock_controller: MagicMock) -> None:
        """Test summary when device needs attention (PIN blocked)."""
        blocked_device = DeviceDisplayInfo(
            serial="12345678",
            label="Blocked",
            device_type="YubiKey 5C",
            firmware_version="5.4.3",
            form_factor="USB-C",
            has_keys=True,
            pin_tries_remaining=0,
            admin_pin_tries_remaining=3,
            is_blocked=True,
            protected=False,
            notes=None,
            openpgp_state=OpenPGPState(pin_tries_remaining=0, admin_pin_tries_remaining=3),
            provisioned_identity="Test User <test@example.com>",
        )
        mock_controller.get_devices.return_value = [blocked_device]
        mock_controller.get_keys.return_value = []

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            assert mock_controller.get_devices.called

    @pytest.mark.asyncio
    async def test_summary_no_controller(self) -> None:
        """Test summary when no controller is available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_summary_error_handling(self, mock_controller: MagicMock) -> None:
        """Test summary handles errors gracefully."""
        mock_controller.get_devices.side_effect = Exception("Failed to get devices")
        mock_controller.get_keys.side_effect = Exception("Failed to get keys")

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = MainMenuScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            # Should not crash
            assert pilot.app.screen is screen
