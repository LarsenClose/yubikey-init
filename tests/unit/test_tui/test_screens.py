"""Tests for TUI screen components using Textual's async testing framework."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from textual.widgets import DataTable, ListView, Static

from yubikey_init.inventory import OpenPGPState
from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import DeviceDisplayInfo, KeyDisplayInfo, TUIController
from yubikey_init.tui.screens import (
    DeviceDetailScreen,
    DeviceListScreen,
    DiagnosticsScreen,
    KeyDetailScreen,
    KeyListScreen,
    MainMenuScreen,
)


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_devices.return_value = []
    controller.get_keys.return_value = []
    controller.run_diagnostics.return_value = {}
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
        openpgp_state=OpenPGPState(pin_tries_remaining=3, admin_pin_tries_remaining=3),
        provisioned_identity="Test User <test@example.com>",
    )


@pytest.fixture
def sample_key() -> KeyDisplayInfo:
    """Create a sample key for testing."""
    return KeyDisplayInfo(
        key_id="ABCDEF1234567890",
        fingerprint="ABC123DEF456789012345678901234567890ABCD",
        identity="Test User <test@example.com>",
        creation_date=datetime(2024, 1, 1, tzinfo=UTC),
        expiry_date=datetime(2030, 1, 1, tzinfo=UTC),
        is_expired=False,
        days_until_expiry=365,
        on_yubikey_serial="12345678",
        on_yubikey_label="Test Device",
    )


class TestMainMenuScreen:
    """Tests for MainMenuScreen."""

    @pytest.mark.asyncio
    async def test_screen_composes(self) -> None:
        """Test that MainMenuScreen composes without errors."""
        async with YubiKeyManagerApp().run_test() as pilot:
            # The main menu should be pushed on mount
            assert pilot.app.screen is not None
            assert isinstance(pilot.app.screen, MainMenuScreen)

    @pytest.mark.asyncio
    async def test_menu_contains_items(self) -> None:
        """Test that menu contains expected items."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.pause()
            # Query within the current screen
            list_view = pilot.app.screen.query_one("#menu-list", ListView)
            assert list_view is not None

    @pytest.mark.asyncio
    async def test_title_displayed(self) -> None:
        """Test that title is displayed."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.pause()
            title = pilot.app.screen.query_one("#title", Static)
            assert title is not None

    @pytest.mark.asyncio
    async def test_devices_keybinding(self) -> None:
        """Test pressing 'd' navigates to devices screen."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("d")
            assert isinstance(pilot.app.screen, DeviceListScreen)

    @pytest.mark.asyncio
    async def test_keys_keybinding(self) -> None:
        """Test pressing 'k' navigates to keys screen."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("k")
            assert isinstance(pilot.app.screen, KeyListScreen)

    @pytest.mark.asyncio
    async def test_diagnostics_keybinding(self) -> None:
        """Test pressing 'x' navigates to diagnostics screen."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("x")
            assert isinstance(pilot.app.screen, DiagnosticsScreen)


class TestDeviceListScreen:
    """Tests for DeviceListScreen."""

    @pytest.mark.asyncio
    async def test_screen_composes(self) -> None:
        """Test that DeviceListScreen composes without errors."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("d")
            await pilot.pause()
            assert isinstance(pilot.app.screen, DeviceListScreen)
            # Query within the current screen
            table = pilot.app.screen.query_one("#device-table", DataTable)
            assert table is not None

    @pytest.mark.asyncio
    async def test_table_columns(self) -> None:
        """Test table has correct columns."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("d")
            await pilot.pause()
            table = pilot.app.screen.query_one("#device-table", DataTable)
            # Check column count using columns property
            assert len(table.columns) == 7

    @pytest.mark.asyncio
    async def test_back_keybinding(self) -> None:
        """Test pressing escape goes back to main menu."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("d")
            assert isinstance(pilot.app.screen, DeviceListScreen)
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)


class TestKeyListScreen:
    """Tests for KeyListScreen."""

    @pytest.mark.asyncio
    async def test_screen_composes(self) -> None:
        """Test that KeyListScreen composes without errors."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("k")
            assert isinstance(pilot.app.screen, KeyListScreen)

    @pytest.mark.asyncio
    async def test_back_keybinding(self) -> None:
        """Test pressing escape goes back to main menu."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("k")
            assert isinstance(pilot.app.screen, KeyListScreen)
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)


class TestDiagnosticsScreen:
    """Tests for DiagnosticsScreen."""

    @pytest.mark.asyncio
    async def test_screen_composes(self) -> None:
        """Test that DiagnosticsScreen composes without errors."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("x")
            assert isinstance(pilot.app.screen, DiagnosticsScreen)

    @pytest.mark.asyncio
    async def test_title_displayed(self) -> None:
        """Test that diagnostics title is displayed."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("x")
            await pilot.pause()
            # Find title Static widget in the current screen
            titles = pilot.app.screen.query(".screen-title")
            assert len(titles) > 0

    @pytest.mark.asyncio
    async def test_back_keybinding(self) -> None:
        """Test pressing escape goes back."""
        async with YubiKeyManagerApp().run_test() as pilot:
            await pilot.press("x")
            assert isinstance(pilot.app.screen, DiagnosticsScreen)
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)


class TestDeviceDetailScreen:
    """Tests for DeviceDetailScreen."""

    def test_screen_init(self, sample_device: DeviceDisplayInfo) -> None:
        """Test DeviceDetailScreen initialization."""
        screen = DeviceDetailScreen(
            device_serial=sample_device.serial,
            controller=None,
        )
        # The screen stores the serial in _serial attribute
        assert screen._serial == sample_device.serial


class TestKeyDetailScreen:
    """Tests for KeyDetailScreen."""

    def test_screen_init(self, sample_key: KeyDisplayInfo) -> None:
        """Test KeyDetailScreen initialization."""
        screen = KeyDetailScreen(
            key_id=sample_key.key_id,
            controller=None,
        )
        assert screen._key_id == sample_key.key_id


class TestNavigationFlow:
    """Tests for navigation between screens."""

    @pytest.mark.asyncio
    async def test_full_navigation_cycle(self) -> None:
        """Test navigating through all screens and back."""
        async with YubiKeyManagerApp().run_test() as pilot:
            # Start at main menu
            assert isinstance(pilot.app.screen, MainMenuScreen)

            # Navigate to devices
            await pilot.press("d")
            assert isinstance(pilot.app.screen, DeviceListScreen)

            # Back to main menu
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)

            # Navigate to keys
            await pilot.press("k")
            assert isinstance(pilot.app.screen, KeyListScreen)

            # Back to main menu
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)

            # Navigate to diagnostics
            await pilot.press("x")
            assert isinstance(pilot.app.screen, DiagnosticsScreen)

            # Back to main menu
            await pilot.press("escape")
            assert isinstance(pilot.app.screen, MainMenuScreen)

    @pytest.mark.asyncio
    async def test_app_quit(self) -> None:
        """Test quitting the application."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            # Pressing 'q' should exit
            await pilot.press("q")
            # App should be exiting
            assert pilot.app._exit

    @pytest.mark.asyncio
    async def test_direct_navigation_from_subscreen(self) -> None:
        """Test direct navigation using global keybindings."""
        async with YubiKeyManagerApp().run_test() as pilot:
            # Navigate to devices
            await pilot.press("d")
            assert isinstance(pilot.app.screen, DeviceListScreen)

            # Directly navigate to keys
            await pilot.press("k")
            assert isinstance(pilot.app.screen, KeyListScreen)

            # Directly navigate to diagnostics
            await pilot.press("x")
            assert isinstance(pilot.app.screen, DiagnosticsScreen)

            # Directly navigate to devices
            await pilot.press("d")
            assert isinstance(pilot.app.screen, DeviceListScreen)
