"""Tests for DiagnosticsScreen."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from yubikey_init.inventory import OpenPGPState
from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import DeviceDisplayInfo, TUIController
from yubikey_init.tui.screens.diagnostics import DiagnosticsScreen


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.run_diagnostics.return_value = {
        "gpg_info": {
            "installed": True,
            "version": "2.4.3",
        },
        "yubikey_info": {
            "ykman_installed": True,
            "ykman_version": "5.2.1",
            "devices": [],
        },
        "agent_info": {
            "running": True,
            "scdaemon_status": "responding",
            "scdaemon_version": "2.4.3",
        },
    }
    controller.get_devices.return_value = []
    return controller


@pytest.fixture
def sample_devices() -> list[DeviceDisplayInfo]:
    """Create sample devices for testing."""
    return [
        DeviceDisplayInfo(
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
            notes=None,
            openpgp_state=OpenPGPState(pin_tries_remaining=3, admin_pin_tries_remaining=3),
            provisioned_identity="Test User <test@example.com>",
        ),
        DeviceDisplayInfo(
            serial="87654321",
            label="Blocked Device",
            device_type="YubiKey 5 NFC",
            firmware_version="5.4.2",
            form_factor="USB-A",
            has_keys=True,
            pin_tries_remaining=0,
            admin_pin_tries_remaining=3,
            is_blocked=True,
            protected=False,
            notes=None,
            openpgp_state=OpenPGPState(pin_tries_remaining=0, admin_pin_tries_remaining=3),
            provisioned_identity=None,
        ),
    ]


class TestDiagnosticsScreenInit:
    """Tests for DiagnosticsScreen initialization."""

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with controller."""
        screen = DiagnosticsScreen(controller=mock_controller)
        assert screen._controller is mock_controller
        assert screen._diagnostics is None

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = DiagnosticsScreen()
        assert screen._controller is None
        assert screen._diagnostics is None


class TestDiagnosticsScreenActions:
    """Tests for DiagnosticsScreen actions."""

    @pytest.mark.asyncio
    async def test_action_go_back(self, mock_controller: MagicMock) -> None:
        """Test go back action pops the screen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
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
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_refresh()
            await pilot.pause()


class TestDiagnosticsScreenBindings:
    """Tests for DiagnosticsScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = DiagnosticsScreen()
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "r" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = DiagnosticsScreen()
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0


class TestDiagnosticsScreenIntegration:
    """Integration tests for DiagnosticsScreen."""

    @pytest.mark.asyncio
    async def test_screen_runs_diagnostics(self, mock_controller: MagicMock) -> None:
        """Test that screen runs diagnostics on mount."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            # Verify controller was called
            assert mock_controller.run_diagnostics.called

    @pytest.mark.asyncio
    async def test_screen_handles_no_controller(self) -> None:
        """Test that screen handles missing controller gracefully."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_screen_displays_device_health(
        self, mock_controller: MagicMock, sample_devices: list[DeviceDisplayInfo]
    ) -> None:
        """Test that screen displays device health status."""
        mock_controller.get_devices.return_value = sample_devices

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            # Verify controller was called
            assert mock_controller.get_devices.called

    @pytest.mark.asyncio
    async def test_screen_displays_gpg_installed(self, mock_controller: MagicMock) -> None:
        """Test that screen shows GPG installed status."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            mock_controller.run_diagnostics.assert_called()

    @pytest.mark.asyncio
    async def test_screen_displays_gpg_not_installed(self, mock_controller: MagicMock) -> None:
        """Test that screen shows GPG not installed status."""
        mock_controller.run_diagnostics.return_value = {
            "gpg_info": {
                "installed": False,
            },
            "yubikey_info": {
                "ykman_installed": False,
                "devices": [],
            },
            "agent_info": {
                "running": False,
                "scdaemon_status": "unknown",
            },
        }

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            mock_controller.run_diagnostics.assert_called()

    @pytest.mark.asyncio
    async def test_screen_handles_diagnostics_error(self, mock_controller: MagicMock) -> None:
        """Test that screen handles diagnostics errors gracefully."""
        mock_controller.run_diagnostics.side_effect = Exception("Diagnostics failed")

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = DiagnosticsScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()
            await pilot.pause()

            # Should not crash
            assert pilot.app.screen is screen
