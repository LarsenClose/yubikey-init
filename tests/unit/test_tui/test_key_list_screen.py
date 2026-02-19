"""Tests for KeyListScreen."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import KeyDisplayInfo, TUIController
from yubikey_init.tui.screens.key_list import KeyListScreen
from yubikey_init.types import Result


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_keys.return_value = []
    controller.get_key_device_mapping.return_value = {}
    controller.export_ssh_key.return_value = Result.ok("ssh-rsa AAAAB3...")
    return controller


@pytest.fixture
def sample_keys() -> list[KeyDisplayInfo]:
    """Create sample keys for testing."""
    now = datetime.now(UTC)
    return [
        KeyDisplayInfo(
            key_id="ABCDEF1234567890",
            fingerprint="ABC123DEF456789012345678901234567890ABCD",
            identity="Test User <test@example.com>",
            creation_date=datetime(2024, 1, 1, tzinfo=UTC),
            expiry_date=now + timedelta(days=365),
            is_expired=False,
            days_until_expiry=365,
            on_yubikey_serial="12345678",
            on_yubikey_label="Test Device",
        ),
        KeyDisplayInfo(
            key_id="1234567890ABCDEF",
            fingerprint="123ABC456DEF789012345678901234567890ABCD",
            identity="Another User <another@example.com>",
            creation_date=datetime(2023, 6, 15, tzinfo=UTC),
            expiry_date=None,
            is_expired=False,
            days_until_expiry=None,
            on_yubikey_serial=None,
            on_yubikey_label=None,
        ),
    ]


class TestKeyListScreenInit:
    """Tests for KeyListScreen initialization."""

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with controller."""
        screen = KeyListScreen(controller=mock_controller)
        assert screen._controller is mock_controller
        assert screen._keys == []
        assert screen._key_yubikey_map == {}

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = KeyListScreen()
        assert screen._controller is None
        assert screen._keys == []


class TestKeyListScreenDisplay:
    """Tests for KeyListScreen display logic."""

    def test_truncate_identity_short(self) -> None:
        """Test truncating identity that is already short."""
        screen = KeyListScreen()
        identity = "Short Name"
        result = screen._truncate_identity(identity, 30)
        assert result == identity

    def test_truncate_identity_long(self) -> None:
        """Test truncating identity that is too long."""
        screen = KeyListScreen()
        identity = "Very Long Identity Name That Exceeds Maximum Length"
        result = screen._truncate_identity(identity, 30)
        assert len(result) == 30
        assert result.endswith("...")

    def test_format_expiry_never(self) -> None:
        """Test formatting expiry when key never expires."""
        screen = KeyListScreen()
        result = screen._format_expiry(None)
        assert "Never" in result

    def test_format_expiry_expired(self) -> None:
        """Test formatting expiry for expired key."""
        screen = KeyListScreen()
        past_date = datetime(2020, 1, 1, tzinfo=UTC)
        result = screen._format_expiry(past_date)
        assert "EXPIRED" in result

    def test_format_expiry_soon(self) -> None:
        """Test formatting expiry for key expiring soon (within 30 days)."""
        screen = KeyListScreen()
        future_date = datetime.now(UTC) + timedelta(days=15)
        result = screen._format_expiry(future_date)
        assert "days" in result.lower() or "yellow" in result.lower()

    def test_format_expiry_warning_range(self) -> None:
        """Test formatting expiry for key in warning range (30-90 days)."""
        screen = KeyListScreen()
        future_date = datetime.now(UTC) + timedelta(days=60)
        result = screen._format_expiry(future_date)
        # Should contain date or warning color
        assert "-" in result or "yellow" in result.lower()

    def test_format_expiry_normal(self) -> None:
        """Test formatting expiry for key with normal expiry."""
        screen = KeyListScreen()
        future_date = datetime(2030, 6, 15, tzinfo=UTC)
        result = screen._format_expiry(future_date)
        assert "2030-06-15" in result or "2030" in result


class TestKeyListScreenActions:
    """Tests for KeyListScreen actions."""

    @pytest.mark.asyncio
    async def test_action_go_back(self, mock_controller: MagicMock) -> None:
        """Test go back action pops the screen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
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
            screen = KeyListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_refresh()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_export_ssh_no_controller(self) -> None:
        """Test export SSH action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_export_ssh()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_export_ssh_success(self, mock_controller: MagicMock) -> None:
        """Test export SSH action with successful export."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
            mock_controller.export_ssh_key.return_value = Result.ok("ssh-rsa AAAAB3...")
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Mock _get_selected_key_id to return a key
            screen._get_selected_key_id = MagicMock(return_value="ABCDEF1234567890")

            screen.action_export_ssh()
            await pilot.pause()
            mock_controller.export_ssh_key.assert_called_once_with("ABCDEF1234567890")

    @pytest.mark.asyncio
    async def test_action_export_ssh_failure(self, mock_controller: MagicMock) -> None:
        """Test export SSH action with failed export."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
            mock_controller.export_ssh_key.return_value = Result.err("Export failed")
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Mock _get_selected_key_id to return a key
            screen._get_selected_key_id = MagicMock(return_value="ABCDEF1234567890")

            screen.action_export_ssh()
            await pilot.pause()
            mock_controller.export_ssh_key.assert_called_once()


class TestKeyListScreenBindings:
    """Tests for KeyListScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = KeyListScreen()
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "enter" in binding_keys
        assert "s" in binding_keys
        assert "r" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = KeyListScreen()
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0


class TestKeyListScreenIntegration:
    """Integration tests for KeyListScreen."""

    @pytest.mark.asyncio
    async def test_screen_loads_keys(
        self, mock_controller: MagicMock, sample_keys: list[KeyDisplayInfo]
    ) -> None:
        """Test that screen loads and displays keys."""
        mock_controller.get_keys.return_value = sample_keys

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()

            # Verify controller was called
            assert mock_controller.get_keys.called
            assert mock_controller.get_key_device_mapping.called

    @pytest.mark.asyncio
    async def test_screen_shows_empty_message(self, mock_controller: MagicMock) -> None:
        """Test that screen shows message when no keys found."""
        mock_controller.get_keys.return_value = []

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()

            mock_controller.get_keys.assert_called()

    @pytest.mark.asyncio
    async def test_screen_handles_error(self, mock_controller: MagicMock) -> None:
        """Test that screen handles errors gracefully."""
        mock_controller.get_keys.side_effect = Exception("Failed to load keys")

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyListScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            # Give time for async work to complete
            await pilot.pause()

            # Should not crash
            assert pilot.app.screen is screen
