"""Tests for KeyDetailScreen."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from yubikey_init.tui.app import YubiKeyManagerApp
from yubikey_init.tui.controller import KeyDisplayInfo, TUIController
from yubikey_init.tui.screens.key_detail import KeyDetailScreen
from yubikey_init.types import Result


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    controller = MagicMock(spec=TUIController)
    controller.get_key_info.return_value = None
    controller.get_subkeys.return_value = []
    controller.get_key_device_mapping.return_value = {}
    controller.export_ssh_key.return_value = Result.ok("ssh-rsa AAAAB3...")
    return controller


@pytest.fixture
def sample_key() -> KeyDisplayInfo:
    """Create a sample key for testing."""
    return KeyDisplayInfo(
        key_id="ABCDEF1234567890",
        fingerprint="ABC123DEF456789012345678901234567890ABCD",
        identity="Test User <test@example.com>",
        creation_date=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
        expiry_date=datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC),
        is_expired=False,
        days_until_expiry=365,
        on_yubikey_serial="12345678",
        on_yubikey_label="Test Device",
    )


class TestKeyDetailScreenInit:
    """Tests for KeyDetailScreen initialization."""

    def test_init_with_key_id(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with key ID."""
        screen = KeyDetailScreen(
            key_id="ABCDEF1234567890",
            controller=mock_controller,
        )
        assert screen._key_id == "ABCDEF1234567890"
        assert screen._controller is mock_controller

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = KeyDetailScreen(key_id="ABCDEF1234567890")
        assert screen._key_id == "ABCDEF1234567890"
        assert screen._controller is None

    def test_init_with_name_and_id(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with name and id."""
        screen = KeyDetailScreen(
            key_id="ABCDEF1234567890",
            controller=mock_controller,
            name="test_screen",
            id="test_id",
        )
        assert screen._key_id == "ABCDEF1234567890"
        assert screen.name == "test_screen"
        assert screen.id == "test_id"


class TestKeyDetailScreenDisplay:
    """Tests for KeyDetailScreen display logic."""

    def test_format_expiry_never(self) -> None:
        """Test formatting expiry when key never expires."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        result = screen._format_expiry(None)
        assert "Never" in result

    def test_format_expiry_expired(self) -> None:
        """Test formatting expiry for expired key."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        past_date = datetime(2020, 1, 1, tzinfo=UTC)
        result = screen._format_expiry(past_date)
        assert "EXPIRED" in result

    def test_format_expiry_soon(self) -> None:
        """Test formatting expiry for key expiring soon."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        # Create a date 15 days in the future
        future_date = (
            datetime.now(UTC).replace(day=datetime.now(UTC).day + 15)
            if datetime.now(UTC).day <= 15
            else datetime.now(UTC).replace(month=datetime.now(UTC).month + 1, day=15)
        )
        result = screen._format_expiry(future_date)
        assert "days" in result.lower() or "yellow" in result.lower()

    def test_format_expiry_warning_range(self) -> None:
        """Test formatting expiry for key in warning range (30-90 days)."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        # Create a date 60 days in the future
        from datetime import timedelta

        future_date = datetime.now(UTC) + timedelta(days=60)
        result = screen._format_expiry(future_date)
        # Should contain date in YYYY-MM-DD format
        assert "-" in result or "yellow" in result.lower()

    def test_format_expiry_normal(self) -> None:
        """Test formatting expiry for key with normal expiry."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        future_date = datetime(2030, 6, 15, tzinfo=UTC)
        result = screen._format_expiry(future_date)
        assert "2030-06-15" in result or "2030" in result


class TestKeyDetailScreenActions:
    """Tests for KeyDetailScreen actions."""

    @pytest.mark.asyncio
    async def test_action_go_back(self, mock_controller: MagicMock) -> None:
        """Test go back action pops the screen."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            assert pilot.app.screen is screen

            screen.action_go_back()
            await pilot.pause()
            assert pilot.app.screen is not screen

    @pytest.mark.asyncio
    async def test_action_export_ssh_no_controller(self) -> None:
        """Test export SSH action when no controller available."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=None)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_export_ssh()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_export_ssh_no_key_info(self, mock_controller: MagicMock) -> None:
        """Test export SSH action when no key info loaded."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            screen._key_info = None
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_export_ssh()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_export_ssh_success(
        self, mock_controller: MagicMock, sample_key: KeyDisplayInfo
    ) -> None:
        """Test export SSH action with successful export."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            screen._key_info = sample_key
            mock_controller.export_ssh_key.return_value = Result.ok("ssh-rsa AAAAB3...")
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_export_ssh()
            await pilot.pause()
            mock_controller.export_ssh_key.assert_called_once_with("ABCDEF1234567890")

    @pytest.mark.asyncio
    async def test_action_export_ssh_failure(
        self, mock_controller: MagicMock, sample_key: KeyDisplayInfo
    ) -> None:
        """Test export SSH action with failed export."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            screen._key_info = sample_key
            mock_controller.export_ssh_key.return_value = Result.err("Export failed")
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_export_ssh()
            await pilot.pause()
            mock_controller.export_ssh_key.assert_called_once()

    @pytest.mark.asyncio
    async def test_action_copy_fingerprint_no_key(self) -> None:
        """Test copy fingerprint action when no key loaded."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890")
            screen._key_info = None
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_copy_fingerprint()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_copy_fingerprint_success(self, sample_key: KeyDisplayInfo) -> None:
        """Test copy fingerprint action with key loaded."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890")
            screen._key_info = sample_key
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_copy_fingerprint()
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_action_refresh(self, mock_controller: MagicMock) -> None:
        """Test refresh action."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_refresh()
            await pilot.pause()


class TestKeyDetailScreenButtonHandlers:
    """Tests for KeyDetailScreen button handlers."""

    @pytest.mark.asyncio
    async def test_on_export_ssh_pressed(
        self, mock_controller: MagicMock, sample_key: KeyDisplayInfo
    ) -> None:
        """Test export SSH button handler."""
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890", controller=mock_controller)
            screen._key_info = sample_key
            mock_controller.export_ssh_key.return_value = Result.ok("ssh-rsa AAAAB3...")
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.on_export_ssh_pressed()
            await pilot.pause()
            mock_controller.export_ssh_key.assert_called_once()

    @pytest.mark.asyncio
    async def test_on_copy_fp_pressed(self, sample_key: KeyDisplayInfo) -> None:
        """Test copy fingerprint button handler."""
        app = YubiKeyManagerApp()
        async with app.run_test() as pilot:
            screen = KeyDetailScreen("ABCDEF1234567890")
            screen._key_info = sample_key
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.on_copy_fp_pressed()
            await pilot.pause()


class TestKeyDetailScreenBindings:
    """Tests for KeyDetailScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "s" in binding_keys
        assert "f" in binding_keys
        assert "r" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = KeyDetailScreen("ABCDEF1234567890")
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0
