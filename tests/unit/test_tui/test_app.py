"""Tests for the main TUI application."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from yubikey_init.tui.app import YubiKeyManagerApp, create_app, run_tui


class TestYubiKeyManagerApp:
    """Tests for the YubiKeyManagerApp class."""

    def test_app_title(self) -> None:
        """Test application title is set correctly."""
        app = YubiKeyManagerApp()
        assert app.TITLE == "YubiKey Manager"
        assert app.SUB_TITLE == "Device and Key Management"

    def test_app_bindings(self) -> None:
        """Test application bindings are defined."""
        app = YubiKeyManagerApp()
        binding_keys = [b.key for b in app.BINDINGS]
        assert "q" in binding_keys
        assert "d" in binding_keys
        assert "k" in binding_keys
        assert "x" in binding_keys
        assert "escape" in binding_keys

    def test_controller_property_none_by_default(self) -> None:
        """Test controller is None by default."""
        app = YubiKeyManagerApp()
        assert app.controller is None

    def test_controller_property_setter(self) -> None:
        """Test controller can be set."""
        app = YubiKeyManagerApp()
        mock_controller = MagicMock()
        app.controller = mock_controller
        assert app.controller is mock_controller

    def test_controller_passed_in_init(self) -> None:
        """Test controller can be passed during initialization."""
        mock_controller = MagicMock()
        app = YubiKeyManagerApp(controller=mock_controller)
        assert app.controller is mock_controller

    def test_selected_device_serial_property(self) -> None:
        """Test selected_device_serial property."""
        app = YubiKeyManagerApp()
        assert app.selected_device_serial is None

        app.selected_device_serial = "12345678"
        assert app.selected_device_serial == "12345678"

    def test_selected_key_id_property(self) -> None:
        """Test selected_key_id property."""
        app = YubiKeyManagerApp()
        assert app.selected_key_id is None

        app.selected_key_id = "ABCDEF12"
        assert app.selected_key_id == "ABCDEF12"


class TestCreateApp:
    """Tests for the create_app factory function."""

    def test_create_app_default(self) -> None:
        """Test create_app returns app instance."""
        app = create_app()
        assert isinstance(app, YubiKeyManagerApp)
        assert app.controller is None

    def test_create_app_with_controller(self) -> None:
        """Test create_app with controller argument."""
        mock_controller = MagicMock()
        app = create_app(controller=mock_controller)
        assert app.controller is mock_controller


class TestRunTUI:
    """Tests for the run_tui entry point."""

    def test_run_tui_creates_app(self) -> None:
        """Test run_tui creates and runs the app."""
        with patch.object(YubiKeyManagerApp, "run") as mock_run:
            run_tui()
            mock_run.assert_called_once()

    def test_run_tui_with_controller(self) -> None:
        """Test run_tui passes controller to app."""
        mock_controller = MagicMock()
        with patch.object(YubiKeyManagerApp, "run") as mock_run:
            run_tui(controller=mock_controller)
            mock_run.assert_called_once()
