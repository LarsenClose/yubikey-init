"""Tests for the tui/__init__.py module entry points."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from yubikey_init.tui import create_app, run, run_tui
from yubikey_init.tui.app import YubiKeyManagerApp


class TestTUIInitRun:
    """Tests for the run() legacy entry point in tui/__init__.py."""

    def test_run_creates_and_runs_app(self) -> None:
        """Test run() creates a YubiKeyManagerApp and calls run()."""
        with patch.object(YubiKeyManagerApp, "run") as mock_run:
            run()
            mock_run.assert_called_once()

    def test_run_creates_app_without_controller(self) -> None:
        """Test run() creates an app with no controller by default."""
        created_apps = []

        original_init = YubiKeyManagerApp.__init__

        def capture_init(self, controller=None):
            created_apps.append(controller)
            original_init(self, controller=controller)

        with (
            patch.object(YubiKeyManagerApp, "__init__", capture_init),
            patch.object(YubiKeyManagerApp, "run"),
        ):
            run()

        assert len(created_apps) == 1
        assert created_apps[0] is None


class TestTUIInitRunTui:
    """Tests for the run_tui() entry point in tui/__init__.py."""

    def test_run_tui_without_controller(self) -> None:
        """Test run_tui() with no controller delegates to app.run_tui."""
        with patch("yubikey_init.tui.app.run_tui") as mock_run_tui:
            run_tui()
            mock_run_tui.assert_called_once_with(None)

    def test_run_tui_with_controller(self) -> None:
        """Test run_tui() passes controller to the underlying function."""
        mock_controller = MagicMock()
        with patch("yubikey_init.tui.app.run_tui") as mock_run_tui:
            run_tui(controller=mock_controller)
            mock_run_tui.assert_called_once_with(mock_controller)


class TestTUIInitCreateApp:
    """Tests for the create_app() factory in tui/__init__.py."""

    def test_create_app_without_controller(self) -> None:
        """Test create_app() returns a YubiKeyManagerApp with no controller."""
        app = create_app()
        assert isinstance(app, YubiKeyManagerApp)
        assert app.controller is None

    def test_create_app_with_controller(self) -> None:
        """Test create_app() passes controller to the app."""
        mock_controller = MagicMock()
        app = create_app(controller=mock_controller)
        assert isinstance(app, YubiKeyManagerApp)
        assert app.controller is mock_controller
