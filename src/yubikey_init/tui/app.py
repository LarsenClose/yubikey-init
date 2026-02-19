"""Main Textual application for YubiKey management TUI.

This module provides the main application class and entry point for the
YubiKey management terminal user interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

from .screens import (
    DeviceDetailScreen,
    DeviceListScreen,
    DiagnosticsScreen,
    KeyDetailScreen,
    KeyListScreen,
    MainMenuScreen,
)

if TYPE_CHECKING:
    from .controller import TUIController


class YubiKeyManagerApp(App[None]):
    """Main TUI application for YubiKey management.

    This application provides an interactive interface for:
    - Viewing and managing YubiKey devices
    - Inspecting GPG keys and their status
    - Running diagnostics
    - Performing device operations (reset, label, protect)
    """

    TITLE = "YubiKey Manager"
    SUB_TITLE = "Device and Key Management"

    CSS_PATH = Path(__file__).parent / "styles.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True, priority=True),
        Binding("d", "devices", "Devices", show=True),
        Binding("k", "keys", "Keys", show=True),
        Binding("x", "diagnostics", "Diagnostics", show=True),
        Binding("escape", "back", "Back", show=True),
        Binding("m", "main_menu", "Main Menu", show=False),
    ]

    def __init__(
        self,
        controller: TUIController | None = None,
    ) -> None:
        """Initialize the YubiKey Manager application.

        Args:
            controller: Optional TUIController instance. If not provided,
                        one will be created on mount.
        """
        super().__init__()
        self._controller = controller
        self._selected_device_serial: str | None = None
        self._selected_key_id: str | None = None

    @property
    def controller(self) -> TUIController | None:
        """Get the TUI controller instance."""
        return self._controller

    @controller.setter
    def controller(self, value: TUIController) -> None:
        """Set the TUI controller instance."""
        self._controller = value

    @property
    def selected_device_serial(self) -> str | None:
        """Get the currently selected device serial number."""
        return self._selected_device_serial

    @selected_device_serial.setter
    def selected_device_serial(self, value: str | None) -> None:
        """Set the currently selected device serial number."""
        self._selected_device_serial = value

    @property
    def selected_key_id(self) -> str | None:
        """Get the currently selected key ID."""
        return self._selected_key_id

    @selected_key_id.setter
    def selected_key_id(self, value: str | None) -> None:
        """Set the currently selected key ID."""
        self._selected_key_id = value

    def compose(self) -> ComposeResult:
        """Compose the application UI.

        Yields:
            Header, main content container, and Footer widgets.
        """
        yield Header(show_clock=True)
        yield Footer()

    def on_mount(self) -> None:
        """Handle application mount event.

        Pushes the main menu screen when the application starts.
        """
        self.push_screen(MainMenuScreen())

    def action_quit(self) -> None:  # type: ignore[override]
        """Handle quit action."""
        self.exit()

    def action_devices(self) -> None:
        """Navigate to the device list screen."""
        # Clear any selected device when going to list
        self._selected_device_serial = None

        # Check if we're already on DeviceListScreen
        if isinstance(self.screen, DeviceListScreen):
            return

        # Pop screens until we're at MainMenuScreen, then push DeviceListScreen
        while len(self.screen_stack) > 1:
            self.pop_screen()

        self.push_screen(DeviceListScreen())

    def action_keys(self) -> None:
        """Navigate to the key list screen."""
        # Clear any selected key when going to list
        self._selected_key_id = None

        # Check if we're already on KeyListScreen
        if isinstance(self.screen, KeyListScreen):
            return

        # Pop screens until we're at MainMenuScreen, then push KeyListScreen
        while len(self.screen_stack) > 1:
            self.pop_screen()

        self.push_screen(KeyListScreen())

    def action_diagnostics(self) -> None:
        """Navigate to the diagnostics screen."""
        # Check if we're already on DiagnosticsScreen
        if isinstance(self.screen, DiagnosticsScreen):
            return

        # Pop screens until we're at MainMenuScreen, then push DiagnosticsScreen
        while len(self.screen_stack) > 1:
            self.pop_screen()

        self.push_screen(DiagnosticsScreen())

    def action_back(self) -> None:  # type: ignore[override]
        """Navigate back to the previous screen.

        If on the main menu, this does nothing.
        """
        if len(self.screen_stack) > 1:
            self.pop_screen()

    def action_main_menu(self) -> None:
        """Navigate directly to the main menu.

        Pops all screens until only the main menu remains.
        """
        while len(self.screen_stack) > 1:
            self.pop_screen()

    def navigate_to_device_detail(self, serial: str) -> None:
        """Navigate to the device detail screen for a specific device.

        Args:
            serial: The serial number of the device to view.
        """
        self._selected_device_serial = serial
        self.push_screen(DeviceDetailScreen(device_serial=serial, controller=self._controller))

    def navigate_to_key_detail(self, key_id: str) -> None:
        """Navigate to the key detail screen for a specific key.

        Args:
            key_id: The ID of the key to view.
        """
        self._selected_key_id = key_id
        self.push_screen(KeyDetailScreen(key_id=key_id, controller=self._controller))


def run_tui(controller: TUIController | None = None) -> None:
    """Run the YubiKey Manager TUI application.

    This is the main entry point for launching the TUI.

    Args:
        controller: Optional TUIController instance. If not provided,
                    the application will create one using default settings.

    Example:
        >>> from yubikey_init.tui.app import run_tui
        >>> run_tui()  # Launch with default controller
    """
    app = YubiKeyManagerApp(controller=controller)
    app.run()


def create_app(controller: TUIController | None = None) -> YubiKeyManagerApp:
    """Create a YubiKey Manager application instance without running it.

    This is useful for testing or custom initialization.

    Args:
        controller: Optional TUIController instance.

    Returns:
        Configured YubiKeyManagerApp instance.

    Example:
        >>> from yubikey_init.tui.app import create_app
        >>> app = create_app()
        >>> # Configure app further if needed
        >>> app.run()
    """
    return YubiKeyManagerApp(controller=controller)
