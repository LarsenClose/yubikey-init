"""Main menu screen for the YubiKey Management TUI.

This screen provides the primary navigation hub for the TUI, allowing
users to access device management, key management, and diagnostics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Footer, Header, ListItem, ListView, Static

if TYPE_CHECKING:
    from ..controller import TUIController


class MainMenuScreen(Screen[None]):
    """Main menu screen for the YubiKey Manager TUI.

    Displays navigation options and summary counts for devices and keys.
    Users can navigate to device management, key management, or diagnostics.

    Keyboard shortcuts:
    - D: Go to device list
    - K: Go to key list
    - X: Go to diagnostics
    - Q: Quit application
    """

    BINDINGS = [
        Binding("d", "goto_devices", "Devices", show=True),
        Binding("k", "goto_keys", "Keys", show=True),
        Binding("x", "goto_diagnostics", "Diagnostics", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    DEFAULT_CSS = """
    MainMenuScreen {
        align: center middle;
    }

    MainMenuScreen #menu-container {
        width: 60;
        height: auto;
        border: round $primary;
        padding: 1 2;
        background: $surface;
    }

    MainMenuScreen #title {
        text-align: center;
        text-style: bold;
        color: $primary;
        padding-bottom: 1;
        border-bottom: solid $primary-darken-2;
        margin-bottom: 1;
    }

    MainMenuScreen #menu-list {
        height: auto;
        min-height: 8;
    }

    MainMenuScreen #menu-list > ListItem {
        height: 2;
        padding: 0 1;
    }

    MainMenuScreen #menu-list > ListItem:hover {
        background: $surface-lighten-1;
    }

    MainMenuScreen #menu-list > ListItem.-active {
        background: $primary;
    }

    MainMenuScreen #menu-list:focus > ListItem.--highlight {
        background: $primary 50%;
    }

    MainMenuScreen #footer-hint {
        text-align: center;
        color: $text-muted;
        padding-top: 1;
        border-top: solid $primary-darken-3;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        controller: TUIController | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the main menu screen.

        Args:
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._controller = controller
        self._device_summary = "..."
        self._key_summary = "..."

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        with Container(id="menu-container"):
            yield Static("YubiKey Manager", id="title")
            yield ListView(
                ListItem(
                    Static(
                        f"[bold cyan][D][/bold cyan] Devices        "
                        f"[dim italic]{self._device_summary}[/dim italic]"
                    ),
                    id="menu-devices",
                ),
                ListItem(
                    Static(
                        f"[bold cyan][K][/bold cyan] Keys           "
                        f"[dim italic]{self._key_summary}[/dim italic]"
                    ),
                    id="menu-keys",
                ),
                ListItem(
                    Static(
                        "[bold cyan][X][/bold cyan] Diagnostics    "
                        "[dim italic]Run system checks[/dim italic]"
                    ),
                    id="menu-diagnostics",
                ),
                ListItem(
                    Static("[bold red][Q][/bold red] Quit"),
                    id="menu-quit",
                ),
                id="menu-list",
            )
            yield Static(
                "[dim]Up/Down Navigate   Enter Select   Q Quit[/dim]",
                id="footer-hint",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Load summary data when the screen is mounted."""
        self._refresh_summaries()

    @work(exclusive=True)
    async def _refresh_summaries(self) -> None:
        """Refresh the device and key summary counts."""
        if self._controller is None:
            self._device_summary = "No controller"
            self._key_summary = "No controller"
            self._update_menu_display()
            return

        try:
            # Get device summary
            devices = self._controller.get_devices()
            device_count = len(devices)
            needs_attention = sum(
                1 for d in devices if d.openpgp_state and d.openpgp_state.is_pin_blocked()
            )

            if device_count == 0:
                self._device_summary = "No devices connected"
            elif needs_attention > 0:
                self._device_summary = (
                    f"{device_count} connected, {needs_attention} needs attention"
                )
            else:
                self._device_summary = f"{device_count} connected"

            # Get key summary
            keys = self._controller.get_keys()
            key_count = len(keys)
            self._key_summary = f"{key_count} key{'s' if key_count != 1 else ''} in keyring"

            # Update the display
            self._update_menu_display()

        except Exception:
            # Gracefully handle errors during refresh
            self._device_summary = "Unable to load"
            self._key_summary = "Unable to load"
            self._update_menu_display()

    def _update_menu_display(self) -> None:
        """Update the menu items with current summary data."""
        try:
            menu_list = self.query_one("#menu-list", ListView)

            # Update devices item
            devices_item = menu_list.query_one("#menu-devices", ListItem)
            devices_static = devices_item.query_one(Static)
            devices_static.update(
                f"[bold cyan][D][/bold cyan] Devices        "
                f"[dim italic]{self._device_summary}[/dim italic]"
            )

            # Update keys item
            keys_item = menu_list.query_one("#menu-keys", ListItem)
            keys_static = keys_item.query_one(Static)
            keys_static.update(
                f"[bold cyan][K][/bold cyan] Keys           "
                f"[dim italic]{self._key_summary}[/dim italic]"
            )
        except Exception:
            # Screen may not be fully mounted yet
            pass

    @on(ListView.Selected, "#menu-list")
    def on_menu_selected(self, event: ListView.Selected) -> None:
        """Handle selection of a menu item."""
        item_id = event.item.id

        if item_id == "menu-devices":
            self.action_goto_devices()
        elif item_id == "menu-keys":
            self.action_goto_keys()
        elif item_id == "menu-diagnostics":
            self.action_goto_diagnostics()
        elif item_id == "menu-quit":
            self.action_quit()

    def action_goto_devices(self) -> None:
        """Navigate to the device list screen."""
        from .device_list import DeviceListScreen

        self.app.push_screen(DeviceListScreen(controller=self._controller))

    def action_goto_keys(self) -> None:
        """Navigate to the key list screen."""
        from .key_list import KeyListScreen

        self.app.push_screen(KeyListScreen(controller=self._controller))

    def action_goto_diagnostics(self) -> None:
        """Navigate to the diagnostics screen."""
        from .diagnostics import DiagnosticsScreen

        self.app.push_screen(DiagnosticsScreen(controller=self._controller))

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()
