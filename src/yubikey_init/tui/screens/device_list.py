"""Device list screen for the YubiKey Manager TUI.

Displays a table of all connected/known YubiKey devices with their
status and key information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.coordinate import Coordinate
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from ..widgets.confirm_dialog import ConfirmDialog, InputDialog

if TYPE_CHECKING:
    from ..controller import DeviceDisplayInfo, TUIController


class DeviceListScreen(Screen[None]):
    """Screen displaying a list of YubiKey devices.

    Shows a table with columns:
    - #: Row number
    - Serial: Device serial number
    - Label: User-assigned label
    - Type: Device type (e.g., "YubiKey 5C NFC")
    - Keys: Whether keys are loaded
    - PIN: PIN tries status
    - Protected: Protection status

    Keyboard bindings:
    - Enter: View device details
    - L: Set device label
    - R: Reset device (with confirmation)
    - Escape: Go back to main menu
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True, priority=True),
        Binding("enter", "select_device", "Details", show=True),
        Binding("l", "label_device", "Label", show=True),
        Binding("r", "reset_device", "Reset", show=True),
        Binding("R", "refresh", "Refresh", show=True),
    ]

    DEFAULT_CSS = """
    DeviceListScreen {
        layout: vertical;
    }

    DeviceListScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    DeviceListScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }

    DeviceListScreen DataTable {
        width: 100%;
        height: 1fr;
    }

    DeviceListScreen .empty-message {
        width: 100%;
        height: 100%;
        content-align: center middle;
        color: $text-muted;
    }

    DeviceListScreen .status-ok {
        color: $success;
    }

    DeviceListScreen .status-warning {
        color: $warning;
    }

    DeviceListScreen .status-blocked {
        color: $error;
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
        """Initialize the device list screen.

        Args:
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._controller = controller

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("Devices", classes="screen-title")

        with Container(classes="content-container"):
            yield DataTable(id="device-table", cursor_type="row")

        yield Footer()

    def on_mount(self) -> None:
        """Set up the data table and load devices."""
        table = self.query_one("#device-table", DataTable)

        # Add columns
        table.add_column("#", key="num", width=3)
        table.add_column("Serial", key="serial", width=12)
        table.add_column("Label", key="label", width=16)
        table.add_column("Type", key="type", width=20)
        table.add_column("Keys", key="keys", width=6)
        table.add_column("PIN", key="pin", width=10)
        table.add_column("Protected", key="protected", width=10)

        # Load devices
        self._refresh_devices()

    def _refresh_devices(self) -> None:
        """Refresh the device list from controller."""
        table = self.query_one("#device-table", DataTable)
        table.clear()

        if not self._controller:
            table.add_row("1", "-", "No controller", "-", "-", "-", "-")
            return

        devices = self._controller.get_devices()

        if not devices:
            table.add_row("", "", "No devices found", "", "", "", "")
            return

        for idx, device in enumerate(devices, 1):
            # Determine status indicators
            pin_status = self._format_pin_status(device)
            keys_status = (
                "Yes" if device.openpgp_state and device.openpgp_state.has_keys() else "No"
            )
            protected = "Yes" if device.protected else "No"

            table.add_row(
                str(idx),
                device.serial,
                device.label or "-",
                device.device_type or "YubiKey",
                keys_status,
                pin_status,
                protected,
                key=device.serial,
            )

    def _format_pin_status(self, device: DeviceDisplayInfo) -> str:
        """Format PIN status for display.

        Args:
            device: DeviceDisplayInfo instance.

        Returns:
            Formatted PIN status string.
        """
        if not device.openpgp_state:
            return "?"

        tries = device.openpgp_state.pin_tries_remaining
        if tries == 0:
            return "! BLOCKED"
        elif tries < 3:
            return f"! {tries}/3"
        else:
            return f"* {tries}/3"

    def _get_selected_device(self) -> tuple[str, int] | None:
        """Get the currently selected device serial and row index.

        Returns:
            Tuple of (serial, row_index) or None if no selection.
        """
        table = self.query_one("#device-table", DataTable)

        if table.row_count == 0:
            return None

        cursor_row = table.cursor_row
        if cursor_row is None:
            return None

        # Get the row key (which is the serial number)
        try:
            row_key = table.get_row_at(cursor_row)
            if row_key:
                # The key is stored as the row key, but we stored serial there
                # Get serial from the second column
                cells = table.get_row_at(cursor_row)
                if cells and len(cells) > 1:
                    serial = str(cells[1])  # Serial is second column
                    if serial and serial != "-" and serial != "":
                        return (serial, cursor_row)
        except Exception:
            pass

        return None

    def _get_selected_serial(self) -> str | None:
        """Get the serial of the currently selected device.

        Returns:
            Device serial or None if no selection.
        """
        table = self.query_one("#device-table", DataTable)

        if table.row_count == 0:
            return None

        cursor_row = table.cursor_row
        if cursor_row is None:
            return None

        try:
            # Get the row data
            row_key, _ = table.coordinate_to_cell_key(Coordinate(cursor_row, 0))
            # The row key is the device serial
            return str(row_key.value) if row_key.value else None
        except Exception:
            return None

    @on(DataTable.RowSelected, "#device-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection - navigate to device detail."""
        if event.row_key.value:
            serial = str(event.row_key.value)
            self._navigate_to_detail(serial)

    def _navigate_to_detail(self, serial: str) -> None:
        """Navigate to the device detail screen.

        Args:
            serial: Device serial number.
        """
        from .device_detail import DeviceDetailScreen

        self.app.push_screen(DeviceDetailScreen(serial, controller=self._controller))

    def action_go_back(self) -> None:
        """Go back to the main menu."""
        self.app.pop_screen()

    def action_select_device(self) -> None:
        """Select the current device and view details."""
        serial = self._get_selected_serial()
        if serial:
            self._navigate_to_detail(serial)

    def action_refresh(self) -> None:
        """Refresh the device list."""
        self._refresh_devices()
        self.notify("Device list refreshed")

    async def action_label_device(self) -> None:
        """Set a label for the selected device."""
        serial = self._get_selected_serial()
        if not serial:
            self.notify("No device selected", severity="warning")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        # Get current label
        device = self._controller.get_device(serial)
        current_label = device.label if device else ""

        # Show input dialog
        new_label = await self.app.push_screen_wait(
            InputDialog(
                title="Set Device Label",
                message=f"Enter a label for device {serial}:",
                placeholder="e.g., Work Primary, Backup",
                initial_value=current_label or "",
            )
        )

        if new_label is not None:
            result = self._controller.set_device_label(serial, new_label)
            if result.is_ok():
                self._refresh_devices()
                self.notify(f"Label set to '{new_label}'")
            else:
                self.notify(f"Failed: {result.unwrap_err()}", severity="error")

    async def action_reset_device(self) -> None:
        """Reset the selected device (with confirmation)."""
        serial = self._get_selected_serial()
        if not serial:
            self.notify("No device selected", severity="warning")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        # Check if device is protected
        device = self._controller.get_device(serial)
        if device and device.protected:
            self.notify(
                f"Device {serial} is protected. Unprotect first.",
                severity="warning",
            )
            return

        # Get device display name
        display_name = device.display_name if device else serial

        # Show confirmation dialog
        confirmed = await self.app.push_screen_wait(
            ConfirmDialog(
                title="Reset OpenPGP Application",
                message=(
                    "This will PERMANENTLY DELETE all keys on this "
                    "YubiKey's OpenPGP application.\n\n"
                    "This action cannot be undone."
                ),
                confirm_text=f"reset {serial}",
                device_info=f"Device: {display_name}",
            )
        )

        if confirmed:
            result = self._controller.reset_device(serial)
            if result.is_ok():
                self._refresh_devices()
                self.notify(f"Device {serial} has been reset")
            else:
                self.notify(f"Reset failed: {result.unwrap_err()}", severity="error")
