"""Key list screen for the YubiKey Management TUI.

This screen displays a table of GPG keys in the keyring, showing key ID,
identity, expiration date, and which YubiKey holds the key (if any).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.coordinate import Coordinate
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

if TYPE_CHECKING:
    from ..controller import KeyDisplayInfo, TUIController


class KeyListScreen(Screen[None]):
    """Screen displaying a list of GPG keys in the keyring.

    Shows key ID, identity, expiration status, and which YubiKey
    holds each key. Keys expiring within 30 days are highlighted.

    Keyboard shortcuts:
    - Enter: View key details
    - S: Export SSH key
    - R: Refresh list
    - Escape: Go back
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True, priority=True),
        Binding("enter", "select_key", "Details", show=True),
        Binding("s", "export_ssh", "Export SSH", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    DEFAULT_CSS = """
    KeyListScreen {
        layout: vertical;
    }

    KeyListScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    KeyListScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }

    KeyListScreen DataTable {
        width: 100%;
        height: 1fr;
    }

    KeyListScreen #empty-message {
        text-align: center;
        color: $text-muted;
        padding: 4;
    }

    KeyListScreen .expiring-soon {
        color: $warning;
        text-style: bold;
    }

    KeyListScreen .expired {
        color: $error;
        text-style: bold;
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
        """Initialize the key list screen.

        Args:
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._controller = controller
        self._keys: list[KeyDisplayInfo] = []
        self._key_yubikey_map: dict[str, str] = {}  # key_id -> yubikey label

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("Keys", classes="screen-title")
        with Container(classes="content-container"):
            yield DataTable(id="key-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize the key table when mounted."""
        table = self.query_one("#key-table", DataTable)
        table.add_column("#", key="num", width=4)
        table.add_column("Key ID", key="key_id", width=18)
        table.add_column("Identity", key="identity", width=32)
        table.add_column("Expires", key="expires", width=16)
        table.add_column("Location", key="location", width=22)

        self._refresh_keys()

    @work(exclusive=True)
    async def _refresh_keys(self) -> None:
        """Refresh the key list from the controller."""
        table = self.query_one("#key-table", DataTable)
        table.clear()

        if self._controller is None:
            table.add_row("", "", "No controller available", "", "")
            return

        try:
            self._keys = self._controller.get_keys()
            self._key_yubikey_map = self._controller.get_key_device_mapping()

            if not self._keys:
                # Show empty message in the table
                table.add_row("", "", "[dim]No keys in keyring[/dim]", "", "")
                return

            for idx, key in enumerate(self._keys, start=1):
                # Format key ID (short form)
                key_id_display = f"0x{key.key_id[-8:]}..."

                # Format expiration with warning colors
                expiry_display = self._format_expiry(key.expiry_date)

                # Get YubiKey location if known
                location = self._key_yubikey_map.get(key.key_id, "")
                if location:
                    location = f"[cyan]{location}[/cyan]"

                table.add_row(
                    str(idx),
                    key_id_display,
                    self._truncate_identity(key.identity, 30),
                    expiry_display,
                    location,
                    key=key.key_id,
                )

        except Exception as e:
            table.add_row("", "", f"[red]Error: {e}[/red]", "", "")

    def _truncate_identity(self, identity: str, max_len: int) -> str:
        """Truncate identity string if too long.

        Args:
            identity: The identity string to truncate.
            max_len: Maximum length.

        Returns:
            Truncated string with ellipsis if needed.
        """
        if len(identity) <= max_len:
            return identity
        return identity[: max_len - 3] + "..."

    def _format_expiry(self, expiry_date: datetime | None) -> str:
        """Format the expiration date with appropriate styling.

        Args:
            expiry_date: The expiration datetime or None for no expiry.

        Returns:
            Formatted expiry string with Rich markup.
        """
        if expiry_date is None:
            return "[dim]Never[/dim]"

        now = datetime.now(UTC)
        days_until = (expiry_date - now).days

        if days_until < 0:
            return "[bold red]EXPIRED[/bold red]"
        elif days_until <= 30:
            return f"[bold yellow]{days_until} days[/bold yellow]"
        elif days_until <= 90:
            return f"[yellow]{expiry_date.strftime('%Y-%m-%d')}[/yellow]"
        else:
            return expiry_date.strftime("%Y-%m-%d")

    def _get_selected_key_id(self) -> str | None:
        """Get the key ID of the currently selected row.

        Returns:
            The key ID string or None if no selection.
        """
        table = self.query_one("#key-table", DataTable)

        if table.row_count == 0:
            return None

        cursor_row = table.cursor_row
        if cursor_row is None:
            return None

        try:
            row_key, _ = table.coordinate_to_cell_key(Coordinate(cursor_row, 0))
            return str(row_key.value) if row_key.value else None
        except Exception:
            return None

    @on(DataTable.RowSelected, "#key-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection - navigate to key detail."""
        if event.row_key.value:
            key_id = str(event.row_key.value)
            self._navigate_to_detail(key_id)

    def _navigate_to_detail(self, key_id: str) -> None:
        """Navigate to the key detail screen.

        Args:
            key_id: The GPG key ID.
        """
        from .key_detail import KeyDetailScreen

        self.app.push_screen(KeyDetailScreen(key_id=key_id, controller=self._controller))

    def action_go_back(self) -> None:
        """Go back to the main menu."""
        self.app.pop_screen()

    def action_select_key(self) -> None:
        """Select the current key and view details."""
        key_id = self._get_selected_key_id()
        if key_id:
            self._navigate_to_detail(key_id)

    def action_refresh(self) -> None:
        """Refresh the key list."""
        self._refresh_keys()
        self.notify("Key list refreshed")

    def action_export_ssh(self) -> None:
        """Export the SSH key for the selected GPG key."""
        key_id = self._get_selected_key_id()
        if not key_id:
            self.notify("No key selected", severity="warning")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        # Export SSH key and show notification
        result = self._controller.export_ssh_key(key_id)
        if result.is_ok():
            ssh_key = result.unwrap()
            # Show first part of key
            key_preview = ssh_key[:60] + "..." if len(ssh_key) > 60 else ssh_key
            self.notify(
                f"SSH key:\n{key_preview}",
                title="SSH Key Exported",
                timeout=8,
            )
        else:
            self.notify(
                f"Failed to export SSH key: {result.unwrap_err()}",
                title="Export Failed",
                severity="error",
                timeout=5,
            )
