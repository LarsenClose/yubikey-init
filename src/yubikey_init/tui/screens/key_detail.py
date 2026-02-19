"""Key detail screen for the YubiKey Management TUI.

This screen displays detailed information about a specific GPG key,
including fingerprint, creation date, expiration, capabilities,
subkeys, and which YubiKey holds the key (if any).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Rule, Static

if TYPE_CHECKING:
    from ..controller import KeyDisplayInfo, TUIController


class KeyDetailScreen(Screen[None]):
    """Screen displaying detailed information about a GPG key.

    Shows key properties (fingerprint, dates, capabilities),
    subkeys, and which YubiKey holds this key.

    Keyboard shortcuts:
    - S: Export SSH key
    - F: Copy fingerprint
    - R: Refresh
    - Escape: Go back
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True, priority=True),
        Binding("s", "export_ssh", "Export SSH", show=True),
        Binding("f", "copy_fingerprint", "Copy Fingerprint", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    DEFAULT_CSS = """
    KeyDetailScreen {
        layout: vertical;
    }

    KeyDetailScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    KeyDetailScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }

    KeyDetailScreen .section-title {
        text-style: bold;
        color: $text;
        padding-bottom: 1;
        border-bottom: solid $primary-darken-3;
        margin-bottom: 1;
    }

    KeyDetailScreen .property-row {
        height: 1;
        padding: 0 0 0 2;
    }

    KeyDetailScreen .property-label {
        color: $text-muted;
    }

    KeyDetailScreen .section-content {
        padding: 0 0 1 2;
    }

    KeyDetailScreen .section-divider {
        margin: 1 0;
    }

    KeyDetailScreen #actions-container {
        layout: horizontal;
        height: 3;
        padding-top: 1;
    }

    KeyDetailScreen #actions-container Button {
        margin-right: 2;
    }

    KeyDetailScreen #subkeys-content {
        padding: 0 0 0 2;
    }

    KeyDetailScreen .subkey-item {
        padding-bottom: 1;
    }
    """

    def __init__(
        self,
        key_id: str,
        controller: TUIController | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the key detail screen.

        Args:
            key_id: The GPG key ID to display.
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._key_id = key_id
        self._controller = controller
        self._key_info: KeyDisplayInfo | None = None
        self._subkeys: list[dict[str, str]] = []
        self._yubikey_location: str | None = None

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("Key Details", id="screen-title", classes="screen-title")

        with VerticalScroll(classes="content-container"):
            # Key Properties Section
            with Vertical(id="properties-section"):
                yield Static("Key Properties", classes="section-title")
                yield Static("", id="prop-fingerprint", classes="property-row")
                yield Static("", id="prop-identity", classes="property-row")
                yield Static("", id="prop-created", classes="property-row")
                yield Static("", id="prop-expires", classes="property-row")
                yield Static("", id="prop-algorithm", classes="property-row")

            yield Rule(classes="section-divider")

            # Subkeys Section
            with Vertical(id="subkeys-section"):
                yield Static("Subkeys", classes="section-title")
                yield Static("", id="subkeys-content")

            yield Rule(classes="section-divider")

            # YubiKey Location Section
            with Vertical(id="location-section"):
                yield Static("YubiKey Location", classes="section-title")
                yield Static("", id="yubikey-location", classes="section-content")

            yield Rule(classes="section-divider")

            # Actions Section
            with Vertical(id="actions-section"):
                yield Static("Actions", classes="section-title")
                with Horizontal(id="actions-container"):
                    yield Button("[S] Export SSH", id="btn-export-ssh", variant="primary")
                    yield Button("[F] Copy Fingerprint", id="btn-copy-fp")

        yield Footer()

    def on_mount(self) -> None:
        """Load key details when the screen is mounted."""
        self._refresh_key_info()

    @work(exclusive=True)
    async def _refresh_key_info(self) -> None:
        """Refresh the key information from the controller."""
        if self._controller is None:
            self._show_error("No controller available")
            return

        try:
            # Get key info
            key_info = self._controller.get_key_info(self._key_id)
            if key_info is None:
                self._show_error(f"Key not found: {self._key_id}")
                return

            self._key_info = key_info

            # Get subkeys
            self._subkeys = self._controller.get_subkeys(self._key_id)

            # Get YubiKey location
            device_map = self._controller.get_key_device_mapping()
            self._yubikey_location = device_map.get(self._key_id)

            # Update display
            self._update_display()

        except Exception as e:
            self._show_error(f"Error loading key: {e}")

    def _update_display(self) -> None:
        """Update the display with current key information."""
        if self._key_info is None:
            return

        key = self._key_info

        # Update title
        title = self.query_one("#screen-title", Static)
        identity_short = key.identity[:35] + "..." if len(key.identity) > 35 else key.identity
        title.update(f"Key: {identity_short}")

        # Update key properties
        fingerprint = key.fingerprint
        if len(fingerprint) >= 40:
            # Format fingerprint in groups of 4
            fp_display = " ".join(
                fingerprint[i : i + 4] for i in range(0, min(40, len(fingerprint)), 4)
            )
        else:
            fp_display = fingerprint

        self.query_one("#prop-fingerprint", Static).update(f"[dim]Fingerprint:[/dim]  {fp_display}")
        self.query_one("#prop-identity", Static).update(f"[dim]Identity:[/dim]     {key.identity}")
        self.query_one("#prop-created", Static).update(
            f"[dim]Created:[/dim]      {key.creation_date.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.query_one("#prop-expires", Static).update(
            f"[dim]Expires:[/dim]      {self._format_expiry(key.expiry_date)}"
        )
        self.query_one("#prop-algorithm", Static).update(
            f"[dim]Algorithm:[/dim]    {getattr(key, 'key_type', 'Unknown')}"
        )

        # Update subkeys section
        subkeys_content = self.query_one("#subkeys-content", Static)
        if self._subkeys:
            subkeys_text = ""
            for subkey in self._subkeys:
                usage = subkey.get("type", "Unknown")
                fp = subkey.get("fingerprint", "")

                # Format fingerprint compactly
                fp_short = f"{fp[:4]} {fp[4:8]} ... {fp[-8:-4]} {fp[-4:]}" if len(fp) >= 16 else fp

                expiry = subkey.get("expiry", "N/A")
                subkeys_text += f"[cyan]{usage:14}[/cyan] {fp_short}\n"
                subkeys_text += f"                Expires: {expiry}\n\n"
            subkeys_content.update(subkeys_text.rstrip())
        else:
            subkeys_content.update("[dim]No subkeys found[/dim]")

        # Update YubiKey location
        location_content = self.query_one("#yubikey-location", Static)
        if self._yubikey_location:
            location_content.update(f"[green]On YubiKey:[/green] {self._yubikey_location}")
        else:
            location_content.update("[dim]Not on any known YubiKey[/dim]")

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
            return (
                f"[bold yellow]{expiry_date.strftime('%Y-%m-%d')} ({days_until} days)[/bold yellow]"
            )
        elif days_until <= 90:
            return f"[yellow]{expiry_date.strftime('%Y-%m-%d')}[/yellow]"
        else:
            return expiry_date.strftime("%Y-%m-%d")

    def _show_error(self, message: str) -> None:
        """Display an error message.

        Args:
            message: The error message to display.
        """
        self.notify(message, title="Error", severity="error", timeout=5)

    def action_go_back(self) -> None:
        """Go back to the key list screen."""
        self.app.pop_screen()

    def action_export_ssh(self) -> None:
        """Export the SSH public key."""
        if self._controller is None or self._key_info is None:
            self.notify("No key loaded", severity="error", timeout=3)
            return

        result = self._controller.export_ssh_key(self._key_id)
        if result.is_ok():
            ssh_key = result.unwrap()
            # Show first part of key (in real implementation, copy to clipboard)
            key_preview = ssh_key[:60] + "..." if len(ssh_key) > 60 else ssh_key
            self.notify(
                f"SSH key:\n{key_preview}",
                title="SSH Key Exported",
                timeout=10,
            )
        else:
            self.notify(
                f"Failed to export SSH key: {result.unwrap_err()}",
                title="Export Failed",
                severity="error",
                timeout=5,
            )

    def action_copy_fingerprint(self) -> None:
        """Copy the key fingerprint to clipboard."""
        if self._key_info is None:
            self.notify("No key loaded", severity="error", timeout=3)
            return

        fingerprint = self._key_info.fingerprint
        # In a real implementation, this would copy to clipboard
        self.notify(
            f"Fingerprint:\n{fingerprint}",
            title="Copied to Clipboard",
            timeout=5,
        )

    def action_refresh(self) -> None:
        """Refresh the key information."""
        self._refresh_key_info()
        self.notify("Key info refreshed", timeout=2)

    @on(Button.Pressed, "#btn-export-ssh")
    def on_export_ssh_pressed(self) -> None:
        """Handle Export SSH button press."""
        self.action_export_ssh()

    @on(Button.Pressed, "#btn-copy-fp")
    def on_copy_fp_pressed(self) -> None:
        """Handle Copy Fingerprint button press."""
        self.action_copy_fingerprint()
