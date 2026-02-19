"""Device detail screen for the YubiKey Manager TUI.

Displays detailed information about a single YubiKey device including
OpenPGP status, key fingerprints, and available actions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Rule, Static

from ..widgets.confirm_dialog import ConfirmDialog, InputDialog
from ..widgets.status_indicator import (
    format_pin_status,
)

if TYPE_CHECKING:
    from ..controller import DeviceDisplayInfo, TUIController


class DeviceDetailScreen(Screen[None]):
    """Screen displaying detailed information about a YubiKey device.

    Shows device properties:
    - Status (Ready, Blocked, etc.)
    - Type (e.g., "YubiKey 5 FIPS (USB-C)")
    - Firmware version
    - Protection status

    OpenPGP status:
    - User PIN status and tries remaining
    - Admin PIN tries remaining
    - Key fingerprints with touch policies for each slot

    Available actions:
    - U: Unblock PIN (if blocked)
    - R: Reset OpenPGP
    - L: Set label
    - P: Toggle protection
    - N: Edit notes

    Keyboard bindings:
    - Escape: Go back to device list
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True, priority=True),
        Binding("u", "unblock_pin", "Unblock PIN", show=True),
        Binding("r", "reset_device", "Reset", show=True),
        Binding("l", "set_label", "Label", show=True),
        Binding("p", "toggle_protect", "Protect", show=True),
        Binding("n", "edit_notes", "Notes", show=True),
    ]

    DEFAULT_CSS = """
    DeviceDetailScreen {
        layout: vertical;
    }

    DeviceDetailScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    DeviceDetailScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
        overflow-y: auto;
    }

    DeviceDetailScreen .section {
        width: 100%;
        margin-bottom: 1;
    }

    DeviceDetailScreen .section-title {
        text-style: bold;
        color: $text;
        padding-bottom: 1;
        border-bottom: solid $primary-darken-2;
    }

    DeviceDetailScreen .property-row {
        width: 100%;
        height: 1;
        padding-left: 2;
    }

    DeviceDetailScreen .property-label {
        width: 18;
        color: $text-muted;
    }

    DeviceDetailScreen .property-value {
        width: 1fr;
    }

    DeviceDetailScreen .key-slot {
        width: 100%;
        height: auto;
        padding-left: 2;
        margin-bottom: 1;
    }

    DeviceDetailScreen .key-fingerprint {
        color: $text;
    }

    DeviceDetailScreen .key-no-key {
        color: $text-disabled;
        text-style: italic;
    }

    DeviceDetailScreen .touch-policy {
        color: $text-muted;
    }

    DeviceDetailScreen .actions-container {
        width: 100%;
        height: auto;
        padding: 1 0;
    }

    DeviceDetailScreen .action-row {
        width: 100%;
        height: 3;
        padding-left: 2;
    }

    DeviceDetailScreen .action-hint {
        color: $text-muted;
        padding-left: 2;
        padding-bottom: 1;
    }

    DeviceDetailScreen .status-ok {
        color: $success;
    }

    DeviceDetailScreen .status-warning {
        color: $warning;
    }

    DeviceDetailScreen .status-error {
        color: $error;
    }

    DeviceDetailScreen .notes-display {
        padding: 1 2;
        background: $surface-darken-1;
        margin-top: 1;
        height: auto;
        max-height: 5;
    }
    """

    def __init__(
        self,
        device_serial: str,
        controller: TUIController | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the device detail screen.

        Args:
            device_serial: The serial number of the device to display.
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._serial = device_serial
        self._controller = controller
        self._device: DeviceDisplayInfo | None = None

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("Device Details", id="screen-title", classes="screen-title")

        with Container(classes="content-container"):
            # Device Info Section
            with Vertical(classes="section", id="device-section"):
                yield Static("Device Information", classes="section-title")
                yield self._create_property_row("status-row", "Status", "Loading...")
                yield self._create_property_row("type-row", "Type", "Loading...")
                yield self._create_property_row("firmware-row", "Firmware", "Loading...")
                yield self._create_property_row("protected-row", "Protected", "Loading...")

            yield Rule()

            # OpenPGP Section
            with Vertical(classes="section", id="openpgp-section"):
                yield Static("OpenPGP Status", classes="section-title")
                yield self._create_property_row("user-pin-row", "User PIN", "Loading...")
                yield self._create_property_row("admin-pin-row", "Admin PIN", "Loading...")

                yield Static("")  # Spacer

                # Key slots
                yield Static("Key Slots:", classes="property-label")
                with Vertical(id="key-slots"):
                    yield self._create_key_slot_row("sig-key", "Signature", None, None)
                    yield self._create_key_slot_row("enc-key", "Encryption", None, None)
                    yield self._create_key_slot_row("auth-key", "Authentication", None, None)

            yield Rule()

            # Notes Section (if any)
            with Vertical(classes="section", id="notes-section"):
                yield Static("Notes", classes="section-title")
                yield Static("", id="notes-display", classes="notes-display")

            yield Rule()

            # Actions Section
            with Vertical(classes="section", id="actions-section"):
                yield Static("Actions", classes="section-title")
                yield Static(
                    "[U] Unblock PIN   [R] Reset OpenPGP   [L] Label",
                    classes="action-hint",
                )
                yield Static(
                    "[P] Toggle Protect   [N] Edit Notes",
                    classes="action-hint",
                )

        yield Footer()

    def _create_property_row(
        self,
        row_id: str,
        label: str,
        value: str,
    ) -> Horizontal:
        """Create a property display row.

        Args:
            row_id: ID for the row container.
            label: Property label.
            value: Property value.

        Returns:
            Horizontal container with label and value.
        """
        return Horizontal(
            Static(label, classes="property-label"),
            Static(value, id=f"{row_id}-value", classes="property-value"),
            id=row_id,
            classes="property-row",
        )

    def _create_key_slot_row(
        self,
        slot_id: str,
        slot_name: str,
        fingerprint: str | None,
        touch_policy: str | None,
    ) -> Horizontal:
        """Create a key slot display row.

        Args:
            slot_id: ID for the slot row.
            slot_name: Name of the key slot (e.g., "Signature").
            fingerprint: Key fingerprint or None if no key.
            touch_policy: Touch policy or None.

        Returns:
            Horizontal container with key slot info.
        """
        return Horizontal(
            Static(f"{slot_name}:", classes="property-label"),
            Static(
                self._format_key_slot(fingerprint, touch_policy),
                id=f"{slot_id}-value",
                classes="property-value",
            ),
            id=slot_id,
            classes="key-slot",
        )

    def _format_key_slot(
        self,
        fingerprint: str | None,
        touch_policy: str | None,
    ) -> str:
        """Format key slot for display.

        Args:
            fingerprint: Key fingerprint or None.
            touch_policy: Touch policy or None.

        Returns:
            Formatted string for display.
        """
        if not fingerprint:
            return "[No key]"

        # Format fingerprint - show last 16 chars with spaces
        short_fp = fingerprint[-16:] if len(fingerprint) >= 16 else fingerprint
        formatted_fp = " ".join(short_fp[i : i + 4] for i in range(0, len(short_fp), 4))

        if touch_policy:
            return f"{formatted_fp} [Touch: {touch_policy}]"
        return formatted_fp

    def on_mount(self) -> None:
        """Load device details on mount."""
        self._refresh_device()

    def _refresh_device(self) -> None:
        """Refresh device details from controller."""
        if not self._controller:
            self._update_display_no_controller()
            return

        self._device = self._controller.get_device(self._serial)
        if not self._device:
            self._update_display_not_found()
            return

        self._update_display()

    def _update_display_no_controller(self) -> None:
        """Update display when no controller is available."""
        title = self.query_one("#screen-title", Static)
        title.update(f"Device {self._serial}")

        self._set_property_value("status-row", "No controller")
        self._set_property_value("type-row", "-")
        self._set_property_value("firmware-row", "-")
        self._set_property_value("protected-row", "-")
        self._set_property_value("user-pin-row", "-")
        self._set_property_value("admin-pin-row", "-")

    def _update_display_not_found(self) -> None:
        """Update display when device is not found."""
        title = self.query_one("#screen-title", Static)
        title.update(f"Device {self._serial} (Not Found)")

        self._set_property_value("status-row", "Device not found")
        self._set_property_value("type-row", "-")
        self._set_property_value("firmware-row", "-")
        self._set_property_value("protected-row", "-")
        self._set_property_value("user-pin-row", "-")
        self._set_property_value("admin-pin-row", "-")

    def _update_display(self) -> None:
        """Update display with device details."""
        if not self._device:
            return

        # Update title
        title = self.query_one("#screen-title", Static)
        display_name = self._device.display_name
        title.update(display_name)

        # Update device info
        status = self._get_device_status()
        self._set_property_value("status-row", status)
        self._set_property_value("type-row", self._device.device_type or "Unknown")
        self._set_property_value("firmware-row", self._device.firmware_version or "Unknown")
        self._set_property_value("protected-row", "Yes" if self._device.protected else "No")

        # Update OpenPGP info
        if self._device.openpgp_state:
            state = self._device.openpgp_state

            # User PIN status
            user_status, user_text = format_pin_status(state.pin_tries_remaining)
            self._set_property_value("user-pin-row", user_text)

            # Admin PIN status
            admin_status, admin_text = format_pin_status(state.admin_pin_tries_remaining)
            self._set_property_value("admin-pin-row", admin_text)

            # Key slots
            self._update_key_slot(
                "sig-key",
                state.signature_key.fingerprint,
                state.signature_key.touch_policy,
            )
            self._update_key_slot(
                "enc-key",
                state.encryption_key.fingerprint,
                state.encryption_key.touch_policy,
            )
            self._update_key_slot(
                "auth-key",
                state.authentication_key.fingerprint,
                state.authentication_key.touch_policy,
            )
        else:
            self._set_property_value("user-pin-row", "Unknown")
            self._set_property_value("admin-pin-row", "Unknown")

        # Update notes
        notes_display = self.query_one("#notes-display", Static)
        if self._device.notes:
            notes_display.update(self._device.notes)
        else:
            notes_display.update("[No notes]")

    def _get_device_status(self) -> str:
        """Get formatted device status.

        Returns:
            Status string with indicator.
        """
        if not self._device or not self._device.openpgp_state:
            return "? Unknown"

        if self._device.openpgp_state.is_pin_blocked():
            return "! PIN BLOCKED"

        if self._device.openpgp_state.pin_tries_remaining < 3:
            return "! PIN tries low"

        return "* Ready"

    def _set_property_value(self, row_id: str, value: str) -> None:
        """Set a property value in a row.

        Args:
            row_id: The row ID.
            value: The new value.
        """
        try:
            widget = self.query_one(f"#{row_id}-value", Static)
            widget.update(value)
        except Exception:
            pass

    def _update_key_slot(
        self,
        slot_id: str,
        fingerprint: str | None,
        touch_policy: str | None,
    ) -> None:
        """Update a key slot display.

        Args:
            slot_id: The slot ID.
            fingerprint: Key fingerprint or None.
            touch_policy: Touch policy or None.
        """
        try:
            widget = self.query_one(f"#{slot_id}-value", Static)
            widget.update(self._format_key_slot(fingerprint, touch_policy))
        except Exception:
            pass

    def action_go_back(self) -> None:
        """Go back to the device list."""
        self.app.pop_screen()

    async def action_unblock_pin(self) -> None:
        """Unblock a blocked PIN using admin PIN."""
        if not self._device or not self._device.openpgp_state:
            self.notify("Device state not available", severity="warning")
            return

        if not self._device.openpgp_state.is_pin_blocked():
            self.notify("PIN is not blocked", severity="information")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        # This would need admin PIN and new PIN - simplified for now
        self.notify(
            "PIN unblock requires admin PIN. Use CLI for now.",
            severity="warning",
        )

    async def action_reset_device(self) -> None:
        """Reset the device OpenPGP application."""
        if not self._device:
            self.notify("Device not available", severity="warning")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        if self._device.protected:
            self.notify(
                "Device is protected. Unprotect first.",
                severity="warning",
            )
            return

        # Show confirmation dialog
        confirmed = await self.app.push_screen_wait(
            ConfirmDialog(
                title="Reset OpenPGP Application",
                message=(
                    "This will PERMANENTLY DELETE all keys on this "
                    "YubiKey's OpenPGP application.\n\n"
                    "This action cannot be undone."
                ),
                confirm_text=f"reset {self._serial}",
                device_info=f"Device: {self._device.display_name}",
            )
        )

        if confirmed:
            result = self._controller.reset_device(self._serial)
            if result.is_ok():
                self._refresh_device()
                self.notify(f"Device {self._serial} has been reset")
            else:
                self.notify(
                    f"Reset failed: {result.unwrap_err()}",
                    severity="error",
                )

    async def action_set_label(self) -> None:
        """Set a label for this device."""
        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        current_label = self._device.label if self._device else ""

        new_label = await self.app.push_screen_wait(
            InputDialog(
                title="Set Device Label",
                message=f"Enter a label for device {self._serial}:",
                placeholder="e.g., Work Primary, Backup",
                initial_value=current_label or "",
            )
        )

        if new_label is not None:
            result = self._controller.set_device_label(self._serial, new_label)
            if result.is_ok():
                self._refresh_device()
                self.notify(f"Label set to '{new_label}'")
            else:
                self.notify(f"Failed: {result.unwrap_err()}", severity="error")

    async def action_toggle_protect(self) -> None:
        """Toggle protection status for this device."""
        if not self._device:
            self.notify("Device not available", severity="warning")
            return

        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        new_protected = not self._device.protected

        if new_protected:
            # Enabling protection - just do it
            result = self._controller.set_device_protected(self._serial, True)
            if result.is_ok():
                self._refresh_device()
                self.notify("Device is now protected")
            else:
                self.notify(f"Failed: {result.unwrap_err()}", severity="error")
        else:
            # Disabling protection - confirm
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Remove Protection",
                    message=(
                        "Removing protection will allow destructive operations "
                        "on this device without extra confirmation.\n\n"
                        "Are you sure?"
                    ),
                    confirm_text=f"unprotect {self._serial}",
                    device_info=f"Device: {self._device.display_name}",
                )
            )

            if confirmed:
                result = self._controller.set_device_protected(self._serial, False)
                if result.is_ok():
                    self._refresh_device()
                    self.notify("Protection removed")
                else:
                    self.notify(
                        f"Failed: {result.unwrap_err()}",
                        severity="error",
                    )

    async def action_edit_notes(self) -> None:
        """Edit notes for this device."""
        if not self._controller:
            self.notify("Controller not available", severity="error")
            return

        current_notes = self._device.notes if self._device else ""

        new_notes = await self.app.push_screen_wait(
            InputDialog(
                title="Edit Device Notes",
                message=f"Enter notes for device {self._serial}:",
                placeholder="Free-form notes about this device",
                initial_value=current_notes or "",
            )
        )

        if new_notes is not None:
            result = self._controller.set_device_notes(self._serial, new_notes)
            if result.is_ok():
                self._refresh_device()
                self.notify("Notes updated")
            else:
                self.notify(f"Failed: {result.unwrap_err()}", severity="error")
