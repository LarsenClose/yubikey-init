"""TUI Controller for managing state and dispatching actions.

This module provides the TUIController class that bridges the TUI layer
with the underlying operations layer (yubikey_ops, gpg_ops, inventory).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..gpg_ops import GPGOperations
from ..inventory import Inventory, OpenPGPState
from ..types import Result
from ..yubikey_ops import YubiKeyOperations

if TYPE_CHECKING:
    pass


@dataclass
class DeviceDisplayInfo:
    """Device information formatted for TUI display.

    This combines data from YubiKeyInfo, CardStatus, and inventory
    into a single structure suitable for rendering.
    """

    serial: str
    label: str | None
    device_type: str | None
    firmware_version: str | None
    form_factor: str | None
    has_keys: bool
    pin_tries_remaining: int
    admin_pin_tries_remaining: int
    is_blocked: bool
    protected: bool
    notes: str | None
    openpgp_state: OpenPGPState | None
    provisioned_identity: str | None

    @property
    def display_name(self) -> str:
        """Get human-readable display name."""
        if self.label:
            return f"{self.label} ({self.serial})"
        if self.device_type:
            return f"{self.device_type} ({self.serial})"
        return f"YubiKey ({self.serial})"

    @property
    def status_text(self) -> str:
        """Get status text for display."""
        if self.is_blocked:
            return "BLOCKED"
        if self.has_keys:
            return "Ready"
        return "Empty"

    @property
    def status_indicator(self) -> str:
        """Get status indicator symbol."""
        if self.is_blocked:
            return "!"
        return "+"


@dataclass
class KeyDisplayInfo:
    """GPG key information formatted for TUI display."""

    key_id: str
    fingerprint: str
    identity: str
    creation_date: datetime
    expiry_date: datetime | None
    is_expired: bool
    days_until_expiry: int | None
    on_yubikey_serial: str | None
    on_yubikey_label: str | None

    @property
    def short_key_id(self) -> str:
        """Get short form of key ID (last 8 characters)."""
        return self.key_id[-8:] if len(self.key_id) >= 8 else self.key_id

    @property
    def expiry_status(self) -> str:
        """Get human-readable expiry status."""
        if self.expiry_date is None:
            return "Never"
        if self.is_expired:
            return "EXPIRED"
        if self.days_until_expiry is not None:
            if self.days_until_expiry <= 30:
                return f"{self.days_until_expiry} days"
            return self.expiry_date.strftime("%Y-%m-%d")
        return self.expiry_date.strftime("%Y-%m-%d")


@dataclass
class TUIState:
    """Current TUI state.

    Tracks navigation history, selections, and cache timestamps.
    """

    screen_stack: list[str] = field(default_factory=list)
    selected_device: str | None = None
    selected_key: str | None = None
    last_refresh: datetime = field(default_factory=lambda: datetime.now(UTC))

    def push_screen(self, screen_name: str) -> None:
        """Push a screen onto the navigation stack."""
        self.screen_stack.append(screen_name)

    def pop_screen(self) -> str | None:
        """Pop the current screen from the navigation stack."""
        if self.screen_stack:
            return self.screen_stack.pop()
        return None

    @property
    def current_screen(self) -> str | None:
        """Get the current screen name."""
        return self.screen_stack[-1] if self.screen_stack else None


class TUIController:
    """Manages TUI state and dispatches actions to the operations layer.

    This controller acts as the bridge between the Textual UI components
    and the underlying YubiKey/GPG operations. It handles:
    - Device discovery and status retrieval
    - Inventory management (labels, protection, notes)
    - Key operations (listing, export)
    - Action dispatch with proper error handling
    """

    def __init__(
        self,
        yubikey_ops: YubiKeyOperations,
        gpg_ops: GPGOperations,
        inventory: Inventory | None = None,
    ) -> None:
        """Initialize the TUI controller.

        Args:
            yubikey_ops: YubiKey operations handler.
            gpg_ops: GPG operations handler.
            inventory: Optional inventory manager. If not provided,
                a default inventory will be created and loaded.
        """
        self.yubikey_ops = yubikey_ops
        self.gpg_ops = gpg_ops

        if inventory is None:
            self._inventory = Inventory()
            self._inventory.load()
        else:
            self._inventory = inventory

        self.state = TUIState()

    @property
    def inventory(self) -> Inventory:
        """Get the inventory manager."""
        return self._inventory

    def get_devices(self) -> list[DeviceDisplayInfo]:
        """Fetch current device list with display information.

        Returns:
            List of DeviceDisplayInfo objects for all connected YubiKeys.
        """
        devices: list[DeviceDisplayInfo] = []
        yubikeys = self.yubikey_ops.list_devices()

        for yk_info in yubikeys:
            # Get or create inventory entry
            entry = self._inventory.get_or_create(yk_info.serial, yk_info)

            # Get card status for PIN info
            card_result = self.yubikey_ops.get_card_status(yk_info.serial)
            pin_tries = 3
            admin_tries = 3
            has_keys = False

            if card_result.is_ok():
                card_status = card_result.unwrap()
                pin_tries = card_status.pin_retries
                admin_tries = card_status.admin_pin_retries
                has_keys = any(
                    [
                        card_status.signature_key,
                        card_status.encryption_key,
                        card_status.authentication_key,
                    ]
                )

            # Parse OpenPGP state if available
            openpgp_state = entry.openpgp_state
            if openpgp_state is None and card_result.is_ok():
                # Try to get detailed OpenPGP info
                openpgp_state = OpenPGPState(
                    pin_tries_remaining=pin_tries,
                    admin_pin_tries_remaining=admin_tries,
                )

            devices.append(
                DeviceDisplayInfo(
                    serial=yk_info.serial,
                    label=entry.label,
                    device_type=entry.device_type or f"YubiKey {yk_info.form_factor}",
                    firmware_version=yk_info.version,
                    form_factor=yk_info.form_factor,
                    has_keys=has_keys,
                    pin_tries_remaining=pin_tries,
                    admin_pin_tries_remaining=admin_tries,
                    is_blocked=pin_tries == 0,
                    protected=entry.protected,
                    notes=entry.notes,
                    openpgp_state=openpgp_state,
                    provisioned_identity=entry.provisioned_identity,
                )
            )

        # Update last refresh timestamp
        self.state.last_refresh = datetime.now(UTC)

        # Save inventory updates
        self._inventory.save()

        return devices

    def get_device_detail(self, serial: str) -> DeviceDisplayInfo | None:
        """Get detailed information for a specific device.

        Args:
            serial: The device serial number.

        Returns:
            DeviceDisplayInfo if device is found and connected, None otherwise.
        """
        devices = self.get_devices()
        for device in devices:
            if device.serial == serial:
                return device
        return None

    def get_keys(self) -> list[KeyDisplayInfo]:
        """Fetch list of GPG keys with display information.

        Returns:
            List of KeyDisplayInfo objects for all secret keys in keyring.
        """
        keys_result = self.gpg_ops.list_secret_keys()
        if keys_result.is_err():
            return []

        keys: list[KeyDisplayInfo] = []
        now = datetime.now(UTC)

        for key_info in keys_result.unwrap():
            # Check expiry
            is_expired = False
            days_until_expiry: int | None = None
            if key_info.expiry_date:
                if key_info.expiry_date < now:
                    is_expired = True
                else:
                    delta = key_info.expiry_date - now
                    days_until_expiry = delta.days

            # Try to find which YubiKey has this key
            on_serial: str | None = None
            on_label: str | None = None

            # Check inventory for matching provisioned identity
            for entry in self._inventory.list_all():
                if (
                    entry.provisioned_identity
                    and key_info.identity
                    and key_info.identity in entry.provisioned_identity
                ):
                    on_serial = entry.serial
                    on_label = entry.label
                    break

            keys.append(
                KeyDisplayInfo(
                    key_id=key_info.key_id,
                    fingerprint=key_info.fingerprint,
                    identity=key_info.identity,
                    creation_date=key_info.creation_date,
                    expiry_date=key_info.expiry_date,
                    is_expired=is_expired,
                    days_until_expiry=days_until_expiry,
                    on_yubikey_serial=on_serial,
                    on_yubikey_label=on_label,
                )
            )

        return keys

    def get_key_detail(self, key_id: str) -> KeyDisplayInfo | None:
        """Get detailed information for a specific key.

        Args:
            key_id: The GPG key ID.

        Returns:
            KeyDisplayInfo if key is found, None otherwise.
        """
        keys = self.get_keys()
        for key in keys:
            if key.key_id == key_id or key_id in key.key_id:
                return key
        return None

    def reset_device(self, serial: str) -> Result[None]:
        """Reset a device's OpenPGP application.

        This is a destructive operation that will delete all keys
        on the device's OpenPGP application.

        Args:
            serial: The device serial number.

        Returns:
            Result indicating success or failure.
        """
        # Check if device is protected
        if self._inventory.is_protected(serial):
            from ..inventory import InventoryError

            return Result.err(InventoryError(f"Device {serial} is protected. Unprotect it first."))

        result = self.yubikey_ops.reset_openpgp(serial)

        # Record in history
        entry = self._inventory.get(serial)
        if entry:
            entry.add_history(
                operation="reset",
                success=result.is_ok(),
                details="OpenPGP application reset",
            )
            # Clear provisioned identity on successful reset
            if result.is_ok():
                entry.provisioned_identity = None
                entry.openpgp_state = None
            self._inventory.save()

        return result

    def label_device(self, serial: str, label: str) -> Result[None]:
        """Set or update a device's label.

        Args:
            serial: The device serial number.
            label: The new label (or empty string to clear).

        Returns:
            Result indicating success or failure.
        """
        label_value = label.strip() if label else None
        return self._inventory.set_label(serial, label_value)

    def protect_device(self, serial: str, protected: bool) -> Result[None]:
        """Set or clear a device's protection status.

        Args:
            serial: The device serial number.
            protected: True to protect, False to unprotect.

        Returns:
            Result indicating success or failure.
        """
        return self._inventory.set_protected(serial, protected)

    def set_device_notes(self, serial: str, notes: str) -> Result[None]:
        """Set or update a device's notes.

        Args:
            serial: The device serial number.
            notes: The new notes (or empty string to clear).

        Returns:
            Result indicating success or failure.
        """
        notes_value = notes.strip() if notes else None
        return self._inventory.set_notes(serial, notes_value)

    def export_ssh_key(self, key_id: str | None = None) -> Result[str]:
        """Export the SSH public key.

        Args:
            key_id: Optional specific key ID. If not provided,
                uses the currently selected key.

        Returns:
            Result containing the SSH public key string.
        """
        target_key = key_id or self.state.selected_key
        if not target_key:
            from ..gpg_ops import GPGError

            return Result.err(GPGError("No key selected"))

        return self.gpg_ops.export_ssh_key(target_key)

    def get_key_fingerprint(self, key_id: str | None = None) -> Result[str]:
        """Get the full fingerprint for a key.

        Args:
            key_id: Optional specific key ID. If not provided,
                uses the currently selected key.

        Returns:
            Result containing the fingerprint string.
        """
        target_key = key_id or self.state.selected_key
        if not target_key:
            from ..gpg_ops import GPGError

            return Result.err(GPGError("No key selected"))

        return self.gpg_ops.get_key_fingerprint(target_key)

    def refresh(self) -> None:
        """Force refresh of cached data."""
        self.state.last_refresh = datetime.now(UTC)
        # Reload inventory
        self._inventory.load()

    # Alias methods for compatibility with screens
    def get_device(self, serial: str) -> DeviceDisplayInfo | None:
        """Alias for get_device_detail for screen compatibility."""
        return self.get_device_detail(serial)

    def set_device_label(self, serial: str, label: str) -> Result[None]:
        """Alias for label_device for screen compatibility."""
        return self.label_device(serial, label)

    def set_device_protected(self, serial: str, protected: bool) -> Result[None]:
        """Alias for protect_device for screen compatibility."""
        return self.protect_device(serial, protected)

    def get_key_info(self, key_id: str) -> KeyDisplayInfo | None:
        """Alias for get_key_detail for screen compatibility."""
        return self.get_key_detail(key_id)

    def get_subkeys(self, key_id: str) -> list[dict[str, str]]:
        """Get subkeys for a given key ID.

        Returns list of dicts with type, fingerprint, expiry info.
        """
        # Get key info from GPG
        keys_result = self.gpg_ops.list_secret_keys()
        if keys_result.is_err():
            return []

        for key_info in keys_result.unwrap():
            if key_id in key_info.key_id or key_info.key_id == key_id:
                # Return subkey info if available
                subkeys = []
                if hasattr(key_info, "subkeys") and key_info.subkeys:
                    for sk in key_info.subkeys:
                        subkeys.append(
                            {
                                "type": sk.get("type", "Unknown"),
                                "fingerprint": sk.get("fingerprint", ""),
                                "expiry": sk.get("expiry", "N/A"),
                            }
                        )
                return subkeys
        return []

    def get_key_device_mapping(self) -> dict[str, str]:
        """Get mapping of key IDs to YubiKey serials.

        Returns dict mapping key_id to serial number.
        """
        mapping: dict[str, str] = {}
        keys = self.get_keys()
        for key in keys:
            if key.on_yubikey_serial:
                mapping[key.key_id] = key.on_yubikey_serial
        return mapping

    def run_diagnostics(self) -> dict[str, tuple[bool, str]]:
        """Run system diagnostics.

        Returns dict of check_name -> (passed, message).
        """
        from ..diagnostics import run_diagnostics as run_diag

        results: dict[str, tuple[bool, str]] = {}

        try:
            diag_result = run_diag()
            # Extract diagnostic results from DiagnosticInfo structure
            # Check GPG installation
            if diag_result.gpg_info.get("installed"):
                results["gpg"] = (True, f"GPG {diag_result.gpg_info.get('version', 'unknown')}")
            else:
                results["gpg"] = (False, "GPG not installed")

            # Check YubiKey detection
            yubikey_count = len(diag_result.yubikey_info.get("devices", []))
            if yubikey_count > 0:
                results["yubikey"] = (True, f"{yubikey_count} device(s) detected")
            else:
                results["yubikey"] = (False, "No YubiKeys detected")

            # Check for issues
            if diag_result.issues:
                results["issues"] = (False, f"{len(diag_result.issues)} issue(s) found")
            else:
                results["issues"] = (True, "No issues found")

        except Exception as e:
            results["diagnostics"] = (False, str(e))

        return results
