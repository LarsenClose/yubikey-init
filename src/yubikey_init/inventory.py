"""YubiKey inventory and catalog management.

Provides a local registry for tracking YubiKey devices with:
- User-assigned labels and notes
- Protection status (prevent accidental operations)
- Key/identity tracking (what's provisioned on each device)
- Operation history
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .types import Result, YubiKeyInfo


class InventoryError(Exception):
    """Inventory-related errors."""

    pass


@dataclass
class KeySlotInfo:
    """Information about a key slot on a YubiKey."""

    fingerprint: str | None = None
    touch_policy: str | None = None
    key_type: str | None = None  # e.g., "ed25519", "rsa4096"


@dataclass
class OpenPGPState:
    """Current OpenPGP state of a YubiKey."""

    signature_key: KeySlotInfo = field(default_factory=KeySlotInfo)
    encryption_key: KeySlotInfo = field(default_factory=KeySlotInfo)
    authentication_key: KeySlotInfo = field(default_factory=KeySlotInfo)
    pin_tries_remaining: int = 3
    admin_pin_tries_remaining: int = 3
    reset_code_tries_remaining: int = 0
    kdf_enabled: bool = False
    cardholder_name: str | None = None
    public_key_url: str | None = None

    def has_keys(self) -> bool:
        """Check if any keys are loaded on the device."""
        return any(
            [
                self.signature_key.fingerprint,
                self.encryption_key.fingerprint,
                self.authentication_key.fingerprint,
            ]
        )

    def is_pin_blocked(self) -> bool:
        """Check if the user PIN is blocked."""
        return self.pin_tries_remaining == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_key": {
                "fingerprint": self.signature_key.fingerprint,
                "touch_policy": self.signature_key.touch_policy,
                "key_type": self.signature_key.key_type,
            },
            "encryption_key": {
                "fingerprint": self.encryption_key.fingerprint,
                "touch_policy": self.encryption_key.touch_policy,
                "key_type": self.encryption_key.key_type,
            },
            "authentication_key": {
                "fingerprint": self.authentication_key.fingerprint,
                "touch_policy": self.authentication_key.touch_policy,
                "key_type": self.authentication_key.key_type,
            },
            "pin_tries_remaining": self.pin_tries_remaining,
            "admin_pin_tries_remaining": self.admin_pin_tries_remaining,
            "reset_code_tries_remaining": self.reset_code_tries_remaining,
            "kdf_enabled": self.kdf_enabled,
            "cardholder_name": self.cardholder_name,
            "public_key_url": self.public_key_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OpenPGPState:
        return cls(
            signature_key=KeySlotInfo(
                fingerprint=data.get("signature_key", {}).get("fingerprint"),
                touch_policy=data.get("signature_key", {}).get("touch_policy"),
                key_type=data.get("signature_key", {}).get("key_type"),
            ),
            encryption_key=KeySlotInfo(
                fingerprint=data.get("encryption_key", {}).get("fingerprint"),
                touch_policy=data.get("encryption_key", {}).get("touch_policy"),
                key_type=data.get("encryption_key", {}).get("key_type"),
            ),
            authentication_key=KeySlotInfo(
                fingerprint=data.get("authentication_key", {}).get("fingerprint"),
                touch_policy=data.get("authentication_key", {}).get("touch_policy"),
                key_type=data.get("authentication_key", {}).get("key_type"),
            ),
            pin_tries_remaining=data.get("pin_tries_remaining", 3),
            admin_pin_tries_remaining=data.get("admin_pin_tries_remaining", 3),
            reset_code_tries_remaining=data.get("reset_code_tries_remaining", 0),
            kdf_enabled=data.get("kdf_enabled", False),
            cardholder_name=data.get("cardholder_name"),
            public_key_url=data.get("public_key_url"),
        )


@dataclass
class OperationRecord:
    """Record of an operation performed on a YubiKey."""

    operation: str  # e.g., "reset", "provision", "key_transfer"
    timestamp: datetime
    success: bool
    details: str | None = None
    identity: str | None = None  # GPG identity if applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "details": self.details,
            "identity": self.identity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OperationRecord:
        return cls(
            operation=data["operation"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            success=data["success"],
            details=data.get("details"),
            identity=data.get("identity"),
        )


@dataclass
class DeviceEntry:
    """A device entry in the inventory."""

    serial: str
    label: str | None = None  # User-assigned name like "Work Primary"
    notes: str | None = None  # Free-form notes
    protected: bool = False  # If True, require extra confirmation
    device_type: str | None = None  # e.g., "YubiKey 5C NFC FIPS"
    firmware_version: str | None = None
    form_factor: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    openpgp_state: OpenPGPState | None = None
    provisioned_identity: str | None = None  # GPG identity on this device
    history: list[OperationRecord] = field(default_factory=list)

    def display_name(self) -> str:
        """Get a human-readable display name for the device."""
        if self.label:
            return f"{self.label} ({self.serial})"
        if self.device_type:
            return f"{self.device_type} ({self.serial})"
        return self.serial

    def short_display(self) -> str:
        """Get a short display string."""
        if self.label:
            return self.label
        return f"YubiKey {self.serial[-4:]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "label": self.label,
            "notes": self.notes,
            "protected": self.protected,
            "device_type": self.device_type,
            "firmware_version": self.firmware_version,
            "form_factor": self.form_factor,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "openpgp_state": self.openpgp_state.to_dict() if self.openpgp_state else None,
            "provisioned_identity": self.provisioned_identity,
            "history": [h.to_dict() for h in self.history],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceEntry:
        return cls(
            serial=data["serial"],
            label=data.get("label"),
            notes=data.get("notes"),
            protected=data.get("protected", False),
            device_type=data.get("device_type"),
            firmware_version=data.get("firmware_version"),
            form_factor=data.get("form_factor"),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            openpgp_state=OpenPGPState.from_dict(data["openpgp_state"])
            if data.get("openpgp_state")
            else None,
            provisioned_identity=data.get("provisioned_identity"),
            history=[OperationRecord.from_dict(h) for h in data.get("history", [])],
        )

    def add_history(
        self,
        operation: str,
        success: bool,
        details: str | None = None,
        identity: str | None = None,
    ) -> None:
        """Add an operation to history."""
        self.history.append(
            OperationRecord(
                operation=operation,
                timestamp=datetime.now(UTC),
                success=success,
                details=details,
                identity=identity,
            )
        )


class Inventory:
    """YubiKey inventory manager."""

    DEFAULT_PATH = Path.home() / ".config" / "yubikey-init" / "inventory.json"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or self.DEFAULT_PATH
        self._devices: dict[str, DeviceEntry] = {}
        self._loaded = False

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Result[None]:
        """Load inventory from disk."""
        if not self._path.exists():
            self._devices = {}
            self._loaded = True
            return Result.ok(None)

        try:
            data = json.loads(self._path.read_text())
            self._devices = {
                serial: DeviceEntry.from_dict(entry)
                for serial, entry in data.get("devices", {}).items()
            }
            self._loaded = True
            return Result.ok(None)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            return Result.err(InventoryError(f"Failed to load inventory: {e}"))

    def save(self) -> Result[None]:
        """Save inventory to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": "1.0",
                "updated_at": datetime.now(UTC).isoformat(),
                "devices": {serial: entry.to_dict() for serial, entry in self._devices.items()},
            }
            self._path.write_text(json.dumps(data, indent=2))
            return Result.ok(None)
        except OSError as e:
            return Result.err(InventoryError(f"Failed to save inventory: {e}"))

    def get(self, serial: str) -> DeviceEntry | None:
        """Get a device entry by serial."""
        return self._devices.get(serial)

    def get_or_create(self, serial: str, info: YubiKeyInfo | None = None) -> DeviceEntry:
        """Get existing entry or create a new one."""
        if serial in self._devices:
            entry = self._devices[serial]
            entry.last_seen = datetime.now(UTC)
            if info:
                entry.device_type = f"YubiKey {info.form_factor}"
                entry.firmware_version = info.version
                entry.form_factor = info.form_factor
            return entry

        entry = DeviceEntry(
            serial=serial,
            device_type=f"YubiKey {info.form_factor}" if info else None,
            firmware_version=info.version if info else None,
            form_factor=info.form_factor if info else None,
        )
        self._devices[serial] = entry
        return entry

    def add(self, entry: DeviceEntry) -> None:
        """Add or update a device entry."""
        self._devices[entry.serial] = entry

    def remove(self, serial: str) -> bool:
        """Remove a device from inventory."""
        if serial in self._devices:
            del self._devices[serial]
            return True
        return False

    def list_all(self) -> list[DeviceEntry]:
        """List all devices in inventory."""
        return list(self._devices.values())

    def list_protected(self) -> list[DeviceEntry]:
        """List all protected devices."""
        return [d for d in self._devices.values() if d.protected]

    def is_protected(self, serial: str) -> bool:
        """Check if a device is marked as protected."""
        entry = self._devices.get(serial)
        return entry.protected if entry else False

    def set_protected(self, serial: str, protected: bool) -> Result[None]:
        """Set the protected status of a device."""
        entry = self._devices.get(serial)
        if not entry:
            return Result.err(InventoryError(f"Device {serial} not in inventory"))
        entry.protected = protected
        return self.save()

    def set_label(self, serial: str, label: str | None) -> Result[None]:
        """Set the label for a device."""
        entry = self._devices.get(serial)
        if not entry:
            return Result.err(InventoryError(f"Device {serial} not in inventory"))
        entry.label = label
        return self.save()

    def set_notes(self, serial: str, notes: str | None) -> Result[None]:
        """Set notes for a device."""
        entry = self._devices.get(serial)
        if not entry:
            return Result.err(InventoryError(f"Device {serial} not in inventory"))
        entry.notes = notes
        return self.save()

    def find_by_label(self, label: str) -> DeviceEntry | None:
        """Find a device by its label (case-insensitive)."""
        label_lower = label.lower()
        for entry in self._devices.values():
            if entry.label and entry.label.lower() == label_lower:
                return entry
        return None

    def find_by_identity(self, identity: str) -> list[DeviceEntry]:
        """Find devices provisioned with a specific identity."""
        return [
            d
            for d in self._devices.values()
            if d.provisioned_identity and identity.lower() in d.provisioned_identity.lower()
        ]


def parse_openpgp_info(output: str) -> OpenPGPState:
    """Parse ykman openpgp info output into OpenPGPState."""
    state = OpenPGPState()

    lines = output.strip().split("\n")
    current_key: str | None = None

    for line in lines:
        line = line.strip()

        # PIN/retry information - check more specific patterns first
        if "Admin PIN tries remaining:" in line:
            with contextlib.suppress(ValueError):
                state.admin_pin_tries_remaining = int(line.split(":")[-1].strip())
        elif "Reset code tries remaining:" in line:
            with contextlib.suppress(ValueError):
                state.reset_code_tries_remaining = int(line.split(":")[-1].strip())
        elif "PIN tries remaining:" in line:
            with contextlib.suppress(ValueError):
                state.pin_tries_remaining = int(line.split(":")[-1].strip())
        elif "KDF enabled:" in line:
            state.kdf_enabled = "True" in line

        # Key slot detection
        elif "Signature key:" in line:
            current_key = "signature"
        elif "Decryption key:" in line or "Encryption key:" in line:
            current_key = "encryption"
        elif "Authentication key:" in line:
            current_key = "authentication"

        # Fingerprint parsing
        elif "Fingerprint:" in line and current_key:
            fp = line.split(":", 1)[-1].strip()
            if fp and fp != "Not set":
                slot = getattr(state, f"{current_key}_key")
                slot.fingerprint = fp

        # Touch policy parsing
        elif "Touch policy:" in line and current_key:
            policy = line.split(":")[-1].strip()
            slot = getattr(state, f"{current_key}_key")
            slot.touch_policy = policy

    return state
