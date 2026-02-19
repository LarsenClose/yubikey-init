"""Comprehensive tests for inventory.py module.

Tests the YubiKey inventory and catalog management:
- KeySlotInfo, OpenPGPState dataclasses
- DeviceEntry - display methods, history tracking
- Inventory - CRUD operations, search, protection
- OperationRecord serialization
- parse_openpgp_info parser
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from yubikey_init.inventory import (
    DeviceEntry,
    Inventory,
    InventoryError,
    KeySlotInfo,
    OpenPGPState,
    OperationRecord,
    parse_openpgp_info,
)
from yubikey_init.types import YubiKeyInfo


class TestKeySlotInfo:
    """Test KeySlotInfo dataclass."""

    def test_creation_with_defaults(self) -> None:
        """Test creating KeySlotInfo with defaults."""
        slot = KeySlotInfo()
        assert slot.fingerprint is None
        assert slot.touch_policy is None
        assert slot.key_type is None

    def test_creation_with_values(self) -> None:
        """Test creating KeySlotInfo with values."""
        slot = KeySlotInfo(
            fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
            touch_policy="On",
            key_type="ed25519",
        )
        assert slot.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        assert slot.touch_policy == "On"
        assert slot.key_type == "ed25519"


class TestOpenPGPState:
    """Test OpenPGPState dataclass."""

    def test_creation_with_defaults(self) -> None:
        """Test creating OpenPGPState with defaults."""
        state = OpenPGPState()
        assert state.pin_tries_remaining == 3
        assert state.admin_pin_tries_remaining == 3
        assert state.reset_code_tries_remaining == 0
        assert state.kdf_enabled is False
        assert state.cardholder_name is None
        assert state.public_key_url is None

    def test_has_keys_no_keys(self) -> None:
        """Test has_keys returns False when no keys loaded."""
        state = OpenPGPState()
        assert state.has_keys() is False

    def test_has_keys_signature_key(self) -> None:
        """Test has_keys returns True with signature key."""
        state = OpenPGPState(signature_key=KeySlotInfo(fingerprint="AAAA1111BBBB2222"))
        assert state.has_keys() is True

    def test_has_keys_encryption_key(self) -> None:
        """Test has_keys returns True with encryption key."""
        state = OpenPGPState(encryption_key=KeySlotInfo(fingerprint="AAAA1111BBBB2222"))
        assert state.has_keys() is True

    def test_has_keys_authentication_key(self) -> None:
        """Test has_keys returns True with authentication key."""
        state = OpenPGPState(authentication_key=KeySlotInfo(fingerprint="AAAA1111BBBB2222"))
        assert state.has_keys() is True

    def test_has_keys_all_keys(self) -> None:
        """Test has_keys returns True with all keys."""
        state = OpenPGPState(
            signature_key=KeySlotInfo(fingerprint="SIG"),
            encryption_key=KeySlotInfo(fingerprint="ENC"),
            authentication_key=KeySlotInfo(fingerprint="AUT"),
        )
        assert state.has_keys() is True

    def test_is_pin_blocked_not_blocked(self) -> None:
        """Test is_pin_blocked returns False when PIN has tries."""
        state = OpenPGPState(pin_tries_remaining=3)
        assert state.is_pin_blocked() is False

    def test_is_pin_blocked_blocked(self) -> None:
        """Test is_pin_blocked returns True when PIN has 0 tries."""
        state = OpenPGPState(pin_tries_remaining=0)
        assert state.is_pin_blocked() is True

    def test_to_dict(self) -> None:
        """Test OpenPGPState to_dict serialization."""
        state = OpenPGPState(
            signature_key=KeySlotInfo(fingerprint="SIG", touch_policy="On"),
            pin_tries_remaining=2,
            kdf_enabled=True,
            cardholder_name="Test User",
        )

        data = state.to_dict()

        assert data["signature_key"]["fingerprint"] == "SIG"
        assert data["signature_key"]["touch_policy"] == "On"
        assert data["pin_tries_remaining"] == 2
        assert data["kdf_enabled"] is True
        assert data["cardholder_name"] == "Test User"

    def test_from_dict(self) -> None:
        """Test OpenPGPState from_dict deserialization."""
        data = {
            "signature_key": {
                "fingerprint": "SIG",
                "touch_policy": "On",
                "key_type": "ed25519",
            },
            "encryption_key": {},
            "authentication_key": {},
            "pin_tries_remaining": 2,
            "admin_pin_tries_remaining": 3,
            "reset_code_tries_remaining": 0,
            "kdf_enabled": True,
            "cardholder_name": "Test User",
            "public_key_url": "https://example.com/key",
        }

        state = OpenPGPState.from_dict(data)

        assert state.signature_key.fingerprint == "SIG"
        assert state.signature_key.touch_policy == "On"
        assert state.pin_tries_remaining == 2
        assert state.kdf_enabled is True
        assert state.cardholder_name == "Test User"

    def test_from_dict_missing_fields(self) -> None:
        """Test OpenPGPState from_dict with missing fields uses defaults."""
        data: dict = {}

        state = OpenPGPState.from_dict(data)

        assert state.pin_tries_remaining == 3
        assert state.admin_pin_tries_remaining == 3
        assert state.kdf_enabled is False

    def test_roundtrip_serialization(self) -> None:
        """Test OpenPGPState roundtrip to_dict/from_dict."""
        original = OpenPGPState(
            signature_key=KeySlotInfo(fingerprint="SIG", touch_policy="On"),
            encryption_key=KeySlotInfo(fingerprint="ENC"),
            pin_tries_remaining=1,
            kdf_enabled=True,
        )

        data = original.to_dict()
        restored = OpenPGPState.from_dict(data)

        assert restored.signature_key.fingerprint == "SIG"
        assert restored.encryption_key.fingerprint == "ENC"
        assert restored.pin_tries_remaining == 1
        assert restored.kdf_enabled is True


class TestOperationRecord:
    """Test OperationRecord dataclass."""

    def test_creation(self) -> None:
        """Test creating OperationRecord."""
        now = datetime.now(UTC)
        record = OperationRecord(
            operation="reset",
            timestamp=now,
            success=True,
            details="Factory reset",
            identity="test@example.com",
        )

        assert record.operation == "reset"
        assert record.timestamp == now
        assert record.success is True
        assert record.details == "Factory reset"
        assert record.identity == "test@example.com"

    def test_creation_minimal(self) -> None:
        """Test creating OperationRecord with minimal fields."""
        now = datetime.now(UTC)
        record = OperationRecord(
            operation="provision",
            timestamp=now,
            success=False,
        )

        assert record.details is None
        assert record.identity is None

    def test_to_dict(self) -> None:
        """Test OperationRecord to_dict serialization."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        record = OperationRecord(
            operation="provision",
            timestamp=timestamp,
            success=True,
            details="Key transferred",
            identity="user@example.com",
        )

        data = record.to_dict()

        assert data["operation"] == "provision"
        assert "2024-01-15" in data["timestamp"]
        assert data["success"] is True
        assert data["details"] == "Key transferred"
        assert data["identity"] == "user@example.com"

    def test_from_dict(self) -> None:
        """Test OperationRecord from_dict deserialization."""
        data = {
            "operation": "reset",
            "timestamp": "2024-01-15T12:00:00+00:00",
            "success": False,
            "details": "Failed - protected",
            "identity": None,
        }

        record = OperationRecord.from_dict(data)

        assert record.operation == "reset"
        assert record.success is False
        assert record.details == "Failed - protected"

    def test_roundtrip_serialization(self) -> None:
        """Test OperationRecord roundtrip serialization."""
        original = OperationRecord(
            operation="pin_change",
            timestamp=datetime.now(UTC),
            success=True,
        )

        data = original.to_dict()
        restored = OperationRecord.from_dict(data)

        assert restored.operation == original.operation
        assert restored.success == original.success


class TestDeviceEntry:
    """Test DeviceEntry dataclass."""

    def test_creation_minimal(self) -> None:
        """Test creating DeviceEntry with minimal fields."""
        entry = DeviceEntry(serial="12345678")
        assert entry.serial == "12345678"
        assert entry.label is None
        assert entry.protected is False
        assert entry.history == []

    def test_creation_full(self) -> None:
        """Test creating DeviceEntry with all fields."""
        entry = DeviceEntry(
            serial="12345678",
            label="My Work Key",
            notes="Primary development key",
            protected=True,
            device_type="YubiKey 5C NFC",
            firmware_version="5.4.3",
            form_factor="USB-C",
            provisioned_identity="dev@example.com",
        )

        assert entry.serial == "12345678"
        assert entry.label == "My Work Key"
        assert entry.notes == "Primary development key"
        assert entry.protected is True

    def test_display_name_with_label(self) -> None:
        """Test display_name returns label with serial."""
        entry = DeviceEntry(serial="12345678", label="My Key")
        assert entry.display_name() == "My Key (12345678)"

    def test_display_name_with_device_type(self) -> None:
        """Test display_name returns device type when no label."""
        entry = DeviceEntry(serial="12345678", device_type="YubiKey 5C NFC")
        assert entry.display_name() == "YubiKey 5C NFC (12345678)"

    def test_display_name_serial_only(self) -> None:
        """Test display_name returns serial when no label or type."""
        entry = DeviceEntry(serial="12345678")
        assert entry.display_name() == "12345678"

    def test_short_display_with_label(self) -> None:
        """Test short_display returns label."""
        entry = DeviceEntry(serial="12345678", label="My Key")
        assert entry.short_display() == "My Key"

    def test_short_display_no_label(self) -> None:
        """Test short_display returns truncated serial."""
        entry = DeviceEntry(serial="12345678")
        assert entry.short_display() == "YubiKey 5678"

    def test_to_dict(self) -> None:
        """Test DeviceEntry to_dict serialization."""
        entry = DeviceEntry(
            serial="12345678",
            label="Test Key",
            protected=True,
        )

        data = entry.to_dict()

        assert data["serial"] == "12345678"
        assert data["label"] == "Test Key"
        assert data["protected"] is True
        assert "first_seen" in data
        assert "last_seen" in data

    def test_from_dict(self) -> None:
        """Test DeviceEntry from_dict deserialization."""
        data = {
            "serial": "12345678",
            "label": "Restored Key",
            "protected": True,
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-06-01T00:00:00+00:00",
            "history": [],
        }

        entry = DeviceEntry.from_dict(data)

        assert entry.serial == "12345678"
        assert entry.label == "Restored Key"
        assert entry.protected is True

    def test_from_dict_with_openpgp_state(self) -> None:
        """Test DeviceEntry from_dict with OpenPGP state."""
        data = {
            "serial": "12345678",
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-06-01T00:00:00+00:00",
            "openpgp_state": {
                "signature_key": {"fingerprint": "SIG"},
                "encryption_key": {},
                "authentication_key": {},
                "pin_tries_remaining": 2,
            },
            "history": [],
        }

        entry = DeviceEntry.from_dict(data)

        assert entry.openpgp_state is not None
        assert entry.openpgp_state.signature_key.fingerprint == "SIG"

    def test_from_dict_with_history(self) -> None:
        """Test DeviceEntry from_dict with operation history."""
        data = {
            "serial": "12345678",
            "first_seen": "2024-01-01T00:00:00+00:00",
            "last_seen": "2024-06-01T00:00:00+00:00",
            "history": [
                {
                    "operation": "provision",
                    "timestamp": "2024-03-01T00:00:00+00:00",
                    "success": True,
                },
            ],
        }

        entry = DeviceEntry.from_dict(data)

        assert len(entry.history) == 1
        assert entry.history[0].operation == "provision"

    def test_add_history(self) -> None:
        """Test add_history method."""
        entry = DeviceEntry(serial="12345678")
        assert len(entry.history) == 0

        entry.add_history("provision", True, "Keys transferred", "test@example.com")

        assert len(entry.history) == 1
        assert entry.history[0].operation == "provision"
        assert entry.history[0].success is True
        assert entry.history[0].details == "Keys transferred"
        assert entry.history[0].identity == "test@example.com"

    def test_add_multiple_history(self) -> None:
        """Test adding multiple history entries."""
        entry = DeviceEntry(serial="12345678")

        entry.add_history("provision", True)
        entry.add_history("pin_change", True)
        entry.add_history("reset", False, "Failed - protected")

        assert len(entry.history) == 3
        assert entry.history[0].operation == "provision"
        assert entry.history[1].operation == "pin_change"
        assert entry.history[2].operation == "reset"

    def test_roundtrip_serialization(self) -> None:
        """Test DeviceEntry roundtrip serialization."""
        original = DeviceEntry(
            serial="12345678",
            label="Test Key",
            protected=True,
            openpgp_state=OpenPGPState(pin_tries_remaining=2),
        )
        original.add_history("provision", True)

        data = original.to_dict()
        restored = DeviceEntry.from_dict(data)

        assert restored.serial == original.serial
        assert restored.label == original.label
        assert restored.protected == original.protected
        assert len(restored.history) == 1


class TestInventory:
    """Test Inventory class."""

    @pytest.fixture
    def inventory_path(self, tmp_path: Path) -> Path:
        """Create inventory path."""
        return tmp_path / "inventory.json"

    @pytest.fixture
    def inventory(self, inventory_path: Path) -> Inventory:
        """Create Inventory instance."""
        return Inventory(inventory_path)

    def test_creation_with_default_path(self) -> None:
        """Test Inventory uses default path when none provided."""
        inv = Inventory()
        assert inv.path == Inventory.DEFAULT_PATH

    def test_creation_with_custom_path(self, inventory_path: Path) -> None:
        """Test Inventory with custom path."""
        inv = Inventory(inventory_path)
        assert inv.path == inventory_path

    def test_load_nonexistent_file(self, inventory: Inventory) -> None:
        """Test loading from nonexistent file initializes empty."""
        result = inventory.load()
        assert result.is_ok()
        assert inventory.list_all() == []

    def test_load_existing_file(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test loading from existing file."""
        data = {
            "version": "1.0",
            "updated_at": "2024-01-01T00:00:00+00:00",
            "devices": {
                "12345678": {
                    "serial": "12345678",
                    "label": "Test Key",
                    "first_seen": "2024-01-01T00:00:00+00:00",
                    "last_seen": "2024-01-01T00:00:00+00:00",
                    "history": [],
                }
            },
        }
        inventory_path.write_text(json.dumps(data))

        result = inventory.load()

        assert result.is_ok()
        assert len(inventory.list_all()) == 1
        assert inventory.get("12345678") is not None

    def test_load_invalid_json(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test loading invalid JSON returns error."""
        inventory_path.write_text("not valid json")

        result = inventory.load()

        assert result.is_err()
        assert "Failed to load inventory" in str(result.unwrap_err())

    def test_load_malformed_data(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test loading malformed data returns error."""
        inventory_path.write_text('{"devices": {"12345678": "invalid"}}')

        result = inventory.load()

        assert result.is_err()

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        """Test save creates parent directories."""
        deep_path = tmp_path / "deep" / "nested" / "inventory.json"
        inv = Inventory(deep_path)

        result = inv.save()

        assert result.is_ok()
        assert deep_path.exists()

    def test_save_writes_json(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test save writes valid JSON."""
        inventory.load()
        entry = DeviceEntry(serial="12345678", label="Test")
        inventory.add(entry)

        result = inventory.save()

        assert result.is_ok()
        data = json.loads(inventory_path.read_text())
        assert "devices" in data
        assert "12345678" in data["devices"]

    def test_save_updates_timestamp(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test save updates updated_at timestamp."""
        inventory.load()
        inventory.save()

        data = json.loads(inventory_path.read_text())
        assert "updated_at" in data

    def test_get_existing_device(self, inventory: Inventory) -> None:
        """Test get returns existing device."""
        inventory.load()
        entry = DeviceEntry(serial="12345678")
        inventory.add(entry)

        result = inventory.get("12345678")

        assert result is not None
        assert result.serial == "12345678"

    def test_get_nonexistent_device(self, inventory: Inventory) -> None:
        """Test get returns None for nonexistent device."""
        inventory.load()

        result = inventory.get("nonexistent")

        assert result is None

    def test_get_or_create_existing(self, inventory: Inventory) -> None:
        """Test get_or_create returns existing entry and updates last_seen."""
        inventory.load()
        original = DeviceEntry(serial="12345678")
        inventory.add(original)
        original_last_seen = original.last_seen

        result = inventory.get_or_create("12345678")

        assert result.serial == "12345678"
        assert result.last_seen >= original_last_seen

    def test_get_or_create_new(self, inventory: Inventory) -> None:
        """Test get_or_create creates new entry."""
        inventory.load()

        result = inventory.get_or_create("12345678")

        assert result.serial == "12345678"
        assert inventory.get("12345678") is not None

    def test_get_or_create_with_yubikey_info(self, inventory: Inventory) -> None:
        """Test get_or_create populates from YubiKeyInfo."""
        inventory.load()
        info = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        result = inventory.get_or_create("12345678", info)

        assert result.device_type == "YubiKey USB-C"
        assert result.firmware_version == "5.4.3"
        assert result.form_factor == "USB-C"

    def test_get_or_create_updates_existing_with_info(self, inventory: Inventory) -> None:
        """Test get_or_create updates existing entry from YubiKeyInfo."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))
        info = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        result = inventory.get_or_create("12345678", info)

        assert result.firmware_version == "5.4.3"

    def test_add_new_device(self, inventory: Inventory) -> None:
        """Test add creates new device entry."""
        inventory.load()
        entry = DeviceEntry(serial="12345678")

        inventory.add(entry)

        assert inventory.get("12345678") is not None

    def test_add_updates_existing(self, inventory: Inventory) -> None:
        """Test add updates existing device entry."""
        inventory.load()
        original = DeviceEntry(serial="12345678", label="Original")
        inventory.add(original)

        updated = DeviceEntry(serial="12345678", label="Updated")
        inventory.add(updated)

        result = inventory.get("12345678")
        assert result.label == "Updated"

    def test_remove_existing(self, inventory: Inventory) -> None:
        """Test remove deletes existing device."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))

        result = inventory.remove("12345678")

        assert result is True
        assert inventory.get("12345678") is None

    def test_remove_nonexistent(self, inventory: Inventory) -> None:
        """Test remove returns False for nonexistent device."""
        inventory.load()

        result = inventory.remove("nonexistent")

        assert result is False

    def test_list_all(self, inventory: Inventory) -> None:
        """Test list_all returns all devices."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))
        inventory.add(DeviceEntry(serial="87654321"))

        result = inventory.list_all()

        assert len(result) == 2
        serials = {e.serial for e in result}
        assert "12345678" in serials
        assert "87654321" in serials

    def test_list_all_empty(self, inventory: Inventory) -> None:
        """Test list_all returns empty list when no devices."""
        inventory.load()

        result = inventory.list_all()

        assert result == []

    def test_list_protected(self, inventory: Inventory) -> None:
        """Test list_protected returns only protected devices."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", protected=True))
        inventory.add(DeviceEntry(serial="87654321", protected=False))
        inventory.add(DeviceEntry(serial="11111111", protected=True))

        result = inventory.list_protected()

        assert len(result) == 2
        serials = {e.serial for e in result}
        assert "12345678" in serials
        assert "11111111" in serials
        assert "87654321" not in serials

    def test_is_protected_true(self, inventory: Inventory) -> None:
        """Test is_protected returns True for protected device."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", protected=True))

        result = inventory.is_protected("12345678")

        assert result is True

    def test_is_protected_false(self, inventory: Inventory) -> None:
        """Test is_protected returns False for unprotected device."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", protected=False))

        result = inventory.is_protected("12345678")

        assert result is False

    def test_is_protected_nonexistent(self, inventory: Inventory) -> None:
        """Test is_protected returns False for nonexistent device."""
        inventory.load()

        result = inventory.is_protected("nonexistent")

        assert result is False

    def test_set_protected_true(self, inventory: Inventory, inventory_path: Path) -> None:
        """Test set_protected sets protection to True."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", protected=False))

        result = inventory.set_protected("12345678", True)

        assert result.is_ok()
        assert inventory.get("12345678").protected is True
        # Should have saved
        assert inventory_path.exists()

    def test_set_protected_false(self, inventory: Inventory) -> None:
        """Test set_protected sets protection to False."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", protected=True))

        result = inventory.set_protected("12345678", False)

        assert result.is_ok()
        assert inventory.get("12345678").protected is False

    def test_set_protected_nonexistent(self, inventory: Inventory) -> None:
        """Test set_protected returns error for nonexistent device."""
        inventory.load()

        result = inventory.set_protected("nonexistent", True)

        assert result.is_err()
        assert "not in inventory" in str(result.unwrap_err())

    def test_set_label(self, inventory: Inventory) -> None:
        """Test set_label sets device label."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))

        result = inventory.set_label("12345678", "My Work Key")

        assert result.is_ok()
        assert inventory.get("12345678").label == "My Work Key"

    def test_set_label_clear(self, inventory: Inventory) -> None:
        """Test set_label with None clears label."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", label="Old Label"))

        result = inventory.set_label("12345678", None)

        assert result.is_ok()
        assert inventory.get("12345678").label is None

    def test_set_label_nonexistent(self, inventory: Inventory) -> None:
        """Test set_label returns error for nonexistent device."""
        inventory.load()

        result = inventory.set_label("nonexistent", "Label")

        assert result.is_err()

    def test_set_notes(self, inventory: Inventory) -> None:
        """Test set_notes sets device notes."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))

        result = inventory.set_notes("12345678", "Primary development key")

        assert result.is_ok()
        assert inventory.get("12345678").notes == "Primary development key"

    def test_set_notes_clear(self, inventory: Inventory) -> None:
        """Test set_notes with None clears notes."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", notes="Old notes"))

        result = inventory.set_notes("12345678", None)

        assert result.is_ok()
        assert inventory.get("12345678").notes is None

    def test_set_notes_nonexistent(self, inventory: Inventory) -> None:
        """Test set_notes returns error for nonexistent device."""
        inventory.load()

        result = inventory.set_notes("nonexistent", "Notes")

        assert result.is_err()

    def test_find_by_label_exact_match(self, inventory: Inventory) -> None:
        """Test find_by_label with exact match."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", label="My Work Key"))

        result = inventory.find_by_label("My Work Key")

        assert result is not None
        assert result.serial == "12345678"

    def test_find_by_label_case_insensitive(self, inventory: Inventory) -> None:
        """Test find_by_label is case insensitive."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", label="My Work Key"))

        result = inventory.find_by_label("my work key")

        assert result is not None
        assert result.serial == "12345678"

    def test_find_by_label_not_found(self, inventory: Inventory) -> None:
        """Test find_by_label returns None when not found."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", label="Other Key"))

        result = inventory.find_by_label("My Work Key")

        assert result is None

    def test_find_by_label_no_label(self, inventory: Inventory) -> None:
        """Test find_by_label skips devices without labels."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678"))

        result = inventory.find_by_label("Anything")

        assert result is None

    def test_find_by_identity_exact(self, inventory: Inventory) -> None:
        """Test find_by_identity with exact identity."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", provisioned_identity="dev@example.com"))

        result = inventory.find_by_identity("dev@example.com")

        assert len(result) == 1
        assert result[0].serial == "12345678"

    def test_find_by_identity_partial(self, inventory: Inventory) -> None:
        """Test find_by_identity with partial match."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", provisioned_identity="dev@example.com"))

        result = inventory.find_by_identity("example")

        assert len(result) == 1

    def test_find_by_identity_case_insensitive(self, inventory: Inventory) -> None:
        """Test find_by_identity is case insensitive."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", provisioned_identity="Dev@Example.com"))

        result = inventory.find_by_identity("dev@example")

        assert len(result) == 1

    def test_find_by_identity_multiple(self, inventory: Inventory) -> None:
        """Test find_by_identity returns multiple matches."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", provisioned_identity="dev@example.com"))
        inventory.add(DeviceEntry(serial="87654321", provisioned_identity="dev@example.org"))
        inventory.add(DeviceEntry(serial="11111111", provisioned_identity="other@company.com"))

        result = inventory.find_by_identity("dev@")

        assert len(result) == 2

    def test_find_by_identity_not_found(self, inventory: Inventory) -> None:
        """Test find_by_identity returns empty list when not found."""
        inventory.load()
        inventory.add(DeviceEntry(serial="12345678", provisioned_identity="dev@example.com"))

        result = inventory.find_by_identity("other@company.com")

        assert result == []


class TestParseOpenpgpInfo:
    """Test parse_openpgp_info function."""

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        state = parse_openpgp_info("")
        assert state.pin_tries_remaining == 3  # Default
        assert state.has_keys() is False

    def test_parse_pin_tries(self) -> None:
        """Test parsing PIN tries remaining."""
        output = """
PIN tries remaining: 2
Admin PIN tries remaining: 1
"""
        state = parse_openpgp_info(output)

        assert state.pin_tries_remaining == 2
        assert state.admin_pin_tries_remaining == 1

    def test_parse_reset_code_tries(self) -> None:
        """Test parsing reset code tries."""
        output = """
PIN tries remaining: 3
Admin PIN tries remaining: 3
Reset code tries remaining: 5
"""
        state = parse_openpgp_info(output)

        assert state.reset_code_tries_remaining == 5

    def test_parse_kdf_enabled(self) -> None:
        """Test parsing KDF enabled."""
        output = """
KDF enabled: True
"""
        state = parse_openpgp_info(output)

        assert state.kdf_enabled is True

    def test_parse_kdf_disabled(self) -> None:
        """Test parsing KDF disabled."""
        output = """
KDF enabled: False
"""
        state = parse_openpgp_info(output)

        assert state.kdf_enabled is False

    def test_parse_signature_key(self) -> None:
        """Test parsing signature key fingerprint."""
        output = """
Signature key:
  Fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
  Touch policy: On
"""
        state = parse_openpgp_info(output)

        assert state.signature_key.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        assert state.signature_key.touch_policy == "On"

    def test_parse_encryption_key(self) -> None:
        """Test parsing encryption key (labeled as Decryption key in ykman)."""
        output = """
Decryption key:
  Fingerprint: FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000
"""
        state = parse_openpgp_info(output)

        assert state.encryption_key.fingerprint == "FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000"

    def test_parse_authentication_key(self) -> None:
        """Test parsing authentication key."""
        output = """
Authentication key:
  Fingerprint: KKKK1111LLLL2222MMMM3333NNNN4444OOOO5555
"""
        state = parse_openpgp_info(output)

        assert state.authentication_key.fingerprint == "KKKK1111LLLL2222MMMM3333NNNN4444OOOO5555"

    def test_parse_fingerprint_not_set(self) -> None:
        """Test parsing 'Not set' fingerprint."""
        output = """
Signature key:
  Fingerprint: Not set
"""
        state = parse_openpgp_info(output)

        assert state.signature_key.fingerprint is None

    def test_parse_all_keys(self) -> None:
        """Test parsing all three keys."""
        output = """
Signature key:
  Fingerprint: SIG1111SIG2222SIG3333SIG4444SIG55555
  Touch policy: On
Decryption key:
  Fingerprint: ENC1111ENC2222ENC3333ENC4444ENC55555
  Touch policy: Off
Authentication key:
  Fingerprint: AUT1111AUT2222AUT3333AUT4444AUT55555
  Touch policy: Cached
"""
        state = parse_openpgp_info(output)

        assert state.signature_key.fingerprint == "SIG1111SIG2222SIG3333SIG4444SIG55555"
        assert state.signature_key.touch_policy == "On"
        assert state.encryption_key.fingerprint == "ENC1111ENC2222ENC3333ENC4444ENC55555"
        assert state.encryption_key.touch_policy == "Off"
        assert state.authentication_key.fingerprint == "AUT1111AUT2222AUT3333AUT4444AUT55555"
        assert state.authentication_key.touch_policy == "Cached"

    def test_parse_full_ykman_output(self) -> None:
        """Test parsing realistic ykman openpgp info output."""
        output = """
OpenPGP version: 3.4
Application version: 5.4.3
PIN tries remaining: 3
Admin PIN tries remaining: 3
Reset code tries remaining: 0
KDF enabled: False

Signature key:
  Fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
  Touch policy: On
  Created: 2024-01-15 12:00:00

Decryption key:
  Fingerprint: FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000
  Touch policy: On
  Created: 2024-01-15 12:00:00

Authentication key:
  Fingerprint: KKKK1111LLLL2222MMMM3333NNNN4444OOOO5555
  Touch policy: On
  Created: 2024-01-15 12:00:00
"""
        state = parse_openpgp_info(output)

        assert state.pin_tries_remaining == 3
        assert state.admin_pin_tries_remaining == 3
        assert state.kdf_enabled is False
        assert state.has_keys() is True
        assert state.signature_key.fingerprint is not None
        assert state.encryption_key.fingerprint is not None
        assert state.authentication_key.fingerprint is not None

    def test_parse_invalid_pin_tries(self) -> None:
        """Test parsing handles invalid PIN tries value."""
        output = """
PIN tries remaining: invalid
"""
        state = parse_openpgp_info(output)

        # Should use default when parsing fails
        assert state.pin_tries_remaining == 3

    def test_parse_encryption_key_alternate_label(self) -> None:
        """Test parsing encryption key with alternate label."""
        output = """
Encryption key:
  Fingerprint: ENC1234567890
"""
        state = parse_openpgp_info(output)

        assert state.encryption_key.fingerprint == "ENC1234567890"


class TestInventoryError:
    """Test InventoryError exception."""

    def test_inventory_error_is_exception(self) -> None:
        """Test InventoryError is an Exception."""
        err = InventoryError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"
