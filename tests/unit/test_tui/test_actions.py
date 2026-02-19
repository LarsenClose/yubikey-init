"""Tests for TUI actions module."""

from __future__ import annotations

import pytest

from yubikey_init.tui.actions import (
    DEVICE_ACTIONS,
    KEY_ACTIONS,
    Action,
    get_action_by_shortcut,
    get_device_action,
    get_key_action,
)


class TestAction:
    """Tests for the Action dataclass."""

    def test_action_creation_minimal(self) -> None:
        """Test creating an action with minimal parameters."""
        action = Action(
            id="test",
            label="Test Action",
            shortcut="T",
        )
        assert action.id == "test"
        assert action.label == "Test Action"
        assert action.shortcut == "T"
        assert action.destructive is False
        assert action.requires_confirmation is False
        assert action.confirmation_prompt is None

    def test_action_creation_full(self) -> None:
        """Test creating an action with all parameters."""
        action = Action(
            id="delete",
            label="Delete Item",
            shortcut="D",
            destructive=True,
            requires_confirmation=True,
            confirmation_prompt="Type 'delete' to confirm",
        )
        assert action.id == "delete"
        assert action.label == "Delete Item"
        assert action.shortcut == "D"
        assert action.destructive is True
        assert action.requires_confirmation is True
        assert action.confirmation_prompt == "Type 'delete' to confirm"

    def test_action_is_frozen(self) -> None:
        """Test that Action dataclass is frozen (immutable)."""
        action = Action(id="test", label="Test", shortcut="T")
        with pytest.raises(Exception):  # FrozenInstanceError in Python 3.11+
            action.id = "modified"  # type: ignore


class TestDeviceActions:
    """Tests for DEVICE_ACTIONS list."""

    def test_device_actions_exists(self) -> None:
        """Test that DEVICE_ACTIONS is defined."""
        assert DEVICE_ACTIONS is not None
        assert isinstance(DEVICE_ACTIONS, list)

    def test_device_actions_count(self) -> None:
        """Test expected number of device actions."""
        assert len(DEVICE_ACTIONS) == 5

    def test_device_action_ids(self) -> None:
        """Test that all expected device actions are present."""
        action_ids = {action.id for action in DEVICE_ACTIONS}
        expected_ids = {"reset", "label", "protect", "unblock", "notes"}
        assert action_ids == expected_ids

    def test_device_action_shortcuts_unique(self) -> None:
        """Test that all shortcuts are unique."""
        shortcuts = [action.shortcut for action in DEVICE_ACTIONS]
        assert len(shortcuts) == len(set(shortcuts))

    def test_reset_action_is_destructive(self) -> None:
        """Test that reset action is marked as destructive."""
        reset = next(a for a in DEVICE_ACTIONS if a.id == "reset")
        assert reset.destructive is True
        assert reset.requires_confirmation is True
        assert reset.confirmation_prompt is not None
        assert "reset" in reset.confirmation_prompt.lower()
        assert "{serial}" in reset.confirmation_prompt

    def test_label_action_not_destructive(self) -> None:
        """Test that label action is not destructive."""
        label = next(a for a in DEVICE_ACTIONS if a.id == "label")
        assert label.destructive is False
        assert label.requires_confirmation is False
        assert label.shortcut == "L"

    def test_protect_action_properties(self) -> None:
        """Test protect action properties."""
        protect = next(a for a in DEVICE_ACTIONS if a.id == "protect")
        assert protect.shortcut == "P"
        assert protect.destructive is False
        assert protect.requires_confirmation is False

    def test_unblock_action_requires_confirmation(self) -> None:
        """Test that unblock action requires confirmation."""
        unblock = next(a for a in DEVICE_ACTIONS if a.id == "unblock")
        assert unblock.requires_confirmation is True
        assert unblock.confirmation_prompt is not None
        assert "PIN" in unblock.confirmation_prompt

    def test_notes_action_properties(self) -> None:
        """Test notes action properties."""
        notes = next(a for a in DEVICE_ACTIONS if a.id == "notes")
        assert notes.shortcut == "N"
        assert notes.destructive is False


class TestKeyActions:
    """Tests for KEY_ACTIONS list."""

    def test_key_actions_exists(self) -> None:
        """Test that KEY_ACTIONS is defined."""
        assert KEY_ACTIONS is not None
        assert isinstance(KEY_ACTIONS, list)

    def test_key_actions_count(self) -> None:
        """Test expected number of key actions."""
        assert len(KEY_ACTIONS) == 2

    def test_key_action_ids(self) -> None:
        """Test that all expected key actions are present."""
        action_ids = {action.id for action in KEY_ACTIONS}
        expected_ids = {"export_ssh", "show_fingerprint"}
        assert action_ids == expected_ids

    def test_key_action_shortcuts_unique(self) -> None:
        """Test that all key action shortcuts are unique."""
        shortcuts = [action.shortcut for action in KEY_ACTIONS]
        assert len(shortcuts) == len(set(shortcuts))

    def test_key_actions_not_destructive(self) -> None:
        """Test that key actions are not destructive."""
        for action in KEY_ACTIONS:
            assert action.destructive is False

    def test_export_ssh_action_properties(self) -> None:
        """Test export SSH action properties."""
        export = next(a for a in KEY_ACTIONS if a.id == "export_ssh")
        assert export.shortcut == "S"
        assert export.label == "Export SSH Key"
        assert export.requires_confirmation is False

    def test_show_fingerprint_action_properties(self) -> None:
        """Test show fingerprint action properties."""
        show_fp = next(a for a in KEY_ACTIONS if a.id == "show_fingerprint")
        assert show_fp.shortcut == "F"
        assert show_fp.label == "Show Fingerprint"
        assert show_fp.requires_confirmation is False


class TestGetDeviceAction:
    """Tests for get_device_action function."""

    def test_get_device_action_found(self) -> None:
        """Test getting a device action by ID."""
        action = get_device_action("reset")
        assert action is not None
        assert action.id == "reset"

    def test_get_device_action_all_actions(self) -> None:
        """Test getting all device actions by ID."""
        for expected_action in DEVICE_ACTIONS:
            action = get_device_action(expected_action.id)
            assert action is not None
            assert action.id == expected_action.id

    def test_get_device_action_not_found(self) -> None:
        """Test getting a non-existent device action."""
        action = get_device_action("nonexistent")
        assert action is None

    def test_get_device_action_empty_string(self) -> None:
        """Test getting action with empty string."""
        action = get_device_action("")
        assert action is None

    def test_get_device_action_case_sensitive(self) -> None:
        """Test that action lookup is case-sensitive."""
        action = get_device_action("RESET")
        assert action is None


class TestGetKeyAction:
    """Tests for get_key_action function."""

    def test_get_key_action_found(self) -> None:
        """Test getting a key action by ID."""
        action = get_key_action("export_ssh")
        assert action is not None
        assert action.id == "export_ssh"

    def test_get_key_action_all_actions(self) -> None:
        """Test getting all key actions by ID."""
        for expected_action in KEY_ACTIONS:
            action = get_key_action(expected_action.id)
            assert action is not None
            assert action.id == expected_action.id

    def test_get_key_action_not_found(self) -> None:
        """Test getting a non-existent key action."""
        action = get_key_action("nonexistent")
        assert action is None

    def test_get_key_action_empty_string(self) -> None:
        """Test getting action with empty string."""
        action = get_key_action("")
        assert action is None

    def test_get_key_action_case_sensitive(self) -> None:
        """Test that action lookup is case-sensitive."""
        action = get_key_action("EXPORT_SSH")
        assert action is None


class TestGetActionByShortcut:
    """Tests for get_action_by_shortcut function."""

    def test_get_action_by_shortcut_device_action(self) -> None:
        """Test getting a device action by shortcut."""
        action = get_action_by_shortcut("R", DEVICE_ACTIONS)
        assert action is not None
        assert action.id == "reset"
        assert action.shortcut == "R"

    def test_get_action_by_shortcut_case_insensitive(self) -> None:
        """Test that shortcut lookup is case-insensitive."""
        action_upper = get_action_by_shortcut("R", DEVICE_ACTIONS)
        action_lower = get_action_by_shortcut("r", DEVICE_ACTIONS)
        assert action_upper is not None
        assert action_lower is not None
        assert action_upper.id == action_lower.id

    def test_get_action_by_shortcut_all_device_actions(self) -> None:
        """Test getting all device actions by shortcut."""
        for expected_action in DEVICE_ACTIONS:
            action = get_action_by_shortcut(expected_action.shortcut, DEVICE_ACTIONS)
            assert action is not None
            assert action.id == expected_action.id

    def test_get_action_by_shortcut_all_key_actions(self) -> None:
        """Test getting all key actions by shortcut."""
        for expected_action in KEY_ACTIONS:
            action = get_action_by_shortcut(expected_action.shortcut, KEY_ACTIONS)
            assert action is not None
            assert action.id == expected_action.id

    def test_get_action_by_shortcut_not_found(self) -> None:
        """Test getting action with non-existent shortcut."""
        action = get_action_by_shortcut("Z", DEVICE_ACTIONS)
        assert action is None

    def test_get_action_by_shortcut_empty_list(self) -> None:
        """Test getting action from empty list."""
        action = get_action_by_shortcut("R", [])
        assert action is None

    def test_get_action_by_shortcut_empty_string(self) -> None:
        """Test getting action with empty shortcut."""
        action = get_action_by_shortcut("", DEVICE_ACTIONS)
        assert action is None

    def test_get_action_by_shortcut_key_action(self) -> None:
        """Test getting a key action by shortcut."""
        action = get_action_by_shortcut("S", KEY_ACTIONS)
        assert action is not None
        assert action.id == "export_ssh"

    def test_get_action_by_shortcut_returns_first_match(self) -> None:
        """Test that only the first matching action is returned."""
        # Create a custom list with duplicate shortcuts
        actions = [
            Action(id="first", label="First", shortcut="A"),
            Action(id="second", label="Second", shortcut="A"),
        ]
        action = get_action_by_shortcut("A", actions)
        assert action is not None
        assert action.id == "first"
