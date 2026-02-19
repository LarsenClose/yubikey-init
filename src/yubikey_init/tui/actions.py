"""Action definitions for the YubiKey Management TUI.

This module defines the actions available for devices and keys,
including metadata about confirmation requirements and destructiveness.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    """Represents a user action in the TUI.

    Attributes:
        id: Unique identifier for the action.
        label: Human-readable label displayed in the UI.
        shortcut: Keyboard shortcut key (single character).
        destructive: If True, the action may cause data loss.
        requires_confirmation: If True, prompt user before executing.
        confirmation_prompt: Template for confirmation dialog.
            May contain {serial} placeholder for device serial.
    """

    id: str
    label: str
    shortcut: str
    destructive: bool = False
    requires_confirmation: bool = False
    confirmation_prompt: str | None = None


# Device actions available in the device detail screen
DEVICE_ACTIONS: list[Action] = [
    Action(
        id="reset",
        label="Reset OpenPGP",
        shortcut="R",
        destructive=True,
        requires_confirmation=True,
        confirmation_prompt="Type 'reset {serial}' to confirm",
    ),
    Action(
        id="label",
        label="Set Label",
        shortcut="L",
        destructive=False,
        requires_confirmation=False,
        confirmation_prompt=None,
    ),
    Action(
        id="protect",
        label="Toggle Protection",
        shortcut="P",
        destructive=False,
        requires_confirmation=False,
        confirmation_prompt=None,
    ),
    Action(
        id="unblock",
        label="Unblock PIN",
        shortcut="U",
        destructive=False,
        requires_confirmation=True,
        confirmation_prompt="This will reset the user PIN. Continue?",
    ),
    Action(
        id="notes",
        label="Edit Notes",
        shortcut="N",
        destructive=False,
        requires_confirmation=False,
        confirmation_prompt=None,
    ),
]


# Key actions available in the key detail screen
KEY_ACTIONS: list[Action] = [
    Action(
        id="export_ssh",
        label="Export SSH Key",
        shortcut="S",
        destructive=False,
        requires_confirmation=False,
        confirmation_prompt=None,
    ),
    Action(
        id="show_fingerprint",
        label="Show Fingerprint",
        shortcut="F",
        destructive=False,
        requires_confirmation=False,
        confirmation_prompt=None,
    ),
]


def get_device_action(action_id: str) -> Action | None:
    """Get a device action by its ID.

    Args:
        action_id: The unique identifier of the action.

    Returns:
        The Action if found, None otherwise.
    """
    for action in DEVICE_ACTIONS:
        if action.id == action_id:
            return action
    return None


def get_key_action(action_id: str) -> Action | None:
    """Get a key action by its ID.

    Args:
        action_id: The unique identifier of the action.

    Returns:
        The Action if found, None otherwise.
    """
    for action in KEY_ACTIONS:
        if action.id == action_id:
            return action
    return None


def get_action_by_shortcut(
    shortcut: str,
    action_list: list[Action],
) -> Action | None:
    """Get an action by its keyboard shortcut.

    Args:
        shortcut: The keyboard shortcut (case-insensitive).
        action_list: The list of actions to search.

    Returns:
        The Action if found, None otherwise.
    """
    shortcut_upper = shortcut.upper()
    for action in action_list:
        if action.shortcut.upper() == shortcut_upper:
            return action
    return None
