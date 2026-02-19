"""TUI Screen components.

This module contains all screen classes for the YubiKey Manager TUI.
"""

from __future__ import annotations

from .device_detail import DeviceDetailScreen
from .device_list import DeviceListScreen
from .diagnostics import DiagnosticsScreen
from .key_detail import KeyDetailScreen
from .key_list import KeyListScreen
from .main_menu import MainMenuScreen

__all__ = [
    "DeviceDetailScreen",
    "DeviceListScreen",
    "DiagnosticsScreen",
    "KeyDetailScreen",
    "KeyListScreen",
    "MainMenuScreen",
]
