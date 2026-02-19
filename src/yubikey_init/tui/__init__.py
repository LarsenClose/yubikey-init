"""YubiKey Management TUI.

This module provides a terminal user interface for managing YubiKey devices
and GPG keys. It uses Textual for the TUI framework.

Entry points:
    - run(): Launch the TUI application (legacy alias)
    - run_tui(): Launch the TUI application with optional controller
    - create_app(): Create app instance without running
    - YubiKeyManagerApp: The main Textual application class
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import YubiKeyManagerApp
    from .controller import TUIController

__all__ = [
    "YubiKeyManagerApp",
    "create_app",
    "run",
    "run_tui",
]


def run() -> None:
    """Launch the YubiKey Manager TUI application.

    This is a legacy entry point. Consider using run_tui() instead.
    """
    from .app import YubiKeyManagerApp

    app = YubiKeyManagerApp()
    app.run()


def run_tui(controller: TUIController | None = None) -> None:
    """Launch the YubiKey Manager TUI application.

    Args:
        controller: Optional TUIController instance for data access.
    """
    from .app import run_tui as _run_tui

    _run_tui(controller)


def create_app(controller: TUIController | None = None) -> YubiKeyManagerApp:
    """Create a YubiKey Manager application instance without running it.

    Args:
        controller: Optional TUIController instance.

    Returns:
        Configured YubiKeyManagerApp instance.
    """
    from .app import create_app as _create_app

    return _create_app(controller)
