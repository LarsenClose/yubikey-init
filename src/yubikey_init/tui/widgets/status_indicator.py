"""Status indicator widget for displaying device/key status.

Displays a status with appropriate icon and color based on state.
"""

from __future__ import annotations

from enum import Enum

from textual.widgets import Static


class Status(Enum):
    """Status states with associated styling."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


# Status configuration: (icon, CSS class suffix)
STATUS_CONFIG: dict[Status, tuple[str, str]] = {
    Status.OK: ("*", "ok"),  # Green checkmark
    Status.WARNING: ("!", "warning"),  # Yellow warning
    Status.ERROR: ("X", "error"),  # Red error
    Status.BLOCKED: ("X", "blocked"),  # Red blocked
    Status.UNKNOWN: ("?", "unknown"),  # Gray unknown
}


class StatusIndicator(Static):
    """Widget to display status with icon and color.

    Displays a status indicator with an icon and text, styled according
    to the status level.

    Attributes:
        status: The current Status enum value.
        text: The text to display alongside the icon.
    """

    DEFAULT_CSS = """
    StatusIndicator {
        width: auto;
        height: 1;
    }

    StatusIndicator.status-ok {
        color: $success;
    }

    StatusIndicator.status-warning {
        color: $warning;
    }

    StatusIndicator.status-error {
        color: $error;
    }

    StatusIndicator.status-blocked {
        color: $error;
    }

    StatusIndicator.status-unknown {
        color: $text-muted;
    }
    """

    def __init__(
        self,
        status: Status = Status.UNKNOWN,
        text: str = "",
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the status indicator.

        Args:
            status: The status level to display.
            text: Text to display after the icon.
            name: Widget name.
            id: Widget ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._status = status
        self._text = text
        self._update_display()

    @property
    def status(self) -> Status:
        """Get the current status."""
        return self._status

    @status.setter
    def status(self, value: Status) -> None:
        """Set the status and update display."""
        self._status = value
        self._update_display()

    @property
    def text(self) -> str:
        """Get the current text."""
        return self._text

    @text.setter
    def text(self, value: str) -> None:
        """Set the text and update display."""
        self._text = value
        self._update_display()

    def set_status(self, status: Status, text: str | None = None) -> None:
        """Update status and optionally text.

        Args:
            status: New status value.
            text: Optional new text (keeps current if None).
        """
        self._status = status
        if text is not None:
            self._text = text
        self._update_display()

    def _update_display(self) -> None:
        """Update the widget display based on current state."""
        icon, css_suffix = STATUS_CONFIG.get(self._status, STATUS_CONFIG[Status.UNKNOWN])

        # Remove old status classes
        for s in Status:
            _, suffix = STATUS_CONFIG.get(s, ("", "unknown"))
            self.remove_class(f"status-{suffix}")

        # Add new status class
        self.add_class(f"status-{css_suffix}")

        # Update content
        if self._text:
            self.update(f"{icon} {self._text}")
        else:
            self.update(icon)


def status_from_pin_tries(tries: int, max_tries: int = 3) -> Status:
    """Determine status based on PIN retry count.

    Args:
        tries: Current number of tries remaining.
        max_tries: Maximum number of tries (default 3).

    Returns:
        Status enum value based on tries remaining.
    """
    if tries == 0:
        return Status.BLOCKED
    elif tries < max_tries:
        return Status.WARNING
    else:
        return Status.OK


def format_pin_status(tries: int, max_tries: int = 3) -> tuple[Status, str]:
    """Format PIN status as status and text tuple.

    Args:
        tries: Current number of tries remaining.
        max_tries: Maximum number of tries.

    Returns:
        Tuple of (Status, formatted text string).
    """
    status = status_from_pin_tries(tries, max_tries)
    if status == Status.BLOCKED:
        return status, "BLOCKED (0 tries remaining)"
    elif status == Status.WARNING:
        return status, f"{tries}/{max_tries} tries remaining"
    else:
        return status, f"{tries}/{max_tries} tries remaining"
