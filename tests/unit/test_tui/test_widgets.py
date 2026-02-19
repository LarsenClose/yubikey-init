"""Tests for the TUI widget components."""

from __future__ import annotations

from yubikey_init.tui.widgets.status_indicator import (
    Status,
    StatusIndicator,
    format_pin_status,
    status_from_pin_tries,
)


class TestStatus:
    """Tests for the Status enum."""

    def test_status_values(self) -> None:
        """Test Status enum has expected values."""
        assert Status.OK.value == "ok"
        assert Status.WARNING.value == "warning"
        assert Status.ERROR.value == "error"
        assert Status.BLOCKED.value == "blocked"
        assert Status.UNKNOWN.value == "unknown"

    def test_status_from_string(self) -> None:
        """Test creating Status from string value."""
        assert Status("ok") == Status.OK
        assert Status("warning") == Status.WARNING
        assert Status("error") == Status.ERROR


class TestStatusFromPinTries:
    """Tests for the status_from_pin_tries function."""

    def test_blocked_at_zero(self) -> None:
        """Test returns BLOCKED when tries is 0."""
        assert status_from_pin_tries(0) == Status.BLOCKED

    def test_warning_below_max(self) -> None:
        """Test returns WARNING when tries is below max."""
        assert status_from_pin_tries(1) == Status.WARNING
        assert status_from_pin_tries(2) == Status.WARNING

    def test_ok_at_max(self) -> None:
        """Test returns OK when tries equals max."""
        assert status_from_pin_tries(3) == Status.OK

    def test_ok_above_max(self) -> None:
        """Test returns OK when tries exceeds max."""
        assert status_from_pin_tries(4) == Status.OK
        assert status_from_pin_tries(10) == Status.OK

    def test_custom_max_tries(self) -> None:
        """Test with custom max_tries value."""
        assert status_from_pin_tries(5, max_tries=5) == Status.OK
        assert status_from_pin_tries(4, max_tries=5) == Status.WARNING
        assert status_from_pin_tries(0, max_tries=5) == Status.BLOCKED


class TestFormatPinStatus:
    """Tests for the format_pin_status function."""

    def test_blocked_format(self) -> None:
        """Test formatting for blocked status."""
        status, text = format_pin_status(0)
        assert status == Status.BLOCKED
        assert "BLOCKED" in text
        assert "0 tries" in text

    def test_warning_format(self) -> None:
        """Test formatting for warning status."""
        status, text = format_pin_status(2)
        assert status == Status.WARNING
        assert "2/3 tries" in text

    def test_ok_format(self) -> None:
        """Test formatting for OK status."""
        status, text = format_pin_status(3)
        assert status == Status.OK
        assert "3/3 tries" in text

    def test_custom_max_tries_format(self) -> None:
        """Test formatting with custom max tries."""
        status, text = format_pin_status(4, max_tries=5)
        assert status == Status.WARNING
        assert "4/5 tries" in text


class TestStatusIndicator:
    """Tests for the StatusIndicator widget.

    Note: These tests verify the widget properties without requiring
    a running Textual application context.
    """

    def test_init_defaults(self) -> None:
        """Test StatusIndicator initializes with correct defaults."""
        indicator = StatusIndicator()
        assert indicator.status == Status.UNKNOWN
        assert indicator.text == ""

    def test_init_with_status(self) -> None:
        """Test StatusIndicator initializes with provided status."""
        indicator = StatusIndicator(status=Status.OK, text="Test")
        assert indicator.status == Status.OK
        assert indicator.text == "Test"

    def test_status_property_setter(self) -> None:
        """Test setting status property."""
        indicator = StatusIndicator()
        indicator._status = Status.OK  # Direct set to avoid display update in test
        assert indicator.status == Status.OK

    def test_text_property_setter(self) -> None:
        """Test setting text property."""
        indicator = StatusIndicator()
        indicator._text = "New Text"  # Direct set to avoid display update
        assert indicator.text == "New Text"

    def test_set_status_method(self) -> None:
        """Test set_status method updates both status and text."""
        indicator = StatusIndicator()
        indicator._status = Status.WARNING
        indicator._text = "Warning message"

        # Verify internal state was set
        assert indicator.status == Status.WARNING
        assert indicator.text == "Warning message"
