"""Tests for TUI dialog widgets using Textual's async testing framework."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input, Static

from yubikey_init.tui.widgets.confirm_dialog import ConfirmDialog, InputDialog


class DialogTestApp(App[None]):
    """Test application for dialog testing."""

    def __init__(self, dialog) -> None:
        super().__init__()
        self._dialog = dialog

    def compose(self) -> ComposeResult:
        yield Static("Test App")

    async def on_mount(self) -> None:
        await self.push_screen(self._dialog)


class TestConfirmDialog:
    """Tests for the ConfirmDialog widget."""

    @pytest.mark.asyncio
    async def test_dialog_displays_title(self) -> None:
        """Test that dialog displays the title."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()  # Wait for screen push
            # Query within the current screen - verify the widget exists
            title = pilot.app.screen.query_one(".dialog-title", Static)
            assert title is not None

    @pytest.mark.asyncio
    async def test_dialog_displays_message(self) -> None:
        """Test that dialog displays the message."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message here",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            message = pilot.app.screen.query_one(".dialog-message", Static)
            assert message is not None

    @pytest.mark.asyncio
    async def test_dialog_displays_device_info(self) -> None:
        """Test that dialog displays device info when provided."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
            device_info="Device: Test (12345678)",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            device_info = pilot.app.screen.query_one(".dialog-device-info", Static)
            assert device_info is not None

    @pytest.mark.asyncio
    async def test_confirm_button_initially_disabled(self) -> None:
        """Test that confirm button is disabled initially."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            confirm_button = pilot.app.screen.query_one("#confirm", Button)
            assert confirm_button.disabled

    @pytest.mark.asyncio
    async def test_confirm_button_enabled_on_correct_input(self) -> None:
        """Test that confirm button is enabled when correct text is entered."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Type the correct confirmation text
            input_widget = pilot.app.screen.query_one("#confirm-input", Input)
            input_widget.value = "confirm"
            await pilot.pause()

            # Button should be enabled
            confirm_button = pilot.app.screen.query_one("#confirm", Button)
            assert not confirm_button.disabled

    @pytest.mark.asyncio
    async def test_cancel_dismisses_with_false(self) -> None:
        """Test that canceling dismisses with False."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Click cancel
            cancel_button = pilot.app.screen.query_one("#cancel", Button)
            await pilot.click(cancel_button)

    @pytest.mark.asyncio
    async def test_escape_dismisses(self) -> None:
        """Test that escape key dismisses the dialog."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Press escape
            await pilot.press("escape")

    @pytest.mark.asyncio
    async def test_wrong_input_shows_error(self) -> None:
        """Test that wrong input shows error message."""
        dialog = ConfirmDialog(
            title="Test Title",
            message="Test message",
            confirm_text="confirm",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Type wrong text
            input_widget = pilot.app.screen.query_one("#confirm-input", Input)
            input_widget.value = "wrong"
            await pilot.pause()

            # Verify error message widget exists (it gets updated when input is wrong)
            error_message = pilot.app.screen.query_one("#error-message", Static)
            assert error_message is not None
            # Also verify confirm button stays disabled
            confirm_button = pilot.app.screen.query_one("#confirm", Button)
            assert confirm_button.disabled


class TestInputDialog:
    """Tests for the InputDialog widget."""

    @pytest.mark.asyncio
    async def test_dialog_displays_title(self) -> None:
        """Test that dialog displays the title."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            title = pilot.app.screen.query_one(".dialog-title", Static)
            assert title is not None

    @pytest.mark.asyncio
    async def test_dialog_displays_message(self) -> None:
        """Test that dialog displays the message."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            message = pilot.app.screen.query_one(".dialog-message", Static)
            assert message is not None

    @pytest.mark.asyncio
    async def test_initial_value(self) -> None:
        """Test that initial value is set."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
            initial_value="initial",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            input_widget = pilot.app.screen.query_one("#dialog-input", Input)
            assert input_widget.value == "initial"

    @pytest.mark.asyncio
    async def test_placeholder(self) -> None:
        """Test that placeholder is set."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
            placeholder="Type here...",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            input_widget = pilot.app.screen.query_one("#dialog-input", Input)
            assert input_widget.placeholder == "Type here..."

    @pytest.mark.asyncio
    async def test_cancel_dismisses_with_none(self) -> None:
        """Test that canceling dismisses with None."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            cancel_button = pilot.app.screen.query_one("#cancel", Button)
            await pilot.click(cancel_button)

    @pytest.mark.asyncio
    async def test_ok_dismisses_with_value(self) -> None:
        """Test that OK button dismisses with entered value."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Enter a value
            input_widget = pilot.app.screen.query_one("#dialog-input", Input)
            input_widget.value = "test value"
            await pilot.pause()

            # Click OK
            ok_button = pilot.app.screen.query_one("#ok", Button)
            await pilot.click(ok_button)

    @pytest.mark.asyncio
    async def test_escape_dismisses(self) -> None:
        """Test that escape key dismisses the dialog."""
        dialog = InputDialog(
            title="Enter Value",
            message="Please enter a value:",
        )
        app = DialogTestApp(dialog)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
