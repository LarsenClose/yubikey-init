"""Confirmation dialog for destructive actions.

Provides a modal dialog that requires typing a specific confirmation
string before proceeding with destructive operations.
"""

from __future__ import annotations

from collections.abc import Callable

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ConfirmDialog(ModalScreen[bool]):
    """Modal confirmation dialog for destructive actions.

    Requires the user to type a specific confirmation string to proceed.
    Returns True if confirmed, False if cancelled.

    Example:
        async def handle_reset(self) -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Reset OpenPGP",
                    message="This will permanently delete all keys.",
                    confirm_text="reset 17722040",
                    device_info="Device: Work Key (17722040)",
                )
            )
            if confirmed:
                # Proceed with reset
                ...
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    ConfirmDialog {
        align: center middle;
    }

    ConfirmDialog > Vertical {
        width: 60;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: thick $error;
        padding: 1 2;
    }

    ConfirmDialog .dialog-title {
        text-style: bold;
        color: $error;
        text-align: center;
        width: 100%;
        padding-bottom: 1;
    }

    ConfirmDialog .dialog-warning-icon {
        text-align: center;
        width: 100%;
        color: $warning;
        padding-bottom: 1;
    }

    ConfirmDialog .dialog-message {
        width: 100%;
        padding-bottom: 1;
    }

    ConfirmDialog .dialog-device-info {
        color: $text-muted;
        padding-bottom: 1;
    }

    ConfirmDialog .dialog-confirm-instruction {
        padding-top: 1;
        padding-bottom: 1;
    }

    ConfirmDialog .dialog-input-container {
        width: 100%;
        height: auto;
        padding: 0;
    }

    ConfirmDialog Input {
        width: 100%;
    }

    ConfirmDialog Input.error {
        border: tall $error;
    }

    ConfirmDialog .dialog-error-message {
        color: $error;
        height: 1;
        padding-top: 0;
    }

    ConfirmDialog .dialog-buttons {
        width: 100%;
        height: 3;
        align: center middle;
        padding-top: 1;
    }

    ConfirmDialog Button {
        margin: 0 1;
    }

    ConfirmDialog .cancel-button {
        background: $surface-darken-1;
    }

    ConfirmDialog .confirm-button {
        background: $error;
    }

    ConfirmDialog .confirm-button:disabled {
        background: $surface-darken-2;
        color: $text-disabled;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        confirm_text: str,
        device_info: str | None = None,
        on_confirm: Callable[[], None] | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the confirmation dialog.

        Args:
            title: Dialog title (e.g., "Reset OpenPGP Application").
            message: Warning message explaining the consequences.
            confirm_text: Exact text user must type to confirm.
            device_info: Optional device information string.
            on_confirm: Optional callback when confirmed (deprecated, use return value).
            name: Widget name.
            id: Widget ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._title = title
        self._message = message
        self._confirm_text = confirm_text
        self._device_info = device_info
        self._on_confirm = on_confirm

    def compose(self) -> ComposeResult:
        """Compose the dialog layout."""
        with Vertical():
            yield Static("! WARNING !", classes="dialog-warning-icon")
            yield Static(self._title, classes="dialog-title")
            yield Static(self._message, classes="dialog-message")

            if self._device_info:
                yield Static(self._device_info, classes="dialog-device-info")

            yield Static(
                f"Type '{self._confirm_text}' to confirm:",
                classes="dialog-confirm-instruction",
            )

            with Container(classes="dialog-input-container"):
                yield Input(
                    placeholder=self._confirm_text,
                    id="confirm-input",
                )
                yield Static("", id="error-message", classes="dialog-error-message")

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel", classes="cancel-button")
                yield Button(
                    "Confirm",
                    id="confirm",
                    variant="error",
                    classes="confirm-button",
                    disabled=True,
                )

    def on_mount(self) -> None:
        """Focus the input when dialog mounts."""
        self.query_one("#confirm-input", Input).focus()

    @on(Input.Changed, "#confirm-input")
    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes to validate confirmation text."""
        input_value = event.value.strip()
        confirm_button = self.query_one("#confirm", Button)
        error_message = self.query_one("#error-message", Static)
        input_widget = self.query_one("#confirm-input", Input)

        if input_value == self._confirm_text:
            # Exact match - enable confirm
            confirm_button.disabled = False
            error_message.update("")
            input_widget.remove_class("error")
        elif input_value and not self._confirm_text.startswith(input_value):
            # Wrong input
            confirm_button.disabled = True
            error_message.update("Text does not match")
            input_widget.add_class("error")
        else:
            # Partial match or empty
            confirm_button.disabled = True
            error_message.update("")
            input_widget.remove_class("error")

    @on(Input.Submitted, "#confirm-input")
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input field."""
        if event.value.strip() == self._confirm_text:
            self._do_confirm()

    @on(Button.Pressed, "#cancel")
    def on_cancel_pressed(self) -> None:
        """Handle cancel button press."""
        self.dismiss(False)

    @on(Button.Pressed, "#confirm")
    def on_confirm_pressed(self) -> None:
        """Handle confirm button press."""
        self._do_confirm()

    def action_cancel(self) -> None:
        """Handle escape key."""
        self.dismiss(False)

    def _do_confirm(self) -> None:
        """Execute confirmation action."""
        if self._on_confirm:
            self._on_confirm()
        self.dismiss(True)


class InputDialog(ModalScreen[str | None]):
    """Simple input dialog for non-destructive actions.

    Returns the entered text if submitted, None if cancelled.

    Example:
        label = await self.app.push_screen_wait(
            InputDialog(
                title="Set Device Label",
                message="Enter a label for this YubiKey:",
                placeholder="e.g., Work Primary",
                initial_value=current_label,
            )
        )
        if label is not None:
            # Apply label
            ...
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    InputDialog {
        align: center middle;
    }

    InputDialog > Vertical {
        width: 50;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    InputDialog .dialog-title {
        text-style: bold;
        text-align: center;
        width: 100%;
        padding-bottom: 1;
    }

    InputDialog .dialog-message {
        width: 100%;
        padding-bottom: 1;
    }

    InputDialog Input {
        width: 100%;
    }

    InputDialog .dialog-buttons {
        width: 100%;
        height: 3;
        align: center middle;
        padding-top: 1;
    }

    InputDialog Button {
        margin: 0 1;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        placeholder: str = "",
        initial_value: str = "",
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the input dialog.

        Args:
            title: Dialog title.
            message: Instructional message.
            placeholder: Input placeholder text.
            initial_value: Initial value for the input.
            name: Widget name.
            id: Widget ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._title = title
        self._message = message
        self._placeholder = placeholder
        self._initial_value = initial_value

    def compose(self) -> ComposeResult:
        """Compose the dialog layout."""
        with Vertical():
            yield Static(self._title, classes="dialog-title")
            yield Static(self._message, classes="dialog-message")
            yield Input(
                value=self._initial_value,
                placeholder=self._placeholder,
                id="dialog-input",
            )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("OK", id="ok", variant="primary")

    def on_mount(self) -> None:
        """Focus the input when dialog mounts."""
        input_widget = self.query_one("#dialog-input", Input)
        input_widget.focus()
        # Select all text if there's an initial value
        if self._initial_value:
            input_widget.cursor_position = len(self._initial_value)

    @on(Input.Submitted, "#dialog-input")
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input field."""
        self.dismiss(event.value)

    @on(Button.Pressed, "#cancel")
    def on_cancel_pressed(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#ok")
    def on_ok_pressed(self) -> None:
        """Handle OK button press."""
        value = self.query_one("#dialog-input", Input).value
        self.dismiss(value)

    def action_cancel(self) -> None:
        """Handle escape key."""
        self.dismiss(None)
