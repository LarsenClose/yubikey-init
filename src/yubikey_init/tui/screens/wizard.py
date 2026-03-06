"""Setup wizard screen for the YubiKey Management TUI.

This screen provides a multi-step wizard that guides users through
the complete YubiKey initialization process. Step 1 performs an
environment verification check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from ...environment import EnvironmentReport, verify_environment

if TYPE_CHECKING:
    from ..controller import TUIController

# Step labels for the wizard
_STEP_LABELS: dict[int, str] = {
    1: "Environment Check",
    2: "Identity Configuration",
    3: "Key Generation",
    4: "Subkey Creation",
    5: "Key Backup",
    6: "YubiKey Selection",
    7: "Key Transfer",
    8: "PIN Configuration",
    9: "Verification",
    10: "Summary",
}


class WizardScreen(Screen[None]):
    """Multi-step setup wizard for YubiKey initialization.

    Guides users through the full YubiKey setup process, starting
    with an environment verification check.

    Keyboard shortcuts:
    - N: Next step
    - Escape: Cancel wizard
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True, priority=True),
        Binding("n", "next_step", "Next", show=True),
    ]

    DEFAULT_CSS = """
    WizardScreen {
        layout: vertical;
    }

    WizardScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    WizardScreen .step-indicator {
        width: 100%;
        height: 1;
        content-align: center middle;
        color: $text-muted;
        background: $primary-darken-2;
    }

    WizardScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }

    WizardScreen .section-title {
        text-style: bold;
        color: $text;
        padding-bottom: 1;
        border-bottom: solid $primary-darken-3;
        margin-bottom: 1;
    }

    WizardScreen .check-item {
        height: 1;
        padding: 0 0 0 2;
    }

    WizardScreen .nav-bar {
        dock: bottom;
        width: 100%;
        height: 3;
        align: center middle;
        background: $surface-darken-1;
        padding: 0 2;
    }

    WizardScreen .nav-bar Button {
        margin: 0 1;
    }
    """

    def __init__(
        self,
        controller: TUIController | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the wizard screen.

        Args:
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._controller = controller
        self._current_step = 1
        self._total_steps = 10
        self._env_report: EnvironmentReport | None = None
        self._step_complete = False

    @property
    def step_label(self) -> str:
        """Get the label for the current step."""
        return _STEP_LABELS.get(self._current_step, "Coming Soon")

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("New Setup Wizard", classes="screen-title")
        yield Static(
            f"Step {self._current_step} of {self._total_steps} -- {self.step_label}",
            classes="step-indicator",
            id="step-indicator",
        )

        with VerticalScroll(classes="content-container"):
            yield Vertical(id="step-content")

        with Horizontal(classes="nav-bar"):
            yield Button("Back", id="btn-back", disabled=True)
            yield Button("Next", id="btn-next", variant="primary", disabled=True)
            yield Button("Cancel", id="btn-cancel", variant="error")

        yield Footer()

    def on_mount(self) -> None:
        """Run the current step when the screen is mounted."""
        self._run_step()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        if button_id == "btn-back":
            self._go_back()
        elif button_id == "btn-next":
            self.action_next_step()
        elif button_id == "btn-cancel":
            self.action_cancel()

    def _run_step(self) -> None:
        """Dispatch to the handler for the current step."""
        self._step_complete = False
        if self._current_step == 1:
            self._run_environment_check()
        else:
            self._show_placeholder()

    @work(exclusive=True)
    async def _run_environment_check(self) -> None:
        """Run environment verification and display results."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Environment Check", classes="section-title"))
        await content.mount(
            Static("[dim]Running environment checks...[/dim]", classes="check-item")
        )

        try:
            self._env_report = verify_environment(include_optional=True)
        except Exception as e:
            await content.remove_children()
            await content.mount(
                Static(f"[red]Environment check failed: {e}[/red]", classes="check-item")
            )
            return

        # Remove the loading message and re-mount section title
        await content.remove_children()
        await content.mount(Static("Environment Check", classes="section-title"))

        # Display each check result
        for check in self._env_report.checks:
            if check.passed:
                icon = "[green]OK[/green]"
            elif check.critical:
                icon = "[red]X[/red]"
            else:
                icon = "[yellow]!![/yellow]"

            label = "required" if check.critical else "optional"
            await content.mount(
                Static(
                    f"  {icon} {check.name}: {check.message} ({label})",
                    classes="check-item",
                )
            )

            # Show fix hint for failed checks
            if not check.passed and check.fix_hint:
                await content.mount(
                    Static(
                        f"      [dim]Fix: {check.fix_hint}[/dim]",
                        classes="check-item",
                    )
                )

        # Show summary
        if self._env_report.all_passed:
            await content.mount(
                Static(
                    "\n  [green]All critical checks passed.[/green]",
                    classes="check-item",
                )
            )
        else:
            failures = self._env_report.critical_failures
            await content.mount(
                Static(
                    f"\n  [red]{len(failures)} critical check(s) failed."
                    " Fix these before proceeding.[/red]",
                    classes="check-item",
                )
            )

        # Mark step complete and enable next button
        self._step_complete = True
        next_btn = self.query_one("#btn-next", Button)
        next_btn.disabled = False

    @work(exclusive=True)
    async def _show_placeholder(self) -> None:
        """Show placeholder content for unimplemented steps."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()
        await content.mount(Static(self.step_label, classes="section-title"))
        await content.mount(
            Static(
                "[dim]Coming soon[/dim]",
                classes="check-item",
            )
        )
        self._step_complete = True
        next_btn = self.query_one("#btn-next", Button)
        next_btn.disabled = False

    def _go_back(self) -> None:
        """Navigate to the previous step."""
        if self._current_step <= 1:
            return
        self._current_step -= 1
        self._update_step_indicator()
        self._update_nav_buttons()
        self._run_step()

    def action_next_step(self) -> None:
        """Advance to the next step."""
        if not self._step_complete:
            return
        if self._current_step >= self._total_steps:
            return
        self._current_step += 1
        self._update_step_indicator()
        self._update_nav_buttons()
        self._run_step()

    def action_cancel(self) -> None:
        """Cancel the wizard and return to the main menu."""
        self.app.pop_screen()

    def _update_step_indicator(self) -> None:
        """Update the step indicator text."""
        try:
            indicator = self.query_one("#step-indicator", Static)
            indicator.update(
                f"Step {self._current_step} of {self._total_steps} -- {self.step_label}"
            )
        except Exception:
            pass

    def _update_nav_buttons(self) -> None:
        """Update navigation button states."""
        try:
            back_btn = self.query_one("#btn-back", Button)
            back_btn.disabled = self._current_step <= 1
        except Exception:
            pass
