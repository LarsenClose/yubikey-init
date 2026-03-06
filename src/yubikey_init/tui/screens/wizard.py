"""Setup wizard screen for the YubiKey Management TUI.

This screen provides a multi-step wizard that guides users through
the complete YubiKey initialization process. Steps include environment
verification, identity configuration, passphrase setup, and key
configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, RadioButton, RadioSet, Static

from ...environment import EnvironmentReport, verify_environment
from ...prompts import PassphraseStrength, analyze_passphrase
from ...types import KeyType, SecureString

if TYPE_CHECKING:
    from ..controller import TUIController

# Step labels for the wizard
_STEP_LABELS: dict[int, str] = {
    1: "Environment Check",
    2: "Identity Configuration",
    3: "Passphrase Setup",
    4: "Key Configuration",
    5: "Storage Setup",
    6: "Key Generation",
    7: "Backup Creation",
    8: "YubiKey Transfer",
    9: "Verification",
    10: "Summary",
}


@dataclass
class WizardState:
    """Accumulated state from wizard steps."""

    identity: str | None = None
    passphrase: SecureString | None = None
    key_type: KeyType = KeyType.ED25519
    expiry_years: int = 2
    skip_storage: bool = False
    storage_path: str = ""
    admin_pin: str = ""
    user_pin: str = ""


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
        self._state = WizardState()

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
        elif self._current_step == 2:
            self._run_identity_step()
        elif self._current_step == 3:
            self._run_passphrase_step()
        elif self._current_step == 4:
            self._run_key_config_step()
        elif self._current_step == 5:
            self._run_storage_step()
        elif self._current_step == 6:
            self._run_generation_step()
        elif self._current_step == 7:
            self._run_backup_step()
        elif self._current_step == 8:
            self._run_transfer_step()
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
    async def _run_identity_step(self) -> None:
        """Run identity configuration step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Identity Configuration", classes="section-title"))
        await content.mount(
            Static(
                "Enter your name and email for the GPG key identity.",
                classes="check-item",
            )
        )

        # Pre-fill from state if navigating back
        name_val = ""
        email_val = ""
        if self._state.identity:
            # Parse "Name <email>" format
            identity = self._state.identity
            if "<" in identity and identity.endswith(">"):
                name_val = identity[: identity.index("<")].strip()
                email_val = identity[identity.index("<") + 1 : -1].strip()

        await content.mount(
            Static("Full Name:", classes="check-item"),
        )
        await content.mount(Input(value=name_val, placeholder="Your Name", id="input-name"))
        await content.mount(
            Static("Email Address:", classes="check-item"),
        )
        await content.mount(Input(value=email_val, placeholder="you@example.com", id="input-email"))
        await content.mount(Static("", id="identity-preview", classes="check-item"))

        self._update_identity_preview()

    @work(exclusive=True)
    async def _run_passphrase_step(self) -> None:
        """Run passphrase setup step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Master Key Passphrase", classes="section-title"))
        await content.mount(
            Static(
                "Choose a strong passphrase to protect your master GPG key. "
                "This passphrase encrypts the key at rest and is required for "
                "key management operations.",
                classes="check-item",
            )
        )

        await content.mount(Static("Passphrase:", classes="check-item"))
        await content.mount(
            Input(password=True, placeholder="Enter passphrase", id="input-passphrase")
        )
        await content.mount(Static("Confirm Passphrase:", classes="check-item"))
        await content.mount(
            Input(
                password=True,
                placeholder="Confirm passphrase",
                id="input-passphrase-confirm",
            )
        )
        await content.mount(Static("", id="strength-feedback", classes="check-item"))

    @work(exclusive=True)
    async def _run_key_config_step(self) -> None:
        """Run key configuration step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Key Configuration", classes="section-title"))
        await content.mount(
            Static(
                "Select the key algorithm and expiration period.",
                classes="check-item",
            )
        )

        await content.mount(Static("Key Algorithm:", classes="check-item"))
        ed_selected = self._state.key_type == KeyType.ED25519
        await content.mount(
            RadioSet(
                RadioButton("ED25519 (recommended)", value=ed_selected),
                RadioButton("RSA 4096", value=not ed_selected),
                id="key-type-radio",
            )
        )

        await content.mount(Static("Expiry (years):", classes="check-item"))
        await content.mount(
            Input(
                value=str(self._state.expiry_years),
                placeholder="2",
                id="input-expiry",
            )
        )

        # Step 4 is always complete (defaults are valid)
        self._step_complete = True
        next_btn = self.query_one("#btn-next", Button)
        next_btn.disabled = False

    @work(exclusive=True)
    async def _run_storage_step(self) -> None:
        """Run storage setup step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Storage Setup", classes="section-title"))
        await content.mount(
            Static(
                "Configure a backup storage location for your GPG keys. "
                "You can specify a directory path or skip this step to "
                "back up later.",
                classes="check-item",
            )
        )

        await content.mount(
            Static("Skip backup storage:", classes="check-item"),
        )
        skip_checked = self._state.skip_storage
        await content.mount(
            Checkbox(
                "Skip storage setup",
                value=skip_checked,
                id="check-skip-storage",
            )
        )

        await content.mount(Static("Backup directory path:", classes="check-item"))
        await content.mount(
            Input(
                value=self._state.storage_path,
                placeholder="/Volumes/backup-drive",
                id="input-storage-path",
                disabled=skip_checked,
            )
        )
        await content.mount(Static("", id="storage-status", classes="check-item"))

        # If skip is checked, step is immediately complete
        if skip_checked:
            self._step_complete = True
            self.query_one("#btn-next", Button).disabled = False
        else:
            self._update_storage_status()

    @work(exclusive=True)
    async def _run_generation_step(self) -> None:
        """Run key generation step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Key Generation", classes="section-title"))
        await content.mount(
            Static(
                "Review your configuration and generate GPG keys.",
                classes="check-item",
            )
        )

        # Show config summary
        identity = self._state.identity or "Not set"
        key_type = self._state.key_type.value
        expiry = f"{self._state.expiry_years} years"

        await content.mount(Static(f"  Identity: {identity}", classes="check-item"))
        await content.mount(Static(f"  Algorithm: {key_type}", classes="check-item"))
        await content.mount(Static(f"  Expiry: {expiry}", classes="check-item"))
        await content.mount(Static("", classes="check-item"))
        await content.mount(
            Static(
                "[dim]Key generation will be performed when the wizard "
                "execution engine is connected.[/dim]",
                id="generation-status",
                classes="check-item",
            )
        )

        self._step_complete = True
        self.query_one("#btn-next", Button).disabled = False

    @work(exclusive=True)
    async def _run_backup_step(self) -> None:
        """Run backup creation step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("Backup Creation", classes="section-title"))

        if self._state.skip_storage:
            await content.mount(
                Static(
                    "Storage setup was skipped. Backup will use the default GNUPG home directory.",
                    classes="check-item",
                )
            )
        else:
            path = self._state.storage_path or "Not configured"
            await content.mount(Static(f"  Backup path: {path}", classes="check-item"))

        await content.mount(Static("", classes="check-item"))
        await content.mount(
            Static(
                "[dim]Backup creation will be performed when the wizard "
                "execution engine is connected.[/dim]",
                id="backup-status",
                classes="check-item",
            )
        )

        self._step_complete = True
        self.query_one("#btn-next", Button).disabled = False

    @work(exclusive=True)
    async def _run_transfer_step(self) -> None:
        """Run YubiKey transfer step."""
        content = self.query_one("#step-content", Vertical)
        await content.remove_children()

        await content.mount(Static("YubiKey Transfer", classes="section-title"))
        await content.mount(
            Static(
                "Configure PINs for your YubiKey. The user PIN is for daily "
                "operations (signing, encrypting). The admin PIN is for "
                "management operations.",
                classes="check-item",
            )
        )

        await content.mount(Static("Admin PIN (8+ digits):", classes="check-item"))
        await content.mount(
            Input(
                value=self._state.admin_pin,
                password=True,
                placeholder="Admin PIN",
                id="input-admin-pin",
            )
        )
        await content.mount(Static("User PIN (6+ digits):", classes="check-item"))
        await content.mount(
            Input(
                value=self._state.user_pin,
                password=True,
                placeholder="User PIN",
                id="input-user-pin",
            )
        )
        await content.mount(Static("", id="transfer-status", classes="check-item"))

        self._update_transfer_status()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox changes for storage step."""
        if self._current_step == 5 and event.checkbox.id == "check-skip-storage":
            self._state.skip_storage = event.value
            try:
                path_input = self.query_one("#input-storage-path", Input)
                path_input.disabled = event.value
            except Exception:
                pass
            if event.value:
                self._step_complete = True
                self.query_one("#btn-next", Button).disabled = False
            else:
                self._update_storage_status()

    def _update_storage_status(self) -> None:
        """Update storage path status and Next button."""
        try:
            path_val = self.query_one("#input-storage-path", Input).value.strip()
            status = self.query_one("#storage-status", Static)
            if path_val:
                status.update(f"Backup path: {path_val}")
                self._step_complete = True
                self.query_one("#btn-next", Button).disabled = False
            else:
                status.update("[dim]Enter a backup path or skip to continue[/dim]")
                self._step_complete = False
                self.query_one("#btn-next", Button).disabled = True
        except Exception:
            pass

    def _update_transfer_status(self) -> None:
        """Update transfer PIN status and Next button."""
        try:
            admin = self.query_one("#input-admin-pin", Input).value
            user = self.query_one("#input-user-pin", Input).value
            status = self.query_one("#transfer-status", Static)

            errors: list[str] = []
            if admin and len(admin) < 8:
                errors.append("Admin PIN must be 8+ digits")
            if user and len(user) < 6:
                errors.append("User PIN must be 6+ digits")

            if errors:
                status.update("[red]" + "; ".join(errors) + "[/red]")
                self._step_complete = False
                self.query_one("#btn-next", Button).disabled = True
            elif admin and user:
                status.update("[green]PINs configured[/green]")
                self._step_complete = True
                self.query_one("#btn-next", Button).disabled = False
            else:
                status.update("[dim]Enter both PINs to continue[/dim]")
                self._step_complete = False
                self.query_one("#btn-next", Button).disabled = True
        except Exception:
            pass

    def on_input_changed(self, _event: Input.Changed) -> None:
        """Handle input value changes for identity and passphrase steps."""
        if self._current_step == 2:
            self._update_identity_preview()
        elif self._current_step == 3:
            self._update_passphrase_strength()
        elif self._current_step == 5:
            self._update_storage_status()
        elif self._current_step == 8:
            self._update_transfer_status()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle radio set changes for key config step."""
        if self._current_step == 4:
            index = event.radio_set.pressed_index
            self._state.key_type = KeyType.ED25519 if index == 0 else KeyType.RSA4096

    def _update_identity_preview(self) -> None:
        """Update the identity preview and Next button state."""
        try:
            name = self.query_one("#input-name", Input).value.strip()
            email = self.query_one("#input-email", Input).value.strip()
            preview = self.query_one("#identity-preview", Static)

            if name and email:
                preview.update(f"Identity: {name} <{email}>")
                self._step_complete = True
                self.query_one("#btn-next", Button).disabled = False
            else:
                preview.update("[dim]Enter both name and email to continue[/dim]")
                self._step_complete = False
                self.query_one("#btn-next", Button).disabled = True
        except Exception:
            pass

    def _update_passphrase_strength(self) -> None:
        """Update the passphrase strength feedback and Next button state."""
        try:
            passphrase = self.query_one("#input-passphrase", Input).value
            confirm = self.query_one("#input-passphrase-confirm", Input).value
            feedback_widget = self.query_one("#strength-feedback", Static)

            if not passphrase:
                feedback_widget.update("")
                self._step_complete = False
                self.query_one("#btn-next", Button).disabled = True
                return

            analysis = analyze_passphrase(passphrase)

            # Build colored strength label
            strength_labels = {
                PassphraseStrength.WEAK: "[red]Weak[/red]",
                PassphraseStrength.FAIR: "[yellow]Fair[/yellow]",
                PassphraseStrength.GOOD: "[green]Good[/green]",
                PassphraseStrength.STRONG: "[green]Strong[/green]",
                PassphraseStrength.EXCELLENT: "[bold green]Excellent[/bold green]",
            }
            strength_text = strength_labels.get(analysis.strength, "Unknown")

            parts = [f"Strength: {strength_text}"]
            parts.append(f"  Entropy: {analysis.entropy_bits:.1f} bits")

            if analysis.feedback:
                suggestions = ", ".join(analysis.feedback[:3])
                parts.append(f"  Suggestions: {suggestions}")

            # Check match
            matches = passphrase == confirm
            if confirm and not matches:
                parts.append("[red]Passphrases do not match[/red]")

            feedback_widget.update("\n".join(parts))

            # Enable next only when valid
            valid = (
                matches
                and len(passphrase) >= 12
                and analysis.strength
                in (
                    PassphraseStrength.FAIR,
                    PassphraseStrength.GOOD,
                    PassphraseStrength.STRONG,
                    PassphraseStrength.EXCELLENT,
                )
            )
            self._step_complete = valid
            self.query_one("#btn-next", Button).disabled = not valid
        except Exception:
            pass

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
        self._capture_step_state()
        self._current_step += 1
        self._update_step_indicator()
        self._update_nav_buttons()
        self._run_step()

    def _capture_step_state(self) -> None:
        """Capture current step's data into wizard state."""
        try:
            if self._current_step == 2:
                name = self.query_one("#input-name", Input).value.strip()
                email = self.query_one("#input-email", Input).value.strip()
                self._state.identity = f"{name} <{email}>"
            elif self._current_step == 3:
                pw = self.query_one("#input-passphrase", Input).value
                self._state.passphrase = SecureString(pw)
            elif self._current_step == 4:
                expiry_str = self.query_one("#input-expiry", Input).value.strip()
                self._state.expiry_years = int(expiry_str) if expiry_str.isdigit() else 2
            elif self._current_step == 5:
                self._state.storage_path = self.query_one(
                    "#input-storage-path", Input
                ).value.strip()
            elif self._current_step == 8:
                self._state.admin_pin = self.query_one("#input-admin-pin", Input).value
                self._state.user_pin = self.query_one("#input-user-pin", Input).value
        except Exception:
            pass

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
