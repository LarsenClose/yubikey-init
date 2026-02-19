"""Diagnostics screen for the YubiKey Management TUI.

This screen displays system health checks including GnuPG version,
ykman version, smartcard daemon status, and device health for each
connected YubiKey.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Rule, Static

if TYPE_CHECKING:
    from ..controller import TUIController


class DiagnosticsScreen(Screen[None]):
    """Screen displaying system diagnostics and device health.

    Shows results of system checks (GnuPG, ykman, scdaemon)
    and health status for each connected YubiKey.

    Keyboard shortcuts:
    - R: Refresh diagnostics
    - Escape: Go back
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True, priority=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    DEFAULT_CSS = """
    DiagnosticsScreen {
        layout: vertical;
    }

    DiagnosticsScreen .screen-title {
        dock: top;
        width: 100%;
        height: 3;
        content-align: center middle;
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 1;
    }

    DiagnosticsScreen .content-container {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }

    DiagnosticsScreen .section-title {
        text-style: bold;
        color: $text;
        padding-bottom: 1;
        border-bottom: solid $primary-darken-3;
        margin-bottom: 1;
    }

    DiagnosticsScreen .section-content {
        padding: 0 0 1 0;
    }

    DiagnosticsScreen .check-item {
        height: 1;
        padding: 0 0 0 2;
    }

    DiagnosticsScreen .section-divider {
        margin: 1 0;
    }

    DiagnosticsScreen .status-ok {
        color: $success;
    }

    DiagnosticsScreen .status-warning {
        color: $warning;
    }

    DiagnosticsScreen .status-error {
        color: $error;
    }

    DiagnosticsScreen #loading-message {
        text-align: center;
        color: $text-muted;
        padding: 2;
    }

    DiagnosticsScreen .action-hint {
        color: $text-muted;
        padding-top: 1;
        text-align: center;
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
        """Initialize the diagnostics screen.

        Args:
            controller: The TUI controller for data access.
            name: Screen name.
            id: Screen ID.
            classes: Additional CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._controller = controller
        self._diagnostics: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Static("Diagnostics", classes="screen-title")

        with VerticalScroll(classes="content-container"):
            # System Checks Section
            with Vertical(id="system-checks-section"):
                yield Static("System Checks", classes="section-title")
                yield Vertical(id="checks-container", classes="section-content")

            yield Rule(classes="section-divider")

            # Device Health Section
            with Vertical(id="device-health-section"):
                yield Static("Device Health", classes="section-title")
                yield Vertical(id="devices-container", classes="section-content")

            yield Rule(classes="section-divider")

            # Actions hint
            yield Static("[R] Refresh   [Esc] Back", classes="action-hint")

        yield Footer()

    def on_mount(self) -> None:
        """Run diagnostics when the screen is mounted."""
        self._refresh_diagnostics()

    @work(exclusive=True)
    async def _refresh_diagnostics(self) -> None:
        """Run diagnostics and update the display."""
        checks_container = self.query_one("#checks-container", Vertical)
        devices_container = self.query_one("#devices-container", Vertical)

        # Clear existing content
        await checks_container.remove_children()
        await devices_container.remove_children()

        # Show loading message
        await checks_container.mount(
            Static("[dim]Running diagnostics...[/dim]", id="loading-message")
        )

        if self._controller is None:
            await checks_container.remove_children()
            await checks_container.mount(Static("[red]No controller available[/red]"))
            return

        try:
            # Get diagnostic info from controller
            self._diagnostics = self._controller.run_diagnostics()

            # Update system checks
            await self._update_system_checks(checks_container)

            # Update device health
            await self._update_device_health(devices_container)

        except Exception as e:
            await checks_container.remove_children()
            await checks_container.mount(Static(f"[red]Diagnostics failed: {e}[/red]"))

    async def _update_system_checks(self, container: Vertical) -> None:
        """Update the system checks section.

        Args:
            container: The container to populate with check results.
        """
        await container.remove_children()

        if self._diagnostics is None:
            return

        gpg_info = self._diagnostics.get("gpg_info", {})
        yubikey_info = self._diagnostics.get("yubikey_info", {})
        agent_info = self._diagnostics.get("agent_info", {})

        # GnuPG check
        if gpg_info.get("installed"):
            version = gpg_info.get("version", "unknown")
            await container.mount(
                Static(f"  [green]OK[/green] GnuPG {version} installed", classes="check-item")
            )
        else:
            await container.mount(
                Static("  [red]X[/red]  GnuPG not installed", classes="check-item")
            )

        # ykman check
        if yubikey_info.get("ykman_installed"):
            version = yubikey_info.get("ykman_version", "unknown")
            await container.mount(
                Static(
                    f"  [green]OK[/green] YubiKey Manager {version} installed", classes="check-item"
                )
            )
        else:
            await container.mount(
                Static(
                    "  [red]X[/red]  YubiKey Manager (ykman) not installed", classes="check-item"
                )
            )

        # Smartcard daemon check
        scdaemon_status = agent_info.get("scdaemon_status", "unknown")
        if scdaemon_status == "responding":
            scdaemon_version = agent_info.get("scdaemon_version", "")
            version_str = f" ({scdaemon_version})" if scdaemon_version else ""
            await container.mount(
                Static(
                    f"  [green]OK[/green] Smartcard daemon running{version_str}",
                    classes="check-item",
                )
            )
        elif scdaemon_status == "timed out":
            await container.mount(
                Static("  [red]X[/red]  Smartcard daemon timed out", classes="check-item")
            )
        else:
            await container.mount(
                Static(
                    f"  [yellow]!![/yellow] Smartcard daemon: {scdaemon_status}",
                    classes="check-item",
                )
            )

        # GPG agent check
        if agent_info.get("running"):
            await container.mount(
                Static("  [green]OK[/green] GPG agent running", classes="check-item")
            )
        else:
            await container.mount(
                Static("  [yellow]!![/yellow] GPG agent not running", classes="check-item")
            )

        # Device count
        devices = yubikey_info.get("devices", [])
        device_count = len(devices)
        if device_count > 0:
            await container.mount(
                Static(
                    f"  [green]OK[/green] {device_count} YubiKey(s) detected", classes="check-item"
                )
            )
        else:
            await container.mount(
                Static("  [yellow]!![/yellow] No YubiKeys detected", classes="check-item")
            )

        # Network warning (informational)
        await container.mount(
            Static(
                "  [yellow]!![/yellow] Network active (consider disabling for key generation)",
                classes="check-item",
            )
        )

    async def _update_device_health(self, container: Vertical) -> None:
        """Update the device health section.

        Args:
            container: The container to populate with device health.
        """
        await container.remove_children()

        if self._controller is None:
            return

        try:
            devices = self._controller.get_devices()

            if not devices:
                await container.mount(
                    Static("  [dim]No devices connected[/dim]", classes="check-item")
                )
                return

            for device in devices:
                serial = device.serial
                label = device.label

                # Determine health status
                status = "ok"
                message = "Healthy"

                if device.openpgp_state:
                    if device.openpgp_state.is_pin_blocked():
                        status = "warning"
                        message = "PIN blocked"
                    elif device.openpgp_state.pin_tries_remaining < 3:
                        status = "warning"
                        message = f"PIN retries: {device.openpgp_state.pin_tries_remaining}"
                    elif device.openpgp_state.admin_pin_tries_remaining < 3:
                        status = "warning"
                        message = (
                            f"Admin PIN retries: {device.openpgp_state.admin_pin_tries_remaining}"
                        )

                # Format device name
                device_name = label or f"YubiKey {serial[-4:]}"

                # Create status line
                icon = {
                    "ok": "[green]OK[/green]",
                    "warning": "[yellow]!![/yellow]",
                    "error": "[red]X[/red]",
                }.get(status, "[dim]?[/dim]")

                await container.mount(
                    Static(
                        f"  {icon} {serial}: {device_name} - {message}",
                        classes="check-item",
                    )
                )

        except Exception as e:
            await container.mount(
                Static(f"  [red]Error loading device health: {e}[/red]", classes="check-item")
            )

    def action_go_back(self) -> None:
        """Go back to the main menu."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Refresh the diagnostics."""
        self._refresh_diagnostics()
        self.notify("Diagnostics refreshed", timeout=2)
