"""Safety checks and guards for YubiKey operations.

Provides safety mechanisms to prevent accidental destructive operations:
- Protected device checks
- Multi-card warnings
- Pre-operation verification
- Single-card mode enforcement for sensitive operations
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .inventory import DeviceEntry, Inventory, OpenPGPState, parse_openpgp_info
from .types import Result, YubiKeyInfo

if TYPE_CHECKING:
    from .yubikey_ops import YubiKeyOperations


class SafetyLevel(Enum):
    """Safety level for operations."""

    READ_ONLY = "read_only"  # Safe: listing, info queries
    MODERATE = "moderate"  # PIN changes, touch policy changes
    DESTRUCTIVE = "destructive"  # Reset, key transfer, provision


class SafetyError(Exception):
    """Safety check failure."""

    pass


class ProtectedDeviceError(SafetyError):
    """Attempt to operate on a protected device."""

    pass


class MultiCardWarningError(SafetyError):
    """Multiple cards connected during sensitive operation."""

    pass


class DeviceVerificationError(SafetyError):
    """Could not verify the target device."""

    pass


@dataclass
class SafetyCheckResult:
    """Result of a safety check."""

    passed: bool
    warnings: list[str]
    errors: list[str]
    device_entry: DeviceEntry | None = None
    openpgp_state: OpenPGPState | None = None

    @property
    def can_proceed(self) -> bool:
        """Check if operation can proceed (no errors)."""
        return len(self.errors) == 0


class SafetyGuard:
    """Safety guard for YubiKey operations."""

    def __init__(
        self,
        inventory: Inventory,
        yubikey_ops: YubiKeyOperations,
        console: Console | None = None,
    ) -> None:
        self._inventory = inventory
        self._yubikey_ops = yubikey_ops
        self._console = console or Console()
        self._single_card_mode = False

    def enable_single_card_mode(self) -> None:
        """Enable single-card mode for sensitive operations."""
        self._single_card_mode = True

    def disable_single_card_mode(self) -> None:
        """Disable single-card mode."""
        self._single_card_mode = False

    def check_device(
        self,
        serial: str,
        safety_level: SafetyLevel,
        _operation_name: str,
    ) -> SafetyCheckResult:
        """Run safety checks for a device before an operation.

        Args:
            serial: Target device serial number
            safety_level: The safety level of the intended operation
            _operation_name: Human-readable name of the operation

        Returns:
            SafetyCheckResult with pass/fail status and details
        """
        warnings: list[str] = []
        errors: list[str] = []

        # Get inventory entry
        entry = self._inventory.get(serial)

        # Get current OpenPGP state
        openpgp_state: OpenPGPState | None = None
        try:
            result = self._yubikey_ops._run_ykman(["--device", serial, "openpgp", "info"])
            if result.returncode == 0:
                openpgp_state = parse_openpgp_info(result.stdout)
        except Exception:
            warnings.append("Could not query OpenPGP state")

        # Check 1: Protected device
        if (
            entry
            and entry.protected
            and safety_level in (SafetyLevel.MODERATE, SafetyLevel.DESTRUCTIVE)
        ):
            errors.append(
                f"Device '{entry.display_name()}' is marked as PROTECTED. "
                "Remove protection first with: yubikey-init inventory unprotect <serial>"
            )

        # Check 2: Multi-card check for destructive operations
        if safety_level == SafetyLevel.DESTRUCTIVE:
            connected = self._yubikey_ops.list_devices()
            if len(connected) > 1:
                other_serials = [d.serial for d in connected if d.serial != serial]
                if self._single_card_mode:
                    errors.append(
                        f"Single-card mode is enabled but {len(connected)} YubiKeys are connected. "
                        f"Please disconnect: {', '.join(other_serials)}"
                    )
                else:
                    warnings.append(
                        f"WARNING: {len(connected)} YubiKeys connected. "
                        f"Ensure you're targeting the correct device ({serial}). "
                        f"Other devices: {', '.join(other_serials)}"
                    )

        # Check 3: Device has existing keys (for destructive operations)
        if safety_level == SafetyLevel.DESTRUCTIVE and openpgp_state and openpgp_state.has_keys():
            fingerprints = []
            if openpgp_state.signature_key.fingerprint:
                fingerprints.append(f"SIG: {openpgp_state.signature_key.fingerprint[-16:]}")
            if openpgp_state.encryption_key.fingerprint:
                fingerprints.append(f"ENC: {openpgp_state.encryption_key.fingerprint[-16:]}")
            if openpgp_state.authentication_key.fingerprint:
                fingerprints.append(f"AUT: {openpgp_state.authentication_key.fingerprint[-16:]}")

            warnings.append(
                "Device has existing keys that will be DESTROYED:\n  " + "\n  ".join(fingerprints)
            )

        # Check 4: PIN state warnings
        if openpgp_state:
            if openpgp_state.is_pin_blocked():
                warnings.append(
                    "User PIN is BLOCKED (0 tries remaining). "
                    "You'll need the admin PIN to reset or unblock."
                )
            elif openpgp_state.pin_tries_remaining <= 1:
                warnings.append(
                    f"User PIN has only {openpgp_state.pin_tries_remaining} try remaining!"
                )

            if openpgp_state.admin_pin_tries_remaining <= 1:
                warnings.append(
                    f"Admin PIN has only {openpgp_state.admin_pin_tries_remaining} try remaining! "
                    "If exhausted, the OpenPGP application must be reset."
                )

        return SafetyCheckResult(
            passed=len(errors) == 0,
            warnings=warnings,
            errors=errors,
            device_entry=entry,
            openpgp_state=openpgp_state,
        )

    def display_check_result(
        self,
        result: SafetyCheckResult,
        serial: str,
        _operation_name: str,
    ) -> None:
        """Display safety check results to the console."""
        # Get display name
        if result.device_entry:
            display_name = result.device_entry.display_name()
        else:
            display_name = f"YubiKey {serial}"

        self._console.print()

        # Show device info
        if result.device_entry or result.openpgp_state:
            table = Table(title=f"Target Device: {display_name}")
            table.add_column("Property", style="cyan")
            table.add_column("Value")

            table.add_row("Serial", serial)

            if result.device_entry:
                if result.device_entry.device_type:
                    table.add_row("Type", result.device_entry.device_type)
                if result.device_entry.label:
                    table.add_row("Label", result.device_entry.label)
                if result.device_entry.protected:
                    table.add_row("Protected", "[red]YES[/red]")
                if result.device_entry.provisioned_identity:
                    table.add_row("Identity", result.device_entry.provisioned_identity)

            if result.openpgp_state:
                has_keys = "Yes" if result.openpgp_state.has_keys() else "No"
                table.add_row("Has Keys", has_keys)
                table.add_row(
                    "PIN State",
                    "[red]BLOCKED[/red]"
                    if result.openpgp_state.is_pin_blocked()
                    else f"{result.openpgp_state.pin_tries_remaining} tries left",
                )

            self._console.print(table)

        # Show warnings
        if result.warnings:
            self._console.print()
            for warning in result.warnings:
                self._console.print(
                    Panel(
                        f"[yellow]{warning}[/yellow]",
                        title="[yellow]Warning[/yellow]",
                        border_style="yellow",
                    )
                )

        # Show errors
        if result.errors:
            self._console.print()
            for error in result.errors:
                self._console.print(
                    Panel(
                        f"[red]{error}[/red]",
                        title="[red]Error - Cannot Proceed[/red]",
                        border_style="red",
                    )
                )

    def require_confirmation(
        self,
        serial: str,
        operation_name: str,
        safety_level: SafetyLevel,
        extra_message: str | None = None,
    ) -> Result[bool]:
        """Require user confirmation before proceeding with an operation.

        Returns Result[True] if confirmed, Result[False] if declined,
        or Result.err if safety checks failed.
        """
        # Run safety checks
        check_result = self.check_device(serial, safety_level, operation_name)

        # Display results
        self.display_check_result(check_result, serial, operation_name)

        # If errors, cannot proceed
        if not check_result.can_proceed:
            return Result.err(
                SafetyError(f"Safety checks failed: {'; '.join(check_result.errors)}")
            )

        # Build confirmation message
        if check_result.device_entry:
            device_name = check_result.device_entry.display_name()
        else:
            device_name = f"YubiKey {serial}"

        if safety_level == SafetyLevel.DESTRUCTIVE:
            self._console.print()
            self._console.print(
                Panel(
                    f"[bold red]DESTRUCTIVE OPERATION[/bold red]\n\n"
                    f"Operation: {operation_name}\n"
                    f"Target: {device_name}\n"
                    f"Serial: {serial}\n" + (f"\n{extra_message}" if extra_message else ""),
                    title="[bold red]Confirm Destructive Action[/bold red]",
                    border_style="red",
                )
            )

            # Require typing the serial to confirm
            self._console.print()
            self._console.print(
                f"[bold]To confirm, type the last 4 digits of the serial ({serial[-4:]}): [/bold]",
                end="",
            )

            try:
                user_input = input().strip()
                if user_input != serial[-4:]:
                    self._console.print(
                        "[yellow]Confirmation failed. Operation cancelled.[/yellow]"
                    )
                    return Result.ok(False)
            except (EOFError, KeyboardInterrupt):
                self._console.print("\n[yellow]Operation cancelled.[/yellow]")
                return Result.ok(False)

        else:
            # Moderate safety level - simple yes/no
            from rich.prompt import Confirm

            self._console.print()
            if not Confirm.ask(
                f"Proceed with {operation_name} on {device_name}?",
                default=False,
            ):
                return Result.ok(False)

        return Result.ok(True)


def list_connected_devices_safely(
    yubikey_ops: YubiKeyOperations,
    inventory: Inventory,
    console: Console | None = None,
) -> list[tuple[YubiKeyInfo, DeviceEntry | None, OpenPGPState | None]]:
    """List connected devices with inventory and state information.

    Returns a list of tuples: (YubiKeyInfo, DeviceEntry or None, OpenPGPState or None)
    """
    console = console or Console()
    devices = yubikey_ops.list_devices()
    results: list[tuple[YubiKeyInfo, DeviceEntry | None, OpenPGPState | None]] = []

    for device in devices:
        # Get or create inventory entry
        entry = inventory.get_or_create(device.serial, device)

        # Get OpenPGP state
        openpgp_state: OpenPGPState | None = None
        try:
            result = yubikey_ops._run_ykman(["--device", device.serial, "openpgp", "info"])
            if result.returncode == 0:
                openpgp_state = parse_openpgp_info(result.stdout)
                entry.openpgp_state = openpgp_state
        except Exception:
            pass

        results.append((device, entry, openpgp_state))

    # Save updated inventory
    inventory.save()

    return results


def display_device_table(
    devices: list[tuple[YubiKeyInfo, DeviceEntry | None, OpenPGPState | None]],
    console: Console | None = None,
    show_fingerprints: bool = False,
) -> None:
    """Display a table of connected devices."""
    console = console or Console()

    table = Table(title="Connected YubiKeys")
    table.add_column("#", style="cyan", width=3)
    table.add_column("Serial", style="green")
    table.add_column("Label")
    table.add_column("Type")
    table.add_column("Keys")
    table.add_column("PIN")
    table.add_column("Protected")

    for i, (info, entry, state) in enumerate(devices, 1):
        label = entry.label if entry and entry.label else "-"
        device_type = info.form_factor
        protected = "[red]YES[/red]" if entry and entry.protected else "-"

        # Key status
        if state and state.has_keys():
            keys = "[green]Yes[/green]"
        elif state:
            keys = "Empty"
        else:
            keys = "?"

        # PIN status
        if state:
            if state.is_pin_blocked():
                pin = "[red]BLOCKED[/red]"
            elif state.pin_tries_remaining <= 1:
                pin = f"[yellow]{state.pin_tries_remaining}[/yellow]"
            else:
                pin = f"{state.pin_tries_remaining}"
        else:
            pin = "?"

        table.add_row(str(i), info.serial, label, device_type, keys, pin, protected)

    console.print(table)

    # Show fingerprints if requested
    if show_fingerprints:
        console.print()
        for info, _entry, state in devices:
            if state and state.has_keys():
                console.print(f"[cyan]{info.serial}[/cyan] Key Fingerprints:")
                if state.signature_key.fingerprint:
                    console.print(f"  SIG: {state.signature_key.fingerprint}")
                if state.encryption_key.fingerprint:
                    console.print(f"  ENC: {state.encryption_key.fingerprint}")
                if state.authentication_key.fingerprint:
                    console.print(f"  AUT: {state.authentication_key.fingerprint}")
