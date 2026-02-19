from __future__ import annotations

import getpass
import math
import re
import string
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .types import DeviceInfo, KeySlot, SecureString, TouchPolicy, YubiKeyInfo

T = TypeVar("T")


class PassphraseStrength(Enum):
    """Passphrase strength levels."""

    WEAK = "weak"
    FAIR = "fair"
    GOOD = "good"
    STRONG = "strong"
    EXCELLENT = "excellent"


@dataclass
class PassphraseAnalysis:
    """Analysis result for passphrase strength."""

    strength: PassphraseStrength
    score: int  # 0-100
    entropy_bits: float
    feedback: list[str]
    meets_minimum: bool


@dataclass
class PINRequirements:
    """PIN requirements specification."""

    min_length: int = 6
    max_length: int = 127
    require_digits: bool = False
    require_no_sequential: bool = False
    require_no_repeated: bool = False


def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits."""
    if not password:
        return 0.0

    # Determine character set size
    charset_size = 0
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_special = any(c in string.punctuation for c in password)
    has_space = " " in password

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digits:
        charset_size += 10
    if has_special:
        charset_size += 32
    if has_space:
        charset_size += 1

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


def analyze_passphrase(passphrase: str, min_length: int = 12) -> PassphraseAnalysis:
    """Analyze passphrase strength and provide feedback."""
    feedback: list[str] = []
    score = 0

    # Length scoring
    length = len(passphrase)
    if length >= min_length:
        score += 20
    if length >= 16:
        score += 10
    if length >= 24:
        score += 10
    if length >= 32:
        score += 10

    # Character diversity scoring
    has_lower = any(c in string.ascii_lowercase for c in passphrase)
    has_upper = any(c in string.ascii_uppercase for c in passphrase)
    has_digits = any(c in string.digits for c in passphrase)
    has_special = any(c in string.punctuation for c in passphrase)
    has_space = " " in passphrase

    diversity = sum([has_lower, has_upper, has_digits, has_special, has_space])
    score += diversity * 8

    # Entropy scoring
    entropy = calculate_entropy(passphrase)
    if entropy >= 40:
        score += 10
    if entropy >= 60:
        score += 10
    if entropy >= 80:
        score += 10

    # Penalty for common patterns
    common_patterns = [
        r"^[a-z]+$",  # All lowercase
        r"^[A-Z]+$",  # All uppercase
        r"^[0-9]+$",  # All digits
        r"(.)\1{2,}",  # Repeated characters
        r"(012|123|234|345|456|567|678|789|890)",  # Sequential digits
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
    ]
    for pattern in common_patterns:
        if re.search(pattern, passphrase.lower()):
            score -= 15
            break

    # Ensure score is within bounds
    score = max(0, min(100, score))

    # Generate feedback
    if length < min_length:
        feedback.append(f"Use at least {min_length} characters")
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_digits:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters (!@#$%^&*)")
    if length < 16:
        feedback.append("Consider using a longer passphrase")

    # Determine strength level
    if score < 25:
        strength = PassphraseStrength.WEAK
    elif score < 45:
        strength = PassphraseStrength.FAIR
    elif score < 65:
        strength = PassphraseStrength.GOOD
    elif score < 85:
        strength = PassphraseStrength.STRONG
    else:
        strength = PassphraseStrength.EXCELLENT

    return PassphraseAnalysis(
        strength=strength,
        score=score,
        entropy_bits=entropy,
        feedback=feedback,
        meets_minimum=length >= min_length,
    )


class Prompts:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def _show_strength_bar(self, analysis: PassphraseAnalysis) -> None:
        """Display passphrase strength feedback bar."""
        # Color based on strength
        colors = {
            PassphraseStrength.WEAK: "red",
            PassphraseStrength.FAIR: "yellow",
            PassphraseStrength.GOOD: "blue",
            PassphraseStrength.STRONG: "green",
            PassphraseStrength.EXCELLENT: "bright_green",
        }
        color = colors[analysis.strength]

        # Build strength bar
        filled = analysis.score // 10
        bar = "[" + "#" * filled + "-" * (10 - filled) + "]"

        # Display
        self._console.print(
            f"  Strength: [{color}]{bar} {analysis.strength.value.upper()}[/{color}]"
        )
        self._console.print(f"  Entropy: {analysis.entropy_bits:.1f} bits")

        if analysis.feedback:
            self._console.print("  Suggestions:")
            for tip in analysis.feedback[:3]:  # Show top 3 suggestions
                self._console.print(f"    - {tip}")

    def get_passphrase(
        self,
        prompt: str,
        confirm: bool = False,
        min_length: int = 12,
        show_strength: bool = True,
    ) -> SecureString:
        """Get passphrase from user with optional strength feedback.

        Args:
            prompt: The prompt message to display
            confirm: Whether to require confirmation
            min_length: Minimum passphrase length
            show_strength: Whether to show strength feedback

        Returns:
            SecureString containing the passphrase
        """
        while True:
            value = getpass.getpass(f"{prompt}: ")

            # Analyze and show strength
            if show_strength:
                analysis = analyze_passphrase(value, min_length)
                self._show_strength_bar(analysis)

                if not analysis.meets_minimum:
                    self._console.print(
                        f"[red]Passphrase must be at least {min_length} characters[/red]"
                    )
                    continue

                # Warn but allow weak passphrases
                if analysis.strength == PassphraseStrength.WEAK:
                    self._console.print(
                        "[yellow]Warning: This passphrase is weak. Consider using a stronger one.[/yellow]"
                    )
                    if not Confirm.ask("Use this passphrase anyway?", default=False):
                        continue
            else:
                if len(value) < min_length:
                    self._console.print(
                        f"[red]Passphrase must be at least {min_length} characters[/red]"
                    )
                    continue

            if confirm:
                confirm_value = getpass.getpass(f"{prompt} (confirm): ")
                if value != confirm_value:
                    self._console.print("[red]Passphrases do not match[/red]")
                    continue

            return SecureString(value)

    def _show_pin_requirements(self, requirements: PINRequirements) -> None:
        """Display PIN requirements before prompting."""
        self._console.print()
        self._console.print("[cyan]PIN Requirements:[/cyan]")
        self._console.print(
            f"  - Length: {requirements.min_length}-{requirements.max_length} characters"
        )
        if requirements.require_digits:
            self._console.print("  - Must contain only digits")
        if requirements.require_no_sequential:
            self._console.print("  - Must not contain sequential digits (123, 234, etc.)")
        if requirements.require_no_repeated:
            self._console.print("  - Must not contain repeated digits (111, 222, etc.)")
        self._console.print()

    def _validate_pin(self, pin: str, requirements: PINRequirements) -> list[str]:
        """Validate PIN against requirements.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors: list[str] = []

        if len(pin) < requirements.min_length:
            errors.append(f"PIN must be at least {requirements.min_length} characters")
        if len(pin) > requirements.max_length:
            errors.append(f"PIN must be at most {requirements.max_length} characters")

        if requirements.require_digits and not pin.isdigit():
            errors.append("PIN must contain only digits")

        if requirements.require_no_sequential:
            sequential_patterns = ["012", "123", "234", "345", "456", "567", "678", "789", "890"]
            for pattern in sequential_patterns:
                if pattern in pin:
                    errors.append("PIN must not contain sequential digits")
                    break

        if requirements.require_no_repeated:
            repeated_pattern = re.compile(r"(.)\1{2,}")
            if repeated_pattern.search(pin):
                errors.append("PIN must not contain 3+ repeated digits")

        return errors

    def get_pin(
        self,
        prompt: str,
        min_length: int = 6,
        max_length: int = 127,
        show_requirements: bool = True,
        requirements: PINRequirements | None = None,
    ) -> SecureString:
        """Get PIN from user with requirements display.

        Args:
            prompt: The prompt message to display
            min_length: Minimum PIN length (default: 6)
            max_length: Maximum PIN length (default: 127)
            show_requirements: Whether to display requirements
            requirements: Optional detailed requirements specification

        Returns:
            SecureString containing the PIN
        """
        if requirements is None:
            requirements = PINRequirements(
                min_length=min_length,
                max_length=max_length,
            )

        if show_requirements:
            self._show_pin_requirements(requirements)

        while True:
            value = getpass.getpass(f"{prompt}: ")

            errors = self._validate_pin(value, requirements)
            if errors:
                for error in errors:
                    self._console.print(f"[red]{error}[/red]")
                continue

            return SecureString(value)

    def get_identity(self, default: str = "") -> str:
        name = Prompt.ask("Full name", default=default.split("<")[0].strip() if default else "")
        email = Prompt.ask("Email address")
        return f"{name} <{email}>"

    def _get_device_safety_warning(self, device: DeviceInfo) -> str | None:
        """Get safety warning for a device if applicable."""
        warnings = []

        # Check if it's a system drive
        system_paths = ["/dev/sda", "/dev/nvme0n1", "/dev/disk0", "/dev/disk1"]
        if any(str(device.path).startswith(p) for p in system_paths) and not device.removable:
            warnings.append("This appears to be a system drive")

        # Check if mounted
        if device.mounted:
            if device.mount_point:
                warnings.append(f"Currently mounted at {device.mount_point}")
            else:
                warnings.append("Has mounted partitions (will be unmounted)")

        # Check size (large drives are more likely to be important)
        size_gb = device.size_bytes / (1024**3)
        if size_gb > 500:
            warnings.append(f"Large drive ({size_gb:.0f} GB) - verify this is correct")

        return "; ".join(warnings) if warnings else None

    def select_device(
        self,
        devices: list[DeviceInfo],
        prompt: str,
        show_warnings: bool = True,
    ) -> DeviceInfo | None:
        """Select a device with safety warnings.

        Args:
            devices: List of available devices
            prompt: Title prompt for selection
            show_warnings: Whether to show safety warnings

        Returns:
            Selected device or None if no devices available
        """
        if not devices:
            self._console.print("[yellow]No devices found[/yellow]")
            return None

        table = Table(title=prompt)
        table.add_column("#", style="cyan")
        table.add_column("Device")
        table.add_column("Name")
        table.add_column("Size")
        table.add_column("Mounted")
        if show_warnings:
            table.add_column("Warnings", style="yellow")

        for i, dev in enumerate(devices, 1):
            size_gb = dev.size_bytes / (1024**3)
            warning = self._get_device_safety_warning(dev) if show_warnings else None
            row = [
                str(i),
                str(dev.path),
                dev.name,
                f"{size_gb:.1f} GB",
                "Yes" if dev.mounted else "No",
            ]
            if show_warnings:
                row.append(warning or "-")
            table.add_row(*row)

        self._console.print(table)

        while True:
            choice = Prompt.ask("Select device number", default="1")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    selected = devices[idx]
                    warning = self._get_device_safety_warning(selected)
                    if warning and show_warnings:
                        self._console.print(
                            Panel(
                                f"[yellow]Warning: {warning}[/yellow]",
                                title="Device Warning",
                                border_style="yellow",
                            )
                        )
                    return selected
            except ValueError:
                pass
            self._console.print("[red]Invalid selection[/red]")

    def select_yubikey(
        self,
        devices: list[YubiKeyInfo],
        prompt: str,
    ) -> YubiKeyInfo | None:
        if not devices:
            self._console.print("[yellow]No YubiKeys found[/yellow]")
            return None

        table = Table(title=prompt)
        table.add_column("#", style="cyan")
        table.add_column("Serial")
        table.add_column("Version")
        table.add_column("Form Factor")

        for i, dev in enumerate(devices, 1):
            table.add_row(
                str(i),
                dev.serial,
                dev.version,
                dev.form_factor,
            )

        self._console.print(table)

        while True:
            choice = Prompt.ask("Select YubiKey number", default="1")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    return devices[idx]
            except ValueError:
                pass
            self._console.print("[red]Invalid selection[/red]")

    def confirm(
        self,
        message: str,
        default: bool = False,
        dangerous: bool = False,
    ) -> bool:
        if dangerous:
            self._console.print(
                Panel(
                    f"[bold red]WARNING: DANGER[/bold red]\n\n{message}",
                    border_style="red",
                )
            )
            return Confirm.ask("Are you absolutely sure?", default=False)

        return Confirm.ask(message, default=default)

    def confirm_destructive(
        self,
        device: DeviceInfo | str,
        operation: str,
    ) -> bool:
        """Confirm a destructive operation by requiring user to type device name.

        Args:
            device: The device being operated on
            operation: Description of the operation (e.g., "format", "erase")

        Returns:
            True if user confirmed, False otherwise
        """
        device_path = str(device.path if isinstance(device, DeviceInfo) else device)
        device_name = device_path.split("/")[-1]  # Get just the device name

        self._console.print()
        self._console.print(
            Panel(
                f"[bold red]DESTRUCTIVE OPERATION[/bold red]\n\n"
                f"This will {operation} [bold]{device_path}[/bold]\n\n"
                f"[yellow]ALL DATA ON THIS DEVICE WILL BE PERMANENTLY LOST![/yellow]\n\n"
                f"To confirm, type the device name: [bold cyan]{device_name}[/bold cyan]",
                border_style="red",
                title="Confirmation Required",
            )
        )

        user_input = Prompt.ask("Type device name to confirm")

        if user_input == device_name:
            self._console.print("[green]Confirmed.[/green]")
            return True

        self._console.print(
            f"[red]Input '{user_input}' does not match '{device_name}'. Aborting.[/red]"
        )
        return False

    def select_touch_policy(
        self,
        slot: KeySlot,
        default: TouchPolicy = TouchPolicy.ON,
    ) -> TouchPolicy:
        """Select touch policy for a YubiKey slot.

        Args:
            slot: The key slot (signature, encryption, authentication)
            default: Default touch policy

        Returns:
            Selected TouchPolicy
        """
        slot_descriptions = {
            KeySlot.SIGNATURE: "Signing (git commits, documents)",
            KeySlot.ENCRYPTION: "Encryption/Decryption (files, emails)",
            KeySlot.AUTHENTICATION: "Authentication (SSH, login)",
        }

        policy_descriptions = {
            TouchPolicy.OFF: "Never require touch (less secure)",
            TouchPolicy.ON: "Require touch for each operation",
            TouchPolicy.FIXED: "Require touch (cannot be changed later)",
            TouchPolicy.CACHED: "Require touch, cache for 15 seconds",
            TouchPolicy.CACHED_FIXED: "Cached touch (cannot be changed later)",
        }

        self._console.print()
        self._console.print(f"[cyan]Touch Policy for {slot.value.upper()} slot[/cyan]")
        self._console.print(f"  Used for: {slot_descriptions.get(slot, 'Unknown')}")
        self._console.print()

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="cyan")
        table.add_column("Policy")
        table.add_column("Description")
        table.add_column("Recommended", style="green")

        policies = list(TouchPolicy)
        for i, policy in enumerate(policies, 1):
            is_default = policy == default
            is_recommended = policy == TouchPolicy.ON
            table.add_row(
                str(i),
                policy.value,
                policy_descriptions.get(policy, ""),
                "***" if is_default else ("*" if is_recommended else ""),
            )

        self._console.print(table)
        self._console.print("[dim]*** = default, * = recommended[/dim]")

        while True:
            default_idx = policies.index(default) + 1
            choice = Prompt.ask(
                "Select touch policy",
                default=str(default_idx),
            )
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(policies):
                    return policies[idx]
            except ValueError:
                pass
            self._console.print("[red]Invalid selection[/red]")

    def show_progress(
        self,
        _description: str,
        total: int | None = None,
    ) -> Progress:
        if total:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self._console,
            )
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self._console,
        )

    @contextmanager
    def long_operation_progress(
        self,
        description: str,
        total: int | None = None,
        show_time: bool = True,
    ) -> Generator[Progress, None, None]:
        """Context manager for long-running operations with progress display.

        Args:
            description: Description of the operation
            total: Total number of steps (None for indeterminate)
            show_time: Whether to show elapsed/remaining time

        Yields:
            Progress object to update
        """
        columns: list[ProgressColumn] = [SpinnerColumn()]

        if total:
            columns.extend(
                [
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    TaskProgressColumn(),
                ]
            )
            if show_time:
                columns.extend(
                    [
                        TimeElapsedColumn(),
                        TextColumn("/"),
                        TimeRemainingColumn(),
                    ]
                )
        else:
            columns.extend(
                [
                    TextColumn("[progress.description]{task.description}"),
                ]
            )
            if show_time:
                columns.append(TimeElapsedColumn())

        progress = Progress(*columns, console=self._console, transient=False)

        with progress:
            task_id = progress.add_task(description, total=total)
            # Store task_id on progress for external access
            progress._yubikey_init_task_id = task_id  # type: ignore
            yield progress

    def show_operation_phases(
        self,
        phases: list[str],
        current_phase: int,
    ) -> None:
        """Display operation phases with current progress.

        Args:
            phases: List of phase descriptions
            current_phase: Current phase index (0-based)
        """
        self._console.print()
        for i, phase in enumerate(phases):
            if i < current_phase:
                status = "[green]OK[/green]"
                style = "dim"
            elif i == current_phase:
                status = "[yellow]...[/yellow]"
                style = "bold"
            else:
                status = "[dim]-[/dim]"
                style = "dim"

            self._console.print(f"  [{style}]{i + 1}. {phase}[/{style}] {status}")

    def show_step(
        self,
        step_number: int,
        total_steps: int,
        description: str,
        explanation: str | None = None,
    ) -> None:
        self._console.print()
        self._console.print(
            f"[bold cyan][Step {step_number}/{total_steps}][/bold cyan] {description}"
        )

        if explanation:
            self._console.print()
            self._console.print(Panel(explanation, title="ℹ", border_style="blue"))

    def show_success(self, message: str) -> None:
        self._console.print(f"[green]✓[/green] {message}")

    def show_error(
        self,
        error: Exception,
        recovery_hint: str | None = None,
    ) -> None:
        self._console.print()
        self._console.print(f"[bold red]✗[/bold red] {error}")

        if recovery_hint:
            self._console.print()
            self._console.print(Panel(recovery_hint, title="Recovery", border_style="yellow"))

    def show_key_info(
        self,
        key_id: str,
        fingerprint: str,
        identity: str,
        expiry: str | None = None,
    ) -> None:
        table = Table(title="Generated Key")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Key ID", key_id)
        table.add_row("Fingerprint", fingerprint)
        table.add_row("Identity", identity)
        if expiry:
            table.add_row("Expires", expiry)

        self._console.print(table)

    def wait_for_yubikey(self, serial: str | None = None) -> None:
        msg = f"Insert YubiKey {serial}" if serial else "Insert YubiKey"
        self._console.print(f"\n[yellow]Wait: {msg} and press Enter...[/yellow]")
        input()

    def checkpoint_backup_verification(
        self,
        backup_path: str,
        files_found: list[str],
        files_missing: list[str],
    ) -> bool:
        """Checkpoint prompt for backup verification.

        Args:
            backup_path: Path to the backup
            files_found: List of files found in backup
            files_missing: List of expected files not found

        Returns:
            True if user confirms backup is acceptable
        """
        self._console.print()
        self._console.print(
            Panel(
                "[bold cyan]CHECKPOINT: Backup Verification[/bold cyan]",
                border_style="cyan",
            )
        )

        self._console.print(f"\nBackup location: [bold]{backup_path}[/bold]")
        self._console.print(f"\nFiles found: [green]{len(files_found)}[/green]")

        if files_found:
            for f in files_found[:10]:  # Show first 10
                self._console.print(f"  [green]OK[/green] {f}")
            if len(files_found) > 10:
                self._console.print(f"  ... and {len(files_found) - 10} more")

        if files_missing:
            self._console.print(f"\n[red]Files missing: {len(files_missing)}[/red]")
            for f in files_missing:
                self._console.print(f"  [red]MISSING[/red] {f}")
            self._console.print()
            self._console.print(
                "[yellow]Warning: Some expected files are missing from the backup.[/yellow]"
            )
            return Confirm.ask("Continue anyway?", default=False)

        self._console.print()
        self._console.print("[green]All expected files found in backup.[/green]")
        return Confirm.ask("Backup verified. Continue to next step?", default=True)

    def checkpoint_before_destructive(
        self,
        description: str,
        items_affected: list[str],
    ) -> bool:
        """Checkpoint prompt before a destructive operation.

        Args:
            description: Description of what will happen
            items_affected: List of items that will be affected

        Returns:
            True if user confirms
        """
        self._console.print()
        self._console.print(
            Panel(
                f"[bold yellow]CHECKPOINT: {description}[/bold yellow]",
                border_style="yellow",
            )
        )

        if items_affected:
            self._console.print("\nThe following will be affected:")
            for item in items_affected[:20]:  # Show first 20
                self._console.print(f"  - {item}")
            if len(items_affected) > 20:
                self._console.print(f"  ... and {len(items_affected) - 20} more")

        self._console.print()
        return Confirm.ask("Proceed with this operation?", default=False)

    def checkpoint_resume(
        self,
        workflow_state: str,
        completed_steps: list[str],
        next_step: str,
    ) -> bool:
        """Checkpoint prompt when resuming an interrupted workflow.

        Args:
            workflow_state: Current workflow state name
            completed_steps: List of previously completed steps
            next_step: Next step that will be performed

        Returns:
            True if user wants to resume
        """
        self._console.print()
        self._console.print(
            Panel(
                "[bold cyan]CHECKPOINT: Resume Workflow[/bold cyan]\n\n"
                f"Current state: [yellow]{workflow_state}[/yellow]",
                border_style="cyan",
            )
        )

        if completed_steps:
            self._console.print("\nCompleted steps:")
            for step in completed_steps[-5:]:  # Show last 5
                self._console.print(f"  [green]OK[/green] {step}")

        self._console.print(f"\nNext step: [bold]{next_step}[/bold]")
        self._console.print()

        return Confirm.ask("Resume from this point?", default=True)


class MockPrompts(Prompts):
    """Mock prompts for testing - returns pre-configured values."""

    def __init__(
        self,
        passphrase: str = "test-passphrase",
        pin: str = "123456",
        admin_pin: str = "12345678",
        confirmations: bool = True,
    ) -> None:
        super().__init__(Console(quiet=True))
        self._passphrase = passphrase
        self._pin = pin
        self._admin_pin = admin_pin
        self._confirmations = confirmations

    def get_passphrase(
        self,
        prompt: str,
        confirm: bool = False,
        min_length: int = 12,
        show_strength: bool = True,
    ) -> SecureString:
        return SecureString(self._passphrase)

    def get_pin(
        self,
        prompt: str,
        min_length: int = 6,
        max_length: int = 127,
        show_requirements: bool = True,
        requirements: PINRequirements | None = None,
    ) -> SecureString:
        if "admin" in prompt.lower():
            return SecureString(self._admin_pin)
        return SecureString(self._pin)

    def confirm(
        self,
        message: str,
        default: bool = False,
        dangerous: bool = False,
    ) -> bool:
        return self._confirmations

    def confirm_destructive(
        self,
        device: DeviceInfo | str,
        operation: str,
    ) -> bool:
        return self._confirmations

    def select_device(
        self,
        devices: list[DeviceInfo],
        prompt: str,
        show_warnings: bool = True,
    ) -> DeviceInfo | None:
        return devices[0] if devices else None

    def select_yubikey(
        self,
        devices: list[YubiKeyInfo],
        prompt: str,
    ) -> YubiKeyInfo | None:
        return devices[0] if devices else None

    def select_touch_policy(
        self,
        slot: KeySlot,
        default: TouchPolicy = TouchPolicy.ON,
    ) -> TouchPolicy:
        return default

    def wait_for_yubikey(self, serial: str | None = None) -> None:
        pass

    def checkpoint_backup_verification(
        self,
        backup_path: str,
        files_found: list[str],
        files_missing: list[str],
    ) -> bool:
        return self._confirmations and not files_missing

    def checkpoint_before_destructive(
        self,
        description: str,
        items_affected: list[str],
    ) -> bool:
        return self._confirmations

    def checkpoint_resume(
        self,
        workflow_state: str,
        completed_steps: list[str],
        next_step: str,
    ) -> bool:
        return self._confirmations
