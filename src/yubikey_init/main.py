from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from .backup import copy_public_files_to_partition, create_full_backup, verify_backup_complete
from .config import generate_ssh_agent_setup_script, restart_gpg_agent, setup_all_configs
from .diagnostics import format_diagnostic_report, run_diagnostics
from .environment import EnvironmentReport, verify_environment
from .gpg_ops import GPGOperations
from .inventory import DeviceEntry, Inventory, parse_openpgp_info
from .prompts import Prompts
from .safety import SafetyGuard, SafetyLevel, display_device_table, list_connected_devices_safely
from .state_machine import StateMachine, WorkflowConfig
from .storage_ops import StorageOperations
from .types import KeySlot, KeyType, SecureString, TouchPolicy, WorkflowState
from .yubikey_ops import YubiKeyOperations

DEFAULT_STATE_PATH = Path.home() / ".config" / "yubikey-init" / "state.json"
console = Console()


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yubikey-init",
        description="Automated YubiKey GPG initialization and management",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=DEFAULT_STATE_PATH,
        help="Path to state file (default: ~/.config/yubikey-init/state.json)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/educational output",
    )
    parser.add_argument(
        "--gnupghome",
        type=Path,
        default=None,
        help="Custom GnuPG home directory",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ========== PRIMARY COMMANDS ==========

    # new command (formerly 'init')
    new_parser = subparsers.add_parser("new", help="Start a new YubiKey initialization workflow")
    new_parser.add_argument(
        "--key-type",
        choices=["ed25519", "rsa4096"],
        default="ed25519",
        help="Key algorithm (default: ed25519)",
    )
    new_parser.add_argument(
        "--expiry-years", type=int, default=2, help="Subkey expiration in years (default: 2)"
    )
    new_parser.add_argument(
        "--skip-storage",
        action="store_true",
        help="Skip encrypted storage setup (use existing backup location)",
    )
    new_parser.add_argument("--backup-path", type=Path, help="Path for backup storage")

    # continue command (formerly 'resume')
    subparsers.add_parser("continue", help="Resume an interrupted workflow")

    # status command
    subparsers.add_parser("status", help="Show current workflow status")

    # reset command (workflow reset, not device reset)
    subparsers.add_parser("reset", help="Reset workflow state (does not affect keys)")

    # doctor command (formerly 'diagnose')
    subparsers.add_parser("doctor", help="Run diagnostics and troubleshooting")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify system environment")
    verify_parser.add_argument(
        "--full", action="store_true", help="Run all checks including optional ones"
    )

    # setup-config command
    config_parser = subparsers.add_parser("setup-config", help="Set up hardened GPG configuration")
    config_parser.add_argument(
        "--no-ssh", action="store_true", help="Disable SSH support in gpg-agent"
    )

    # provision command (provision additional YubiKey)
    provision_parser = subparsers.add_parser(
        "provision", help="Provision a YubiKey with existing keys"
    )
    provision_parser.add_argument("--key-id", required=True, help="Key ID to provision")
    provision_parser.add_argument(
        "--backup-path", type=Path, required=True, help="Path to backup containing keys"
    )

    # ========== DEVICES COMMAND GROUP (formerly 'inventory') ==========
    devices_parser = subparsers.add_parser("devices", help="Manage YubiKey devices")
    devices_subparsers = devices_parser.add_subparsers(
        dest="devices_command", help="Device commands"
    )

    # devices list (default when no subcommand)
    devices_list = devices_subparsers.add_parser(
        "list", help="List all devices (connected and registered)"
    )
    devices_list.add_argument(
        "--all",
        "-a",
        action="store_true",
        dest="show_all",
        help="Show all registered devices, not just connected",
    )
    devices_list.add_argument(
        "--fingerprints", "-f", action="store_true", help="Show key fingerprints"
    )

    # devices scan
    devices_subparsers.add_parser("scan", help="Scan connected devices and add to inventory")

    # devices show
    devices_show = devices_subparsers.add_parser("show", help="Show detailed info for a device")
    devices_show.add_argument("serial", help="Device serial number or label")

    # devices label
    devices_label = devices_subparsers.add_parser("label", help="Set a label/nickname for a device")
    devices_label.add_argument("serial", help="Device serial number")
    devices_label.add_argument("label", help="Label to set (use '' to clear)")

    # devices protect
    devices_protect = devices_subparsers.add_parser("protect", help="Mark a device as protected")
    devices_protect.add_argument("serial", help="Device serial number or label")

    # devices unprotect
    devices_unprotect = devices_subparsers.add_parser(
        "unprotect", help="Remove protection from a device"
    )
    devices_unprotect.add_argument("serial", help="Device serial number or label")

    # devices notes
    devices_notes = devices_subparsers.add_parser("notes", help="Set notes for a device")
    devices_notes.add_argument("serial", help="Device serial number or label")
    devices_notes.add_argument(
        "notes", nargs="?", default=None, help="Notes to set (omit to clear)"
    )

    # devices remove
    devices_remove = devices_subparsers.add_parser("remove", help="Remove a device from inventory")
    devices_remove.add_argument("serial", help="Device serial number or label")

    # devices reset (formerly 'reset-yubikey')
    devices_reset = devices_subparsers.add_parser(
        "reset", help="Reset a YubiKey OpenPGP application (DESTRUCTIVE - erases all keys)"
    )
    devices_reset.add_argument(
        "serial",
        nargs="?",
        help="Device serial number or label (required if multiple devices connected)",
    )
    devices_reset.add_argument(
        "--force", action="store_true", help="Skip confirmation prompt (use with extreme caution)"
    )
    devices_reset.add_argument(
        "--set-pins", action="store_true", help="Also set new PINs after reset"
    )

    # ========== KEYS COMMAND GROUP ==========
    keys_parser = subparsers.add_parser("keys", help="Manage GPG keys")
    keys_subparsers = keys_parser.add_subparsers(dest="keys_command", help="Key commands")

    # keys list (default when no subcommand)
    keys_subparsers.add_parser("list", help="List keys in keyring")

    # keys renew
    keys_renew = keys_subparsers.add_parser("renew", help="Renew expiring subkeys")
    keys_renew.add_argument("key_id", help="Key ID to renew")
    keys_renew.add_argument(
        "--expiry-years", type=int, default=2, help="New expiration in years (default: 2)"
    )

    # keys export-ssh
    keys_export_ssh = keys_subparsers.add_parser("export-ssh", help="Export SSH public key")
    keys_export_ssh.add_argument("key_id", nargs="?", help="Key ID to export SSH key from")

    # ========== BACKUP COMMAND GROUP ==========
    backup_parser = subparsers.add_parser("backup", help="Backup operations")
    backup_subparsers = backup_parser.add_subparsers(dest="backup_command", help="Backup commands")

    # backup verify
    backup_verify = backup_subparsers.add_parser("verify", help="Verify backup integrity")
    backup_verify.add_argument("path", type=Path, help="Path to backup directory")

    # backup restore
    backup_restore = backup_subparsers.add_parser("restore", help="Restore from backup")
    backup_restore.add_argument("path", type=Path, help="Path to backup directory")
    backup_restore.add_argument(
        "--subkeys-only", action="store_true", help="Only restore subkeys (not master key)"
    )

    # ========== MANAGEMENT TUI ==========
    subparsers.add_parser("manage", help="Interactive device and key management (TUI)")

    # ========== DEPRECATED COMMANDS (show migration hints) ==========
    # These are hidden but still parse, allowing helpful error messages
    subparsers.add_parser("init", help=argparse.SUPPRESS)
    subparsers.add_parser("resume", help=argparse.SUPPRESS)
    subparsers.add_parser("diagnose", help=argparse.SUPPRESS)
    subparsers.add_parser("inventory", help=argparse.SUPPRESS)
    reset_yk_parser = subparsers.add_parser("reset-yubikey", help=argparse.SUPPRESS)
    reset_yk_parser.add_argument("serial", nargs="?")
    reset_yk_parser.add_argument("--force", action="store_true")
    reset_yk_parser.add_argument("--set-pins", action="store_true")
    renew_parser = subparsers.add_parser("renew", help=argparse.SUPPRESS)
    renew_parser.add_argument("--key-id", required=False)
    renew_parser.add_argument("--expiry-years", type=int, default=2)
    ssh_parser = subparsers.add_parser("export-ssh", help=argparse.SUPPRESS)
    ssh_parser.add_argument("--key-id", required=False)

    return parser


# ========== DEPRECATED COMMAND HANDLERS ==========

DEPRECATED_COMMANDS = {
    "init": ("new", "yubikey-init new"),
    "resume": ("continue", "yubikey-init continue"),
    "diagnose": ("doctor", "yubikey-init doctor"),
    "inventory": ("devices", "yubikey-init devices"),
    "reset-yubikey": ("devices reset", "yubikey-init devices reset <serial>"),
    "renew": ("keys renew", "yubikey-init keys renew <key_id>"),
    "export-ssh": ("keys export-ssh", "yubikey-init keys export-ssh [key_id]"),
}


def handle_deprecated_command(command: str) -> int:
    """Show helpful error message for deprecated commands."""
    if command in DEPRECATED_COMMANDS:
        new_cmd, example = DEPRECATED_COMMANDS[command]
        console.print(f"[yellow]Command '{command}' has been renamed to '{new_cmd}'.[/yellow]")
        console.print(f"\nPlease use: [bold]{example}[/bold]")
        return 1
    return 1


def show_environment_report(report: EnvironmentReport) -> None:
    """Display environment verification report."""
    console.print("\n[bold]Environment Verification Report[/bold]")
    console.print(f"System: {report.system}\n")

    for check in report.checks:
        status = "[green]PASS[/green]" if check.passed else "[red]FAIL[/red]"
        if not check.critical and not check.passed:
            status = "[yellow]WARN[/yellow]"
        console.print(f"  {status} {check.name}: {check.message}")
        if check.fix_hint and not check.passed:
            console.print(f"       Fix: {check.fix_hint}")

    if report.all_passed:
        console.print("\n[green]All critical checks passed.[/green]")
    else:
        console.print("\n[red]Some critical checks failed. Please fix before proceeding.[/red]")


def cmd_new(sm: StateMachine, args: argparse.Namespace, prompts: Prompts) -> int:
    """Start a new YubiKey initialization workflow."""
    load_result = sm.load()
    if load_result.is_err():
        console.print(f"[red]Error loading state: {load_result.unwrap_err()}[/red]")
        return 1

    if sm.current_state != WorkflowState.UNINITIALIZED:
        console.print(
            f"[yellow]Workflow already in progress (state: {sm.current_state.value})[/yellow]"
        )
        console.print("Use 'yubikey-init continue' to resume or 'yubikey-init reset' to start over")
        return 1

    # Verify environment
    console.print("\n[bold]Step 1: Verifying Environment[/bold]")
    env_report = verify_environment(include_optional=True)
    show_environment_report(env_report)

    if not env_report.all_passed and not prompts.confirm(
        "Continue despite failed checks?", dangerous=True
    ):
        return 1

    # Get identity
    console.print("\n[bold]Step 2: Configure Identity[/bold]")
    identity = prompts.get_identity()

    # Get key type
    key_type = KeyType.ED25519 if args.key_type == "ed25519" else KeyType.RSA4096
    expiry_days = args.expiry_years * 365

    # Get passphrase
    console.print("\n[bold]Step 3: Set Master Key Passphrase[/bold]")
    console.print("This passphrase protects your master key. Use a strong, unique passphrase.")
    console.print("You will need this passphrase to access your offline backup.")
    passphrase = prompts.get_passphrase("Master key passphrase", confirm=True, min_length=12)

    # Store config
    sm.session.config = WorkflowConfig(
        identity=identity,
        key_type=key_type.value,
        expiry_years=args.expiry_years,
    )

    # Storage setup
    # Variables to track whether we need to mount an encrypted volume in Step 7
    backup_device_path = None  # Device path if we prepared a backup drive
    storage_passphrase_for_mount = None  # Passphrase to unlock the backup drive

    if not args.skip_storage:
        console.print("\n[bold]Step 4: Set Up Encrypted Backup Storage[/bold]")
        storage = StorageOperations()
        devices = storage.list_removable_devices()

        if not devices:
            console.print("[yellow]No removable devices found.[/yellow]")
            direct_backup_path = args.backup_path or Path(
                prompts._console.input("Enter backup path: ")
            )
        else:
            device = prompts.select_device(devices, "Select backup device")
            if device:
                # Confirm destructive operation
                if not prompts.confirm_destructive(device, "erase and format"):
                    console.print("[yellow]Storage setup cancelled.[/yellow]")
                    return 1

                storage_passphrase = prompts.get_passphrase(
                    "Backup volume passphrase", confirm=True
                )

                # Use platform-specific backup drive preparation
                import platform

                with console.status("Preparing backup drive..."):
                    if platform.system() == "Darwin":
                        drive_result = storage.prepare_backup_drive_macos(
                            device.path, storage_passphrase
                        )
                    elif platform.system() == "Linux":
                        drive_result = storage.prepare_backup_drive_linux(
                            device.path, storage_passphrase
                        )
                    else:
                        console.print(f"[red]Unsupported platform: {platform.system()}[/red]")
                        return 1

                if drive_result.is_err():
                    console.print(f"[red]Storage setup failed: {drive_result.unwrap_err()}[/red]")
                    return 1

                backup_drive_info = drive_result.unwrap()
                console.print("[green]Backup drive prepared successfully[/green]")
                console.print(f"  Encrypted volume: {backup_drive_info.encrypted_label}")
                console.print(f"  Public volume: {backup_drive_info.public_label}")

                # Store for later mounting in Step 7
                backup_device_path = device.path
                storage_passphrase_for_mount = storage_passphrase
                direct_backup_path = None
            else:
                return 1

        sm.session.config.backup_device = (
            str(backup_device_path) if backup_device_path else str(direct_backup_path)
        )
        result = sm.transition(
            WorkflowState.STORAGE_SETUP, {"backup_path": sm.session.config.backup_device}
        )
        if result.is_err():
            console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
            return 1
    else:
        if args.backup_path:
            direct_backup_path = args.backup_path
            sm.session.config.backup_device = str(direct_backup_path)
        else:
            console.print("[red]--backup-path required when using --skip-storage[/red]")
            return 1

    # Mark storage verified
    result = sm.transition(WorkflowState.STORAGE_VERIFIED)
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Generate master key
    console.print("\n[bold]Step 5: Generate Master Key[/bold]")
    gnupghome = args.gnupghome or Path.home() / ".gnupg"
    gpg = GPGOperations(gnupghome)

    console.print(f"Generating {key_type.value} master key for: {identity}")

    with console.status("Generating master key..."):
        key_result = gpg.generate_master_key(identity, passphrase, key_type, expiry_days=0)

    if key_result.is_err():
        console.print(f"[red]Key generation failed: {key_result.unwrap_err()}[/red]")
        sm.log_error(key_result.unwrap_err(), "master key generation")
        return 1

    key_info = key_result.unwrap()
    prompts.show_key_info(
        key_info.key_id,
        key_info.fingerprint,
        key_info.identity,
        key_info.expiry_date.isoformat() if key_info.expiry_date else "Never",
    )

    result = sm.transition(WorkflowState.GPG_MASTER_GENERATED, {"key_id": key_info.key_id})
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Generate subkeys
    console.print("\n[bold]Step 6: Generate Subkeys[/bold]")
    console.print("Creating Sign, Encrypt, and Authenticate subkeys...")

    with console.status("Generating subkeys..."):
        subkeys_result = gpg.generate_all_subkeys(
            key_info.key_id, passphrase, key_type, expiry_days
        )

    if subkeys_result.is_err():
        console.print(f"[red]Subkey generation failed: {subkeys_result.unwrap_err()}[/red]")
        sm.log_error(subkeys_result.unwrap_err(), "subkey generation")
        return 1

    subkeys = subkeys_result.unwrap()
    for subkey in subkeys:
        console.print(f"  Created {subkey.usage.value} subkey: {subkey.key_id}")

    result = sm.transition(
        WorkflowState.GPG_SUBKEYS_GENERATED, {"subkeys": [s.key_id for s in subkeys]}
    )
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Create backup
    console.print("\n[bold]Step 7: Create Backup[/bold]")

    # Mount encrypted volume if we prepared a backup drive
    mounted_backup = None
    if backup_device_path and storage_passphrase_for_mount:
        import platform

        console.print("Mounting encrypted backup volume...")
        with console.status("Unlocking backup drive..."):
            if platform.system() == "Darwin":
                mount_result = storage.open_backup_drive_macos(
                    backup_device_path, storage_passphrase_for_mount
                )
            elif platform.system() == "Linux":
                mount_result = storage.open_backup_drive_linux(
                    backup_device_path, storage_passphrase_for_mount
                )
            else:
                console.print(f"[red]Unsupported platform: {platform.system()}[/red]")
                return 1

        if mount_result.is_err():
            console.print(f"[red]Failed to mount backup drive: {mount_result.unwrap_err()}[/red]")
            return 1

        mounted_backup = mount_result.unwrap()
        backup_path = mounted_backup.encrypted_mount
        console.print(f"Backup volume mounted at: {backup_path}")
    else:
        # Direct path (either --skip-storage or no removable devices found)
        backup_path = Path(sm.session.config.backup_device)

    with console.status("Creating backup..."):
        backup_result = create_full_backup(
            gnupghome,
            backup_path,
            key_info.key_id,
            passphrase,
            include_paperkey=True,
            include_ssh=True,
        )

    if backup_result.is_err():
        console.print(f"[red]Backup failed: {backup_result.unwrap_err()}[/red]")
        sm.log_error(backup_result.unwrap_err(), "backup creation")
        # Unmount if we mounted
        if mounted_backup:
            import platform

            if platform.system() == "Darwin":
                storage.close_backup_drive_macos(mounted_backup)
            elif platform.system() == "Linux":
                storage.close_backup_drive_linux(mounted_backup)
        return 1

    manifest = backup_result.unwrap()
    console.print(f"Backup created at: {manifest.backup_path}")
    console.print(f"Files: {', '.join(manifest.files)}")

    # Copy public files to public partition if available
    if mounted_backup:
        with console.status("Copying public files to public partition..."):
            copy_result = copy_public_files_to_partition(
                manifest.backup_path,
                mounted_backup.public_mount,
            )
        if copy_result.is_err():
            console.print(f"[yellow]Warning: {copy_result.unwrap_err()}[/yellow]")
        else:
            copied_files = copy_result.unwrap()
            if copied_files:
                console.print(f"Public partition files: {', '.join(copied_files)}")

    result = sm.transition(
        WorkflowState.BACKUP_CREATED,
        {
            "backup_path": str(manifest.backup_path),
            "files": manifest.files,
        },
    )
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Verify backup
    console.print("\n[bold]Step 8: Verify Backup[/bold]")
    verify_result = verify_backup_complete(manifest.backup_path)
    if verify_result.is_err():
        console.print(f"[red]Backup verification failed: {verify_result.unwrap_err()}[/red]")
        return 1

    console.print("[green]Backup verified successfully.[/green]")

    # Unmount backup drive after successful verification
    if mounted_backup:
        console.print("Unmounting backup drive...")
        import platform

        if platform.system() == "Darwin":
            close_result = storage.close_backup_drive_macos(mounted_backup)
        elif platform.system() == "Linux":
            close_result = storage.close_backup_drive_linux(mounted_backup)
        else:
            close_result = None
        if close_result and close_result.is_err():
            console.print(
                f"[yellow]Warning: Failed to unmount backup drive: {close_result.unwrap_err()}[/yellow]"
            )
        else:
            console.print("Backup drive unmounted and locked.")

    if not prompts.confirm("Have you verified the backup and stored it securely?"):
        console.print("Please verify your backup before continuing.")
        console.print("Run 'yubikey-init continue' when ready.")
        return 0

    result = sm.transition(WorkflowState.BACKUP_VERIFIED)
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Provision YubiKey
    console.print("\n[bold]Step 9: Provision YubiKey[/bold]")
    return provision_yubikey(sm, gpg, key_info.key_id, passphrase, prompts, args)


def provision_yubikey(
    sm: StateMachine,
    gpg: GPGOperations,
    key_id: str,
    passphrase: SecureString,
    prompts: Prompts,
    args: argparse.Namespace,
) -> int:
    """Provision a YubiKey with keys."""
    yubikey = YubiKeyOperations(args.gnupghome)
    devices = yubikey.list_devices()

    if not devices:
        console.print("[yellow]No YubiKey detected. Insert YubiKey and press Enter.[/yellow]")
        prompts.wait_for_yubikey()
        devices = yubikey.list_devices()

    if not devices:
        console.print("[red]No YubiKey detected. Cannot continue.[/red]")
        return 1

    device = prompts.select_yubikey(devices, "Select YubiKey to provision")
    if not device:
        return 1

    # Load inventory and run safety checks
    inventory = Inventory()
    inventory.load()
    safety = SafetyGuard(inventory, yubikey, console)

    # Run safety checks for destructive operation
    confirm_result = safety.require_confirmation(
        device.serial,
        "Reset and Provision YubiKey",
        SafetyLevel.DESTRUCTIVE,
        extra_message="All existing keys and data on the OpenPGP applet will be permanently erased.",
    )

    if confirm_result.is_err():
        console.print(f"[red]Safety check failed: {confirm_result.unwrap_err()}[/red]")
        return 1

    if not confirm_result.unwrap():
        console.print("[yellow]Operation cancelled.[/yellow]")
        return 1

    # Reset YubiKey
    console.print("Resetting YubiKey OpenPGP application...")
    reset_result = yubikey.reset_openpgp(device.serial)
    if reset_result.is_err():
        console.print(f"[red]Reset failed: {reset_result.unwrap_err()}[/red]")
        return 1

    # Set PINs
    console.print("\n[bold]Set YubiKey PINs[/bold]")
    console.print("User PIN: Used for daily operations (signing, decrypting)")
    user_pin = prompts.get_pin("User PIN (6+ digits)", min_length=6)

    console.print("Admin PIN: Used for administrative operations")
    admin_pin = prompts.get_pin("Admin PIN (8+ digits)", min_length=8)

    pin_result = yubikey.set_pins(device.serial, user_pin, admin_pin)
    if pin_result.is_err():
        console.print(f"[red]PIN setup failed: {pin_result.unwrap_err()}[/red]")
        return 1

    # Enable KDF
    console.print("Enabling Key Derivation Function (KDF)...")
    kdf_result = yubikey.enable_kdf(device.serial, admin_pin)
    if kdf_result.is_err():
        console.print(
            f"[yellow]KDF enablement failed (may not be supported): {kdf_result.unwrap_err()}[/yellow]"
        )

    # Transfer keys
    console.print("\nTransferring keys to YubiKey...")

    # Get subkeys
    subkeys_result = gpg.list_subkeys(key_id)
    if subkeys_result.is_err():
        console.print(f"[red]Could not list subkeys: {subkeys_result.unwrap_err()}[/red]")
        return 1

    subkeys = subkeys_result.unwrap()

    # Transfer each subkey
    from .types import KeyUsage

    usage_to_slot = {
        KeyUsage.SIGN: KeySlot.SIGNATURE,
        KeyUsage.ENCRYPT: KeySlot.ENCRYPTION,
        KeyUsage.AUTHENTICATE: KeySlot.AUTHENTICATION,
    }

    for i, subkey in enumerate(subkeys, start=1):
        slot = usage_to_slot.get(subkey.usage)
        if slot:
            console.print(f"  Transferring {subkey.usage.value} key to {slot.value} slot...")
            transfer_result = yubikey.transfer_key(
                device.serial, key_id, slot, passphrase, admin_pin, i
            )
            if transfer_result.is_err():
                console.print(f"[red]Transfer failed: {transfer_result.unwrap_err()}[/red]")
                return 1

    # Set touch policies
    console.print("Setting touch policies (require physical touch for operations)...")
    for slot in [KeySlot.SIGNATURE, KeySlot.ENCRYPTION, KeySlot.AUTHENTICATION]:
        touch_result = yubikey.set_touch_policy(device.serial, slot, TouchPolicy.ON, admin_pin)
        if touch_result.is_err():
            console.print(
                f"[yellow]Touch policy for {slot.value} failed: {touch_result.unwrap_err()}[/yellow]"
            )

    # Verify card
    status_result = yubikey.get_card_status(device.serial)
    if status_result.is_ok():
        status = status_result.unwrap()
        console.print("\n[green]YubiKey provisioned successfully![/green]")
        console.print(f"  Serial: {status.serial}")
        if status.signature_key:
            console.print(f"  Signature key: {status.signature_key}")
        if status.encryption_key:
            console.print(f"  Encryption key: {status.encryption_key}")
        if status.authentication_key:
            console.print(f"  Authentication key: {status.authentication_key}")

    # Record in inventory
    entry = inventory.get_or_create(device.serial, device)
    key_info_result = gpg.get_key_info(key_id)
    if key_info_result.is_ok():
        entry.provisioned_identity = key_info_result.unwrap().identity
    else:
        entry.provisioned_identity = key_id
    entry.add_history("provision", True, f"Provisioned with key {key_id}")
    inventory.save()

    sm.session.config.yubikey_serials.append(device.serial)
    result = sm.transition(WorkflowState.YUBIKEY_1_PROVISIONED, {"serial": device.serial})
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    # Offer second YubiKey
    if prompts.confirm("\nDo you want to provision a second YubiKey (backup)?"):
        console.print("\n[bold]Provision Second YubiKey[/bold]")
        console.print(
            "[yellow]Note: You need to re-import keys from backup for second YubiKey.[/yellow]"
        )
        # This is complex - would need to reimport keys from backup
        # For now, just note it
        console.print("Second YubiKey provisioning requires reimporting keys from backup.")
        console.print("Use 'yubikey-init provision --key-id KEY --backup-path PATH' later.")

    # Remove master key from local keyring
    console.print("\n[bold]Step 10: Remove Master Key from Local Keyring[/bold]")
    if prompts.confirm(
        "Remove master key from local keyring? (Recommended - keep only on encrypted backup)",
        default=True,
    ):
        # Delete secret key but keep subkey stubs
        delete_result = gpg.delete_secret_key(key_id, confirm=True)
        if delete_result.is_err():
            console.print(
                f"[yellow]Could not delete master key: {delete_result.unwrap_err()}[/yellow]"
            )
        else:
            console.print("[green]Master key removed from local keyring.[/green]")

        result = sm.transition(WorkflowState.MASTER_KEY_REMOVED)
        if result.is_err():
            console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
            return 1

    # Complete
    result = sm.transition(WorkflowState.COMPLETE)
    if result.is_err():
        console.print(f"[red]State transition failed: {result.unwrap_err()}[/red]")
        return 1

    console.print("\n" + "=" * 60)
    console.print("[bold green]YubiKey initialization complete![/bold green]")
    console.print("=" * 60)

    console.print("\n[bold]Next Steps:[/bold]")
    console.print("1. Store your encrypted backup securely (offline, safe location)")
    console.print("2. Export your SSH public key: yubikey-init export-ssh --key-id " + key_id)
    console.print("3. Upload public key to keyserver: gpg --send-keys " + key_id)
    console.print("4. Set up SSH agent: yubikey-init setup-config")

    return 0


def cmd_continue(sm: StateMachine, args: argparse.Namespace, prompts: Prompts) -> int:
    """Resume an interrupted workflow (smart continue)."""
    result = sm.load()
    if result.is_err():
        console.print(f"[red]Error loading state: {result.unwrap_err()}[/red]")
        return 1

    if sm.current_state == WorkflowState.UNINITIALIZED:
        console.print("No workflow in progress. Use 'yubikey-init new' to start.")
        return 1

    if sm.current_state == WorkflowState.COMPLETE:
        console.print("[green]Workflow already complete.[/green]")
        return 0

    console.print(f"Resuming workflow from state: {sm.current_state.value}")

    # Get key_id from artifacts
    key_id = sm.get_artifact(WorkflowState.GPG_MASTER_GENERATED, "key_id")
    if not key_id:
        console.print("[red]Could not find key ID from previous session.[/red]")
        return 1

    console.print(f"Continuing with key: {key_id}")

    # Get passphrase
    passphrase = prompts.get_passphrase("Master key passphrase", confirm=False)

    gnupghome = args.gnupghome or Path.home() / ".gnupg"
    gpg = GPGOperations(gnupghome)

    # Resume based on current state
    if sm.current_state == WorkflowState.GPG_MASTER_GENERATED:
        # Need to generate subkeys
        console.print("Generating subkeys...")
        key_type = KeyType(sm.session.config.key_type)
        expiry_days = sm.session.config.expiry_years * 365

        subkeys_result = gpg.generate_all_subkeys(key_id, passphrase, key_type, expiry_days)
        if subkeys_result.is_err():
            console.print(f"[red]Subkey generation failed: {subkeys_result.unwrap_err()}[/red]")
            return 1

        sm.transition(
            WorkflowState.GPG_SUBKEYS_GENERATED,
            {"subkeys": [s.key_id for s in subkeys_result.unwrap()]},
        )

    if sm.current_state == WorkflowState.GPG_SUBKEYS_GENERATED:
        # Need to create backup
        backup_path = Path(sm.session.config.backup_device)
        backup_result = create_full_backup(gnupghome, backup_path, key_id, passphrase)
        if backup_result.is_err():
            console.print(f"[red]Backup failed: {backup_result.unwrap_err()}[/red]")
            return 1
        sm.transition(
            WorkflowState.BACKUP_CREATED, {"backup_path": str(backup_result.unwrap().backup_path)}
        )

    if sm.current_state == WorkflowState.BACKUP_CREATED and prompts.confirm(
        "Have you verified and secured your backup?"
    ):
        sm.transition(WorkflowState.BACKUP_VERIFIED)

    if sm.current_state == WorkflowState.BACKUP_VERIFIED:
        return provision_yubikey(sm, gpg, key_id, passphrase, prompts, args)

    if sm.current_state == WorkflowState.YUBIKEY_1_PROVISIONED:
        if prompts.confirm("Remove master key from local keyring?", default=True):
            gpg.delete_secret_key(key_id, confirm=True)
            sm.transition(WorkflowState.MASTER_KEY_REMOVED)
        sm.transition(WorkflowState.COMPLETE)
        console.print("[green]Workflow complete![/green]")

    return 0


def cmd_status(sm: StateMachine, verbose: bool) -> int:
    """Show current workflow status."""
    result = sm.load()
    if result.is_err():
        console.print(f"[red]Error loading state: {result.unwrap_err()}[/red]")
        return 1

    session = sm.session
    console.print(f"Session ID: {session.session_id}")
    console.print(f"Current state: {session.current_state.value}")
    console.print(f"Created: {session.created_at.isoformat()}")
    console.print(f"Updated: {session.updated_at.isoformat()}")

    if session.completed_steps:
        console.print("\nCompleted steps:")
        for step in session.completed_steps:
            console.print(f"  - {step.state.value} ({step.completed_at.isoformat()})")

    if session.config.identity:
        console.print(f"\nIdentity: {session.config.identity}")

    if session.config.yubikey_serials:
        console.print(f"YubiKeys: {', '.join(session.config.yubikey_serials)}")

    if session.error_log and verbose:
        console.print("\nErrors:")
        for error in session.error_log:
            console.print(f"  - [{error['timestamp']}] {error['error']}")

    return 0


def cmd_reset(sm: StateMachine, prompts: Prompts) -> int:
    """Reset workflow state."""
    sm.load()

    if sm.current_state == WorkflowState.UNINITIALIZED:
        console.print("No workflow to reset.")
        return 0

    console.print("This will reset the workflow state. Keys and backups are NOT affected.")
    if not prompts.confirm("Are you sure?"):
        console.print("Aborted.")
        return 1

    reset_result = sm.reset()
    if reset_result.is_err():
        console.print(f"[red]Error resetting state: {reset_result.unwrap_err()}[/red]")
        return 1

    console.print("Workflow state reset.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify system environment."""
    report = verify_environment(include_optional=args.full)
    show_environment_report(report)
    return 0 if report.all_passed else 1


def cmd_doctor() -> int:
    """Run diagnostics and troubleshooting."""
    console.print("Running diagnostics...")
    diagnostic = run_diagnostics()
    report = format_diagnostic_report(diagnostic)
    console.print(report)
    return 0


def cmd_setup_config(args: argparse.Namespace) -> int:
    """Set up hardened GPG configuration."""
    gnupghome = args.gnupghome

    console.print("Setting up hardened GPG configuration...")
    result = setup_all_configs(
        gnupghome=gnupghome,
        enable_ssh=not args.no_ssh,
        backup_existing=True,
    )

    if result.is_err():
        console.print(f"[red]Configuration setup failed: {result.unwrap_err()}[/red]")
        return 1

    paths = result.unwrap()
    console.print("[green]Configuration files created:[/green]")
    for name, path in paths.items():
        console.print(f"  {name}: {path}")

    console.print("\nRestarting gpg-agent...")
    restart_result = restart_gpg_agent()
    if restart_result.is_err():
        console.print(
            f"[yellow]Could not restart gpg-agent: {restart_result.unwrap_err()}[/yellow]"
        )

    if not args.no_ssh:
        console.print("\n[bold]SSH Agent Setup[/bold]")
        console.print("Add the following to your shell configuration:\n")
        console.print(generate_ssh_agent_setup_script())

    return 0


def cmd_export_ssh(args: argparse.Namespace) -> int:
    """Export SSH public key."""
    gnupghome = args.gnupghome or Path.home() / ".gnupg"
    gpg = GPGOperations(gnupghome)

    result = gpg.export_ssh_key(args.key_id)
    if result.is_err():
        console.print(f"[red]SSH key export failed: {result.unwrap_err()}[/red]")
        return 1

    console.print(result.unwrap())
    return 0


def cmd_renew(args: argparse.Namespace, prompts: Prompts) -> int:
    """Renew expiring subkeys."""
    gnupghome = args.gnupghome or Path.home() / ".gnupg"
    gpg = GPGOperations(gnupghome)

    passphrase = prompts.get_passphrase("Master key passphrase")
    expiry_days = args.expiry_years * 365

    console.print(f"Renewing subkeys for {args.key_id}...")
    result = gpg.renew_all_subkeys(args.key_id, passphrase, expiry_days)

    if result.is_err():
        console.print(f"[red]Renewal failed: {result.unwrap_err()}[/red]")
        return 1

    console.print("[green]Subkeys renewed successfully.[/green]")
    console.print("Remember to update your YubiKey and redistribute your public key.")
    return 0


def cmd_reset_yubikey(args: argparse.Namespace, prompts: Prompts) -> int:
    """Reset a YubiKey OpenPGP application.

    This follows the drduh YubiKey-Guide reset procedure:
    - Warns about data destruction
    - Shows what will be erased
    - Requires explicit confirmation
    - Optionally sets new PINs after reset
    """
    from rich.panel import Panel

    yubikey = YubiKeyOperations(args.gnupghome)
    inventory = Inventory()
    inventory.load()
    safety = SafetyGuard(inventory, yubikey, console)

    # Get connected devices
    devices = yubikey.list_devices()
    if not devices:
        console.print("[red]No YubiKey detected.[/red]")
        return 1

    # Resolve target device
    target_serial: str | None = None
    if args.serial:
        # Try to find by serial or label
        if args.serial.isdigit():
            target_serial = args.serial
        else:
            entry = inventory.find_by_label(args.serial)
            if entry:
                target_serial = entry.serial

        if not target_serial:
            # Try partial match
            for dev in devices:
                if dev.serial.endswith(args.serial) or dev.serial == args.serial:
                    target_serial = dev.serial
                    break

        if not target_serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        # Verify device is connected
        if not any(d.serial == target_serial for d in devices):
            console.print(f"[red]Device {target_serial} is not connected.[/red]")
            return 1
    elif len(devices) == 1:
        target_serial = devices[0].serial
    else:
        console.print("[yellow]Multiple YubiKeys connected. Specify which one to reset:[/yellow]")
        connected = list_connected_devices_safely(yubikey, inventory, console)
        display_device_table(connected, console)
        console.print("\nUsage: yubikey-init devices reset <serial or label>")
        return 1

    # Display prominent warning (per drduh guide)
    console.print()
    console.print(
        Panel(
            "[bold red]WARNING: DESTRUCTIVE OPERATION[/bold red]\n\n"
            "This will perform a FACTORY RESET of the YubiKey OpenPGP application.\n\n"
            "[bold]The following will be PERMANENTLY ERASED:[/bold]\n"
            "  - All OpenPGP keys (signature, encryption, authentication)\n"
            "  - Cardholder name and URL\n"
            "  - PIN settings (will be reset to defaults: 123456 / 12345678)\n"
            "  - Touch policy settings\n"
            "  - KDF settings\n\n"
            "[yellow]This operation CANNOT be undone![/yellow]\n\n"
            "If you have important keys on this device, ensure you have:\n"
            "  1. A backup of your private keys\n"
            "  2. Exported your public key",
            title="[bold red]YubiKey OpenPGP Reset[/bold red]",
            border_style="red",
        )
    )

    # Run safety checks
    if not args.force:
        confirm_result = safety.require_confirmation(
            target_serial,
            "Factory Reset OpenPGP Application",
            SafetyLevel.DESTRUCTIVE,
            extra_message="Default PINs after reset: User PIN = 123456, Admin PIN = 12345678",
        )

        if confirm_result.is_err():
            console.print(f"[red]Safety check failed: {confirm_result.unwrap_err()}[/red]")
            return 1

        if not confirm_result.unwrap():
            console.print("[yellow]Reset cancelled.[/yellow]")
            return 0
    else:
        console.print("[yellow]--force flag used, skipping confirmation...[/yellow]")
        # Still check if protected
        if inventory.is_protected(target_serial):
            console.print(
                f"[red]Device {target_serial} is PROTECTED. Remove protection first.[/red]"
            )
            console.print(f"Use: yubikey-init devices unprotect {target_serial}")
            return 1

    # Perform the reset
    console.print(f"\n[bold]Resetting YubiKey {target_serial}...[/bold]")

    with console.status("Resetting OpenPGP application..."):
        reset_result = yubikey.reset_openpgp(target_serial)

    if reset_result.is_err():
        console.print(f"[red]Reset failed: {reset_result.unwrap_err()}[/red]")
        # Record failure in inventory
        entry = inventory.get_or_create(target_serial)
        entry.add_history("reset", False, str(reset_result.unwrap_err()))
        inventory.save()
        return 1

    console.print("[green]OpenPGP application reset successfully.[/green]")

    # Record in inventory
    entry = inventory.get_or_create(target_serial)
    entry.provisioned_identity = None  # Clear identity since keys are gone
    entry.openpgp_state = None  # Clear cached state
    entry.add_history("reset", True, "Factory reset performed")
    inventory.save()

    # Show post-reset info
    console.print("\n[bold]Post-Reset Information:[/bold]")
    console.print("  Default User PIN:  123456")
    console.print("  Default Admin PIN: 12345678")
    console.print("  PIN retry counts:  User=3, Admin=3, Reset=0")

    # Optionally set new PINs
    if args.set_pins:
        console.print("\n[bold]Setting New PINs[/bold]")
        console.print("User PIN: Used for daily operations (signing, decrypting)")
        user_pin = prompts.get_pin("New User PIN (6+ digits)", min_length=6)

        console.print("Admin PIN: Used for administrative operations")
        admin_pin = prompts.get_pin("New Admin PIN (8+ digits)", min_length=8)

        # Use default admin PIN to set new PINs
        default_admin_pin = SecureString("12345678")
        pin_result = yubikey.set_pins(target_serial, user_pin, admin_pin, default_admin_pin)
        if pin_result.is_err():
            console.print(f"[red]PIN setup failed: {pin_result.unwrap_err()}[/red]")
            console.print("You can set PINs manually: ykman openpgp access change-pin")
            return 1

        console.print("[green]PINs updated successfully.[/green]")
        entry.add_history("pin_change", True, "PINs changed after reset")
        inventory.save()
    else:
        console.print("\n[yellow]Remember to change the default PINs![/yellow]")
        console.print("Use: ykman openpgp access change-pin")
        console.print("Or:  yubikey-init devices reset <serial> --set-pins")

    return 0


def cmd_devices_reset(
    args: argparse.Namespace,
    prompts: Prompts,
    inventory: Inventory,
    yubikey: YubiKeyOperations,
    resolve_serial: Callable[[str], str | None],
) -> int:
    """Reset a YubiKey OpenPGP application (called from devices subcommand)."""
    from rich.panel import Panel

    safety = SafetyGuard(inventory, yubikey, console)

    # Get connected devices
    devices = yubikey.list_devices()
    if not devices:
        console.print("[red]No YubiKey detected.[/red]")
        return 1

    # Resolve target device
    target_serial: str | None = None
    if args.serial:
        target_serial = resolve_serial(args.serial)
        if not target_serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        # Verify device is connected
        if not any(d.serial == target_serial for d in devices):
            console.print(f"[red]Device {target_serial} is not connected.[/red]")
            return 1
    elif len(devices) == 1:
        target_serial = devices[0].serial
    else:
        console.print("[yellow]Multiple YubiKeys connected. Specify which one to reset:[/yellow]")
        connected = list_connected_devices_safely(yubikey, inventory, console)
        display_device_table(connected, console)
        console.print("\nUsage: yubikey-init devices reset <serial or label>")
        return 1

    # Display prominent warning (per drduh guide)
    console.print()
    console.print(
        Panel(
            "[bold red]WARNING: DESTRUCTIVE OPERATION[/bold red]\n\n"
            "This will perform a FACTORY RESET of the YubiKey OpenPGP application.\n\n"
            "[bold]The following will be PERMANENTLY ERASED:[/bold]\n"
            "  - All OpenPGP keys (signature, encryption, authentication)\n"
            "  - Cardholder name and URL\n"
            "  - PIN settings (will be reset to defaults: 123456 / 12345678)\n"
            "  - Touch policy settings\n"
            "  - KDF settings\n\n"
            "[yellow]This operation CANNOT be undone![/yellow]\n\n"
            "If you have important keys on this device, ensure you have:\n"
            "  1. A backup of your private keys\n"
            "  2. Exported your public key",
            title="[bold red]YubiKey OpenPGP Reset[/bold red]",
            border_style="red",
        )
    )

    # Run safety checks
    if not args.force:
        confirm_result = safety.require_confirmation(
            target_serial,
            "Factory Reset OpenPGP Application",
            SafetyLevel.DESTRUCTIVE,
            extra_message="Default PINs after reset: User PIN = 123456, Admin PIN = 12345678",
        )

        if confirm_result.is_err():
            console.print(f"[red]Safety check failed: {confirm_result.unwrap_err()}[/red]")
            return 1

        if not confirm_result.unwrap():
            console.print("[yellow]Reset cancelled.[/yellow]")
            return 0
    else:
        console.print("[yellow]--force flag used, skipping confirmation...[/yellow]")
        # Still check if protected
        if inventory.is_protected(target_serial):
            console.print(
                f"[red]Device {target_serial} is PROTECTED. Remove protection first.[/red]"
            )
            console.print(f"Use: yubikey-init devices unprotect {target_serial}")
            return 1

    # Perform the reset
    console.print(f"\n[bold]Resetting YubiKey {target_serial}...[/bold]")

    with console.status("Resetting OpenPGP application..."):
        reset_result = yubikey.reset_openpgp(target_serial)

    if reset_result.is_err():
        console.print(f"[red]Reset failed: {reset_result.unwrap_err()}[/red]")
        # Record failure in inventory
        entry = inventory.get_or_create(target_serial)
        entry.add_history("reset", False, str(reset_result.unwrap_err()))
        inventory.save()
        return 1

    console.print("[green]OpenPGP application reset successfully.[/green]")

    # Record in inventory
    entry = inventory.get_or_create(target_serial)
    entry.provisioned_identity = None  # Clear identity since keys are gone
    entry.openpgp_state = None  # Clear cached state
    entry.add_history("reset", True, "Factory reset performed")
    inventory.save()

    # Show post-reset info
    console.print("\n[bold]Post-Reset Information:[/bold]")
    console.print("  Default User PIN:  123456")
    console.print("  Default Admin PIN: 12345678")
    console.print("  PIN retry counts:  User=3, Admin=3, Reset=0")

    # Optionally set new PINs
    if args.set_pins:
        console.print("\n[bold]Setting New PINs[/bold]")
        console.print("User PIN: Used for daily operations (signing, decrypting)")
        user_pin = prompts.get_pin("New User PIN (6+ digits)", min_length=6)

        console.print("Admin PIN: Used for administrative operations")
        admin_pin = prompts.get_pin("New Admin PIN (8+ digits)", min_length=8)

        # Use default admin PIN to set new PINs
        default_admin_pin = SecureString("12345678")
        pin_result = yubikey.set_pins(target_serial, user_pin, admin_pin, default_admin_pin)
        if pin_result.is_err():
            console.print(f"[red]PIN setup failed: {pin_result.unwrap_err()}[/red]")
            console.print("You can set PINs manually: ykman openpgp access change-pin")
            return 1

        console.print("[green]PINs updated successfully.[/green]")
        entry.add_history("pin_change", True, "PINs changed after reset")
        inventory.save()
    else:
        console.print("\n[yellow]Remember to change the default PINs![/yellow]")
        console.print("Use: ykman openpgp access change-pin")
        console.print("Or:  yubikey-init devices reset <serial> --set-pins")

    return 0


def cmd_keys(args: argparse.Namespace, prompts: Prompts) -> int:
    """Manage GPG keys."""
    gnupghome = args.gnupghome or Path.home() / ".gnupg"
    gpg = GPGOperations(gnupghome)

    if args.keys_command == "list" or args.keys_command is None:
        # List keys in keyring
        console.print("[bold]GPG Keys in Keyring[/bold]\n")
        result = gpg.list_secret_keys()
        if result.is_err():
            console.print(f"[red]Error listing keys: {result.unwrap_err()}[/red]")
            return 1

        keys = result.unwrap()
        if not keys:
            console.print("[yellow]No keys found in keyring.[/yellow]")
            return 0

        for key in keys:
            console.print(f"  {key.key_id} - {key.identity}")
            if key.expiry_date:
                console.print(f"    Expires: {key.expiry_date.isoformat()}")
        return 0

    elif args.keys_command == "renew":
        passphrase = prompts.get_passphrase("Master key passphrase")
        expiry_days = args.expiry_years * 365

        console.print(f"Renewing subkeys for {args.key_id}...")
        renew_result = gpg.renew_all_subkeys(args.key_id, passphrase, expiry_days)

        if renew_result.is_err():
            console.print(f"[red]Renewal failed: {renew_result.unwrap_err()}[/red]")
            return 1

        console.print("[green]Subkeys renewed successfully.[/green]")
        console.print("Remember to update your YubiKey and redistribute your public key.")
        return 0

    elif args.keys_command == "export-ssh":
        key_id = args.key_id if hasattr(args, "key_id") and args.key_id else None

        # If no key_id provided, try to find the authentication key
        if not key_id:
            keys_result = gpg.list_secret_keys()
            if keys_result.is_ok() and keys_result.unwrap():
                key_id = keys_result.unwrap()[0].key_id
                console.print(f"[dim]Using key: {key_id}[/dim]\n")
            else:
                console.print("[red]No key ID provided and no keys found in keyring.[/red]")
                console.print("Usage: yubikey-init keys export-ssh <key_id>")
                return 1

        ssh_result = gpg.export_ssh_key(key_id)
        if ssh_result.is_err():
            console.print(f"[red]SSH key export failed: {ssh_result.unwrap_err()}[/red]")
            return 1

        console.print(ssh_result.unwrap())
        return 0

    else:
        console.print("Usage: yubikey-init keys <command>")
        console.print("\nCommands:")
        console.print("  list        List keys in keyring")
        console.print("  renew       Renew expiring subkeys")
        console.print("  export-ssh  Export SSH public key")
        return 0


def cmd_backup(args: argparse.Namespace, prompts: Prompts) -> int:
    """Backup operations."""
    from .backup import import_from_backup

    if args.backup_command == "verify":
        console.print(f"Verifying backup at: {args.path}")
        result = verify_backup_complete(args.path)
        if result.is_err():
            console.print(f"[red]Backup verification failed: {result.unwrap_err()}[/red]")
            return 1

        files = result.unwrap()
        console.print("[green]Backup verified successfully.[/green]")
        console.print(f"Files found: {', '.join(files)}")
        return 0

    elif args.backup_command == "restore":
        gnupghome = args.gnupghome or Path.home() / ".gnupg"
        passphrase = prompts.get_passphrase("Master key passphrase")

        console.print(f"Restoring from backup at: {args.path}")
        restore_result = import_from_backup(
            args.path,
            gnupghome,
            passphrase,
            subkeys_only=args.subkeys_only if hasattr(args, "subkeys_only") else False,
        )

        if restore_result.is_err():
            console.print(f"[red]Restore failed: {restore_result.unwrap_err()}[/red]")
            return 1

        key_id = restore_result.unwrap()
        console.print(f"[green]Restored key: {key_id}[/green]")
        return 0

    else:
        console.print("Usage: yubikey-init backup <command>")
        console.print("\nCommands:")
        console.print("  verify   Verify backup integrity")
        console.print("  restore  Restore from backup")
        return 0


def cmd_dashboard(sm: StateMachine, _verbose: bool) -> int:
    """Show status dashboard with suggested next action (default when no command given)."""
    from rich.panel import Panel

    result = sm.load()
    if result.is_err():
        # No state file - show welcome message
        console.print(
            Panel(
                "[bold]Welcome to YubiKey Init[/bold]\n\n"
                "Automated YubiKey GPG initialization following best practices.\n\n"
                "[bold]Quick Start:[/bold]\n"
                "  yubikey-init new       Start a new setup workflow\n"
                "  yubikey-init doctor    Check system requirements\n"
                "  yubikey-init devices   List connected YubiKeys\n",
                title="YubiKey Init",
                border_style="blue",
            )
        )
        return 0

    session = sm.session
    yubikey = YubiKeyOperations()
    devices = yubikey.list_devices()

    # Build status panel
    if session.current_state == WorkflowState.UNINITIALIZED:
        status_line = "[dim]No workflow in progress[/dim]"
        suggestion = "Run [bold]yubikey-init new[/bold] to start a new setup"
    elif session.current_state == WorkflowState.COMPLETE:
        status_line = "[green]Workflow: COMPLETE[/green]"
        suggestion = "Your YubiKey is configured and ready to use"
    else:
        status_line = f"[yellow]Workflow: IN PROGRESS ({session.current_state.value})[/yellow]"
        suggestion = "Run [bold]yubikey-init continue[/bold] to resume"

    # Build device summary
    device_lines = []
    if devices:
        for dev in devices:
            device_lines.append(f"  - {dev.version or 'YubiKey'} ({dev.serial})")
    else:
        device_lines.append("  [dim]No YubiKeys connected[/dim]")

    # Build panel content
    content = f"{status_line}\n"
    if session.config.identity:
        content += f"Identity: {session.config.identity}\n"
    content += "\n[bold]Connected Devices:[/bold]\n"
    content += "\n".join(device_lines)
    content += f"\n\n[bold]Suggested:[/bold] {suggestion}"

    console.print()
    console.print(
        Panel(
            content,
            title="[bold]YubiKey Init Status[/bold]",
            border_style="blue",
        )
    )

    console.print("\n[bold]Quick Commands:[/bold]")
    console.print("  yubikey-init new        Start new setup")
    console.print("  yubikey-init continue   Resume setup")
    console.print("  yubikey-init status     Detailed status")
    console.print("  yubikey-init doctor     Run diagnostics")
    console.print("  yubikey-init devices    Manage YubiKeys")
    console.print()

    return 0


def cmd_devices(args: argparse.Namespace, prompts: Prompts) -> int:
    """Manage YubiKey devices."""
    from rich.panel import Panel
    from rich.table import Table

    inventory = Inventory()
    load_result = inventory.load()
    if load_result.is_err():
        console.print(f"[red]Error loading inventory: {load_result.unwrap_err()}[/red]")
        return 1

    yubikey = YubiKeyOperations()

    def resolve_serial(identifier: str) -> str | None:
        """Resolve a serial number or label to a serial number."""
        # First, try as a serial number
        if identifier.isdigit():
            return identifier

        # Try to find by label
        entry = inventory.find_by_label(identifier)
        if entry:
            return entry.serial

        # Could be a partial serial - try connected devices
        for dev in yubikey.list_devices():
            if dev.serial.endswith(identifier) or dev.serial == identifier:
                return dev.serial

        return None

    if args.devices_command == "list" or args.devices_command is None:
        # Get connected devices with state
        connected = list_connected_devices_safely(yubikey, inventory, console)
        show_all = getattr(args, "show_all", False)
        show_fingerprints = getattr(args, "fingerprints", False)

        if not connected and not show_all:
            console.print("[yellow]No YubiKeys connected.[/yellow]")
            console.print("Use 'yubikey-init devices list --all' to see all registered devices.")
            return 0

        if connected:
            display_device_table(connected, console, show_fingerprints=show_fingerprints)

        if show_all:
            # Show registered but not connected devices
            connected_serials = {info.serial for info, _, _ in connected}
            offline = [e for e in inventory.list_all() if e.serial not in connected_serials]

            if offline:
                console.print("\n[dim]Registered but not connected:[/dim]")
                table = Table()
                table.add_column("Serial", style="dim")
                table.add_column("Label")
                table.add_column("Last Seen")
                table.add_column("Protected")

                for entry in offline:
                    protected = "[red]YES[/red]" if entry.protected else "-"
                    label = entry.label or "-"
                    last_seen = entry.last_seen.strftime("%Y-%m-%d %H:%M")
                    table.add_row(entry.serial, label, last_seen, protected)

                console.print(table)

        # Save updated inventory (last_seen timestamps)
        inventory.save()
        return 0

    elif args.devices_command == "scan":
        console.print("Scanning for YubiKeys...")
        connected = list_connected_devices_safely(yubikey, inventory, console)

        if not connected:
            console.print("[yellow]No YubiKeys found.[/yellow]")
            return 0

        console.print(f"\n[green]Found {len(connected)} device(s):[/green]")
        display_device_table(connected, console, show_fingerprints=True)

        # Save inventory
        save_result = inventory.save()
        if save_result.is_err():
            console.print(f"[red]Error saving inventory: {save_result.unwrap_err()}[/red]")
            return 1

        console.print(f"\n[green]Inventory updated at: {inventory.path}[/green]")
        return 0

    elif args.devices_command == "show":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        show_entry: DeviceEntry | None = inventory.get(serial)

        # Try to get live status
        openpgp_state = None
        device_connected = False
        for dev in yubikey.list_devices():
            if dev.serial == serial:
                device_connected = True
                ykman_result = yubikey._run_ykman(["--device", serial, "openpgp", "info"])
                if ykman_result.returncode == 0:
                    openpgp_state = parse_openpgp_info(ykman_result.stdout)
                break

        # Display info
        console.print()
        title = show_entry.display_name() if show_entry else f"YubiKey {serial}"
        if show_entry and show_entry.protected:
            title += " [red][PROTECTED][/red]"

        table = Table(title=title)
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Serial", serial)
        table.add_row(
            "Status", "[green]Connected[/green]" if device_connected else "[dim]Offline[/dim]"
        )

        if show_entry:
            if show_entry.label:
                table.add_row("Label", show_entry.label)
            if show_entry.device_type:
                table.add_row("Type", show_entry.device_type)
            if show_entry.firmware_version:
                table.add_row("Firmware", show_entry.firmware_version)
            if show_entry.notes:
                table.add_row("Notes", show_entry.notes)
            if show_entry.provisioned_identity:
                table.add_row("Identity", show_entry.provisioned_identity)
            table.add_row("First Seen", show_entry.first_seen.strftime("%Y-%m-%d %H:%M"))
            table.add_row("Last Seen", show_entry.last_seen.strftime("%Y-%m-%d %H:%M"))

        if openpgp_state:
            table.add_row("", "")  # Separator
            table.add_row("[bold]OpenPGP State[/bold]", "")
            table.add_row(
                "PIN Status",
                "[red]BLOCKED[/red]"
                if openpgp_state.is_pin_blocked()
                else f"{openpgp_state.pin_tries_remaining} tries left",
            )
            table.add_row("Admin PIN", f"{openpgp_state.admin_pin_tries_remaining} tries left")
            table.add_row("KDF Enabled", "Yes" if openpgp_state.kdf_enabled else "No")

            if openpgp_state.signature_key.fingerprint:
                fp = openpgp_state.signature_key.fingerprint
                touch = openpgp_state.signature_key.touch_policy or "?"
                table.add_row("Signature Key", f"{fp}\n  Touch: {touch}")

            if openpgp_state.encryption_key.fingerprint:
                fp = openpgp_state.encryption_key.fingerprint
                touch = openpgp_state.encryption_key.touch_policy or "?"
                table.add_row("Encryption Key", f"{fp}\n  Touch: {touch}")

            if openpgp_state.authentication_key.fingerprint:
                fp = openpgp_state.authentication_key.fingerprint
                touch = openpgp_state.authentication_key.touch_policy or "?"
                table.add_row("Auth Key", f"{fp}\n  Touch: {touch}")

        console.print(table)

        # Show history
        if show_entry and show_entry.history:
            console.print("\n[bold]Operation History[/bold]")
            for record in show_entry.history[-10:]:  # Last 10 operations
                status = "[green]OK[/green]" if record.success else "[red]FAIL[/red]"
                console.print(
                    f"  {record.timestamp.strftime('%Y-%m-%d %H:%M')} "
                    f"{status} {record.operation}"
                    + (f" ({record.details})" if record.details else "")
                )

        return 0

    elif args.devices_command == "label":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        # Ensure device is in inventory
        _entry = inventory.get_or_create(serial)
        label_value: str | None = args.label if args.label else None

        set_result = inventory.set_label(serial, label_value)
        if set_result.is_err():
            console.print(f"[red]Error: {set_result.unwrap_err()}[/red]")
            return 1

        if label_value:
            console.print(f"[green]Label set for {serial}: {label_value}[/green]")
        else:
            console.print(f"[green]Label cleared for {serial}[/green]")
        return 0

    elif args.devices_command == "protect":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        protect_entry = inventory.get_or_create(serial)
        protect_result = inventory.set_protected(serial, True)
        if protect_result.is_err():
            console.print(f"[red]Error: {protect_result.unwrap_err()}[/red]")
            return 1

        console.print(
            Panel(
                f"Device {protect_entry.display_name()} is now [bold red]PROTECTED[/bold red].\n\n"
                "Destructive operations will be blocked until protection is removed.\n"
                f"To remove: yubikey-init devices unprotect {serial}",
                title="[green]Protection Enabled[/green]",
                border_style="green",
            )
        )
        return 0

    elif args.devices_command == "unprotect":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        unprotect_entry = inventory.get(serial)
        if not unprotect_entry or not unprotect_entry.protected:
            console.print(f"[yellow]Device {serial} is not protected.[/yellow]")
            return 0

        # Confirm unprotection
        console.print(
            Panel(
                f"[yellow]You are about to remove protection from:[/yellow]\n\n"
                f"  Serial: {serial}\n"
                f"  Label: {unprotect_entry.label or '(none)'}\n\n"
                "This will allow destructive operations on this device.",
                title="[yellow]Confirm Unprotect[/yellow]",
                border_style="yellow",
            )
        )

        if not prompts.confirm("Remove protection?"):
            console.print("Aborted.")
            return 1

        unprotect_result = inventory.set_protected(serial, False)
        if unprotect_result.is_err():
            console.print(f"[red]Error: {unprotect_result.unwrap_err()}[/red]")
            return 1

        console.print(f"[green]Protection removed from {unprotect_entry.display_name()}[/green]")
        return 0

    elif args.devices_command == "notes":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        _notes_entry = inventory.get_or_create(serial)
        notes_result = inventory.set_notes(serial, args.notes)
        if notes_result.is_err():
            console.print(f"[red]Error: {notes_result.unwrap_err()}[/red]")
            return 1

        if args.notes:
            console.print(f"[green]Notes set for {serial}[/green]")
        else:
            console.print(f"[green]Notes cleared for {serial}[/green]")
        return 0

    elif args.devices_command == "remove":
        serial = resolve_serial(args.serial)
        if not serial:
            console.print(f"[red]Device not found: {args.serial}[/red]")
            return 1

        remove_entry = inventory.get(serial)
        if not remove_entry:
            console.print(f"[yellow]Device {serial} not in inventory.[/yellow]")
            return 0

        if not prompts.confirm(f"Remove {remove_entry.display_name()} from inventory?"):
            console.print("Aborted.")
            return 1

        inventory.remove(serial)
        save_result = inventory.save()
        if save_result.is_err():
            console.print(f"[red]Error saving: {save_result.unwrap_err()}[/red]")
            return 1

        console.print(f"[green]Removed {serial} from inventory.[/green]")
        return 0

    elif args.devices_command == "reset":
        # Device reset - moved from standalone reset-yubikey command
        return cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)

    else:
        # Should not reach here with valid commands, but provide help
        console.print("Usage: yubikey-init devices <command>")
        console.print("\nCommands:")
        console.print("  list      List connected and registered devices")
        console.print("  scan      Scan and register connected devices")
        console.print("  show      Show detailed info for a device")
        console.print("  label     Set a label/nickname for a device")
        console.print("  protect   Mark a device as protected")
        console.print("  unprotect Remove protection from a device")
        console.print("  notes     Set notes for a device")
        console.print("  remove    Remove a device from inventory")
        console.print("  reset     Reset YubiKey OpenPGP application (DESTRUCTIVE)")
        return 0


def cmd_provision(args: argparse.Namespace, prompts: Prompts) -> int:
    """Provision a YubiKey with existing keys."""
    from .backup import import_from_backup

    gnupghome = args.gnupghome or Path.home() / ".gnupg"

    # Import keys from backup
    passphrase = prompts.get_passphrase("Master key passphrase")

    console.print("Importing keys from backup...")
    import_result = import_from_backup(
        args.backup_path,
        gnupghome,
        passphrase,
        subkeys_only=False,  # Need full key for provisioning
    )

    if import_result.is_err():
        console.print(f"[red]Import failed: {import_result.unwrap_err()}[/red]")
        return 1

    key_id = import_result.unwrap()
    gpg = GPGOperations(gnupghome)

    # Create a minimal state machine for provisioning
    sm = StateMachine(":memory:")
    sm.load()

    # Fake namespace for provision
    return provision_yubikey(sm, gpg, key_id, passphrase, prompts, args)


def run(args: list[str]) -> int:
    """Main entry point."""
    parser = get_parser()
    ns = parser.parse_args(args)

    # Create state machine
    sm = StateMachine(ns.state_file)

    # No command: show dashboard (default behavior)
    if not ns.command:
        return cmd_dashboard(sm, ns.verbose)

    # Check for deprecated commands first
    if ns.command in DEPRECATED_COMMANDS:
        return handle_deprecated_command(ns.command)

    # Create prompts
    prompts = Prompts()

    # Dispatch commands - PRIMARY COMMANDS
    if ns.command == "new":
        return cmd_new(sm, ns, prompts)
    elif ns.command == "continue":
        return cmd_continue(sm, ns, prompts)
    elif ns.command == "status":
        return cmd_status(sm, ns.verbose)
    elif ns.command == "reset":
        return cmd_reset(sm, prompts)
    elif ns.command == "doctor":
        return cmd_doctor()
    elif ns.command == "verify":
        return cmd_verify(ns)
    elif ns.command == "setup-config":
        return cmd_setup_config(ns)
    elif ns.command == "provision":
        return cmd_provision(ns, prompts)

    # COMMAND GROUPS
    elif ns.command == "devices":
        return cmd_devices(ns, prompts)
    elif ns.command == "keys":
        return cmd_keys(ns, prompts)
    elif ns.command == "backup":
        return cmd_backup(ns, prompts)

    # MANAGEMENT TUI
    elif ns.command == "manage":
        return cmd_manage(ns)

    parser.print_help()
    return 1


def cmd_manage(_ns: argparse.Namespace) -> int:
    """Launch the interactive management TUI."""
    try:
        from .tui import run_tui

        run_tui()
        return 0
    except ImportError as e:
        console.print(f"[red]Error:[/red] TUI not available: {e}")
        console.print("Try: pip install yubikey-init[tui]")
        return 1
    except Exception as e:
        console.print(f"[red]Error:[/red] TUI failed: {e}")
        return 1
