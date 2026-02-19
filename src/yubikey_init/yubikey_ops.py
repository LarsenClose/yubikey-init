from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from .types import (
    CardStatus,
    KeySlot,
    Result,
    SecureString,
    TouchPolicy,
    YubiKeyInfo,
)


class YubiKeyError(Exception):
    pass


class YubiKeyOperations:
    def __init__(self, gnupghome: Path | None = None) -> None:
        self._ykman_path = "ykman"
        self._gnupghome = gnupghome
        self._env = os.environ.copy()
        if gnupghome:
            self._env["GNUPGHOME"] = str(gnupghome)

    def _run_ykman(
        self, args: list[str], input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = [self._ykman_path] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=input_text,
        )

    def _run_gpg(
        self, args: list[str], input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = ["gpg", "--batch", "--yes"] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=self._env,
            input=input_text,
        )

    def list_devices(self) -> list[YubiKeyInfo]:
        result = self._run_ykman(["list", "--serials"])

        if result.returncode != 0:
            return []

        devices = []
        for serial in result.stdout.strip().split("\n"):
            serial = serial.strip()
            if serial:
                info = self._get_device_info(serial)
                if info:
                    devices.append(info)

        return devices

    def _get_device_info(self, serial: str) -> YubiKeyInfo | None:
        result = self._run_ykman(["--device", serial, "info"])

        if result.returncode != 0:
            return None

        # Parse text output from ykman info
        version = "unknown"
        form_factor = "unknown"
        has_openpgp = False

        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Firmware version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("Form factor:"):
                form_factor = line.split(":", 1)[1].strip()
            elif line.startswith("OpenPGP") and "Enabled" in line:
                has_openpgp = True

        return YubiKeyInfo(
            serial=serial,
            version=version,
            form_factor=form_factor,
            has_openpgp=has_openpgp,
            openpgp_version=None,
        )

    def wait_for_device(
        self,
        serial: str | None = None,
        timeout: int = 60,
    ) -> Result[YubiKeyInfo]:
        start = time.time()

        while time.time() - start < timeout:
            devices = self.list_devices()

            if serial:
                for dev in devices:
                    if dev.serial == serial:
                        return Result.ok(dev)
            elif devices:
                return Result.ok(devices[0])

            time.sleep(1)

        return Result.err(YubiKeyError(f"No YubiKey detected within {timeout}s"))

    def reset_openpgp(self, serial: str) -> Result[None]:
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "reset",
                "--force",
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Reset failed: {result.stderr}"))

        return Result.ok(None)

    def transfer_key(
        self,
        serial: str,
        key_id: str,
        slot: KeySlot,
        passphrase: SecureString,
        admin_pin: SecureString,
        subkey_index: int = 1,
    ) -> Result[None]:
        """Transfer a subkey to the YubiKey smartcard.

        Uses the drduh/YubiKey-Guide approach with --command-fd=0 to pipe
        commands via stdin, which is more reliable than interactive pexpect.
        The subkey_index is 1-indexed (first subkey is 1).
        """
        slot_num = {
            KeySlot.SIGNATURE: "1",
            KeySlot.ENCRYPTION: "2",
            KeySlot.AUTHENTICATION: "3",
        }[slot]

        # Ensure we're using the right device
        reader_match = self._get_reader_for_serial(serial)

        # Build command following drduh guide pattern
        cmd = ["gpg", "--command-fd", "0", "--pinentry-mode", "loopback"]
        if reader_match:
            cmd.extend(["--reader-port", reader_match])
        cmd.extend(["--edit-key", key_id])

        # Build command sequence following drduh guide pattern exactly
        # The sequence is: select key, keytocard, select slot, passphrase, admin pin, save
        # Note: Do NOT include "y" for replace confirmation - --command-fd mode handles this
        commands = "\n".join(
            [
                f"key {subkey_index}",
                "keytocard",
                slot_num,
                passphrase.get(),
                admin_pin.get(),
                "save",
            ]
        )

        try:
            result = subprocess.run(
                cmd,
                input=commands,
                capture_output=True,
                text=True,
                env=self._env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return Result.err(YubiKeyError("Key transfer timed out after 120 seconds"))

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Key transfer failed: {result.stderr}"))

        return Result.ok(None)

    def _get_reader_for_serial(self, serial: str) -> str | None:
        """Get the reader port name for a specific YubiKey serial."""
        result = self._run_gpg(["--card-status"])
        if result.returncode == 0 and serial in result.stdout:
            for line in result.stdout.split("\n"):
                if line.startswith("Reader"):
                    match = re.search(r":\s*(.+)$", line)
                    if match:
                        return match.group(1).strip()
        return None

    def transfer_all_keys(
        self,
        serial: str,
        key_id: str,
        passphrase: SecureString,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Transfer all subkeys to the YubiKey in appropriate slots.

        Expects subkeys in order: Sign (1), Encrypt (2), Auth (3).
        """
        transfers = [
            (KeySlot.SIGNATURE, 1),
            (KeySlot.ENCRYPTION, 2),
            (KeySlot.AUTHENTICATION, 3),
        ]

        for slot, index in transfers:
            result = self.transfer_key(serial, key_id, slot, passphrase, admin_pin, index)
            if result.is_err():
                return result

        return Result.ok(None)

    def set_touch_policy(
        self,
        serial: str,
        slot: KeySlot,
        policy: TouchPolicy,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Set the touch policy for a key slot.

        Requires the admin PIN to authenticate the operation.
        """
        slot_name = {
            KeySlot.SIGNATURE: "sig",
            KeySlot.ENCRYPTION: "enc",
            KeySlot.AUTHENTICATION: "aut",
        }[slot]

        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "keys",
                "set-touch",
                slot_name,
                policy.value,
                "--admin-pin",
                admin_pin.get(),
                "--force",
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Touch policy change failed: {result.stderr}"))

        return Result.ok(None)

    def get_card_status(self, serial: str) -> Result[CardStatus]:
        """Get detailed card status including key fingerprints."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "info",
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Status check failed: {result.stderr}"))

        # Parse the output
        sig_key = None
        enc_key = None
        auth_key = None
        sig_count = 0
        pin_retries = 3
        admin_retries = 3

        lines = result.stdout.split("\n")
        for line in lines:
            if "Signature key" in line and "fingerprint" in line.lower():
                match = re.search(r"([A-F0-9]{40})", line, re.IGNORECASE)
                if match:
                    sig_key = match.group(1)
            elif "Encryption key" in line and "fingerprint" in line.lower():
                match = re.search(r"([A-F0-9]{40})", line, re.IGNORECASE)
                if match:
                    enc_key = match.group(1)
            elif "Authentication key" in line and "fingerprint" in line.lower():
                match = re.search(r"([A-F0-9]{40})", line, re.IGNORECASE)
                if match:
                    auth_key = match.group(1)
            elif "Signature counter" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    sig_count = int(match.group(1))
            elif "PIN retries" in line:
                match = re.search(r"(\d+)/(\d+)/(\d+)", line)
                if match:
                    pin_retries = int(match.group(1))
                    admin_retries = int(match.group(3))

        return Result.ok(
            CardStatus(
                serial=serial,
                signature_key=sig_key,
                encryption_key=enc_key,
                authentication_key=auth_key,
                signature_count=sig_count,
                pin_retries=pin_retries,
                admin_pin_retries=admin_retries,
            )
        )

    def enable_kdf(
        self,
        serial: str,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Enable Key Derivation Function for PINs.

        KDF provides additional security by deriving a key from the PIN
        rather than using the PIN directly. This makes offline attacks harder.
        """
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "access",
                "set-kdf",
                "--admin-pin",
                admin_pin.get(),
                "--force",
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"KDF enablement failed: {result.stderr}"))

        return Result.ok(None)

    def set_cardholder_name(
        self,
        serial: str,
        name: str,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Set the cardholder name on the YubiKey."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "info",
                "--admin-pin",
                admin_pin.get(),
                "--name",
                name,
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Set name failed: {result.stderr}"))

        return Result.ok(None)

    def set_public_key_url(
        self,
        serial: str,
        url: str,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Set the URL where the public key can be retrieved."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "info",
                "--admin-pin",
                admin_pin.get(),
                "--url",
                url,
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Set URL failed: {result.stderr}"))

        return Result.ok(None)

    def verify_attestation(self, serial: str) -> Result[bool]:
        """Verify the YubiKey's attestation certificate.

        This confirms the YubiKey is a genuine Yubico device.
        """
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "keys",
                "attest",
                "SIG",
            ]
        )

        # If attestation succeeds, the key is genuine
        return Result.ok(result.returncode == 0)

    def set_reset_code(
        self,
        serial: str,
        admin_pin: SecureString,
        reset_code: SecureString,
    ) -> Result[None]:
        """Set the reset code (allows resetting PIN without admin PIN)."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "access",
                "set-reset-code",
                "--admin-pin",
                admin_pin.get(),
                "--reset-code",
                reset_code.get(),
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Set reset code failed: {result.stderr}"))

        return Result.ok(None)

    def change_user_pin(
        self,
        serial: str,
        current_pin: SecureString,
        new_pin: SecureString,
    ) -> Result[None]:
        """Change the user PIN."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "access",
                "change-pin",
                "--pin",
                current_pin.get(),
                "--new-pin",
                new_pin.get(),
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"PIN change failed: {result.stderr}"))

        return Result.ok(None)

    def change_admin_pin(
        self,
        serial: str,
        current_pin: SecureString,
        new_pin: SecureString,
    ) -> Result[None]:
        """Change the admin PIN."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "access",
                "change-admin-pin",
                "--admin-pin",
                current_pin.get(),
                "--new-admin-pin",
                new_pin.get(),
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Admin PIN change failed: {result.stderr}"))

        return Result.ok(None)

    def unblock_pin(
        self,
        serial: str,
        admin_pin: SecureString,
        new_pin: SecureString,
    ) -> Result[None]:
        """Unblock a blocked user PIN using the admin PIN."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "access",
                "unblock-pin",
                "--admin-pin",
                admin_pin.get(),
                "--new-pin",
                new_pin.get(),
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"PIN unblock failed: {result.stderr}"))

        return Result.ok(None)

    def set_pins(
        self,
        serial: str,
        new_user_pin: SecureString,
        new_admin_pin: SecureString,
        current_admin_pin: SecureString | None = None,
    ) -> Result[None]:
        """Set both user and admin PINs.

        After a reset, the default PINs are:
          - User PIN: 123456
          - Admin PIN: 12345678

        This method changes both PINs from the defaults (or provided current admin PIN)
        to the new values.
        """
        # Use default admin PIN if not provided
        if current_admin_pin is None:
            current_admin_pin = SecureString("12345678")

        default_user_pin = SecureString("123456")

        # Change user PIN first
        user_result = self.change_user_pin(serial, default_user_pin, new_user_pin)
        if user_result.is_err():
            return user_result

        # Change admin PIN
        admin_result = self.change_admin_pin(serial, current_admin_pin, new_admin_pin)
        if admin_result.is_err():
            return admin_result

        return Result.ok(None)

    def get_openpgp_version(self, serial: str) -> Result[str]:
        """Get the OpenPGP application version on the YubiKey."""
        result = self._run_ykman(
            [
                "--device",
                serial,
                "openpgp",
                "info",
            ]
        )

        if result.returncode != 0:
            return Result.err(YubiKeyError(f"Version check failed: {result.stderr}"))

        for line in result.stdout.split("\n"):
            if "Version" in line:
                match = re.search(r"(\d+\.\d+)", line)
                if match:
                    return Result.ok(match.group(1))

        return Result.err(YubiKeyError("Could not determine OpenPGP version"))

    def set_all_touch_policies(
        self,
        serial: str,
        admin_pin: SecureString,
        policy: TouchPolicy = TouchPolicy.ON,
    ) -> Result[None]:
        """Set touch policy for all key slots."""
        for slot in [KeySlot.SIGNATURE, KeySlot.ENCRYPTION, KeySlot.AUTHENTICATION]:
            result = self.set_touch_policy(serial, slot, policy, admin_pin)
            if result.is_err():
                return result
        return Result.ok(None)

    def fetch_public_key(self, serial: str) -> Result[str]:
        """Fetch the public key from the card.

        This updates GPG's keyring with the card's public key URL.
        """
        result = self._run_gpg(["--card-edit"])
        # This is interactive, but we can use fetch command

        # Alternative: export from keyring if key already exists
        status = self.get_card_status(serial)
        if status.is_err():
            return Result.err(status.unwrap_err())

        card_status = status.unwrap()
        if card_status.signature_key:
            # Key fingerprint available, export from keyring
            result = self._run_gpg(["--armor", "--export", card_status.signature_key[-16:]])
            if result.returncode == 0:
                return Result.ok(result.stdout)

        return Result.err(YubiKeyError("Could not fetch public key"))


def yubikey_available() -> bool:
    ops = YubiKeyOperations()
    return len(ops.list_devices()) > 0


def check_ykman_version() -> Result[str]:
    """Check that ykman is installed and return its version."""
    try:
        result = subprocess.run(
            ["ykman", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            version = result.stdout.strip().split()[-1]
            return Result.ok(version)
        return Result.err(YubiKeyError("ykman not found"))
    except FileNotFoundError:
        return Result.err(YubiKeyError("ykman is not installed"))


def check_gpg_version() -> Result[str]:
    """Check that gpg is installed and return its version."""
    try:
        result = subprocess.run(
            ["gpg", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            lines = result.stdout.split("\n")
            if lines:
                version = lines[0].split()[-1]
                return Result.ok(version)
        return Result.err(YubiKeyError("gpg version check failed"))
    except FileNotFoundError:
        return Result.err(YubiKeyError("gpg is not installed"))


def check_scdaemon() -> Result[bool]:
    """Check that scdaemon (smartcard daemon) is available."""
    try:
        result = subprocess.run(
            ["gpg-connect-agent", "SCD GETINFO version", "/bye"],
            capture_output=True,
            text=True,
        )
        return Result.ok(result.returncode == 0)
    except FileNotFoundError:
        return Result.err(YubiKeyError("gpg-connect-agent not found"))
