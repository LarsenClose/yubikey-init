from __future__ import annotations

import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pexpect

from .types import (
    KeyInfo,
    KeySlot,
    KeyType,
    KeyUsage,
    Result,
    SecureString,
    SubkeyInfo,
)


class GPGError(Exception):
    pass


class GPGOperations:
    def __init__(self, gnupghome: Path | None = None) -> None:
        self._gnupghome = gnupghome
        self._env = os.environ.copy()
        if gnupghome:
            self._env["GNUPGHOME"] = str(gnupghome)

    @property
    def gnupghome(self) -> Path:
        if self._gnupghome:
            return self._gnupghome
        return Path(os.environ.get("GNUPGHOME", Path.home() / ".gnupg"))

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

    def generate_master_key(
        self,
        identity: str,
        passphrase: SecureString,
        key_type: KeyType = KeyType.ED25519,
        expiry_days: int = 730,
    ) -> Result[KeyInfo]:
        if key_type == KeyType.ED25519:
            key_params = "Key-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: cert"
        else:
            key_params = "Key-Type: RSA\nKey-Length: 4096\nKey-Usage: cert"

        batch_script = f"""%echo Generating master key
{key_params}
Name-Real: {identity.split("<")[0].strip()}
Name-Email: {identity.split("<")[1].rstrip(">").strip() if "<" in identity else ""}
Expire-Date: {expiry_days}d
Passphrase: {passphrase.get()}
%commit
%echo Done
"""
        result = self._run_gpg(
            ["--full-generate-key", "--expert"],
            input_text=batch_script,
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Key generation failed: {result.stderr}"))

        key_id = self._extract_key_id(result.stderr)
        if not key_id:
            keys = self.list_secret_keys()
            if keys.is_ok() and keys.unwrap():
                key_id = keys.unwrap()[0].key_id
            else:
                return Result.err(GPGError("Could not determine generated key ID"))

        return self.get_key_info(key_id)

    def _extract_key_id(self, output: str) -> str | None:
        patterns = [
            r"key ([A-F0-9]{16}) marked as ultimately trusted",
            r"gpg: key ([A-F0-9]{16})",
            r"/([A-F0-9]{40})",
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def get_key_info(self, key_id: str) -> Result[KeyInfo]:
        result = self._run_gpg(
            [
                "--with-colons",
                "--list-keys",
                key_id,
            ]
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Could not get key info: {result.stderr}"))

        for line in result.stdout.split("\n"):
            if line.startswith("pub:"):
                fields = line.split(":")
                return Result.ok(
                    KeyInfo(
                        key_id=fields[4],
                        fingerprint=fields[4],
                        creation_date=datetime.fromtimestamp(int(fields[5]), tz=UTC),
                        expiry_date=datetime.fromtimestamp(int(fields[6]), tz=UTC)
                        if fields[6]
                        else None,
                        identity=self._get_uid_for_key(key_id),
                        key_type=KeyType.ED25519,
                    )
                )

        return Result.err(GPGError(f"Key not found: {key_id}"))

    def _get_uid_for_key(self, key_id: str) -> str:
        result = self._run_gpg(["--with-colons", "--list-keys", key_id])
        for line in result.stdout.split("\n"):
            if line.startswith("uid:"):
                fields = line.split(":")
                return fields[9]
        return ""

    def generate_subkey(
        self,
        master_key_id: str,
        passphrase: SecureString,
        usage: KeyUsage,
        key_type: KeyType = KeyType.ED25519,
        expiry_days: int = 730,
    ) -> Result[SubkeyInfo]:
        """Generate a subkey for the given master key using gpg --quick-add-key.

        This uses the non-interactive --quick-add-key command which is more reliable
        than the interactive --edit-key approach, as it doesn't depend on GPG's
        menu structure which varies between versions.
        """
        if usage == KeyUsage.CERTIFY:
            return Result.err(GPGError("Cannot create subkey with CERTIFY usage"))

        # Get the fingerprint (--quick-add-key requires fingerprint, not key ID)
        fingerprint_result = self.get_key_fingerprint(master_key_id)
        if fingerprint_result.is_err():
            return Result.err(fingerprint_result.unwrap_err())
        fingerprint = fingerprint_result.unwrap()

        # Map key type and usage to GPG algorithm and usage strings
        # For ED25519: sign/auth use ed25519, encrypt uses cv25519
        # For RSA4096: all use rsa4096
        if key_type == KeyType.ED25519:
            algo = "cv25519" if usage == KeyUsage.ENCRYPT else "ed25519"
        else:  # RSA4096
            algo = "rsa4096"

        # Map usage to GPG usage string
        usage_map = {
            KeyUsage.SIGN: "sign",
            KeyUsage.ENCRYPT: "encr",
            KeyUsage.AUTHENTICATE: "auth",
        }
        gpg_usage = usage_map[usage]

        # Build expiration string (e.g., "730d" for 730 days)
        expire = f"{expiry_days}d"

        # Run gpg --quick-add-key with passphrase via stdin
        result = self._run_gpg_with_passphrase(
            [
                "--quick-add-key",
                fingerprint,
                algo,
                gpg_usage,
                expire,
            ],
            passphrase,
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Subkey generation failed: {result.stderr}"))

        # Get the newly created subkey info
        return self._get_latest_subkey(master_key_id, usage)

    def get_key_fingerprint(self, key_id: str) -> Result[str]:
        """Get the full fingerprint for a key ID."""
        result = self._run_gpg(["--with-colons", "--fingerprint", key_id])
        if result.returncode != 0:
            return Result.err(GPGError(f"Could not get fingerprint: {result.stderr}"))

        for line in result.stdout.split("\n"):
            if line.startswith("fpr:"):
                fields = line.split(":")
                return Result.ok(fields[9])

        return Result.err(GPGError(f"No fingerprint found for key: {key_id}"))

    def _run_gpg_with_passphrase(
        self, args: list[str], passphrase: SecureString
    ) -> subprocess.CompletedProcess[str]:
        """Run GPG command with passphrase provided via stdin."""
        cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
        ] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=self._env,
            input=passphrase.get(),
        )

    def _get_latest_subkey(self, master_key_id: str, usage: KeyUsage) -> Result[SubkeyInfo]:
        """Get info about the most recently created subkey."""
        result = self._run_gpg(["--with-colons", "--list-keys", master_key_id])

        if result.returncode != 0:
            return Result.err(GPGError(f"Could not get key info: {result.stderr}"))

        # Parse subkeys from colon-delimited output
        subkeys: list[dict[str, str]] = []
        for line in result.stdout.split("\n"):
            if line.startswith("sub:"):
                fields = line.split(":")
                cap = fields[11] if len(fields) > 11 else ""
                subkeys.append(
                    {
                        "key_id": fields[4],
                        "creation": fields[5],
                        "expiry": fields[6],
                        "capabilities": cap,
                    }
                )

        if not subkeys:
            return Result.err(GPGError("No subkeys found"))

        # Find the subkey matching the usage (most recent)
        usage_cap_map = {
            KeyUsage.SIGN: "s",
            KeyUsage.ENCRYPT: "e",
            KeyUsage.AUTHENTICATE: "a",
        }
        target_cap = usage_cap_map.get(usage, "")

        matching = [s for s in subkeys if target_cap in s["capabilities"].lower()]
        if not matching:
            # Return the most recent subkey
            matching = subkeys

        latest = matching[-1]

        return Result.ok(
            SubkeyInfo(
                key_id=latest["key_id"],
                fingerprint=latest["key_id"],
                creation_date=datetime.fromtimestamp(int(latest["creation"]), tz=UTC),
                expiry_date=datetime.fromtimestamp(int(latest["expiry"]), tz=UTC)
                if latest["expiry"]
                else None,
                usage=usage,
                key_type=KeyType.ED25519,  # Could be detected from output
                parent_key_id=master_key_id,
            )
        )

    def export_secret_keys(
        self,
        key_id: str,
        passphrase: SecureString,
        output_path: Path,
    ) -> Result[Path]:
        result = self._run_gpg(
            [
                "--armor",
                "--export-secret-keys",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--output",
                str(output_path),
                key_id,
            ],
            input_text=passphrase.get(),
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Export failed: {result.stderr}"))

        return Result.ok(output_path)

    def export_secret_subkeys(
        self,
        key_id: str,
        passphrase: SecureString,
        output_path: Path,
    ) -> Result[Path]:
        result = self._run_gpg(
            [
                "--armor",
                "--export-secret-subkeys",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--output",
                str(output_path),
                key_id,
            ],
            input_text=passphrase.get(),
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Export failed: {result.stderr}"))

        return Result.ok(output_path)

    def export_public_key(
        self,
        key_id: str,
        output_path: Path,
    ) -> Result[Path]:
        result = self._run_gpg(
            [
                "--armor",
                "--export",
                "--output",
                str(output_path),
                key_id,
            ]
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Export failed: {result.stderr}"))

        return Result.ok(output_path)

    def import_key(
        self,
        key_path: Path,
        passphrase: SecureString | None = None,
    ) -> Result[KeyInfo]:
        args = ["--import", str(key_path)]
        input_text = None

        if passphrase:
            args = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"] + args
            input_text = passphrase.get()

        result = self._run_gpg(args, input_text=input_text)

        if result.returncode != 0:
            return Result.err(GPGError(f"Import failed: {result.stderr}"))

        key_id = self._extract_key_id(result.stderr)
        if not key_id:
            return Result.err(GPGError("Could not determine imported key ID"))

        return self.get_key_info(key_id)

    def delete_secret_key(
        self,
        key_id: str,
        confirm: bool = False,
    ) -> Result[None]:
        """Delete a secret key from the keyring.

        In batch mode, GPG requires the full fingerprint, not just key ID.
        """
        if not confirm:
            return Result.err(GPGError("Deletion requires explicit confirmation"))

        # Get the full fingerprint (required for batch mode deletion)
        fp_result = self.get_key_fingerprint(key_id)
        if fp_result.is_err():
            return Result.err(GPGError(f"Could not get fingerprint: {fp_result.unwrap_err()}"))

        fingerprint = fp_result.unwrap()

        # Use fingerprint with exclamation mark to delete only the primary key
        result = self._run_gpg(["--delete-secret-keys", f"{fingerprint}!"])

        if result.returncode != 0:
            return Result.err(GPGError(f"Deletion failed: {result.stderr}"))

        return Result.ok(None)

    def verify_key_exists(
        self,
        key_id: str,
        secret: bool = False,
    ) -> bool:
        cmd = "--list-secret-keys" if secret else "--list-keys"
        result = self._run_gpg([cmd, key_id])
        return result.returncode == 0

    def list_secret_keys(self) -> Result[list[KeyInfo]]:
        result = self._run_gpg(["--with-colons", "--list-secret-keys"])

        if result.returncode != 0:
            return Result.err(GPGError(f"List failed: {result.stderr}"))

        keys = []
        current_keyid = None

        for line in result.stdout.split("\n"):
            if line.startswith("sec:"):
                fields = line.split(":")
                current_keyid = fields[4]
            elif line.startswith("uid:") and current_keyid:
                fields = line.split(":")
                keys.append(
                    KeyInfo(
                        key_id=current_keyid,
                        fingerprint=current_keyid,
                        creation_date=datetime.now(UTC),
                        expiry_date=None,
                        identity=fields[9],
                        key_type=KeyType.ED25519,
                    )
                )
                current_keyid = None

        return Result.ok(keys)

    def generate_all_subkeys(
        self,
        master_key_id: str,
        passphrase: SecureString,
        key_type: KeyType = KeyType.ED25519,
        expiry_days: int = 730,
    ) -> Result[list[SubkeyInfo]]:
        """Generate all three subkeys (sign, encrypt, authenticate) for a master key."""
        subkeys: list[SubkeyInfo] = []

        for usage in [KeyUsage.SIGN, KeyUsage.ENCRYPT, KeyUsage.AUTHENTICATE]:
            result = self.generate_subkey(
                master_key_id,
                passphrase,
                usage,
                key_type,
                expiry_days,
            )
            if result.is_err():
                return Result.err(result.unwrap_err())
            subkeys.append(result.unwrap())

        return Result.ok(subkeys)

    def add_uid(
        self,
        key_id: str,
        passphrase: SecureString,
        name: str,
        email: str,
        comment: str = "",
    ) -> Result[None]:
        """Add a new user ID to an existing key."""
        cmd = ["gpg", "--expert", "--pinentry-mode", "loopback", "--edit-key", key_id]

        try:
            child = pexpect.spawn(
                cmd[0],
                cmd[1:],
                env=self._env,
                encoding="utf-8",
                timeout=60,
            )

            child.expect(r"gpg>")
            child.sendline("adduid")

            child.expect(r"Real name:")
            child.sendline(name)

            child.expect(r"Email address:")
            child.sendline(email)

            child.expect(r"Comment:")
            child.sendline(comment)

            # Confirm
            child.expect(r"\(O\)kay")
            child.sendline("o")

            # Passphrase
            child.expect(r"Enter passphrase:|passphrase:")
            child.sendline(passphrase.get())

            child.expect(r"gpg>")
            child.sendline("save")
            child.expect(pexpect.EOF)
            child.close()

            if child.exitstatus != 0:
                return Result.err(GPGError(f"Add UID failed with status {child.exitstatus}"))

        except pexpect.exceptions.TIMEOUT as e:
            return Result.err(GPGError(f"Timeout adding UID: {e}"))
        except pexpect.exceptions.EOF as e:
            return Result.err(GPGError(f"Unexpected EOF adding UID: {e}"))

        return Result.ok(None)

    def set_primary_uid(
        self,
        key_id: str,
        passphrase: SecureString,
        uid_index: int,
    ) -> Result[None]:
        """Set a UID as the primary UID."""
        cmd = ["gpg", "--expert", "--pinentry-mode", "loopback", "--edit-key", key_id]

        try:
            child = pexpect.spawn(
                cmd[0],
                cmd[1:],
                env=self._env,
                encoding="utf-8",
                timeout=60,
            )

            child.expect(r"gpg>")
            child.sendline(f"uid {uid_index}")

            child.expect(r"gpg>")
            child.sendline("primary")

            child.expect(r"Enter passphrase:|passphrase:")
            child.sendline(passphrase.get())

            child.expect(r"gpg>")
            child.sendline("save")
            child.expect(pexpect.EOF)
            child.close()

        except pexpect.exceptions.TIMEOUT as e:
            return Result.err(GPGError(f"Timeout setting primary UID: {e}"))
        except pexpect.exceptions.EOF as e:
            return Result.err(GPGError(f"Unexpected EOF setting primary UID: {e}"))

        return Result.ok(None)

    def renew_subkey(
        self,
        key_id: str,
        passphrase: SecureString,
        subkey_index: int,
        expiry_days: int = 730,
    ) -> Result[None]:
        """Extend the expiration date of a subkey."""
        cmd = ["gpg", "--expert", "--pinentry-mode", "loopback", "--edit-key", key_id]

        try:
            child = pexpect.spawn(
                cmd[0],
                cmd[1:],
                env=self._env,
                encoding="utf-8",
                timeout=60,
            )

            child.expect(r"gpg>")
            child.sendline(f"key {subkey_index}")

            child.expect(r"gpg>")
            child.sendline("expire")

            child.expect(r"Key is valid for\?")
            child.sendline(f"{expiry_days}d")

            child.expect(r"Is this correct\?")
            child.sendline("y")

            child.expect(r"Enter passphrase:|passphrase:")
            child.sendline(passphrase.get())

            child.expect(r"gpg>")
            child.sendline("save")
            child.expect(pexpect.EOF)
            child.close()

        except pexpect.exceptions.TIMEOUT as e:
            return Result.err(GPGError(f"Timeout renewing subkey: {e}"))
        except pexpect.exceptions.EOF as e:
            return Result.err(GPGError(f"Unexpected EOF renewing subkey: {e}"))

        return Result.ok(None)

    def renew_all_subkeys(
        self,
        key_id: str,
        passphrase: SecureString,
        expiry_days: int = 730,
    ) -> Result[None]:
        """Extend the expiration of all subkeys."""
        # Get count of subkeys
        result = self._run_gpg(["--with-colons", "--list-keys", key_id])
        if result.returncode != 0:
            return Result.err(GPGError(f"Could not get key info: {result.stderr}"))

        subkey_count = sum(1 for line in result.stdout.split("\n") if line.startswith("sub:"))

        for i in range(1, subkey_count + 1):
            res = self.renew_subkey(key_id, passphrase, i, expiry_days)
            if res.is_err():
                return res

        return Result.ok(None)

    def export_ssh_key(self, key_id: str) -> Result[str]:
        """Export the authentication subkey in SSH format."""
        result = self._run_gpg(["--export-ssh-key", key_id])

        if result.returncode != 0:
            return Result.err(GPGError(f"SSH key export failed: {result.stderr}"))

        return Result.ok(result.stdout.strip())

    def send_to_keyserver(
        self,
        key_id: str,
        keyserver: str = "hkps://keys.openpgp.org",
    ) -> Result[None]:
        """Upload public key to a keyserver."""
        result = self._run_gpg(
            [
                "--keyserver",
                keyserver,
                "--send-keys",
                key_id,
            ]
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Keyserver upload failed: {result.stderr}"))

        return Result.ok(None)

    def receive_from_keyserver(
        self,
        key_id: str,
        keyserver: str = "hkps://keys.openpgp.org",
    ) -> Result[KeyInfo]:
        """Download a key from a keyserver."""
        result = self._run_gpg(
            [
                "--keyserver",
                keyserver,
                "--recv-keys",
                key_id,
            ]
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Keyserver download failed: {result.stderr}"))

        return self.get_key_info(key_id)

    def search_keyserver(
        self,
        query: str,
        keyserver: str = "hkps://keys.openpgp.org",
    ) -> Result[list[str]]:
        """Search for keys on a keyserver."""
        result = subprocess.run(
            ["gpg", "--batch", "--keyserver", keyserver, "--search-keys", query],
            capture_output=True,
            text=True,
            env=self._env,
            input="",  # Don't select any
        )

        # Parse results - gpg outputs key IDs in search results
        key_ids = re.findall(r"key ([A-F0-9]{16})", result.stdout + result.stderr, re.IGNORECASE)
        return Result.ok(list(set(key_ids)))

    def list_subkeys(self, key_id: str) -> Result[list[SubkeyInfo]]:
        """List all subkeys for a given master key."""
        result = self._run_gpg(["--with-colons", "--list-keys", key_id])

        if result.returncode != 0:
            return Result.err(GPGError(f"Could not list subkeys: {result.stderr}"))

        subkeys: list[SubkeyInfo] = []
        for line in result.stdout.split("\n"):
            if line.startswith("sub:"):
                fields = line.split(":")
                cap = fields[11] if len(fields) > 11 else ""

                # Determine usage from capabilities
                if "e" in cap.lower():
                    usage = KeyUsage.ENCRYPT
                elif "s" in cap.lower():
                    usage = KeyUsage.SIGN
                elif "a" in cap.lower():
                    usage = KeyUsage.AUTHENTICATE
                else:
                    usage = KeyUsage.SIGN  # Default

                subkeys.append(
                    SubkeyInfo(
                        key_id=fields[4],
                        fingerprint=fields[4],
                        creation_date=datetime.fromtimestamp(int(fields[5]), tz=UTC),
                        expiry_date=datetime.fromtimestamp(int(fields[6]), tz=UTC)
                        if fields[6]
                        else None,
                        usage=usage,
                        key_type=KeyType.ED25519,
                        parent_key_id=key_id,
                    )
                )

        return Result.ok(subkeys)

    def transfer_key_to_card(
        self,
        key_id: str,
        passphrase: SecureString,
        admin_pin: SecureString,
        slot: KeySlot,
        subkey_index: int,
    ) -> Result[None]:
        """Transfer a subkey to a smartcard (YubiKey).

        Uses the drduh/YubiKey-Guide approach with --command-fd=0 to pipe
        commands via stdin, which is more reliable than interactive pexpect.
        """
        slot_num = {
            KeySlot.SIGNATURE: "1",
            KeySlot.ENCRYPTION: "2",
            KeySlot.AUTHENTICATION: "3",
        }[slot]

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

        cmd = [
            "gpg",
            "--command-fd",
            "0",
            "--pinentry-mode",
            "loopback",
            "--edit-key",
            key_id,
        ]

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
            return Result.err(GPGError("Key transfer timed out after 120 seconds"))

        if result.returncode != 0:
            return Result.err(GPGError(f"Key transfer failed: {result.stderr}"))

        return Result.ok(None)

    def transfer_all_subkeys_to_card(
        self,
        key_id: str,
        passphrase: SecureString,
        admin_pin: SecureString,
    ) -> Result[None]:
        """Transfer all subkeys to a smartcard in the correct slots."""
        # Get subkey info to determine which index goes to which slot
        subkeys_result = self.list_subkeys(key_id)
        if subkeys_result.is_err():
            return Result.err(subkeys_result.unwrap_err())

        subkeys = subkeys_result.unwrap()

        usage_to_slot = {
            KeyUsage.SIGN: KeySlot.SIGNATURE,
            KeyUsage.ENCRYPT: KeySlot.ENCRYPTION,
            KeyUsage.AUTHENTICATE: KeySlot.AUTHENTICATION,
        }

        for i, subkey in enumerate(subkeys, start=1):
            slot = usage_to_slot.get(subkey.usage)
            if slot:
                result = self.transfer_key_to_card(key_id, passphrase, admin_pin, slot, i)
                if result.is_err():
                    return result

        return Result.ok(None)

    def generate_revocation_certificate(
        self,
        key_id: str,
        output_path: Path,
        passphrase: SecureString | None = None,
        reason: int = 0,
        description: str = "",
    ) -> Result[Path]:
        """Generate a revocation certificate for the key.

        Reason codes:
        0 = No reason specified
        1 = Key has been compromised
        2 = Key is superseded
        3 = Key is no longer used

        Uses pexpect to handle the interactive prompts:
        1. "Create a revocation certificate for this key? (y/N)" -> y
        2. "Your decision?" -> reason code (0-3)
        3. "Enter an optional description" -> description + empty line
        4. "Is this okay? (y/N)" -> y
        5. Passphrase prompt (if key is protected)
        """
        cmd = [
            "gpg",
            "--pinentry-mode",
            "loopback",
            "--output",
            str(output_path),
            "--gen-revoke",
            key_id,
        ]

        try:
            child = pexpect.spawn(
                cmd[0],
                cmd[1:],
                env=self._env,
                encoding="utf-8",
                timeout=30,
            )

            # 1. Create revocation certificate? (y/N)
            child.expect(r"Create a revocation certificate.*\(y/N\)", timeout=10)
            child.sendline("y")

            # 2. Select reason (shows menu, then "Your decision?")
            child.expect(r"Your decision\?", timeout=10)
            child.sendline(str(reason))

            # 3. Enter optional description (end with empty line)
            child.expect(r"Enter an optional description", timeout=10)
            if description:
                child.sendline(description)
            child.sendline("")  # Empty line to end description

            # 4. Is this okay? (y/N)
            child.expect(r"Is this okay\?.*\(y/N\)", timeout=10)
            child.sendline("y")

            # 5. Passphrase prompt (if key is protected)
            if passphrase:
                try:
                    child.expect(r"Enter passphrase:|passphrase:", timeout=10)
                    child.sendline(passphrase.get())
                except pexpect.TIMEOUT:
                    # Key might not be protected, continue
                    pass

            child.expect(pexpect.EOF, timeout=30)
            child.close()

            if child.exitstatus != 0:
                return Result.err(
                    GPGError(
                        f"Revocation certificate generation failed with status {child.exitstatus}"
                    )
                )

            return Result.ok(output_path)

        except pexpect.TIMEOUT as e:
            return Result.err(GPGError(f"Revocation certificate generation timed out: {e}"))
        except pexpect.EOF as e:
            return Result.err(
                GPGError(f"Revocation certificate generation ended unexpectedly: {e}")
            )

    def sign_data(
        self,
        key_id: str,
        data: bytes,
        passphrase: SecureString,
        detached: bool = True,
    ) -> Result[bytes]:
        """Sign data using the specified key."""
        args = [
            "--armor",
            "--local-user",
            key_id,
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
        ]
        if detached:
            args.append("--detach-sign")
        else:
            args.append("--sign")

        result = subprocess.run(
            ["gpg", "--batch", "--yes"] + args,
            input=passphrase.get().encode() + b"\n" + data,
            capture_output=True,
            env=self._env,
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Signing failed: {result.stderr.decode()}"))

        return Result.ok(result.stdout)

    def encrypt_data(
        self,
        recipient_key_id: str,
        data: bytes,
        sign_key_id: str | None = None,
        passphrase: SecureString | None = None,
    ) -> Result[bytes]:
        """Encrypt data for a recipient."""
        args = ["--armor", "--recipient", recipient_key_id, "--encrypt"]

        if sign_key_id and passphrase:
            args.extend(
                [
                    "--sign",
                    "--local-user",
                    sign_key_id,
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase-fd",
                    "0",
                ]
            )
            input_data = passphrase.get().encode() + b"\n" + data
        else:
            input_data = data

        result = subprocess.run(
            ["gpg", "--batch", "--yes"] + args,
            input=input_data,
            capture_output=True,
            env=self._env,
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Encryption failed: {result.stderr.decode()}"))

        return Result.ok(result.stdout)

    def decrypt_data(
        self,
        data: bytes,
        passphrase: SecureString,
    ) -> Result[bytes]:
        """Decrypt data."""
        result = subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--decrypt",
            ],
            input=passphrase.get().encode() + b"\n" + data,
            capture_output=True,
            env=self._env,
        )

        if result.returncode != 0:
            return Result.err(GPGError(f"Decryption failed: {result.stderr.decode()}"))

        return Result.ok(result.stdout)
