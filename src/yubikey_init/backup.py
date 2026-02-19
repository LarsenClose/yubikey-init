from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .types import Result, SecureString


class BackupError(Exception):
    pass


@dataclass
class FileChecksum:
    """Checksum information for a backup file."""

    filename: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileChecksum:
        return cls(
            filename=data["filename"],
            sha256=data["sha256"],
            size_bytes=data["size_bytes"],
        )


@dataclass
class BackupManifest:
    """Manifest of backup contents."""

    created_at: datetime
    key_id: str
    fingerprint: str
    identity: str
    files: list[str]
    backup_path: Path
    checksums: list[FileChecksum] = field(default_factory=list)
    gnupghome_included: bool = False
    version: str = "2.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "identity": self.identity,
            "files": self.files,
            "backup_path": str(self.backup_path),
            "checksums": [c.to_dict() for c in self.checksums],
            "gnupghome_included": self.gnupghome_included,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupManifest:
        checksums = [FileChecksum.from_dict(c) for c in data.get("checksums", [])]
        return cls(
            version=data.get("version", "1.0.0"),
            created_at=datetime.fromisoformat(data["created_at"]),
            key_id=data["key_id"],
            fingerprint=data["fingerprint"],
            identity=data["identity"],
            files=data["files"],
            backup_path=Path(data["backup_path"]),
            checksums=checksums,
            gnupghome_included=data.get("gnupghome_included", False),
        )


EXPECTED_BACKUP_FILES = [
    "master-key.asc",  # Full secret key (master + subkeys)
    "subkeys.asc",  # Secret subkeys only (for daily use)
    "public-key.asc",  # Public key
    "revocation-cert.asc",  # Revocation certificate
    "manifest.json",  # Backup manifest
]

OPTIONAL_BACKUP_FILES = [
    "master-key.paper",  # Paperkey output
    "ssh-public-key.pub",  # SSH public key
    "gnupghome/",  # Full GNUPGHOME directory copy
]

# Files that go on the PUBLIC partition (shareable)
PUBLIC_PARTITION_FILES = [
    "public-key.asc",
    "ssh-public-key.pub",
]


def create_backup_directory(
    backup_path: Path,
    key_id: str,
) -> Result[Path]:
    """Create a timestamped backup directory."""
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    key_short = key_id[-8:] if len(key_id) >= 8 else key_id
    dir_name = f"gpg-backup-{key_short}-{timestamp}"
    full_path = backup_path / dir_name

    try:
        full_path.mkdir(parents=True, exist_ok=True)
        return Result.ok(full_path)
    except OSError as e:
        return Result.err(BackupError(f"Could not create backup directory: {e}"))


def copy_public_files_to_partition(
    backup_path: Path,
    public_mount: Path,
) -> Result[list[str]]:
    """Copy public files from the backup to the public partition.

    This copies the public key and SSH public key to the unencrypted
    public partition so they can be accessed without unlocking the
    encrypted partition.

    Args:
        backup_path: Path to the backup directory (on encrypted partition)
        public_mount: Mount point of the public partition

    Returns:
        List of files copied successfully
    """
    copied = []

    for filename in PUBLIC_PARTITION_FILES:
        source = backup_path / filename
        dest = public_mount / filename

        if source.exists():
            try:
                shutil.copy2(source, dest)
                copied.append(filename)
            except OSError as e:
                return Result.err(
                    BackupError(f"Failed to copy {filename} to public partition: {e}")
                )

    return Result.ok(copied)


def verify_backup_complete(backup_path: Path) -> Result[list[str]]:
    """Verify that all required backup files are present."""
    missing = []

    for filename in EXPECTED_BACKUP_FILES:
        filepath = backup_path / filename
        if not filepath.exists():
            missing.append(filename)

    if missing:
        return Result.err(BackupError(f"Missing backup files: {', '.join(missing)}"))

    return Result.ok(list(EXPECTED_BACKUP_FILES))


def generate_paperkey(
    secret_key_path: Path,
    output_path: Path,
) -> Result[Path]:
    """Generate a paperkey backup from a secret key file.

    Paperkey extracts only the secret parts of a GPG key,
    which can be printed and stored as a physical backup.
    """
    if not shutil.which("paperkey"):
        return Result.err(BackupError("paperkey is not installed"))

    try:
        with open(secret_key_path, "rb") as key_file:
            result = subprocess.run(
                ["paperkey", "--output", str(output_path)],
                stdin=key_file,
                capture_output=True,
            )

        if result.returncode != 0:
            return Result.err(BackupError(f"paperkey failed: {result.stderr.decode()}"))

        return Result.ok(output_path)
    except Exception as e:
        return Result.err(BackupError(f"paperkey generation failed: {e}"))


def restore_from_paperkey(
    paperkey_path: Path,
    public_key_path: Path,
    output_path: Path,
) -> Result[Path]:
    """Restore a secret key from paperkey and public key.

    This combines the paperkey backup with the public key
    to recreate the full secret key.
    """
    if not shutil.which("paperkey"):
        return Result.err(BackupError("paperkey is not installed"))

    try:
        with open(paperkey_path, "rb") as paper_file:
            result = subprocess.run(
                [
                    "paperkey",
                    "--pubring",
                    str(public_key_path),
                    "--output",
                    str(output_path),
                ],
                stdin=paper_file,
                capture_output=True,
            )

        if result.returncode != 0:
            return Result.err(BackupError(f"paperkey restore failed: {result.stderr.decode()}"))

        return Result.ok(output_path)
    except Exception as e:
        return Result.err(BackupError(f"paperkey restore failed: {e}"))


def create_full_backup(
    gnupghome: Path,
    backup_path: Path,
    key_id: str,
    passphrase: SecureString,
    include_paperkey: bool = True,
    include_ssh: bool = True,
) -> Result[BackupManifest]:
    """Create a complete backup of GPG keys.

    This creates:
    - Full secret key export (master + subkeys)
    - Secret subkeys only export (for daily use import)
    - Public key export
    - Revocation certificate
    - Optionally: paperkey backup
    - Optionally: SSH public key
    - Manifest file
    """
    import json

    from .gpg_ops import GPGOperations

    # Create backup directory
    dir_result = create_backup_directory(backup_path, key_id)
    if dir_result.is_err():
        return Result.err(dir_result.unwrap_err())

    backup_dir = dir_result.unwrap()
    gpg = GPGOperations(gnupghome)
    files_created = []

    # Get key info for manifest
    key_info_result = gpg.get_key_info(key_id)
    if key_info_result.is_err():
        return Result.err(key_info_result.unwrap_err())
    key_info = key_info_result.unwrap()

    # Get fingerprint
    fp_result = gpg.get_key_fingerprint(key_id)
    fingerprint = fp_result.unwrap() if fp_result.is_ok() else key_id

    # Export full secret key
    master_key_path = backup_dir / "master-key.asc"
    result = gpg.export_secret_keys(key_id, passphrase, master_key_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("master-key.asc")

    # Export secret subkeys only
    subkeys_path = backup_dir / "subkeys.asc"
    result = gpg.export_secret_subkeys(key_id, passphrase, subkeys_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("subkeys.asc")

    # Export public key
    public_key_path = backup_dir / "public-key.asc"
    result = gpg.export_public_key(key_id, public_key_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("public-key.asc")

    # Generate revocation certificate (required for complete backup)
    revoke_path = backup_dir / "revocation-cert.asc"
    result = gpg.generate_revocation_certificate(key_id, revoke_path, passphrase=passphrase)
    if result.is_err():
        return Result.err(
            BackupError(f"Failed to generate revocation certificate: {result.unwrap_err()}")
        )
    files_created.append("revocation-cert.asc")

    # Generate paperkey backup
    if include_paperkey and shutil.which("paperkey"):
        paper_path = backup_dir / "master-key.paper"
        result = generate_paperkey(master_key_path, paper_path)
        if result.is_ok():
            files_created.append("master-key.paper")

    # Export SSH public key
    if include_ssh:
        ssh_result = gpg.export_ssh_key(key_id)
        if ssh_result.is_ok():
            ssh_path = backup_dir / "ssh-public-key.pub"
            ssh_path.write_text(ssh_result.unwrap())
            files_created.append("ssh-public-key.pub")

    # Create manifest
    manifest = BackupManifest(
        created_at=datetime.now(UTC),
        key_id=key_id,
        fingerprint=fingerprint,
        identity=key_info.identity,
        files=files_created,
        backup_path=backup_dir,
    )

    manifest_path = backup_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))
    files_created.append("manifest.json")

    # Set restrictive permissions on all files
    import contextlib

    for filename in files_created:
        filepath = backup_dir / filename
        with contextlib.suppress(Exception):
            filepath.chmod(0o600)

    with contextlib.suppress(Exception):
        backup_dir.chmod(0o700)

    return Result.ok(manifest)


def list_backups(backup_root: Path) -> list[BackupManifest]:
    """List all backup manifests in a directory."""
    import json

    manifests: list[BackupManifest] = []

    if not backup_root.exists():
        return manifests

    for item in backup_root.iterdir():
        if item.is_dir():
            manifest_path = item / "manifest.json"
            if manifest_path.exists():
                try:
                    data = json.loads(manifest_path.read_text())
                    manifests.append(
                        BackupManifest(
                            created_at=datetime.fromisoformat(data["created_at"]),
                            key_id=data["key_id"],
                            fingerprint=data["fingerprint"],
                            identity=data["identity"],
                            files=data["files"],
                            backup_path=Path(data["backup_path"]),
                        )
                    )
                except Exception:
                    pass

    # Sort by creation date, newest first
    manifests.sort(key=lambda m: m.created_at, reverse=True)
    return manifests


def verify_backup_integrity(backup_path: Path) -> Result[bool]:
    """Verify that backup files haven't been corrupted.

    This checks:
    - All expected files exist
    - GPG can parse the key files
    - Manifest matches actual files
    """
    import json

    # Check manifest exists
    manifest_path = backup_path / "manifest.json"
    if not manifest_path.exists():
        return Result.err(BackupError("Manifest file not found"))

    try:
        manifest_data = json.loads(manifest_path.read_text())
    except Exception as e:
        return Result.err(BackupError(f"Could not read manifest: {e}"))

    # Verify all listed files exist
    for filename in manifest_data.get("files", []):
        filepath = backup_path / filename
        if not filepath.exists():
            return Result.err(BackupError(f"Missing file from manifest: {filename}"))

    # Verify GPG can read the key files
    for key_file in ["master-key.asc", "subkeys.asc", "public-key.asc"]:
        filepath = backup_path / key_file
        if filepath.exists():
            result = subprocess.run(
                ["gpg", "--batch", "--list-packets", str(filepath)],
                capture_output=True,
            )
            if result.returncode != 0:
                return Result.err(BackupError(f"GPG cannot parse {key_file}"))

    return Result.ok(True)


def import_from_backup(
    backup_path: Path,
    gnupghome: Path,
    passphrase: SecureString,
    subkeys_only: bool = True,
) -> Result[str]:
    """Import keys from a backup.

    By default, only imports subkeys (recommended for daily use).
    The master key should remain on encrypted offline storage.
    """
    from .gpg_ops import GPGOperations

    gpg = GPGOperations(gnupghome)

    # Choose which key file to import
    key_file = backup_path / "subkeys.asc" if subkeys_only else backup_path / "master-key.asc"

    if not key_file.exists():
        return Result.err(BackupError(f"Key file not found: {key_file}"))

    # Import the key
    result = gpg.import_key(key_file, passphrase)
    if result.is_err():
        return Result.err(result.unwrap_err())

    key_info = result.unwrap()
    return Result.ok(key_info.key_id)


def calculate_file_checksum(file_path: Path) -> FileChecksum:
    """Calculate SHA256 checksum of a file."""
    sha256 = hashlib.sha256()
    size = 0

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            size += len(chunk)

    return FileChecksum(
        filename=file_path.name,
        sha256=sha256.hexdigest(),
        size_bytes=size,
    )


def calculate_directory_checksums(directory: Path) -> list[FileChecksum]:
    """Calculate checksums for all files in a directory (recursive)."""
    checksums = []

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(directory)
            checksum = calculate_file_checksum(file_path)
            checksum.filename = str(relative_path)
            checksums.append(checksum)

    return checksums


def copy_gnupghome(
    source_gnupghome: Path,
    backup_dir: Path,
) -> Result[Path]:
    """Copy entire GNUPGHOME directory to backup location.

    This provides a complete backup that can be used for full recovery,
    including trust database, configuration, and all keys.
    """
    dest_dir = backup_dir / "gnupghome"

    try:
        # Remove existing if present
        if dest_dir.exists():
            shutil.rmtree(dest_dir)

        # Copy entire directory
        shutil.copytree(
            source_gnupghome,
            dest_dir,
            symlinks=False,
            ignore=shutil.ignore_patterns(
                "*.lock",
                "S.*",  # Socket files
                "random_seed",
            ),
        )

        # Set restrictive permissions
        dest_dir.chmod(0o700)
        for item in dest_dir.rglob("*"):
            if item.is_file():
                item.chmod(0o600)
            elif item.is_dir():
                item.chmod(0o700)

        return Result.ok(dest_dir)
    except Exception as e:
        return Result.err(BackupError(f"Failed to copy GNUPGHOME: {e}"))


def copy_to_backup_drive(
    gnupghome: Path,
    encrypted_mount: Path,
    public_mount: Path,
    key_id: str,
    passphrase: SecureString,
    include_gnupghome: bool = True,
    include_paperkey: bool = True,
    include_ssh: bool = True,
) -> Result[BackupManifest]:
    """Create a complete backup on a dual-partition backup drive.

    This is the main backup function for the new workflow that:
    1. Creates a backup directory on the encrypted partition
    2. Exports all key material to the encrypted partition
    3. Copies public key and SSH key to the public partition
    4. Generates checksums for verification
    5. Returns a manifest with all backup information

    Args:
        gnupghome: Path to GNUPGHOME to backup
        encrypted_mount: Mount point of encrypted partition
        public_mount: Mount point of public partition
        key_id: GPG key ID to backup
        passphrase: Passphrase for the key
        include_gnupghome: Whether to copy full GNUPGHOME directory
        include_paperkey: Whether to generate paperkey backup
        include_ssh: Whether to export SSH public key
    """
    from .gpg_ops import GPGOperations

    # Create backup directory on encrypted partition
    dir_result = create_backup_directory(encrypted_mount, key_id)
    if dir_result.is_err():
        return Result.err(dir_result.unwrap_err())

    backup_dir = dir_result.unwrap()
    gpg = GPGOperations(gnupghome)
    files_created: list[str] = []
    checksums: list[FileChecksum] = []

    # Get key info for manifest
    key_info_result = gpg.get_key_info(key_id)
    if key_info_result.is_err():
        return Result.err(key_info_result.unwrap_err())
    key_info = key_info_result.unwrap()

    # Get fingerprint
    fp_result = gpg.get_key_fingerprint(key_id)
    fingerprint = fp_result.unwrap() if fp_result.is_ok() else key_id

    # 1. Copy entire GNUPGHOME (if requested)
    gnupghome_copied = False
    if include_gnupghome:
        result = copy_gnupghome(gnupghome, backup_dir)
        if result.is_ok():
            files_created.append("gnupghome/")
            gnupghome_copied = True
            # Add checksums for gnupghome contents
            checksums.extend(calculate_directory_checksums(result.unwrap()))

    # 2. Export full secret key
    master_key_path = backup_dir / "master-key.asc"
    result = gpg.export_secret_keys(key_id, passphrase, master_key_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("master-key.asc")
    checksums.append(calculate_file_checksum(master_key_path))

    # 3. Export secret subkeys only
    subkeys_path = backup_dir / "subkeys.asc"
    result = gpg.export_secret_subkeys(key_id, passphrase, subkeys_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("subkeys.asc")
    checksums.append(calculate_file_checksum(subkeys_path))

    # 4. Export public key (to BOTH partitions)
    public_key_path = backup_dir / "public-key.asc"
    result = gpg.export_public_key(key_id, public_key_path)
    if result.is_err():
        return Result.err(result.unwrap_err())
    files_created.append("public-key.asc")
    checksums.append(calculate_file_checksum(public_key_path))

    # Copy public key to public partition
    public_partition_key = public_mount / "public-key.asc"
    try:
        shutil.copy2(public_key_path, public_partition_key)
    except Exception as e:
        return Result.err(BackupError(f"Failed to copy public key to public partition: {e}"))

    # 5. Generate revocation certificate (required for complete backup)
    revoke_path = backup_dir / "revocation-cert.asc"
    result = gpg.generate_revocation_certificate(key_id, revoke_path, passphrase=passphrase)
    if result.is_err():
        return Result.err(
            BackupError(f"Failed to generate revocation certificate: {result.unwrap_err()}")
        )
    files_created.append("revocation-cert.asc")
    checksums.append(calculate_file_checksum(revoke_path))

    # 6. Generate paperkey backup
    if include_paperkey and shutil.which("paperkey"):
        paper_path = backup_dir / "master-key.paper"
        result = generate_paperkey(master_key_path, paper_path)
        if result.is_ok():
            files_created.append("master-key.paper")
            checksums.append(calculate_file_checksum(paper_path))

    # 7. Export SSH public key (to BOTH partitions)
    if include_ssh:
        ssh_result = gpg.export_ssh_key(key_id)
        if ssh_result.is_ok():
            ssh_content = ssh_result.unwrap()

            # Write to encrypted partition
            ssh_path = backup_dir / "ssh-public-key.pub"
            ssh_path.write_text(ssh_content)
            files_created.append("ssh-public-key.pub")
            checksums.append(calculate_file_checksum(ssh_path))

            # Copy to public partition
            public_ssh_path = public_mount / "ssh-public-key.pub"
            public_ssh_path.write_text(ssh_content)

    # 8. Create manifest with checksums
    manifest = BackupManifest(
        created_at=datetime.now(UTC),
        key_id=key_id,
        fingerprint=fingerprint,
        identity=key_info.identity,
        files=files_created,
        backup_path=backup_dir,
        checksums=checksums,
        gnupghome_included=gnupghome_copied,
        version="2.0.0",
    )

    manifest_path = backup_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))

    # 9. Set restrictive permissions
    import contextlib

    for filename in files_created:
        if filename.endswith("/"):
            continue  # Directory, already handled
        filepath = backup_dir / filename
        with contextlib.suppress(Exception):
            filepath.chmod(0o600)

    with contextlib.suppress(Exception):
        backup_dir.chmod(0o700)
        manifest_path.chmod(0o600)

    return Result.ok(manifest)


def verify_backup_checksums(backup_path: Path) -> Result[list[str]]:
    """Verify backup files against stored checksums.

    Returns a list of files that failed verification, or empty list if all good.
    """
    manifest_path = backup_path / "manifest.json"

    if not manifest_path.exists():
        return Result.err(BackupError("Manifest file not found"))

    try:
        data = json.loads(manifest_path.read_text())
        manifest = BackupManifest.from_dict(data)
    except Exception as e:
        return Result.err(BackupError(f"Could not read manifest: {e}"))

    failed_files: list[str] = []

    for expected in manifest.checksums:
        file_path = backup_path / expected.filename

        if not file_path.exists():
            failed_files.append(f"{expected.filename} (missing)")
            continue

        actual = calculate_file_checksum(file_path)
        # For files in subdirectories, recalculate with relative path
        if "/" in expected.filename:
            actual.filename = expected.filename

        if actual.sha256 != expected.sha256:
            failed_files.append(f"{expected.filename} (checksum mismatch)")
        elif actual.size_bytes != expected.size_bytes:
            failed_files.append(f"{expected.filename} (size mismatch)")

    return Result.ok(failed_files)


def readback_verify_backup(
    backup_path: Path,
    public_mount: Path,
) -> Result[bool]:
    """Perform read-back verification of a backup.

    This reads all backup files from disk to verify they're readable
    and match expected checksums. Also verifies public partition files.
    """
    # Verify encrypted partition
    checksum_result = verify_backup_checksums(backup_path)
    if checksum_result.is_err():
        return Result.err(checksum_result.unwrap_err())

    failed = checksum_result.unwrap()
    if failed:
        return Result.err(BackupError(f"Verification failed for: {', '.join(failed)}"))

    # Verify public partition files exist and are readable
    for filename in PUBLIC_PARTITION_FILES:
        public_file = public_mount / filename
        encrypted_file = backup_path / filename

        if encrypted_file.exists():
            if not public_file.exists():
                return Result.err(BackupError(f"Missing from public partition: {filename}"))

            # Verify contents match
            try:
                public_content = public_file.read_bytes()
                encrypted_content = encrypted_file.read_bytes()
                if public_content != encrypted_content:
                    return Result.err(BackupError(f"Public partition mismatch: {filename}"))
            except Exception as e:
                return Result.err(BackupError(f"Could not verify {filename}: {e}"))

    # Verify GPG can parse the key files
    for key_file in ["master-key.asc", "subkeys.asc", "public-key.asc"]:
        filepath = backup_path / key_file
        if filepath.exists():
            result = subprocess.run(
                ["gpg", "--batch", "--list-packets", str(filepath)],
                capture_output=True,
            )
            if result.returncode != 0:
                return Result.err(BackupError(f"GPG cannot parse {key_file}"))

    return Result.ok(True)
