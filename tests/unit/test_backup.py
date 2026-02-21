"""Tests for backup module."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from yubikey_init.backup import (
    EXPECTED_BACKUP_FILES,
    BackupManifest,
    copy_public_files_to_partition,
    create_backup_directory,
    generate_paperkey,
    list_backups,
    restore_from_paperkey,
    verify_backup_complete,
    verify_backup_integrity,
)


class TestBackupManifest:
    """Test BackupManifest dataclass."""

    def test_manifest_creation(self):
        """Test creating a backup manifest."""
        manifest = BackupManifest(
            created_at=datetime.now(UTC),
            key_id="ABCD1234",
            fingerprint="1234567890ABCDEF",
            identity="Test User <test@example.com>",
            files=["master-key.asc", "public-key.asc"],
            backup_path=Path("/tmp/backup"),
        )

        assert manifest.key_id == "ABCD1234"
        assert len(manifest.files) == 2

    def test_manifest_to_dict(self):
        """Test manifest serialization."""
        manifest = BackupManifest(
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            key_id="ABCD1234",
            fingerprint="1234567890ABCDEF",
            identity="Test User <test@example.com>",
            files=["master-key.asc"],
            backup_path=Path("/tmp/backup"),
        )

        data = manifest.to_dict()

        assert data["key_id"] == "ABCD1234"
        assert "2024-01-01" in data["created_at"]
        assert data["files"] == ["master-key.asc"]


class TestBackupDirectory:
    """Test backup directory creation."""

    def test_create_backup_directory(self, tmp_path):
        """Test creating a timestamped backup directory."""
        result = create_backup_directory(tmp_path, "ABCD1234567890EF")

        assert result.is_ok()
        backup_dir = result.unwrap()
        assert backup_dir.exists()
        assert "gpg-backup" in str(backup_dir)
        assert "7890EF" in str(backup_dir)  # Last 8 chars of key ID

    def test_create_backup_directory_creates_parents(self, tmp_path):
        """Test that parent directories are created."""
        nested_path = tmp_path / "deep" / "nested" / "path"
        result = create_backup_directory(nested_path, "ABCD1234")

        assert result.is_ok()
        assert result.unwrap().exists()


class TestVerifyBackup:
    """Test backup verification."""

    def test_verify_backup_complete_all_files(self, tmp_path):
        """Test verification passes when all files present."""
        # Create expected files
        for filename in EXPECTED_BACKUP_FILES:
            (tmp_path / filename).write_text("test content")

        result = verify_backup_complete(tmp_path)

        assert result.is_ok()
        found_files = result.unwrap()
        assert len(found_files) == len(EXPECTED_BACKUP_FILES)

    def test_verify_backup_complete_missing_files(self, tmp_path):
        """Test verification fails when files are missing."""
        # Create only some files
        (tmp_path / "master-key.asc").write_text("test")

        result = verify_backup_complete(tmp_path)

        assert result.is_err()
        assert "Missing" in str(result.unwrap_err())

    def test_verify_backup_complete_nonexistent_path(self, tmp_path):
        """Test verification fails for nonexistent path."""
        nonexistent = tmp_path / "does_not_exist"
        result = verify_backup_complete(nonexistent)

        assert result.is_err()


class TestPaperkey:
    """Test paperkey operations."""

    @patch("shutil.which")
    def test_generate_paperkey_not_installed(self, mock_which, tmp_path):
        """Test generate_paperkey when paperkey is not installed."""
        mock_which.return_value = None

        result = generate_paperkey(
            tmp_path / "key.asc",
            tmp_path / "output.paper",
        )

        assert result.is_err()
        assert "not installed" in str(result.unwrap_err())

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_generate_paperkey_success(self, mock_run, mock_which, tmp_path):
        """Test successful paperkey generation."""
        mock_which.return_value = "/usr/bin/paperkey"
        mock_run.return_value = MagicMock(returncode=0)

        key_file = tmp_path / "key.asc"
        key_file.write_text("test key")
        output_file = tmp_path / "output.paper"

        result = generate_paperkey(key_file, output_file)

        assert result.is_ok()

    @patch("shutil.which")
    def test_restore_from_paperkey_not_installed(self, mock_which, tmp_path):
        """Test restore_from_paperkey when paperkey is not installed."""
        mock_which.return_value = None

        result = restore_from_paperkey(
            tmp_path / "paper.txt",
            tmp_path / "pubkey.asc",
            tmp_path / "output.asc",
        )

        assert result.is_err()


class TestListBackups:
    """Test listing backups."""

    def test_list_backups_empty_directory(self, tmp_path):
        """Test listing backups in empty directory."""
        manifests = list_backups(tmp_path)
        assert manifests == []

    def test_list_backups_finds_manifests(self, tmp_path):
        """Test listing backups finds manifest files."""
        # Create a backup directory with manifest
        backup_dir = tmp_path / "gpg-backup-1234-20240101-120000"
        backup_dir.mkdir()

        manifest_data = {
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "1234567890ABCDEF",
            "identity": "Test <test@example.com>",
            "files": ["master-key.asc"],
            "backup_path": str(backup_dir),
        }
        (backup_dir / "manifest.json").write_text(json.dumps(manifest_data))

        manifests = list_backups(tmp_path)

        assert len(manifests) == 1
        assert manifests[0].key_id == "ABCD1234"

    def test_list_backups_sorted_by_date(self, tmp_path):
        """Test that backups are sorted by date, newest first."""
        # Create two backup directories
        for i, date in enumerate(["2024-01-01", "2024-06-01"]):
            backup_dir = tmp_path / f"backup-{i}"
            backup_dir.mkdir()

            manifest_data = {
                "created_at": f"{date}T12:00:00+00:00",
                "key_id": f"KEY{i}",
                "fingerprint": f"FP{i}",
                "identity": "Test",
                "files": [],
                "backup_path": str(backup_dir),
            }
            (backup_dir / "manifest.json").write_text(json.dumps(manifest_data))

        manifests = list_backups(tmp_path)

        assert len(manifests) == 2
        # Newest first
        assert manifests[0].key_id == "KEY1"
        assert manifests[1].key_id == "KEY0"

    def test_list_backups_nonexistent_directory(self, tmp_path):
        """Test listing backups in nonexistent directory."""
        manifests = list_backups(tmp_path / "nonexistent")
        assert manifests == []


class TestVerifyBackupIntegrity:
    """Test backup integrity verification."""

    def test_verify_backup_integrity_no_manifest(self, tmp_path):
        """Test verification fails without manifest."""
        result = verify_backup_integrity(tmp_path)
        assert result.is_err()
        assert "Manifest" in str(result.unwrap_err())

    def test_verify_backup_integrity_missing_file(self, tmp_path):
        """Test verification fails when listed file is missing."""
        manifest_data = {
            "files": ["master-key.asc", "public-key.asc"],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        (tmp_path / "master-key.asc").write_text("key")
        # Note: public-key.asc is missing

        result = verify_backup_integrity(tmp_path)

        assert result.is_err()
        assert "Missing" in str(result.unwrap_err())


class TestGeneratePaperkey:
    """Additional paperkey tests."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_generate_paperkey_failure(self, mock_run, mock_which, tmp_path):
        """Test paperkey generation failure."""
        mock_which.return_value = "/usr/bin/paperkey"
        mock_run.return_value = MagicMock(returncode=1, stderr=b"Error generating paperkey")

        key_file = tmp_path / "key.asc"
        key_file.write_text("test key")
        output_file = tmp_path / "output.paper"

        result = generate_paperkey(key_file, output_file)

        assert result.is_err()
        assert "paperkey failed" in str(result.unwrap_err())

    @patch("shutil.which")
    def test_generate_paperkey_file_error(self, mock_which, tmp_path):
        """Test paperkey with file that doesn't exist."""
        mock_which.return_value = "/usr/bin/paperkey"

        # Non-existent key file
        result = generate_paperkey(
            tmp_path / "nonexistent.asc",
            tmp_path / "output.paper",
        )

        assert result.is_err()
        assert "generation failed" in str(result.unwrap_err())


class TestRestoreFromPaperkey:
    """Additional restore_from_paperkey tests."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_restore_from_paperkey_success(self, mock_run, mock_which, tmp_path):
        """Test successful paperkey restore."""
        mock_which.return_value = "/usr/bin/paperkey"
        mock_run.return_value = MagicMock(returncode=0)

        paper_file = tmp_path / "paper.txt"
        paper_file.write_text("paperkey data")
        pub_file = tmp_path / "pub.asc"
        pub_file.write_text("public key")
        output_file = tmp_path / "output.asc"

        result = restore_from_paperkey(paper_file, pub_file, output_file)

        assert result.is_ok()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_restore_from_paperkey_failure(self, mock_run, mock_which, tmp_path):
        """Test paperkey restore failure."""
        mock_which.return_value = "/usr/bin/paperkey"
        mock_run.return_value = MagicMock(returncode=1, stderr=b"Restore failed")

        paper_file = tmp_path / "paper.txt"
        paper_file.write_text("paperkey data")
        pub_file = tmp_path / "pub.asc"
        pub_file.write_text("public key")
        output_file = tmp_path / "output.asc"

        result = restore_from_paperkey(paper_file, pub_file, output_file)

        assert result.is_err()
        assert "restore failed" in str(result.unwrap_err())

    @patch("shutil.which")
    def test_restore_from_paperkey_file_error(self, mock_which, tmp_path):
        """Test restore with nonexistent file."""
        mock_which.return_value = "/usr/bin/paperkey"

        result = restore_from_paperkey(
            tmp_path / "nonexistent.txt",
            tmp_path / "pub.asc",
            tmp_path / "output.asc",
        )

        assert result.is_err()


class TestCopyPublicFilesToPartitionExtended:
    """Additional tests for copy_public_files_to_partition function."""

    def test_copy_public_files_oserror(self, tmp_path):
        """Test that OSError during copy returns error."""
        backup_path = tmp_path / "backup"
        backup_path.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create the source file
        (backup_path / "public-key.asc").write_text("public key data")

        # Patch shutil.copy2 to raise OSError
        with patch("yubikey_init.backup.shutil.copy2", side_effect=OSError("Permission denied")):
            result = copy_public_files_to_partition(backup_path, public_mount)

        assert result.is_err()
        assert "Failed to copy" in str(result.unwrap_err())


class TestVerifyBackupChecksumsExtended:
    """Additional tests for verify_backup_checksums function."""

    def test_verify_backup_checksums_no_manifest(self, tmp_path):
        """Test verify_backup_checksums fails without manifest."""
        from yubikey_init.backup import verify_backup_checksums

        result = verify_backup_checksums(tmp_path)
        assert result.is_err()
        assert "Manifest" in str(result.unwrap_err())

    def test_verify_backup_checksums_invalid_json(self, tmp_path):
        """Test verify_backup_checksums fails with invalid JSON."""
        from yubikey_init.backup import verify_backup_checksums

        (tmp_path / "manifest.json").write_text("not valid json")
        result = verify_backup_checksums(tmp_path)
        assert result.is_err()

    def test_verify_backup_checksums_with_subdirectory_filename(self, tmp_path):
        """Test verify_backup_checksums handles files in subdirectories (line 714)."""
        import hashlib
        import json

        from yubikey_init.backup import verify_backup_checksums

        # Create a subdirectory file
        subdir = tmp_path / "gnupghome"
        subdir.mkdir()
        test_file = subdir / "pubring.kbx"
        content = b"test key data"
        test_file.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()

        # Create manifest with subdirectory-style checksum entry
        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": ["gnupghome/"],
            "backup_path": str(tmp_path),
            "checksums": [
                {
                    "filename": "gnupghome/pubring.kbx",
                    "sha256": sha256,
                    "size_bytes": len(content),
                }
            ],
            "gnupghome_included": True,
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = verify_backup_checksums(tmp_path)
        assert result.is_ok()
        assert result.unwrap() == []

    def test_verify_backup_checksums_missing_file(self, tmp_path):
        """Test verify_backup_checksums reports missing files."""
        import json

        from yubikey_init.backup import verify_backup_checksums

        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": [],
            "backup_path": str(tmp_path),
            "checksums": [
                {
                    "filename": "master-key.asc",
                    "sha256": "deadbeef",
                    "size_bytes": 100,
                }
            ],
            "gnupghome_included": False,
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = verify_backup_checksums(tmp_path)
        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "missing" in failed[0]

    def test_verify_backup_checksums_checksum_mismatch(self, tmp_path):
        """Test verify_backup_checksums reports checksum mismatch."""
        import json

        from yubikey_init.backup import verify_backup_checksums

        # Create the file with known content
        (tmp_path / "master-key.asc").write_bytes(b"actual content")

        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": [],
            "backup_path": str(tmp_path),
            "checksums": [
                {
                    "filename": "master-key.asc",
                    "sha256": "wrongsha256hash",
                    "size_bytes": 14,  # correct size
                }
            ],
            "gnupghome_included": False,
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = verify_backup_checksums(tmp_path)
        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "checksum mismatch" in failed[0]

    def test_verify_backup_checksums_size_mismatch(self, tmp_path):
        """Test verify_backup_checksums reports size mismatch."""
        import hashlib
        import json

        from yubikey_init.backup import verify_backup_checksums

        content = b"actual content"
        sha256 = hashlib.sha256(content).hexdigest()
        (tmp_path / "master-key.asc").write_bytes(content)

        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": [],
            "backup_path": str(tmp_path),
            "checksums": [
                {
                    "filename": "master-key.asc",
                    "sha256": sha256,
                    "size_bytes": 999,  # wrong size
                }
            ],
            "gnupghome_included": False,
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = verify_backup_checksums(tmp_path)
        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "size mismatch" in failed[0]


class TestReadbackVerifyBackupExtended:
    """Additional tests for readback_verify_backup function."""

    def test_readback_verify_backup_checksum_failure(self, tmp_path):
        """Test readback_verify_backup fails when checksums fail (line 740)."""
        import hashlib
        import json

        from yubikey_init.backup import readback_verify_backup

        backup_path = tmp_path / "backup"
        backup_path.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create file with wrong checksum in manifest
        (backup_path / "master-key.asc").write_bytes(b"actual content")

        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": [],
            "backup_path": str(backup_path),
            "checksums": [
                {
                    "filename": "master-key.asc",
                    "sha256": "wronghash",
                    "size_bytes": 14,
                }
            ],
            "gnupghome_included": False,
        }
        (backup_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = readback_verify_backup(backup_path, public_mount)
        assert result.is_err()
        assert "Verification failed" in str(result.unwrap_err())

    def test_readback_verify_backup_unreadable_public_file(self, tmp_path):
        """Test readback_verify_backup handles unreadable public file (lines 757-758)."""
        import json

        from yubikey_init.backup import readback_verify_backup

        backup_path = tmp_path / "backup"
        backup_path.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create public-key.asc on both partitions
        (backup_path / "public-key.asc").write_bytes(b"key content")
        public_key_dest = public_mount / "public-key.asc"

        # Create a directory where the file should be so read_bytes raises IsADirectoryError
        public_key_dest.mkdir()

        # Manifest with no checksums so checksum verification passes
        manifest_data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "ABCD1234",
            "fingerprint": "FP",
            "identity": "Test",
            "files": [],
            "backup_path": str(backup_path),
            "checksums": [],
            "gnupghome_included": False,
        }
        (backup_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = readback_verify_backup(backup_path, public_mount)
        assert result.is_err()
        assert "Could not verify" in str(result.unwrap_err())


class TestCreateFullBackup:
    """Test create_full_backup function."""

    def test_create_full_backup_directory_failure(self, tmp_path):
        """Test backup fails when directory creation fails."""
        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import SecureString

        # Create a file where directory should be (to cause mkdir to fail)
        backup_path = tmp_path / "backup"
        backup_path.write_text("blocking file")

        result = create_full_backup(
            tmp_path / ".gnupg",
            backup_path,
            "ABCDEF1234567890",
            SecureString("pass"),
        )

        # Should fail because can't create directory
        assert result.is_err()

    @patch("yubikey_init.backup.create_backup_directory")
    def test_create_full_backup_key_info_failure(self, mock_create_dir, tmp_path):
        """Test backup fails when key info fails."""
        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import Result, SecureString

        # Setup mocks
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        mock_create_dir.return_value = Result.ok(backup_dir)

        # Patch GPGOperations where it's imported inside the function
        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_gpg.get_key_info.return_value = Result.err(Exception("Key not found"))
            mock_gpg_class.return_value = mock_gpg

            result = create_full_backup(
                tmp_path / ".gnupg",
                tmp_path,
                "ABCDEF1234567890",
                SecureString("pass"),
            )

            assert result.is_err()

    @patch("yubikey_init.backup.create_backup_directory")
    def test_create_full_backup_export_failure(self, mock_create_dir, tmp_path):
        """Test backup fails when export fails."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        # Setup mocks
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        mock_create_dir.return_value = Result.ok(backup_dir)

        mock_key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            identity="Test User <test@example.com>",
            key_type=KeyType.ED25519,
        )

        # Patch GPGOperations where it's imported inside the function
        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("1234567890ABCDEF")
            mock_gpg.export_secret_keys.return_value = Result.err(Exception("Export failed"))
            mock_gpg_class.return_value = mock_gpg

            result = create_full_backup(
                tmp_path / ".gnupg",
                tmp_path,
                "ABCDEF1234567890",
                SecureString("pass"),
            )

            assert result.is_err()

    @patch("yubikey_init.backup.create_backup_directory")
    def test_create_full_backup_revocation_cert_failure(self, mock_create_dir, tmp_path):
        """Test backup fails when revocation cert generation fails (line 304)."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        mock_create_dir.return_value = Result.ok(backup_dir)

        mock_key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            identity="Test User <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("1234567890ABCDEF")
            mock_gpg.export_secret_keys.return_value = Result.ok(None)
            mock_gpg.export_secret_subkeys.return_value = Result.ok(None)
            mock_gpg.export_public_key.return_value = Result.ok(None)
            mock_gpg.generate_revocation_certificate.return_value = Result.err(
                Exception("Revocation cert failed")
            )
            mock_gpg_class.return_value = mock_gpg

            # Create the files that GPG would create
            (backup_dir / "master-key.asc").write_text("key data")
            (backup_dir / "subkeys.asc").write_text("subkey data")
            (backup_dir / "public-key.asc").write_text("pub key data")

            result = create_full_backup(
                tmp_path / ".gnupg",
                tmp_path,
                "ABCDEF1234567890",
                SecureString("pass"),
            )

            assert result.is_err()
            assert "revocation certificate" in str(result.unwrap_err()).lower()

    @patch("shutil.which")
    @patch("yubikey_init.backup.create_backup_directory")
    def test_create_full_backup_with_paperkey_and_ssh(
        self, mock_create_dir, mock_which, tmp_path
    ):
        """Test create_full_backup with paperkey and SSH export (lines 313-325)."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        mock_create_dir.return_value = Result.ok(backup_dir)
        mock_which.return_value = "/usr/bin/paperkey"

        mock_key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
            creation_date=datetime.now(UTC),
            expiry_date=None,
            identity="Test User <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            with patch("yubikey_init.backup.generate_paperkey") as mock_paperkey:
                mock_gpg = MagicMock()
                mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
                mock_gpg.get_key_fingerprint.return_value = Result.ok("1234567890ABCDEF")
                mock_gpg.export_secret_keys.return_value = Result.ok(None)
                mock_gpg.export_secret_subkeys.return_value = Result.ok(None)
                mock_gpg.export_public_key.return_value = Result.ok(None)
                mock_gpg.generate_revocation_certificate.return_value = Result.ok(None)
                mock_gpg.export_ssh_key.return_value = Result.ok("ssh-ed25519 AAAA test@test")
                mock_gpg_class.return_value = mock_gpg

                # paperkey succeeds and creates the output file
                def fake_paperkey(master_path, output_path):
                    output_path.write_text("paperkey data")
                    return Result.ok(None)

                mock_paperkey.side_effect = fake_paperkey

                # Create placeholder files that GPG would create
                (backup_dir / "master-key.asc").write_text("key data")
                (backup_dir / "subkeys.asc").write_text("subkey data")
                (backup_dir / "public-key.asc").write_text("pub key data")
                (backup_dir / "revocation-cert.asc").write_text("revoke cert")

                result = create_full_backup(
                    tmp_path / ".gnupg",
                    tmp_path,
                    "ABCDEF1234567890",
                    SecureString("pass"),
                    include_paperkey=True,
                    include_ssh=True,
                )

                assert result.is_ok()
                manifest = result.unwrap()
                assert "master-key.paper" in manifest.files
                assert "ssh-public-key.pub" in manifest.files


class TestVerifyBackupIntegritySuccess:
    """Additional verify_backup_integrity tests."""

    def test_verify_backup_integrity_invalid_manifest_json(self, tmp_path):
        """Test verification fails with invalid JSON in manifest."""
        (tmp_path / "manifest.json").write_text("not valid json")

        result = verify_backup_integrity(tmp_path)

        assert result.is_err()

    def test_verify_backup_integrity_empty_manifest(self, tmp_path):
        """Test verification succeeds with empty files list."""
        manifest_data = {
            "files": [],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))

        result = verify_backup_integrity(tmp_path)

        # Should succeed since all listed files (none) are present
        assert result.is_ok()

    @patch("subprocess.run")
    def test_verify_backup_integrity_gpg_validates_key_files(self, mock_run, tmp_path):
        """Test that verify_backup_integrity validates key files with GPG."""
        manifest_data = {
            "files": ["master-key.asc"],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        (tmp_path / "master-key.asc").write_text("-----BEGIN PGP PRIVATE KEY BLOCK-----")

        mock_run.return_value = MagicMock(returncode=0)

        result = verify_backup_integrity(tmp_path)

        assert result.is_ok()
        mock_run.assert_called()

    @patch("subprocess.run")
    def test_verify_backup_integrity_gpg_parse_fails(self, mock_run, tmp_path):
        """Test verify_backup_integrity fails when GPG cannot parse key."""
        manifest_data = {
            "files": ["master-key.asc"],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        (tmp_path / "master-key.asc").write_text("corrupted data")

        mock_run.return_value = MagicMock(returncode=1)

        result = verify_backup_integrity(tmp_path)

        assert result.is_err()
        assert "GPG cannot parse" in str(result.unwrap_err())

    @patch("subprocess.run")
    def test_verify_backup_integrity_validates_all_key_files(self, mock_run, tmp_path):
        """Test verify_backup_integrity validates all key file types."""
        manifest_data = {
            "files": ["master-key.asc", "subkeys.asc", "public-key.asc"],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        (tmp_path / "master-key.asc").write_text("key data")
        (tmp_path / "subkeys.asc").write_text("key data")
        (tmp_path / "public-key.asc").write_text("key data")

        mock_run.return_value = MagicMock(returncode=0)

        result = verify_backup_integrity(tmp_path)

        assert result.is_ok()
        # Should call gpg --list-packets for each key file
        assert mock_run.call_count == 3


class TestImportFromBackup:
    """Tests for import_from_backup function."""

    def test_import_from_backup_subkeys_only(self, tmp_path):
        """Test importing subkeys only from backup."""
        from datetime import UTC, datetime

        from yubikey_init.backup import import_from_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        # Create mock backup directory
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        (backup_dir / "subkeys.asc").write_text("subkeys data")

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.import_key.return_value = Result.ok(mock_key_info)
            mock_gpg_class.return_value = mock_gpg

            result = import_from_backup(
                backup_dir,
                tmp_path / ".gnupg",
                SecureString("pass"),
                subkeys_only=True,
            )

            assert result.is_ok()
            assert result.unwrap() == "ABCDEF1234567890"

    def test_import_from_backup_master_key(self, tmp_path):
        """Test importing master key from backup."""
        from datetime import UTC, datetime

        from yubikey_init.backup import import_from_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        # Create mock backup directory
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        (backup_dir / "master-key.asc").write_text("master key data")

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.import_key.return_value = Result.ok(mock_key_info)
            mock_gpg_class.return_value = mock_gpg

            result = import_from_backup(
                backup_dir,
                tmp_path / ".gnupg",
                SecureString("pass"),
                subkeys_only=False,
            )

            assert result.is_ok()
            assert result.unwrap() == "ABCDEF1234567890"

    def test_import_from_backup_file_not_found(self, tmp_path):
        """Test import_from_backup fails when key file not found."""
        from yubikey_init.backup import import_from_backup
        from yubikey_init.types import SecureString

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        # No key files created

        result = import_from_backup(
            backup_dir,
            tmp_path / ".gnupg",
            SecureString("pass"),
            subkeys_only=True,
        )

        assert result.is_err()
        assert "not found" in str(result.unwrap_err())

    def test_import_from_backup_import_fails(self, tmp_path):
        """Test import_from_backup fails when import fails."""
        from yubikey_init.backup import import_from_backup
        from yubikey_init.gpg_ops import GPGError
        from yubikey_init.types import Result, SecureString

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        (backup_dir / "subkeys.asc").write_text("key data")

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_gpg.import_key.return_value = Result.err(GPGError("Import failed"))
            mock_gpg_class.return_value = mock_gpg

            result = import_from_backup(
                backup_dir,
                tmp_path / ".gnupg",
                SecureString("pass"),
                subkeys_only=True,
            )

            assert result.is_err()


class TestCreateFullBackupSuccess:
    """Tests for create_full_backup success paths."""

    def test_create_full_backup_success(self, tmp_path):
        """Test successful full backup creation."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_path = tmp_path / "backups"
        backup_path.mkdir()

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test User <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("FP12345678")
            mock_gpg.export_secret_keys.return_value = Result.ok(Path("master-key.asc"))
            mock_gpg.export_secret_subkeys.return_value = Result.ok(Path("subkeys.asc"))
            mock_gpg.export_public_key.return_value = Result.ok(Path("public-key.asc"))
            mock_gpg.generate_revocation_certificate.return_value = Result.ok(
                Path("revocation-cert.asc")
            )
            mock_gpg.export_ssh_key.return_value = Result.ok("ssh-rsa AAAA...")
            mock_gpg_class.return_value = mock_gpg

            with patch("shutil.which", return_value=None):  # No paperkey
                result = create_full_backup(
                    gnupghome,
                    backup_path,
                    "ABCDEF1234567890",
                    SecureString("pass"),
                    include_paperkey=False,
                    include_ssh=True,
                )

            assert result.is_ok()
            manifest = result.unwrap()
            assert manifest.key_id == "ABCDEF1234567890"
            assert "master-key.asc" in manifest.files

    def test_create_full_backup_with_paperkey(self, tmp_path):
        """Test full backup creation with paperkey."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_path = tmp_path / "backups"
        backup_path.mkdir()

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test User <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("FP12345678")
            mock_gpg.export_secret_keys.return_value = Result.ok(Path("master-key.asc"))
            mock_gpg.export_secret_subkeys.return_value = Result.ok(Path("subkeys.asc"))
            mock_gpg.export_public_key.return_value = Result.ok(Path("public-key.asc"))
            mock_gpg.generate_revocation_certificate.return_value = Result.ok(
                Path("revocation-cert.asc")
            )
            mock_gpg.export_ssh_key.return_value = Result.err(Exception("No auth key"))
            mock_gpg_class.return_value = mock_gpg

            with (
                patch("shutil.which", return_value="/usr/bin/paperkey"),
                patch("yubikey_init.backup.generate_paperkey") as mock_paperkey,
            ):
                mock_paperkey.return_value = Result.ok(Path("master-key.paper"))
                result = create_full_backup(
                    gnupghome,
                    backup_path,
                    "ABCDEF1234567890",
                    SecureString("pass"),
                    include_paperkey=True,
                    include_ssh=False,
                )

            assert result.is_ok()

    def test_create_full_backup_subkeys_export_fails(self, tmp_path):
        """Test full backup fails when subkeys export fails."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.gpg_ops import GPGError
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_path = tmp_path / "backups"
        backup_path.mkdir()

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test User <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("FP12345678")
            mock_gpg.export_secret_keys.return_value = Result.ok(Path("master-key.asc"))
            mock_gpg.export_secret_subkeys.return_value = Result.err(GPGError("Export failed"))
            mock_gpg_class.return_value = mock_gpg

            result = create_full_backup(
                gnupghome,
                backup_path,
                "ABCDEF1234567890",
                SecureString("pass"),
            )

            assert result.is_err()

    def test_create_full_backup_public_key_export_fails(self, tmp_path):
        """Test full backup fails when public key export fails."""
        from datetime import UTC, datetime

        from yubikey_init.backup import create_full_backup
        from yubikey_init.gpg_ops import GPGError
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_path = tmp_path / "backups"
        backup_path.mkdir()

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="ABCDEF1234567890",
                fingerprint="FP12345678",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test User <test@example.com>",
                key_type=KeyType.ED25519,
            )
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("FP12345678")
            mock_gpg.export_secret_keys.return_value = Result.ok(Path("master-key.asc"))
            mock_gpg.export_secret_subkeys.return_value = Result.ok(Path("subkeys.asc"))
            mock_gpg.export_public_key.return_value = Result.err(GPGError("Export failed"))
            mock_gpg_class.return_value = mock_gpg

            result = create_full_backup(
                gnupghome,
                backup_path,
                "ABCDEF1234567890",
                SecureString("pass"),
            )

            assert result.is_err()


class TestListBackupsAdditional:
    """Additional list_backups tests."""

    def test_list_backups_skips_invalid_manifests(self, tmp_path):
        """Test list_backups skips directories with invalid manifests."""
        # Create a valid backup
        valid_backup = tmp_path / "backup-valid"
        valid_backup.mkdir()
        valid_manifest = {
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "VALID123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": [],
            "backup_path": str(valid_backup),
        }
        (valid_backup / "manifest.json").write_text(json.dumps(valid_manifest))

        # Create an invalid backup (bad JSON)
        invalid_backup = tmp_path / "backup-invalid"
        invalid_backup.mkdir()
        (invalid_backup / "manifest.json").write_text("not valid json")

        manifests = list_backups(tmp_path)

        # Should only return the valid one
        assert len(manifests) == 1
        assert manifests[0].key_id == "VALID123"

    def test_list_backups_skips_dirs_without_manifest(self, tmp_path):
        """Test list_backups skips directories without manifest."""
        # Create a directory without manifest
        no_manifest_dir = tmp_path / "no-manifest"
        no_manifest_dir.mkdir()

        # Create a valid backup
        valid_backup = tmp_path / "backup-valid"
        valid_backup.mkdir()
        valid_manifest = {
            "created_at": "2024-01-01T12:00:00+00:00",
            "key_id": "VALID123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": [],
            "backup_path": str(valid_backup),
        }
        (valid_backup / "manifest.json").write_text(json.dumps(valid_manifest))

        manifests = list_backups(tmp_path)

        assert len(manifests) == 1
        assert manifests[0].key_id == "VALID123"


class TestFileChecksum:
    """Test FileChecksum dataclass."""

    def test_file_checksum_creation(self) -> None:
        """Test creating FileChecksum."""
        from yubikey_init.backup import FileChecksum

        checksum = FileChecksum(
            filename="test.txt",
            sha256="abc123",
            size_bytes=100,
        )

        assert checksum.filename == "test.txt"
        assert checksum.sha256 == "abc123"
        assert checksum.size_bytes == 100

    def test_file_checksum_to_dict(self) -> None:
        """Test FileChecksum to_dict serialization."""
        from yubikey_init.backup import FileChecksum

        checksum = FileChecksum(
            filename="master-key.asc",
            sha256="deadbeef1234",
            size_bytes=2048,
        )

        data = checksum.to_dict()

        assert data["filename"] == "master-key.asc"
        assert data["sha256"] == "deadbeef1234"
        assert data["size_bytes"] == 2048

    def test_file_checksum_from_dict(self) -> None:
        """Test FileChecksum from_dict deserialization."""
        from yubikey_init.backup import FileChecksum

        data = {
            "filename": "subkeys.asc",
            "sha256": "cafebabe",
            "size_bytes": 1024,
        }

        checksum = FileChecksum.from_dict(data)

        assert checksum.filename == "subkeys.asc"
        assert checksum.sha256 == "cafebabe"
        assert checksum.size_bytes == 1024

    def test_file_checksum_roundtrip(self) -> None:
        """Test FileChecksum roundtrip serialization."""
        from yubikey_init.backup import FileChecksum

        original = FileChecksum(
            filename="test.txt",
            sha256="abc123",
            size_bytes=512,
        )

        data = original.to_dict()
        restored = FileChecksum.from_dict(data)

        assert restored.filename == original.filename
        assert restored.sha256 == original.sha256
        assert restored.size_bytes == original.size_bytes


class TestCalculateFileChecksum:
    """Test calculate_file_checksum function."""

    def test_calculate_checksum_simple_file(self, tmp_path) -> None:
        """Test checksum calculation for simple file."""
        from yubikey_init.backup import calculate_file_checksum

        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        checksum = calculate_file_checksum(test_file)

        assert checksum.filename == "test.txt"
        assert len(checksum.sha256) == 64  # SHA256 hex is 64 chars
        assert checksum.size_bytes == 13  # "Hello, World!" is 13 bytes

    def test_calculate_checksum_empty_file(self, tmp_path) -> None:
        """Test checksum calculation for empty file."""
        from yubikey_init.backup import calculate_file_checksum

        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        checksum = calculate_file_checksum(test_file)

        assert checksum.size_bytes == 0
        # Empty file SHA256 is well-known
        assert checksum.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_calculate_checksum_binary_file(self, tmp_path) -> None:
        """Test checksum calculation for binary file."""
        from yubikey_init.backup import calculate_file_checksum

        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03\x04")

        checksum = calculate_file_checksum(test_file)

        assert checksum.size_bytes == 5
        assert len(checksum.sha256) == 64

    def test_calculate_checksum_deterministic(self, tmp_path) -> None:
        """Test checksum is deterministic for same content."""
        from yubikey_init.backup import calculate_file_checksum

        test_file = tmp_path / "test.txt"
        test_file.write_text("Deterministic content")

        checksum1 = calculate_file_checksum(test_file)
        checksum2 = calculate_file_checksum(test_file)

        assert checksum1.sha256 == checksum2.sha256

    def test_calculate_checksum_different_content(self, tmp_path) -> None:
        """Test different content produces different checksums."""
        from yubikey_init.backup import calculate_file_checksum

        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("Content A")
        file2.write_text("Content B")

        checksum1 = calculate_file_checksum(file1)
        checksum2 = calculate_file_checksum(file2)

        assert checksum1.sha256 != checksum2.sha256


class TestCalculateDirectoryChecksums:
    """Test calculate_directory_checksums function."""

    def test_calculate_checksums_single_file(self, tmp_path) -> None:
        """Test checksum calculation for directory with single file."""
        from yubikey_init.backup import calculate_directory_checksums

        (tmp_path / "test.txt").write_text("content")

        checksums = calculate_directory_checksums(tmp_path)

        assert len(checksums) == 1
        assert checksums[0].filename == "test.txt"

    def test_calculate_checksums_multiple_files(self, tmp_path) -> None:
        """Test checksum calculation for directory with multiple files."""
        from yubikey_init.backup import calculate_directory_checksums

        (tmp_path / "file1.txt").write_text("content 1")
        (tmp_path / "file2.txt").write_text("content 2")
        (tmp_path / "file3.txt").write_text("content 3")

        checksums = calculate_directory_checksums(tmp_path)

        assert len(checksums) == 3
        filenames = {c.filename for c in checksums}
        assert "file1.txt" in filenames
        assert "file2.txt" in filenames
        assert "file3.txt" in filenames

    def test_calculate_checksums_nested_directory(self, tmp_path) -> None:
        """Test checksum calculation for nested directory structure."""
        from yubikey_init.backup import calculate_directory_checksums

        (tmp_path / "root.txt").write_text("root content")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested content")

        checksums = calculate_directory_checksums(tmp_path)

        assert len(checksums) == 2
        filenames = {c.filename for c in checksums}
        assert "root.txt" in filenames
        # Nested file should have relative path
        assert any("nested.txt" in f for f in filenames)

    def test_calculate_checksums_empty_directory(self, tmp_path) -> None:
        """Test checksum calculation for empty directory."""
        from yubikey_init.backup import calculate_directory_checksums

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        checksums = calculate_directory_checksums(empty_dir)

        assert len(checksums) == 0

    def test_calculate_checksums_skips_directories(self, tmp_path) -> None:
        """Test checksum calculation skips directories (only files)."""
        from yubikey_init.backup import calculate_directory_checksums

        (tmp_path / "file.txt").write_text("content")
        (tmp_path / "subdir").mkdir()

        checksums = calculate_directory_checksums(tmp_path)

        # Should only have the file, not the directory
        assert len(checksums) == 1


class TestCopyGnupghome:
    """Test copy_gnupghome function."""

    def test_copy_gnupghome_success(self, tmp_path) -> None:
        """Test successful GNUPGHOME copy."""
        from yubikey_init.backup import copy_gnupghome

        # Create source directory with files
        source = tmp_path / ".gnupg"
        source.mkdir()
        (source / "gpg.conf").write_text("# GPG config")
        (source / "pubring.kbx").write_text("keyring data")
        (source / "private-keys-v1.d").mkdir()
        (source / "private-keys-v1.d" / "key.key").write_text("private key")

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        result = copy_gnupghome(source, backup_dir)

        assert result.is_ok()
        dest = result.unwrap()
        assert dest.exists()
        assert (dest / "gpg.conf").exists()
        assert (dest / "pubring.kbx").exists()
        assert (dest / "private-keys-v1.d" / "key.key").exists()

    def test_copy_gnupghome_skips_lock_files(self, tmp_path) -> None:
        """Test copy_gnupghome skips lock files."""
        from yubikey_init.backup import copy_gnupghome

        source = tmp_path / ".gnupg"
        source.mkdir()
        (source / "gpg.conf").write_text("# GPG config")
        (source / "pubring.kbx.lock").write_text("lock")

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        result = copy_gnupghome(source, backup_dir)

        assert result.is_ok()
        dest = result.unwrap()
        assert (dest / "gpg.conf").exists()
        assert not (dest / "pubring.kbx.lock").exists()

    def test_copy_gnupghome_skips_socket_files(self, tmp_path) -> None:
        """Test copy_gnupghome skips socket files (S.*)."""
        from yubikey_init.backup import copy_gnupghome

        source = tmp_path / ".gnupg"
        source.mkdir()
        (source / "gpg.conf").write_text("# GPG config")
        # Can't create actual socket, but the pattern S.* is ignored

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        result = copy_gnupghome(source, backup_dir)

        assert result.is_ok()

    def test_copy_gnupghome_overwrites_existing(self, tmp_path) -> None:
        """Test copy_gnupghome overwrites existing backup."""
        from yubikey_init.backup import copy_gnupghome

        source = tmp_path / ".gnupg"
        source.mkdir()
        (source / "gpg.conf").write_text("new config")

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        old_gnupghome = backup_dir / "gnupghome"
        old_gnupghome.mkdir()
        (old_gnupghome / "old_file.txt").write_text("old content")

        result = copy_gnupghome(source, backup_dir)

        assert result.is_ok()
        dest = result.unwrap()
        assert not (dest / "old_file.txt").exists()
        assert (dest / "gpg.conf").exists()

    def test_copy_gnupghome_sets_permissions(self, tmp_path) -> None:
        """Test copy_gnupghome sets restrictive permissions."""
        from yubikey_init.backup import copy_gnupghome

        source = tmp_path / ".gnupg"
        source.mkdir()
        (source / "gpg.conf").write_text("# GPG config")

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        result = copy_gnupghome(source, backup_dir)

        assert result.is_ok()
        dest = result.unwrap()
        # Directory should be 0o700
        assert dest.stat().st_mode & 0o777 == 0o700


class TestVerifyBackupChecksums:
    """Test verify_backup_checksums function."""

    def test_verify_checksums_no_manifest(self, tmp_path) -> None:
        """Test verify fails without manifest."""
        from yubikey_init.backup import verify_backup_checksums

        result = verify_backup_checksums(tmp_path)

        assert result.is_err()
        assert "Manifest" in str(result.unwrap_err())

    def test_verify_checksums_invalid_manifest(self, tmp_path) -> None:
        """Test verify fails with invalid manifest JSON."""
        from yubikey_init.backup import verify_backup_checksums

        (tmp_path / "manifest.json").write_text("not json")

        result = verify_backup_checksums(tmp_path)

        assert result.is_err()

    def test_verify_checksums_empty_checksums(self, tmp_path) -> None:
        """Test verify succeeds with no checksums to verify."""
        from yubikey_init.backup import verify_backup_checksums

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": [],
            "backup_path": str(tmp_path),
            "checksums": [],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))

        result = verify_backup_checksums(tmp_path)

        assert result.is_ok()
        assert result.unwrap() == []

    def test_verify_checksums_missing_file(self, tmp_path) -> None:
        """Test verify reports missing file."""
        from yubikey_init.backup import verify_backup_checksums

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["missing.txt"],
            "backup_path": str(tmp_path),
            "checksums": [{"filename": "missing.txt", "sha256": "abc123", "size_bytes": 100}],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))

        result = verify_backup_checksums(tmp_path)

        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "missing" in failed[0]

    def test_verify_checksums_checksum_mismatch(self, tmp_path) -> None:
        """Test verify reports checksum mismatch."""
        from yubikey_init.backup import verify_backup_checksums

        (tmp_path / "test.txt").write_text("modified content")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["test.txt"],
            "backup_path": str(tmp_path),
            "checksums": [{"filename": "test.txt", "sha256": "wrong_checksum", "size_bytes": 16}],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))

        result = verify_backup_checksums(tmp_path)

        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "checksum mismatch" in failed[0]

    def test_verify_checksums_size_mismatch(self, tmp_path) -> None:
        """Test verify reports size mismatch."""
        from yubikey_init.backup import calculate_file_checksum, verify_backup_checksums

        content = "test content"
        (tmp_path / "test.txt").write_text(content)
        actual_checksum = calculate_file_checksum(tmp_path / "test.txt")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["test.txt"],
            "backup_path": str(tmp_path),
            "checksums": [
                {"filename": "test.txt", "sha256": actual_checksum.sha256, "size_bytes": 999}
            ],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))

        result = verify_backup_checksums(tmp_path)

        assert result.is_ok()
        failed = result.unwrap()
        assert len(failed) == 1
        assert "size mismatch" in failed[0]

    def test_verify_checksums_all_valid(self, tmp_path) -> None:
        """Test verify succeeds when all checksums match."""
        from yubikey_init.backup import calculate_file_checksum, verify_backup_checksums

        (tmp_path / "test.txt").write_text("test content")
        checksum = calculate_file_checksum(tmp_path / "test.txt")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["test.txt"],
            "backup_path": str(tmp_path),
            "checksums": [checksum.to_dict()],
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))

        result = verify_backup_checksums(tmp_path)

        assert result.is_ok()
        assert result.unwrap() == []


class TestReadbackVerifyBackup:
    """Test readback_verify_backup function."""

    def test_readback_verify_checksum_fails(self, tmp_path) -> None:
        """Test readback verify fails when checksum verification fails."""
        from yubikey_init.backup import readback_verify_backup

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # No manifest - should fail
        result = readback_verify_backup(backup_dir, public_mount)

        assert result.is_err()

    def test_readback_verify_missing_public_file(self, tmp_path) -> None:
        """Test readback verify fails when public partition file is missing."""
        from yubikey_init.backup import calculate_file_checksum, readback_verify_backup

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create backup with public-key.asc
        (backup_dir / "public-key.asc").write_text("public key data")
        checksum = calculate_file_checksum(backup_dir / "public-key.asc")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["public-key.asc"],
            "backup_path": str(backup_dir),
            "checksums": [checksum.to_dict()],
        }
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))

        # Don't create public-key.asc on public partition
        result = readback_verify_backup(backup_dir, public_mount)

        assert result.is_err()
        assert "Missing from public partition" in str(result.unwrap_err())

    def test_readback_verify_public_content_mismatch(self, tmp_path) -> None:
        """Test readback verify fails when public partition content differs."""
        from yubikey_init.backup import calculate_file_checksum, readback_verify_backup

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create backup with public-key.asc
        (backup_dir / "public-key.asc").write_text("public key data")
        checksum = calculate_file_checksum(backup_dir / "public-key.asc")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["public-key.asc"],
            "backup_path": str(backup_dir),
            "checksums": [checksum.to_dict()],
        }
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))

        # Create different content on public partition
        (public_mount / "public-key.asc").write_text("different data")

        result = readback_verify_backup(backup_dir, public_mount)

        assert result.is_err()
        assert "mismatch" in str(result.unwrap_err())

    @patch("subprocess.run")
    def test_readback_verify_gpg_parse_fails(self, mock_run, tmp_path) -> None:
        """Test readback verify fails when GPG cannot parse key files."""
        from yubikey_init.backup import calculate_file_checksum, readback_verify_backup

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create backup with master-key.asc (one of the validated files)
        (backup_dir / "master-key.asc").write_text("corrupted key data")
        checksum = calculate_file_checksum(backup_dir / "master-key.asc")

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["master-key.asc"],
            "backup_path": str(backup_dir),
            "checksums": [checksum.to_dict()],
        }
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))

        # GPG fails to parse
        mock_run.return_value = MagicMock(returncode=1)

        result = readback_verify_backup(backup_dir, public_mount)

        assert result.is_err()
        assert "GPG cannot parse" in str(result.unwrap_err())

    @patch("subprocess.run")
    def test_readback_verify_success(self, mock_run, tmp_path) -> None:
        """Test readback verify succeeds with valid backup."""
        from yubikey_init.backup import calculate_file_checksum, readback_verify_backup

        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        # Create backup files
        (backup_dir / "master-key.asc").write_text("master key data")
        (backup_dir / "public-key.asc").write_text("public key data")

        checksums = [
            calculate_file_checksum(backup_dir / "master-key.asc"),
            calculate_file_checksum(backup_dir / "public-key.asc"),
        ]

        manifest = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test",
            "files": ["master-key.asc", "public-key.asc"],
            "backup_path": str(backup_dir),
            "checksums": [c.to_dict() for c in checksums],
        }
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))

        # Create matching public partition
        (public_mount / "public-key.asc").write_text("public key data")

        # GPG succeeds
        mock_run.return_value = MagicMock(returncode=0)

        result = readback_verify_backup(backup_dir, public_mount)

        assert result.is_ok()
        assert result.unwrap() is True


class TestBackupManifestWithChecksums:
    """Test BackupManifest with checksums."""

    def test_manifest_with_checksums_to_dict(self) -> None:
        """Test manifest with checksums serialization."""
        from yubikey_init.backup import BackupManifest, FileChecksum

        checksums = [
            FileChecksum(filename="test.txt", sha256="abc", size_bytes=100),
        ]

        manifest = BackupManifest(
            created_at=datetime.now(UTC),
            key_id="TEST123",
            fingerprint="FP123",
            identity="Test User",
            files=["test.txt"],
            backup_path=Path("/tmp/backup"),
            checksums=checksums,
            gnupghome_included=True,
            version="2.0.0",
        )

        data = manifest.to_dict()

        assert len(data["checksums"]) == 1
        assert data["checksums"][0]["filename"] == "test.txt"
        assert data["gnupghome_included"] is True
        assert data["version"] == "2.0.0"

    def test_manifest_from_dict_with_checksums(self) -> None:
        """Test manifest with checksums deserialization."""
        from yubikey_init.backup import BackupManifest

        data = {
            "version": "2.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test User",
            "files": ["test.txt"],
            "backup_path": "/tmp/backup",
            "checksums": [{"filename": "test.txt", "sha256": "abc", "size_bytes": 100}],
            "gnupghome_included": True,
        }

        manifest = BackupManifest.from_dict(data)

        assert len(manifest.checksums) == 1
        assert manifest.checksums[0].filename == "test.txt"
        assert manifest.gnupghome_included is True

    def test_manifest_from_dict_defaults(self) -> None:
        """Test manifest from_dict uses defaults for missing fields."""
        from yubikey_init.backup import BackupManifest

        data = {
            "created_at": "2024-01-01T00:00:00+00:00",
            "key_id": "TEST123",
            "fingerprint": "FP123",
            "identity": "Test User",
            "files": [],
            "backup_path": "/tmp/backup",
        }

        manifest = BackupManifest.from_dict(data)

        assert manifest.checksums == []
        assert manifest.gnupghome_included is False
        assert manifest.version == "1.0.0"  # Default for older manifests


class TestCopyPublicFilesToPartition:
    """Test copy_public_files_to_partition function."""

    def test_copy_public_files_success(self, tmp_path: Path) -> None:
        """Test successful copying of public files to public partition."""
        # Create backup directory with public files
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        (backup_dir / "public-key.asc").write_text("PUBLIC KEY")
        (backup_dir / "ssh-public-key.pub").write_text("SSH KEY")

        # Create public partition mount
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        result = copy_public_files_to_partition(backup_dir, public_mount)

        assert result.is_ok()
        copied = result.unwrap()
        assert "public-key.asc" in copied
        assert "ssh-public-key.pub" in copied
        assert (public_mount / "public-key.asc").read_text() == "PUBLIC KEY"
        assert (public_mount / "ssh-public-key.pub").read_text() == "SSH KEY"

    def test_copy_public_files_partial(self, tmp_path: Path) -> None:
        """Test copying when only some public files exist."""
        # Create backup directory with only public key
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        (backup_dir / "public-key.asc").write_text("PUBLIC KEY")
        # No ssh-public-key.pub

        # Create public partition mount
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        result = copy_public_files_to_partition(backup_dir, public_mount)

        assert result.is_ok()
        copied = result.unwrap()
        assert "public-key.asc" in copied
        assert "ssh-public-key.pub" not in copied
        assert (public_mount / "public-key.asc").exists()
        assert not (public_mount / "ssh-public-key.pub").exists()

    def test_copy_public_files_no_files(self, tmp_path: Path) -> None:
        """Test copying when no public files exist."""
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        public_mount = tmp_path / "public"
        public_mount.mkdir()

        result = copy_public_files_to_partition(backup_dir, public_mount)

        assert result.is_ok()
        assert result.unwrap() == []


class TestCopyToBackupDrive:
    """Test copy_to_backup_drive function."""

    def test_copy_to_backup_drive_directory_failure(self, tmp_path) -> None:
        """Test copy fails when directory creation fails."""
        from yubikey_init.backup import copy_to_backup_drive
        from yubikey_init.types import SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()

        # Create file where encrypted mount should be (causes mkdir to fail)
        encrypted_mount = tmp_path / "encrypted"
        encrypted_mount.write_text("blocking file")

        public_mount = tmp_path / "public"
        public_mount.mkdir()

        result = copy_to_backup_drive(
            gnupghome,
            encrypted_mount,
            public_mount,
            "TEST123",
            SecureString("pass"),
        )

        assert result.is_err()

    @patch("yubikey_init.backup.create_backup_directory")
    def test_copy_to_backup_drive_key_info_failure(self, mock_create_dir, tmp_path) -> None:
        """Test copy fails when key info fails."""
        from yubikey_init.backup import copy_to_backup_drive
        from yubikey_init.types import Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        public_mount = tmp_path / "public"
        public_mount.mkdir()

        mock_create_dir.return_value = Result.ok(backup_dir)

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_gpg.get_key_info.return_value = Result.err(Exception("Key not found"))
            mock_gpg_class.return_value = mock_gpg

            result = copy_to_backup_drive(
                gnupghome,
                tmp_path,
                public_mount,
                "TEST123",
                SecureString("pass"),
            )

            assert result.is_err()

    @patch("yubikey_init.backup.create_backup_directory")
    @patch("yubikey_init.backup.calculate_file_checksum")
    def test_copy_to_backup_drive_public_copy_failure(
        self, mock_checksum, mock_create_dir, tmp_path
    ) -> None:
        """Test copy fails when copying to public partition fails."""
        from datetime import UTC, datetime

        from yubikey_init.backup import FileChecksum, copy_to_backup_drive
        from yubikey_init.types import KeyInfo, KeyType, Result, SecureString

        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        # Create the files that would be exported
        master_key = backup_dir / "master-key.asc"
        master_key.write_text("secret key")
        subkeys = backup_dir / "subkeys.asc"
        subkeys.write_text("subkeys")
        public_key = backup_dir / "public-key.asc"
        public_key.write_text("public key")

        # Make public mount a file to cause copy to fail
        public_mount = tmp_path / "public"
        public_mount.write_text("blocking file")

        mock_create_dir.return_value = Result.ok(backup_dir)
        mock_checksum.return_value = FileChecksum(filename="test", sha256="abc123", size_bytes=100)

        with patch("yubikey_init.gpg_ops.GPGOperations") as mock_gpg_class:
            mock_gpg = MagicMock()
            mock_key_info = KeyInfo(
                key_id="TEST123",
                fingerprint="FP123",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                identity="Test User",
                key_type=KeyType.ED25519,
            )
            mock_gpg.get_key_info.return_value = Result.ok(mock_key_info)
            mock_gpg.get_key_fingerprint.return_value = Result.ok("FP123")
            mock_gpg.export_secret_keys.return_value = Result.ok(master_key)
            mock_gpg.export_secret_subkeys.return_value = Result.ok(subkeys)
            mock_gpg.export_public_key.return_value = Result.ok(public_key)
            mock_gpg_class.return_value = mock_gpg

            result = copy_to_backup_drive(
                gnupghome,
                tmp_path,
                public_mount,
                "TEST123",
                SecureString("pass"),
                include_gnupghome=False,
            )

            assert result.is_err()
            assert "public partition" in str(result.unwrap_err()).lower()
