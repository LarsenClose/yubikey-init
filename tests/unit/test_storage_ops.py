"""Tests for storage operations with mocked subprocess calls."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from yubikey_init.storage_ops import StorageError, StorageOperations


class TestStorageOperations:
    """Test StorageOperations class."""

    def test_init_detects_platform(self) -> None:
        """Test initialization detects platform."""
        ops = StorageOperations()
        assert ops._system in ["Darwin", "Linux", "Windows"]


class TestListRemovableDevices:
    """Tests for list_removable_devices method."""

    def test_list_removable_devices_macos(self) -> None:
        """Test listing devices on macOS."""
        ops = StorageOperations()
        ops._system = "Darwin"

        with patch.object(ops, "_list_macos_devices") as mock_list:
            mock_list.return_value = []
            devices = ops.list_removable_devices()
            mock_list.assert_called_once()
            assert devices == []

    def test_list_removable_devices_linux(self) -> None:
        """Test listing devices on Linux."""
        ops = StorageOperations()
        ops._system = "Linux"

        with patch.object(ops, "_list_linux_devices") as mock_list:
            mock_list.return_value = []
            devices = ops.list_removable_devices()
            mock_list.assert_called_once()
            assert devices == []

    def test_list_removable_devices_unknown_platform(self) -> None:
        """Test listing devices on unknown platform returns empty."""
        ops = StorageOperations()
        ops._system = "Windows"
        devices = ops.list_removable_devices()
        assert devices == []


class TestListMacosDevices:
    """Tests for _list_macos_devices method."""

    def test_list_macos_devices_empty(self) -> None:
        """Test listing macOS devices when none are connected."""
        ops = StorageOperations()
        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"")
            devices = ops._list_macos_devices()
            assert devices == []

    def test_list_macos_devices_invalid_plist(self) -> None:
        """Test listing macOS devices with invalid plist."""
        ops = StorageOperations()
        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"not valid plist")
            devices = ops._list_macos_devices()
            assert devices == []

    def test_list_macos_devices_filters_apfs_containers(self) -> None:
        """Test that synthesized APFS containers are filtered out.

        When an external disk has an APFS partition, macOS creates a synthesized
        container (e.g., disk4) that appears alongside the physical disk (e.g., disk6).
        We should only show the physical disk to avoid user confusion.
        """
        import plistlib

        ops = StorageOperations()

        # Simulate diskutil list output with both APFS container and physical disk
        list_plist = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        # Synthesized APFS container - should be filtered out
                        "DeviceIdentifier": "disk4",
                        "Size": 15721783296,
                        "Content": "Apple_APFS_Container",
                        "APFSPhysicalStores": [{"DeviceIdentifier": "disk6s2"}],
                        "APFSVolumes": [
                            {"DeviceIdentifier": "disk4s1", "VolumeName": "gnupg-secrets"},
                            {"DeviceIdentifier": "disk4s2", "VolumeName": "gnupg-public"},
                        ],
                    },
                    {
                        # Physical disk - should be included
                        "DeviceIdentifier": "disk6",
                        "Size": 15931539456,
                        "Content": "GUID_partition_scheme",
                    },
                ]
            }
        )

        # Simulate diskutil info output for disk6
        info_plist = plistlib.dumps(
            {
                "DeviceIdentifier": "disk6",
                "MediaName": "USB3.0 CRW   -SD",
                "Removable": True,
                "Virtual": False,
            }
        )

        def mock_run_side_effect(cmd, **kwargs):
            if "list" in cmd and "-plist" in cmd:
                if "external" in cmd:
                    return MagicMock(returncode=0, stdout=list_plist)
                else:
                    # For mount info check
                    return MagicMock(returncode=0, stdout=plistlib.dumps({"AllDisks": []}))
            elif "info" in cmd:
                return MagicMock(returncode=0, stdout=info_plist)
            return MagicMock(returncode=1)

        with patch("yubikey_init.storage_ops.subprocess.run", side_effect=mock_run_side_effect):
            devices = ops._list_macos_devices()

            # Should only return the physical disk, not the APFS container
            assert len(devices) == 1
            assert devices[0].path.name == "disk6"
            assert devices[0].name == "USB3.0 CRW   -SD"


class TestListLinuxDevices:
    """Tests for _list_linux_devices method."""

    def test_list_linux_devices_empty(self) -> None:
        """Test listing Linux devices when none are connected."""
        ops = StorageOperations()
        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            devices = ops._list_linux_devices()
            assert devices == []

    def test_list_linux_devices_invalid_json(self) -> None:
        """Test listing Linux devices with invalid JSON."""
        ops = StorageOperations()
        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="not json")
            devices = ops._list_linux_devices()
            assert devices == []

    def test_list_linux_devices_with_devices(self) -> None:
        """Test listing Linux devices with results."""
        ops = StorageOperations()
        lsblk_output = json.dumps(
            {
                "blockdevices": [
                    {
                        "name": "sda",
                        "size": "8G",
                        "rm": "1",
                        "mountpoint": "/media/usb",
                        "type": "disk",
                    }
                ]
            }
        )
        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=lsblk_output)
            devices = ops._list_linux_devices()
            assert len(devices) == 1
            assert devices[0].name == "sda"
            assert devices[0].removable is True


class TestStorageError:
    """Tests for StorageError exception."""

    def test_storage_error_message(self) -> None:
        """Test StorageError can be raised with message."""
        with pytest.raises(StorageError, match="test error"):
            raise StorageError("test error")


class TestParseSize:
    """Tests for _parse_size method."""

    def test_parse_size_kilobytes(self) -> None:
        """Test parsing kilobyte size."""
        ops = StorageOperations()
        assert ops._parse_size("10K") == 10 * 1024

    def test_parse_size_megabytes(self) -> None:
        """Test parsing megabyte size."""
        ops = StorageOperations()
        assert ops._parse_size("100M") == 100 * 1024**2

    def test_parse_size_gigabytes(self) -> None:
        """Test parsing gigabyte size."""
        ops = StorageOperations()
        assert ops._parse_size("8G") == 8 * 1024**3

    def test_parse_size_terabytes(self) -> None:
        """Test parsing terabyte size."""
        ops = StorageOperations()
        assert ops._parse_size("1T") == 1 * 1024**4

    def test_parse_size_plain_number(self) -> None:
        """Test parsing plain number."""
        ops = StorageOperations()
        assert ops._parse_size("1000") == 1000

    def test_parse_size_empty_string(self) -> None:
        """Test parsing empty string returns 0."""
        ops = StorageOperations()
        assert ops._parse_size("") == 0

    def test_parse_size_invalid_string(self) -> None:
        """Test parsing invalid string returns 0."""
        ops = StorageOperations()
        assert ops._parse_size("invalid") == 0


class TestCreateEncryptedVolume:
    """Tests for create_encrypted_volume method."""

    def test_create_encrypted_volume_macos(self, tmp_path: Path) -> None:
        """Test creating encrypted volume on macOS."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        with patch.object(ops, "_create_apfs_encrypted") as mock_create:
            from yubikey_init.types import Result, VolumeInfo

            mock_create.return_value = Result.ok(
                VolumeInfo(
                    device=tmp_path,
                    name="test",
                    uuid="",
                    size_bytes=0,
                )
            )

            result = ops.create_encrypted_volume(tmp_path, SecureString("pass"), "test")
            assert result.is_ok()
            mock_create.assert_called_once()

    def test_create_encrypted_volume_linux(self, tmp_path: Path) -> None:
        """Test creating encrypted volume on Linux."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        with patch.object(ops, "_create_luks_volume") as mock_create:
            from yubikey_init.types import Result, VolumeInfo

            mock_create.return_value = Result.ok(
                VolumeInfo(
                    device=tmp_path,
                    name="test",
                    uuid="",
                    size_bytes=0,
                )
            )

            result = ops.create_encrypted_volume(tmp_path, SecureString("pass"), "test")
            assert result.is_ok()
            mock_create.assert_called_once()

    def test_create_encrypted_volume_unsupported(self, tmp_path: Path) -> None:
        """Test creating encrypted volume on unsupported system."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Windows"

        result = ops.create_encrypted_volume(tmp_path, SecureString("pass"), "test")
        assert result.is_err()
        assert "Unsupported system" in str(result.unwrap_err())


class TestCreateLuksVolume:
    """Tests for _create_luks_volume method."""

    def test_create_luks_volume_success(self, tmp_path: Path) -> None:
        """Test creating LUKS volume successfully."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = ops._create_luks_volume(tmp_path, SecureString("pass"), "test")
            assert result.is_ok()
            assert result.unwrap().name == "test"

    def test_create_luks_volume_failure(self, tmp_path: Path) -> None:
        """Test creating LUKS volume failure."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="LUKS error")

            result = ops._create_luks_volume(tmp_path, SecureString("pass"), "test")
            assert result.is_err()
            assert "LUKS format failed" in str(result.unwrap_err())


class TestOpenEncryptedVolume:
    """Tests for open_encrypted_volume method."""

    def test_open_encrypted_volume_linux_success(self, tmp_path: Path) -> None:
        """Test opening encrypted volume on Linux."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = ops.open_encrypted_volume(tmp_path, SecureString("pass"), "backup")
            assert result.is_ok()
            assert result.unwrap() == Path("/dev/mapper/backup")

    def test_open_encrypted_volume_linux_failure(self, tmp_path: Path) -> None:
        """Test opening encrypted volume fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Wrong passphrase")

            result = ops.open_encrypted_volume(tmp_path, SecureString("wrong"), "backup")
            assert result.is_err()
            assert "Open failed" in str(result.unwrap_err())

    def test_open_encrypted_volume_macos(self, tmp_path: Path) -> None:
        """Test opening encrypted volume on macOS returns error."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        result = ops.open_encrypted_volume(tmp_path, SecureString("pass"), "backup")
        assert result.is_err()
        assert "Manual mount required" in str(result.unwrap_err())


class TestCloseEncryptedVolume:
    """Tests for close_encrypted_volume method."""

    def test_close_encrypted_volume_linux_success(self) -> None:
        """Test closing encrypted volume on Linux."""
        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = ops.close_encrypted_volume("backup")
            assert result.is_ok()

    def test_close_encrypted_volume_linux_failure(self) -> None:
        """Test closing encrypted volume fails."""
        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Device busy")

            result = ops.close_encrypted_volume("backup")
            assert result.is_err()
            assert "Close failed" in str(result.unwrap_err())

    def test_close_encrypted_volume_macos(self) -> None:
        """Test closing encrypted volume on macOS returns error."""
        ops = StorageOperations()
        ops._system = "Darwin"

        result = ops.close_encrypted_volume("backup")
        assert result.is_err()
        assert "Manual unmount required" in str(result.unwrap_err())


class TestMountUnmountVolume:
    """Tests for mount_volume and unmount_volume methods."""

    def test_mount_volume_success(self, tmp_path: Path) -> None:
        """Test mounting volume successfully."""
        ops = StorageOperations()
        device = tmp_path / "device"
        mount_point = tmp_path / "mount"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = ops.mount_volume(device, mount_point)
            assert result.is_ok()
            assert result.unwrap() == mount_point

    def test_mount_volume_failure(self, tmp_path: Path) -> None:
        """Test mount volume fails."""
        ops = StorageOperations()
        device = tmp_path / "device"
        mount_point = tmp_path / "mount"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Mount failed")

            result = ops.mount_volume(device, mount_point)
            assert result.is_err()

    def test_unmount_volume_macos_success(self, tmp_path: Path) -> None:
        """Test unmounting volume on macOS."""
        ops = StorageOperations()
        ops._system = "Darwin"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = ops.unmount_volume(tmp_path)
            assert result.is_ok()
            # Verify diskutil was used
            args = mock_run.call_args[0][0]
            assert "diskutil" in args

    def test_unmount_volume_linux_success(self, tmp_path: Path) -> None:
        """Test unmounting volume on Linux."""
        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = ops.unmount_volume(tmp_path)
            assert result.is_ok()
            # Verify umount was used
            args = mock_run.call_args[0][0]
            assert "umount" in args

    def test_unmount_volume_failure(self, tmp_path: Path) -> None:
        """Test unmount volume fails."""
        ops = StorageOperations()
        ops._system = "Linux"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Device busy")

            result = ops.unmount_volume(tmp_path)
            assert result.is_err()


class TestVerifyBackup:
    """Tests for verify_backup method."""

    def test_verify_backup_all_files_found(self, tmp_path: Path) -> None:
        """Test verifying backup when all files exist."""
        ops = StorageOperations()

        # Create expected files
        (tmp_path / "key.asc").touch()
        (tmp_path / "secret.asc").touch()

        result = ops.verify_backup(tmp_path, ["key.asc", "secret.asc"])
        assert result.is_ok()
        verification = result.unwrap()
        assert verification.is_complete
        assert len(verification.files_found) == 2
        assert len(verification.files_missing) == 0

    def test_verify_backup_some_files_missing(self, tmp_path: Path) -> None:
        """Test verifying backup when some files are missing."""
        ops = StorageOperations()

        # Create only one file
        (tmp_path / "key.asc").touch()

        result = ops.verify_backup(tmp_path, ["key.asc", "secret.asc"])
        assert result.is_ok()
        verification = result.unwrap()
        assert not verification.is_complete
        assert "key.asc" in verification.files_found
        assert "secret.asc" in verification.files_missing

    def test_verify_backup_path_not_exists(self) -> None:
        """Test verifying backup when path doesn't exist."""
        ops = StorageOperations()

        result = ops.verify_backup(Path("/nonexistent/path"), ["file.asc"])
        assert result.is_err()
        assert "does not exist" in str(result.unwrap_err())


class TestPrepareBackupDriveMacOS:
    """Tests for prepare_backup_drive_macos method."""

    def test_prepare_backup_drive_success(self, tmp_path: Path) -> None:
        """Test preparing backup drive on macOS successfully."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        # Use device path as the identifier prefix (without /dev/ prefix, full path is used)
        device_id = str(tmp_path)

        # Mock plist for apfs list (used by _get_apfs_container)
        # The container has a PhysicalStore that starts with our device_id
        mock_apfs_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [
                            {"DeviceIdentifier": device_id + "s2"}  # matches startswith check
                        ],
                        "Volumes": [{"DeviceIdentifier": "disk4s1", "Name": "GPG-BACKUP"}],
                    }
                ]
            }
        )

        # Mock plist for diskutil list (volume identifiers)
        mock_disk_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                            {"VolumeName": "gnupg-public", "DeviceIdentifier": "disk4s2"},
                        ]
                    }
                ]
            }
        )

        mock_list_response = MagicMock(returncode=0, stdout=mock_apfs_list)
        mock_disk_list_response = MagicMock(returncode=0, stdout=mock_disk_list)
        mock_success = MagicMock(returncode=0, stdout=b"", stderr="")

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock_success,  # unmountDisk
                mock_success,  # eraseDisk
                mock_list_response,  # apfs list (get container)
                mock_list_response,  # apfs list (find default volume)
                mock_success,  # deleteVolume
                mock_success,  # addVolume encrypted
                mock_success,  # addVolume public
                mock_success,  # unmount encrypted
                mock_success,  # unmount public
                mock_disk_list_response,  # list for encrypted volume identifier
                mock_disk_list_response,  # list for public volume identifier
            ]

            result = ops.prepare_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_ok()
            info = result.unwrap()
            assert info.device_path == tmp_path
            assert info.encrypted_label == "gnupg-secrets"
            assert info.public_label == "gnupg-public"

    def test_prepare_backup_drive_erase_fails(self, tmp_path: Path) -> None:
        """Test prepare backup drive when erase fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # unmountDisk
                MagicMock(returncode=1, stderr="Erase failed"),  # eraseDisk
            ]

            result = ops.prepare_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to erase disk" in str(result.unwrap_err())

    def test_prepare_backup_drive_encrypted_volume_fails(self, tmp_path: Path) -> None:
        """Test prepare backup drive when encrypted volume creation fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        # Use device path as the identifier prefix
        device_id = str(tmp_path)

        mock_apfs_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [{"DeviceIdentifier": device_id + "s2"}],
                        "Volumes": [{"DeviceIdentifier": "disk4s1", "Name": "GPG-BACKUP"}],
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # unmountDisk
                MagicMock(returncode=0),  # eraseDisk
                MagicMock(returncode=0, stdout=mock_apfs_list),  # apfs list (get container)
                MagicMock(returncode=0, stdout=mock_apfs_list),  # apfs list (find default volume)
                MagicMock(returncode=0),  # deleteVolume
                MagicMock(returncode=1, stderr="Encryption failed"),  # addVolume encrypted
            ]

            result = ops.prepare_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to create encrypted volume" in str(result.unwrap_err())

    def test_prepare_backup_drive_uses_correct_stdinpassphrase_syntax(self, tmp_path: Path) -> None:
        """Test that encrypted volume uses -stdinpassphrase correctly (not -passphrase).

        Regression test: previously used '-passphrase -stdinpassphrase' which incorrectly
        set the passphrase to the literal string '-stdinpassphrase' instead of reading from stdin.
        """
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        device_id = str(tmp_path)

        mock_apfs_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [{"DeviceIdentifier": device_id + "s2"}],
                        "Volumes": [{"DeviceIdentifier": "disk4s1", "Name": "GPG-BACKUP"}],
                    }
                ]
            }
        )

        mock_disk_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                            {"VolumeName": "gnupg-public", "DeviceIdentifier": "disk4s2"},
                        ]
                    }
                ]
            }
        )

        mock_list_response = MagicMock(returncode=0, stdout=mock_apfs_list)
        mock_disk_list_response = MagicMock(returncode=0, stdout=mock_disk_list)
        mock_success = MagicMock(returncode=0, stdout=b"", stderr="")

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock_success,  # unmountDisk
                mock_success,  # eraseDisk
                mock_list_response,  # apfs list (get container)
                mock_list_response,  # apfs list (find default volume)
                mock_success,  # deleteVolume
                mock_success,  # addVolume encrypted
                mock_success,  # addVolume public
                mock_success,  # unmount encrypted
                mock_success,  # unmount public
                mock_disk_list_response,  # list for encrypted volume identifier
                mock_disk_list_response,  # list for public volume identifier
            ]

            result = ops.prepare_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_ok()

            # Find the addVolume encrypted call (6th call, index 5)
            add_encrypted_call = mock_run.call_args_list[5]
            args = add_encrypted_call[0][0]  # First positional argument is the command list

            # Verify -stdinpassphrase is used WITHOUT -passphrase flag
            assert "-stdinpassphrase" in args
            assert "-passphrase" not in args, (
                "Should not use -passphrase flag with -stdinpassphrase"
            )

            # Verify passphrase was passed via stdin
            assert add_encrypted_call[1].get("input") == "test-pass"


class TestOpenBackupDriveMacOS:
    """Tests for open_backup_drive_macos method."""

    def test_open_backup_drive_success(self, tmp_path: Path) -> None:
        """Test opening backup drive on macOS successfully."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                            {"VolumeName": "gnupg-public", "DeviceIdentifier": "disk4s2"},
                        ]
                    }
                ]
            }
        )

        mock_info_encrypted = plistlib.dumps({"MountPoint": "/Volumes/gnupg-secrets"})
        mock_info_public = plistlib.dumps({"MountPoint": "/Volumes/gnupg-public"})

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # list for encrypted volume id
                MagicMock(returncode=0),  # unlockVolume
                MagicMock(returncode=0),  # mount encrypted
                MagicMock(returncode=0, stdout=mock_list),  # list for public volume id
                MagicMock(returncode=0),  # mount public
                MagicMock(returncode=0, stdout=mock_list),  # list for mount point (encrypted)
                MagicMock(returncode=0, stdout=mock_info_encrypted),  # info encrypted
                MagicMock(returncode=0, stdout=mock_list),  # list for mount point (public)
                MagicMock(returncode=0, stdout=mock_info_public),  # info public
            ]

            result = ops.open_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_ok()
            mounted = result.unwrap()
            assert mounted.encrypted_mount == Path("/Volumes/gnupg-secrets")
            assert mounted.public_mount == Path("/Volumes/gnupg-public")
            assert mounted.device_path == tmp_path

    def test_open_backup_drive_unlock_fails(self, tmp_path: Path) -> None:
        """Test opening backup drive when unlock fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # list for encrypted volume id
                MagicMock(returncode=1, stderr="Wrong passphrase"),  # unlockVolume fails
            ]

            result = ops.open_backup_drive_macos(tmp_path, SecureString("wrong-pass"))
            assert result.is_err()
            assert "Failed to unlock encrypted volume" in str(result.unwrap_err())

    def test_open_backup_drive_public_mount_fails(self, tmp_path: Path) -> None:
        """Test opening backup drive when public volume mount fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                            {"VolumeName": "gnupg-public", "DeviceIdentifier": "disk4s2"},
                        ]
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # list for encrypted volume id
                MagicMock(returncode=0),  # unlockVolume
                MagicMock(returncode=0),  # mount encrypted
                MagicMock(returncode=0, stdout=mock_list),  # list for public volume id
                MagicMock(returncode=1, stderr="Mount failed"),  # mount public fails
                MagicMock(returncode=0),  # unmount encrypted (cleanup)
            ]

            result = ops.open_backup_drive_macos(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to mount public volume" in str(result.unwrap_err())


class TestCloseBackupDriveMacOS:
    """Tests for close_backup_drive_macos method."""

    def test_close_backup_drive_success(self, tmp_path: Path) -> None:
        """Test closing backup drive on macOS successfully."""
        from yubikey_init.types import MountedBackupDrive

        ops = StorageOperations()
        ops._system = "Darwin"

        mounted = MountedBackupDrive(
            encrypted_mount=Path("/Volumes/gnupg-secrets"),
            public_mount=Path("/Volumes/gnupg-public"),
            device_path=tmp_path,
        )

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # unmount encrypted
                MagicMock(returncode=0),  # unmount public
                MagicMock(returncode=0, stdout=mock_list),  # list for volume id
                MagicMock(returncode=0),  # lockVolume
            ]

            result = ops.close_backup_drive_macos(mounted)
            assert result.is_ok()

    def test_close_backup_drive_unmount_fails(self, tmp_path: Path) -> None:
        """Test closing backup drive when unmount fails."""
        from yubikey_init.types import MountedBackupDrive

        ops = StorageOperations()
        ops._system = "Darwin"

        mounted = MountedBackupDrive(
            encrypted_mount=Path("/Volumes/gnupg-secrets"),
            public_mount=Path("/Volumes/gnupg-public"),
            device_path=tmp_path,
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Device busy")

            result = ops.close_backup_drive_macos(mounted)
            assert result.is_err()
            assert "Failed to unmount encrypted volume" in str(result.unwrap_err())


class TestVerifyBackupDriveMacOS:
    """Tests for verify_backup_drive_macos method."""

    def test_verify_backup_drive_valid(self, tmp_path: Path) -> None:
        """Test verifying valid backup drive on macOS."""
        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        # Use device path as the identifier prefix
        device_id = str(tmp_path)

        mock_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [{"DeviceIdentifier": device_id + "s2"}],
                        "Volumes": [
                            {"Name": "gnupg-secrets"},
                            {"Name": "gnupg-public"},
                        ],
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # apfs list (get container)
                MagicMock(returncode=0, stdout=mock_list),  # apfs list (verify volumes)
            ]

            result = ops.verify_backup_drive_macos(tmp_path)
            assert result.is_ok()
            assert result.unwrap() is True

    def test_verify_backup_drive_missing_volumes(self, tmp_path: Path) -> None:
        """Test verifying backup drive with missing volumes."""
        ops = StorageOperations()
        ops._system = "Darwin"

        import plistlib

        # Use device path as the identifier prefix
        device_id = str(tmp_path)

        mock_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [{"DeviceIdentifier": device_id + "s2"}],
                        "Volumes": [
                            {"Name": "gnupg-secrets"},
                            # Missing gnupg-public
                        ],
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # apfs list (get container)
                MagicMock(returncode=0, stdout=mock_list),  # apfs list (verify volumes)
            ]

            result = ops.verify_backup_drive_macos(tmp_path)
            assert result.is_ok()
            assert result.unwrap() is False

    def test_verify_backup_drive_no_container(self, tmp_path: Path) -> None:
        """Test verifying backup drive with no APFS container."""
        ops = StorageOperations()
        ops._system = "Darwin"

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Not APFS")

            result = ops.verify_backup_drive_macos(tmp_path)
            assert result.is_ok()
            assert result.unwrap() is False


class TestGetApfsContainer:
    """Tests for _get_apfs_container helper method."""

    def test_get_apfs_container_success(self, tmp_path: Path) -> None:
        """Test getting APFS container successfully."""
        ops = StorageOperations()

        import plistlib

        # Use device path as the identifier prefix
        device_id = str(tmp_path)

        mock_apfs_list = plistlib.dumps(
            {
                "Containers": [
                    {
                        "ContainerReference": "disk4",
                        "PhysicalStores": [{"DeviceIdentifier": device_id + "s2"}],
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_apfs_list)

            result = ops._get_apfs_container(tmp_path)
            assert result.is_ok()
            assert result.unwrap() == "disk4"

    def test_get_apfs_container_fails(self, tmp_path: Path) -> None:
        """Test getting APFS container when command fails."""
        ops = StorageOperations()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Error")

            result = ops._get_apfs_container(tmp_path)
            assert result.is_err()
            assert "Failed to list APFS containers" in str(result.unwrap_err())


class TestGetVolumeIdentifier:
    """Tests for _get_volume_identifier helper method."""

    def test_get_volume_identifier_success(self) -> None:
        """Test getting volume identifier successfully."""
        ops = StorageOperations()

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_list)

            result = ops._get_volume_identifier("gnupg-secrets")
            assert result.is_ok()
            assert result.unwrap() == "disk4s1"

    def test_get_volume_identifier_not_found(self) -> None:
        """Test getting volume identifier when volume not found."""
        ops = StorageOperations()

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "other-volume", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_list)

            result = ops._get_volume_identifier("gnupg-secrets")
            assert result.is_err()
            assert "Volume not found" in str(result.unwrap_err())


class TestGetVolumeMountPoint:
    """Tests for _get_volume_mount_point helper method."""

    def test_get_volume_mount_point_success(self) -> None:
        """Test getting volume mount point successfully."""
        ops = StorageOperations()

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )
        mock_info = plistlib.dumps({"MountPoint": "/Volumes/gnupg-secrets"})

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # list
                MagicMock(returncode=0, stdout=mock_info),  # info
            ]

            result = ops._get_volume_mount_point("gnupg-secrets")
            assert result.is_ok()
            assert result.unwrap() == Path("/Volumes/gnupg-secrets")

    def test_get_volume_mount_point_not_mounted(self) -> None:
        """Test getting volume mount point when not mounted."""
        ops = StorageOperations()

        import plistlib

        mock_list = plistlib.dumps(
            {
                "AllDisksAndPartitions": [
                    {
                        "APFSVolumes": [
                            {"VolumeName": "gnupg-secrets", "DeviceIdentifier": "disk4s1"},
                        ]
                    }
                ]
            }
        )
        mock_info = plistlib.dumps({})  # No MountPoint

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=mock_list),  # list
                MagicMock(returncode=0, stdout=mock_info),  # info
            ]

            result = ops._get_volume_mount_point("gnupg-secrets")
            assert result.is_err()
            assert "Volume not mounted" in str(result.unwrap_err())


class TestPrepareBackupDriveLinux:
    """Tests for prepare_backup_drive_linux method."""

    def test_prepare_backup_drive_success(self, tmp_path: Path) -> None:
        """Test preparing backup drive on Linux successfully."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        mock_success = MagicMock(returncode=0, stdout="", stderr="")

        # Mock pexpect.spawn for LUKS operations
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.expect = MagicMock()
        mock_child.sendline = MagicMock()
        mock_child.close = MagicMock()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            with patch("pexpect.spawn", return_value=mock_child):
                # Mock all subprocess calls to succeed
                mock_run.return_value = mock_success

                # Mock time.sleep to speed up test
                with patch("time.sleep"):
                    result = ops.prepare_backup_drive_linux(tmp_path, SecureString("test-pass"))

                assert result.is_ok()
                info = result.unwrap()
                assert info.device_path == tmp_path
                assert info.encrypted_partition == Path(f"{tmp_path}1")
                assert info.public_partition == Path(f"{tmp_path}2")
                assert info.encrypted_label == "gnupg-secrets"
                assert info.public_label == "GNUPG-PUB"

    def test_prepare_backup_drive_zero_fails(self, tmp_path: Path) -> None:
        """Test prepare backup drive when zeroing header fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock lsblk for unmount step (no partitions mounted)
        lsblk_response = MagicMock(returncode=0, stdout='{"blockdevices":[]}')

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                lsblk_response,  # lsblk for unmount
                MagicMock(returncode=1, stderr="Permission denied"),  # dd fails
            ]

            result = ops.prepare_backup_drive_linux(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to zero device header" in str(result.unwrap_err())

    def test_prepare_backup_drive_gpt_fails(self, tmp_path: Path) -> None:
        """Test prepare backup drive when GPT creation fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock lsblk for unmount step (no partitions mounted)
        lsblk_response = MagicMock(returncode=0, stdout='{"blockdevices":[]}')

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                lsblk_response,  # lsblk for unmount
                MagicMock(returncode=0),  # dd success
                MagicMock(returncode=1, stderr="GPT error"),  # parted mklabel fails
            ]

            result = ops.prepare_backup_drive_linux(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to create GPT partition table" in str(result.unwrap_err())

    def test_prepare_backup_drive_partition_creation_fails(self, tmp_path: Path) -> None:
        """Test prepare backup drive when partition creation fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock lsblk for unmount step (no partitions mounted)
        lsblk_response = MagicMock(returncode=0, stdout='{"blockdevices":[]}')

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                lsblk_response,  # lsblk for unmount
                MagicMock(returncode=0),  # dd success
                MagicMock(returncode=0),  # parted mklabel success
                MagicMock(returncode=1, stderr="Partition error"),  # parted mkpart fails
            ]

            result = ops.prepare_backup_drive_linux(tmp_path, SecureString("test-pass"))
            assert result.is_err()
            assert "Failed to create encrypted partition" in str(result.unwrap_err())


class TestOpenBackupDriveLinux:
    """Tests for open_backup_drive_linux method."""

    def test_open_backup_drive_success(self, tmp_path: Path) -> None:
        """Test opening backup drive on Linux successfully."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        mock_success = MagicMock(returncode=0, stdout="", stderr="")

        # Mock pexpect.spawn for LUKS open
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.expect = MagicMock()
        mock_child.sendline = MagicMock()
        mock_child.close = MagicMock()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            with patch("pexpect.spawn", return_value=mock_child):
                mock_run.return_value = mock_success

                result = ops.open_backup_drive_linux(tmp_path, SecureString("test-pass"))

                assert result.is_ok()
                mounted = result.unwrap()
                assert mounted.device_path == tmp_path
                assert "yubikey-encrypted-" in str(mounted.encrypted_mount)
                assert "yubikey-public-" in str(mounted.public_mount)

    def test_open_backup_drive_luks_open_fails(self, tmp_path: Path) -> None:
        """Test opening backup drive when LUKS open fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock pexpect.spawn to simulate failure
        mock_child = MagicMock()
        mock_child.exitstatus = 1
        mock_child.expect = MagicMock()
        mock_child.sendline = MagicMock()
        mock_child.close = MagicMock()

        with patch("pexpect.spawn", return_value=mock_child):
            result = ops.open_backup_drive_linux(tmp_path, SecureString("wrong-pass"))
            assert result.is_err()
            assert "Failed to open LUKS volume" in str(result.unwrap_err())

    def test_open_backup_drive_encrypted_mount_fails(self, tmp_path: Path) -> None:
        """Test opening backup drive when encrypted partition mount fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock pexpect.spawn for successful LUKS open
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.expect = MagicMock()
        mock_child.sendline = MagicMock()
        mock_child.close = MagicMock()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            with patch("pexpect.spawn", return_value=mock_child):
                mock_run.side_effect = [
                    MagicMock(returncode=1, stderr="Mount failed"),  # mount encrypted fails
                    MagicMock(returncode=0),  # cryptsetup close (cleanup)
                ]

                result = ops.open_backup_drive_linux(tmp_path, SecureString("test-pass"))
                assert result.is_err()
                assert "Failed to mount encrypted partition" in str(result.unwrap_err())

    def test_open_backup_drive_public_mount_fails(self, tmp_path: Path) -> None:
        """Test opening backup drive when public partition mount fails."""
        from yubikey_init.types import SecureString

        ops = StorageOperations()
        ops._system = "Linux"

        # Mock pexpect.spawn for successful LUKS open
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.expect = MagicMock()
        mock_child.sendline = MagicMock()
        mock_child.close = MagicMock()

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            with patch("pexpect.spawn", return_value=mock_child):
                mock_run.side_effect = [
                    MagicMock(returncode=0),  # mount encrypted success
                    MagicMock(returncode=1, stderr="Mount failed"),  # mount public fails
                    MagicMock(returncode=0),  # umount encrypted (cleanup)
                    MagicMock(returncode=0),  # cryptsetup close (cleanup)
                ]

                result = ops.open_backup_drive_linux(tmp_path, SecureString("test-pass"))
                assert result.is_err()
                assert "Failed to mount public partition" in str(result.unwrap_err())


class TestCloseBackupDriveLinux:
    """Tests for close_backup_drive_linux method."""

    def test_close_backup_drive_success(self, tmp_path: Path) -> None:
        """Test closing backup drive on Linux successfully."""
        from yubikey_init.types import MountedBackupDrive

        ops = StorageOperations()
        ops._system = "Linux"

        # Create temporary directories for mount points
        encrypted_mount = tmp_path / "encrypted"
        public_mount = tmp_path / "public"
        encrypted_mount.mkdir()
        public_mount.mkdir()

        mounted = MountedBackupDrive(
            encrypted_mount=encrypted_mount,
            public_mount=public_mount,
            device_path=tmp_path,
        )

        mock_success = MagicMock(returncode=0, stdout="", stderr="")

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = mock_success

            result = ops.close_backup_drive_linux(mounted)
            assert result.is_ok()

    def test_close_backup_drive_unmount_fails(self, tmp_path: Path) -> None:
        """Test closing backup drive when unmount fails."""
        from yubikey_init.types import MountedBackupDrive

        ops = StorageOperations()
        ops._system = "Linux"

        encrypted_mount = tmp_path / "encrypted"
        public_mount = tmp_path / "public"
        encrypted_mount.mkdir()
        public_mount.mkdir()

        mounted = MountedBackupDrive(
            encrypted_mount=encrypted_mount,
            public_mount=public_mount,
            device_path=tmp_path,
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Device busy")

            result = ops.close_backup_drive_linux(mounted)
            assert result.is_err()
            assert "Failed to unmount" in str(result.unwrap_err())

    def test_close_backup_drive_luks_close_fails(self, tmp_path: Path) -> None:
        """Test closing backup drive when LUKS close fails."""
        from yubikey_init.types import MountedBackupDrive

        ops = StorageOperations()
        ops._system = "Linux"

        encrypted_mount = tmp_path / "encrypted"
        public_mount = tmp_path / "public"
        encrypted_mount.mkdir()
        public_mount.mkdir()

        mounted = MountedBackupDrive(
            encrypted_mount=encrypted_mount,
            public_mount=public_mount,
            device_path=tmp_path,
        )

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # umount public success
                MagicMock(returncode=0),  # umount encrypted success
                MagicMock(returncode=1, stderr="LUKS close failed"),  # cryptsetup close fails
                MagicMock(returncode=0),  # sync
            ]

            result = ops.close_backup_drive_linux(mounted)
            assert result.is_err()
            assert "Failed to close LUKS volume" in str(result.unwrap_err())


class TestVerifyBackupDriveLinux:
    """Tests for verify_backup_drive_linux method."""

    def test_verify_backup_drive_valid(self, tmp_path: Path) -> None:
        """Test verifying valid backup drive on Linux."""
        ops = StorageOperations()
        ops._system = "Linux"

        # Create fake partition paths that the function will check
        partition1 = Path(f"{tmp_path}1")
        partition2 = Path(f"{tmp_path}2")

        def mock_exists(path: Path) -> bool:
            return path in [tmp_path, partition1, partition2]

        with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)  # cryptsetup isLuks succeeds

            with patch.object(Path, "exists", mock_exists):
                result = ops.verify_backup_drive_linux(tmp_path)
                assert result.is_ok()
                assert result.unwrap() is True

    def test_verify_backup_drive_device_not_exists(self) -> None:
        """Test verifying backup drive when device doesn't exist."""
        ops = StorageOperations()
        ops._system = "Linux"

        result = ops.verify_backup_drive_linux(Path("/dev/nonexistent"))
        assert result.is_err()
        assert "Device does not exist" in str(result.unwrap_err())

    def test_verify_backup_drive_partition1_missing(self, tmp_path: Path) -> None:
        """Test verifying backup drive when partition 1 is missing."""
        ops = StorageOperations()
        ops._system = "Linux"

        def mock_exists(path: Path) -> bool:
            # Device exists, but partition1 doesn't
            return path == tmp_path

        with patch.object(Path, "exists", mock_exists):
            result = ops.verify_backup_drive_linux(tmp_path)
            assert result.is_ok()
            assert result.unwrap() is False

    def test_verify_backup_drive_partition2_missing(self, tmp_path: Path) -> None:
        """Test verifying backup drive when partition 2 is missing."""
        ops = StorageOperations()
        ops._system = "Linux"

        partition1 = Path(f"{tmp_path}1")

        def mock_exists(path: Path) -> bool:
            # Device and partition1 exist, but partition2 doesn't
            return path in [tmp_path, partition1]

        with patch.object(Path, "exists", mock_exists):
            result = ops.verify_backup_drive_linux(tmp_path)
            assert result.is_ok()
            assert result.unwrap() is False

    def test_verify_backup_drive_no_luks_header(self, tmp_path: Path) -> None:
        """Test verifying backup drive when partition 1 has no LUKS header."""
        ops = StorageOperations()
        ops._system = "Linux"

        def mock_exists(path: Path) -> bool:
            return True  # All paths exist

        with patch.object(Path, "exists", mock_exists):
            with patch("yubikey_init.storage_ops.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)  # cryptsetup isLuks fails

                result = ops.verify_backup_drive_linux(tmp_path)
                assert result.is_ok()
                assert result.unwrap() is False
