from __future__ import annotations

import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .types import (
    BackupDriveInfo,
    BackupVerification,
    DeviceInfo,
    MountedBackupDrive,
    Result,
    SecureString,
    VolumeInfo,
)


class StorageError(Exception):
    pass


class StorageOperations:
    def __init__(self) -> None:
        self._system = platform.system()

    def list_removable_devices(self) -> list[DeviceInfo]:
        if self._system == "Darwin":
            return self._list_macos_devices()
        elif self._system == "Linux":
            return self._list_linux_devices()
        return []

    def _list_macos_devices(self) -> list[DeviceInfo]:
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external"],
            capture_output=True,
        )

        if result.returncode != 0:
            return []

        import plistlib

        try:
            data = plistlib.loads(result.stdout)
        except Exception:
            return []

        devices = []
        for disk in data.get("AllDisksAndPartitions", []):
            device_id = disk.get("DeviceIdentifier", "")
            size = disk.get("Size", 0)
            content = disk.get("Content", "")

            if device_id and size > 0:
                # Skip synthesized APFS containers (they appear alongside the physical disk)
                # These have Content="Apple_APFS_Container" or APFSPhysicalStores property
                if content == "Apple_APFS_Container" or disk.get("APFSPhysicalStores"):
                    continue

                result = subprocess.run(
                    ["diskutil", "info", "-plist", device_id],
                    capture_output=True,
                )
                if result.returncode == 0:
                    try:
                        info = plistlib.loads(result.stdout)
                        # Skip synthesized/virtual disks (additional check via diskutil info)
                        if info.get("Virtual", False):
                            continue

                        # Check if any partitions are mounted
                        mount_info = self._get_disk_mount_info(device_id)

                        devices.append(
                            DeviceInfo(
                                path=Path(f"/dev/{device_id}"),
                                name=info.get("MediaName", device_id),
                                size_bytes=size,
                                removable=info.get("Removable", False),
                                mounted=mount_info[0],
                                mount_point=mount_info[1],
                            )
                        )
                    except Exception:
                        pass

        return devices

    def _get_disk_mount_info(self, device_id: str) -> tuple[bool, Path | None]:
        """Check if a disk or any of its partitions are mounted.

        Args:
            device_id: Device identifier (e.g., "disk6")

        Returns:
            Tuple of (is_mounted, first_mount_point)
        """
        import plistlib

        # Get list of all partitions on this disk
        result = subprocess.run(
            ["diskutil", "list", "-plist", device_id],
            capture_output=True,
        )

        if result.returncode != 0:
            return (False, None)

        try:
            data = plistlib.loads(result.stdout)
            all_disks = data.get("AllDisks", [])

            for partition_id in all_disks:
                # Check each partition's mount point
                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", partition_id],
                    capture_output=True,
                )
                if info_result.returncode == 0:
                    part_info = plistlib.loads(info_result.stdout)
                    mount_point = part_info.get("MountPoint", "")
                    if mount_point:  # Non-empty string means mounted
                        return (True, Path(mount_point))

            return (False, None)
        except Exception:
            return (False, None)

    def _list_linux_devices(self) -> list[DeviceInfo]:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,RM,MOUNTPOINT,TYPE"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        devices = []
        for device in data.get("blockdevices", []):
            if device.get("type") == "disk" and device.get("rm"):
                devices.append(
                    DeviceInfo(
                        path=Path(f"/dev/{device['name']}"),
                        name=device["name"],
                        size_bytes=self._parse_size(device.get("size", "0")),
                        removable=True,
                        mounted=device.get("mountpoint") is not None,
                        mount_point=Path(device["mountpoint"])
                        if device.get("mountpoint")
                        else None,
                    )
                )

        return devices

    def _parse_size(self, size_str: str) -> int:
        multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        size_str = size_str.strip()
        if not size_str:
            return 0

        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                return int(float(size_str[:-1]) * mult)

        try:
            return int(size_str)
        except ValueError:
            return 0

    def create_encrypted_volume(
        self,
        device: Path,
        passphrase: SecureString,
        label: str = "yubikey-backup",
    ) -> Result[VolumeInfo]:
        if self._system == "Darwin":
            return self._create_apfs_encrypted(device, passphrase, label)
        elif self._system == "Linux":
            return self._create_luks_volume(device, passphrase, label)

        return Result.err(StorageError(f"Unsupported system: {self._system}"))

    def _create_apfs_encrypted(
        self,
        device: Path,
        passphrase: SecureString,
        label: str,
    ) -> Result[VolumeInfo]:
        result = subprocess.run(
            [
                "diskutil",
                "apfs",
                "createContainer",
                str(device),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Container creation failed: {result.stderr}"))

        result = subprocess.run(
            [
                "diskutil",
                "apfs",
                "addVolume",
                str(device),
                "APFS",
                label,
                "-passphrase",
                passphrase.get(),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Volume creation failed: {result.stderr}"))

        return Result.ok(
            VolumeInfo(
                device=device,
                name=label,
                uuid="",
                size_bytes=0,
            )
        )

    def _create_luks_volume(
        self,
        device: Path,
        passphrase: SecureString,
        label: str,
    ) -> Result[VolumeInfo]:
        result = subprocess.run(
            [
                "cryptsetup",
                "luksFormat",
                "--type",
                "luks2",
                "--label",
                label,
                "--batch-mode",
                str(device),
            ],
            input=passphrase.get(),
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"LUKS format failed: {result.stderr}"))

        return Result.ok(
            VolumeInfo(
                device=device,
                name=label,
                uuid="",
                size_bytes=0,
            )
        )

    def open_encrypted_volume(
        self,
        device: Path,
        passphrase: SecureString,
        name: str = "yubikey-backup",
    ) -> Result[Path]:
        if self._system == "Linux":
            result = subprocess.run(
                ["cryptsetup", "open", str(device), name],
                input=passphrase.get(),
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return Result.err(StorageError(f"Open failed: {result.stderr}"))

            return Result.ok(Path(f"/dev/mapper/{name}"))

        return Result.err(StorageError(f"Manual mount required on {self._system}"))

    def close_encrypted_volume(self, name: str) -> Result[None]:
        if self._system == "Linux":
            result = subprocess.run(
                ["cryptsetup", "close", name],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return Result.err(StorageError(f"Close failed: {result.stderr}"))

            return Result.ok(None)

        return Result.err(StorageError(f"Manual unmount required on {self._system}"))

    def mount_volume(
        self,
        device: Path,
        mount_point: Path,
    ) -> Result[Path]:
        mount_point.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["mount", str(device), str(mount_point)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Mount failed: {result.stderr}"))

        return Result.ok(mount_point)

    def unmount_volume(self, mount_point: Path) -> Result[None]:
        if self._system == "Darwin":
            cmd = ["diskutil", "unmount", str(mount_point)]
        else:
            cmd = ["umount", str(mount_point)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return Result.err(StorageError(f"Unmount failed: {result.stderr}"))

        return Result.ok(None)

    def unmount_disk(self, device: Path) -> Result[None]:
        """Unmount a disk and all its partitions.

        Args:
            device: Device path (e.g., /dev/disk6)

        Returns:
            Result indicating success or failure
        """
        if self._system == "Darwin":
            # diskutil unmountDisk unmounts all volumes on the disk
            result = subprocess.run(
                ["diskutil", "unmountDisk", str(device)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return Result.err(StorageError(f"Failed to unmount disk: {result.stderr}"))
            return Result.ok(None)
        else:
            # On Linux, find and unmount all mounted partitions
            result = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,MOUNTPOINT", str(device)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return Result.ok(None)  # No partitions to unmount

            try:
                data = json.loads(result.stdout)
                for dev in data.get("blockdevices", []):
                    for child in dev.get("children", []):
                        mount = child.get("mountpoint")
                        if mount:
                            umount_result = subprocess.run(
                                ["umount", mount],
                                capture_output=True,
                                text=True,
                            )
                            if umount_result.returncode != 0:
                                return Result.err(
                                    StorageError(
                                        f"Failed to unmount {mount}: {umount_result.stderr}"
                                    )
                                )
            except json.JSONDecodeError:
                pass

            return Result.ok(None)

    def verify_backup(
        self,
        backup_path: Path,
        expected_files: list[str],
    ) -> Result[BackupVerification]:
        if not backup_path.exists():
            return Result.err(StorageError(f"Backup path does not exist: {backup_path}"))

        found = []
        missing = []

        for filename in expected_files:
            filepath = backup_path / filename
            if filepath.exists():
                found.append(filename)
            else:
                missing.append(filename)

        return Result.ok(
            BackupVerification(
                path=backup_path,
                files_found=found,
                files_missing=missing,
                verified_at=datetime.now(UTC),
                is_complete=len(missing) == 0,
            )
        )

    def prepare_backup_drive_macos(
        self,
        device: Path,
        passphrase: SecureString,
    ) -> Result[BackupDriveInfo]:
        """Prepare backup drive on macOS using APFS encryption.

        This function implements the macOS-specific backup drive setup
        following the dr duh YubiKey guide:
        0. Unmount disk if mounted
        1. Erase disk with GPT partition table and APFS container
        2. Get APFS container reference
        3. Delete default volume
        4. Create encrypted APFS volume for secrets
        5. Create unencrypted APFS volume for public keys
        6. Unmount both volumes

        Args:
            device: Device path (e.g., /dev/disk4)
            passphrase: Passphrase for encrypted volume

        Returns:
            Result containing BackupDriveInfo with volume paths
        """
        # 0. Unmount disk if any partitions are mounted
        unmount_result = self.unmount_disk(device)
        if unmount_result.is_err():
            return Result.err(unmount_result.unwrap_err())

        # 1. Erase disk and create APFS container
        result = subprocess.run(
            ["diskutil", "eraseDisk", "APFS", "GPG-BACKUP", str(device)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to erase disk: {result.stderr}"))

        # 2. Get APFS container reference
        container_result = self._get_apfs_container(device)
        if container_result.is_err():
            return Result.err(container_result.unwrap_err())
        container = container_result.unwrap()

        # 3. Delete default volume that was created
        # Get volume info to find the default volume
        info_result = subprocess.run(
            ["diskutil", "apfs", "list", "-plist"],
            capture_output=True,
        )

        if info_result.returncode != 0:
            return Result.err(StorageError("Failed to list APFS volumes"))

        import plistlib

        try:
            apfs_data = plistlib.loads(info_result.stdout)
            # Find the container and its default volume
            default_volume = None
            for cont in apfs_data.get("Containers", []):
                if cont.get("ContainerReference", "") == container:
                    volumes = cont.get("Volumes", [])
                    if volumes:
                        default_volume = volumes[0].get("DeviceIdentifier")
                    break

            if default_volume:
                subprocess.run(
                    ["diskutil", "apfs", "deleteVolume", default_volume],
                    capture_output=True,
                )
        except Exception as e:
            return Result.err(StorageError(f"Failed to delete default volume: {e}"))

        # 4. Add encrypted volume with passphrase via stdin
        result = subprocess.run(
            [
                "diskutil",
                "apfs",
                "addVolume",
                container,
                "APFS",
                "gnupg-secrets",
                "-stdinpassphrase",
            ],
            input=passphrase.get(),
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to create encrypted volume: {result.stderr}"))

        # 5. Add unencrypted public volume
        result = subprocess.run(
            ["diskutil", "apfs", "addVolume", container, "APFS", "gnupg-public"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to create public volume: {result.stderr}"))

        # 6. Unmount both volumes
        subprocess.run(
            ["diskutil", "unmount", "gnupg-secrets"],
            capture_output=True,
        )
        subprocess.run(
            ["diskutil", "unmount", "gnupg-public"],
            capture_output=True,
        )

        # Get volume identifiers for the partitions
        encrypted_vol_id_result = self._get_volume_identifier("gnupg-secrets")
        public_vol_id_result = self._get_volume_identifier("gnupg-public")

        encrypted_partition = (
            Path(f"/dev/{encrypted_vol_id_result.unwrap()}")
            if encrypted_vol_id_result.is_ok()
            else device / "gnupg-secrets"
        )
        public_partition = (
            Path(f"/dev/{public_vol_id_result.unwrap()}")
            if public_vol_id_result.is_ok()
            else device / "gnupg-public"
        )

        return Result.ok(
            BackupDriveInfo(
                device_path=device,
                encrypted_partition=encrypted_partition,
                public_partition=public_partition,
                encrypted_label="gnupg-secrets",
                public_label="gnupg-public",
            )
        )

    def open_backup_drive_macos(
        self,
        device: Path,
        passphrase: SecureString,
    ) -> Result[MountedBackupDrive]:
        """Open and mount macOS backup drive volumes.

        Unlocks the encrypted APFS volume with the passphrase and mounts
        both the encrypted and public volumes.

        Args:
            device: Device path (e.g., /dev/disk4)
            passphrase: Passphrase for encrypted volume

        Returns:
            Result containing MountedBackupDrive with mount points
        """
        # First, get the encrypted volume identifier
        volume_id_result = self._get_volume_identifier("gnupg-secrets")
        if volume_id_result.is_err():
            return Result.err(volume_id_result.unwrap_err())
        encrypted_volume_id = volume_id_result.unwrap()

        # Unlock the encrypted volume with passphrase
        result = subprocess.run(
            [
                "diskutil",
                "apfs",
                "unlockVolume",
                encrypted_volume_id,
                "-stdinpassphrase",
            ],
            input=passphrase.get(),
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to unlock encrypted volume: {result.stderr}"))

        # Mount the encrypted volume
        result = subprocess.run(
            ["diskutil", "mount", encrypted_volume_id],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to mount encrypted volume: {result.stderr}"))

        # Mount the public volume
        public_volume_id_result = self._get_volume_identifier("gnupg-public")
        if public_volume_id_result.is_err():
            return Result.err(public_volume_id_result.unwrap_err())
        public_volume_id = public_volume_id_result.unwrap()

        result = subprocess.run(
            ["diskutil", "mount", public_volume_id],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            # Try to unmount encrypted before returning error
            subprocess.run(
                ["diskutil", "unmount", encrypted_volume_id],
                capture_output=True,
            )
            return Result.err(StorageError(f"Failed to mount public volume: {result.stderr}"))

        # Get mount points
        encrypted_mount_result = self._get_volume_mount_point("gnupg-secrets")
        if encrypted_mount_result.is_err():
            return Result.err(encrypted_mount_result.unwrap_err())
        encrypted_mount = encrypted_mount_result.unwrap()

        public_mount_result = self._get_volume_mount_point("gnupg-public")
        if public_mount_result.is_err():
            return Result.err(public_mount_result.unwrap_err())
        public_mount = public_mount_result.unwrap()

        return Result.ok(
            MountedBackupDrive(
                encrypted_mount=encrypted_mount,
                public_mount=public_mount,
                device_path=device,
            )
        )

    def close_backup_drive_macos(
        self,
        mounted: MountedBackupDrive,
    ) -> Result[None]:
        """Close and lock macOS backup drive volumes.

        Unmounts both volumes and locks the encrypted volume.

        Args:
            mounted: MountedBackupDrive with mount points and device info

        Returns:
            Result indicating success or failure
        """
        # Unmount both volumes
        result = subprocess.run(
            ["diskutil", "unmount", str(mounted.encrypted_mount)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to unmount encrypted volume: {result.stderr}"))

        result = subprocess.run(
            ["diskutil", "unmount", str(mounted.public_mount)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to unmount public volume: {result.stderr}"))

        # Lock the encrypted volume
        volume_id_result = self._get_volume_identifier("gnupg-secrets")
        if volume_id_result.is_err():
            return Result.err(volume_id_result.unwrap_err())
        volume_id = volume_id_result.unwrap()

        result = subprocess.run(
            ["diskutil", "apfs", "lockVolume", volume_id],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to lock encrypted volume: {result.stderr}"))

        return Result.ok(None)

    def verify_backup_drive_macos(
        self,
        device: Path,
    ) -> Result[bool]:
        """Verify macOS backup drive structure.

        Checks that the device has a valid APFS container with both
        required volumes (gnupg-secrets and gnupg-public).

        Args:
            device: Device path (e.g., /dev/disk4)

        Returns:
            Result containing True if drive is valid, False otherwise
        """
        # Get APFS container
        container_result = self._get_apfs_container(device)
        if container_result.is_err():
            return Result.ok(False)
        container = container_result.unwrap()

        # Check for both volumes
        result = subprocess.run(
            ["diskutil", "apfs", "list", "-plist"],
            capture_output=True,
        )

        if result.returncode != 0:
            return Result.ok(False)

        import plistlib

        try:
            apfs_data = plistlib.loads(result.stdout)
            for cont in apfs_data.get("Containers", []):
                if cont.get("ContainerReference", "") == container:
                    volumes = cont.get("Volumes", [])
                    volume_names = {v.get("Name") for v in volumes}
                    has_encrypted = "gnupg-secrets" in volume_names
                    has_public = "gnupg-public" in volume_names
                    return Result.ok(has_encrypted and has_public)
        except Exception:
            return Result.ok(False)

        return Result.ok(False)

    def _get_apfs_container(self, device: Path) -> Result[str]:
        """Get APFS container reference for a device.

        Args:
            device: Device path (e.g., /dev/disk6)

        Returns:
            Result containing synthesized container reference (e.g., disk4)
        """
        import plistlib

        # Extract device identifier (e.g., "disk6" from "/dev/disk6")
        device_str = str(device)
        device_id = device_str[5:] if device_str.startswith("/dev/") else device_str

        # Query APFS containers to find the one with physical store on this device
        result = subprocess.run(
            ["diskutil", "apfs", "list", "-plist"],
            capture_output=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError("Failed to list APFS containers"))

        try:
            apfs_data = plistlib.loads(result.stdout)
            for container in apfs_data.get("Containers", []):
                # Check if any physical store is on our device
                for store in container.get("PhysicalStores", []):
                    store_id = store.get("DeviceIdentifier", "")
                    # Physical store will be like "disk6s2" for device "disk6"
                    if store_id.startswith(device_id):
                        container_ref = container.get("ContainerReference", "")
                        if container_ref:
                            return Result.ok(container_ref)

            return Result.err(StorageError(f"No APFS container found for {device}"))
        except Exception as e:
            return Result.err(StorageError(f"Failed to parse APFS info: {e}"))

    def _get_volume_identifier(self, volume_name: str) -> Result[str]:
        """Get volume device identifier by name.

        Args:
            volume_name: Volume name (e.g., "gnupg-secrets")

        Returns:
            Result containing volume identifier (e.g., disk4s1)
        """
        result = subprocess.run(
            ["diskutil", "list", "-plist"],
            capture_output=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError("Failed to list volumes"))

        import plistlib

        try:
            data = plistlib.loads(result.stdout)
            for disk in data.get("AllDisksAndPartitions", []):
                # Check volumes in partitions
                for partition in disk.get("Partitions", []):
                    if partition.get("VolumeName") == volume_name:
                        return Result.ok(partition.get("DeviceIdentifier", ""))

                # Check APFS volumes
                for volume in disk.get("APFSVolumes", []):
                    if volume.get("VolumeName") == volume_name:
                        return Result.ok(volume.get("DeviceIdentifier", ""))

            return Result.err(StorageError(f"Volume not found: {volume_name}"))
        except Exception as e:
            return Result.err(StorageError(f"Failed to parse volume list: {e}"))

    def _get_volume_mount_point(self, volume_name: str) -> Result[Path]:
        """Get mount point for a volume by name.

        Args:
            volume_name: Volume name (e.g., "gnupg-secrets")

        Returns:
            Result containing mount point path
        """
        volume_id_result = self._get_volume_identifier(volume_name)
        if volume_id_result.is_err():
            return Result.err(volume_id_result.unwrap_err())
        volume_id = volume_id_result.unwrap()

        result = subprocess.run(
            ["diskutil", "info", "-plist", volume_id],
            capture_output=True,
        )

        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to get volume info for {volume_id}"))

        import plistlib

        try:
            info = plistlib.loads(result.stdout)
            mount_point = info.get("MountPoint")
            if mount_point:
                return Result.ok(Path(mount_point))

            return Result.err(StorageError(f"Volume not mounted: {volume_name}"))
        except Exception as e:
            return Result.err(StorageError(f"Failed to parse volume info: {e}"))

    def prepare_backup_drive_linux(
        self,
        device: Path,
        passphrase: SecureString,
    ) -> Result[BackupDriveInfo]:
        """
        Prepare a backup drive on Linux with encrypted and public partitions.

        This function performs the following operations (requires sudo):
        1. Zero the device header to clear any existing partition table
        2. Create a new GPT partition table
        3. Create partition 1 (20MB) for encrypted secrets (LUKS2)
        4. Create partition 2 (20MB) for public key storage (FAT32)
        5. Format partition 1 with LUKS2 encryption
        6. Open the LUKS volume temporarily
        7. Create ext2 filesystem on encrypted volume
        8. Create FAT32 filesystem on public partition
        9. Close the LUKS volume
        10. Sync to ensure all writes are complete

        Args:
            device: Path to the device (e.g., /dev/sdb)
            passphrase: Passphrase for LUKS encryption

        Returns:
            Result containing BackupDriveInfo with partition paths and labels,
            or StorageError if any step fails.

        Note:
            This operation is destructive and will erase all data on the device.
            Requires root/sudo privileges.
        """
        encrypted_label = "gnupg-secrets"
        public_label = "GNUPG-PUB"

        # Step 0: Unmount any mounted partitions
        unmount_result = self.unmount_disk(device)
        if unmount_result.is_err():
            return Result.err(unmount_result.unwrap_err())

        # Step 1: Zero header
        result = subprocess.run(
            ["dd", "if=/dev/zero", f"of={device}", "bs=4M", "count=1"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to zero device header: {result.stderr}"))

        # Step 2: Create GPT partition table
        result = subprocess.run(
            ["parted", "-s", str(device), "mklabel", "gpt"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return Result.err(
                StorageError(f"Failed to create GPT partition table: {result.stderr}")
            )

        # Step 3: Create encrypted partition (1MiB to 21MiB = 20MB)
        result = subprocess.run(
            ["parted", "-s", str(device), "mkpart", "primary", "1MiB", "21MiB"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return Result.err(
                StorageError(f"Failed to create encrypted partition: {result.stderr}")
            )

        # Step 4: Create public partition (21MiB to 41MiB = 20MB)
        result = subprocess.run(
            ["parted", "-s", str(device), "mkpart", "primary", "21MiB", "41MiB"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to create public partition: {result.stderr}"))

        # Determine partition paths (usually device + partition number)
        encrypted_partition = Path(f"{device}1")
        public_partition = Path(f"{device}2")

        # Wait for kernel to recognize partitions
        subprocess.run(["partprobe", str(device)], capture_output=True)

        # Small delay to ensure device nodes are created
        import time

        time.sleep(1)

        # Step 5: LUKS format partition 1 (use pexpect to avoid passphrase in command line)
        try:
            import pexpect

            child = pexpect.spawn(
                "cryptsetup",
                [
                    "luksFormat",
                    "--type",
                    "luks2",
                    str(encrypted_partition),
                ],
                timeout=60,
            )

            # Expect confirmation prompt
            child.expect("Are you sure.*", timeout=10)
            child.sendline("YES")

            # Expect passphrase prompt
            child.expect("Enter passphrase.*", timeout=10)
            child.sendline(passphrase.get())

            # Expect passphrase verification
            child.expect("Verify passphrase.*", timeout=10)
            child.sendline(passphrase.get())

            child.expect(pexpect.EOF, timeout=30)
            child.close()

            if child.exitstatus != 0:
                return Result.err(
                    StorageError(f"LUKS format failed with exit code {child.exitstatus}")
                )

        except ImportError:
            # Fallback to subprocess if pexpect not available (less secure)
            result = subprocess.run(
                [
                    "cryptsetup",
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--batch-mode",
                    str(encrypted_partition),
                ],
                input=passphrase.get(),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return Result.err(StorageError(f"LUKS format failed: {result.stderr}"))
        except Exception as e:
            return Result.err(StorageError(f"LUKS format failed: {e}"))

        # Step 6: Open LUKS volume
        try:
            import pexpect

            child = pexpect.spawn(
                "cryptsetup",
                ["open", str(encrypted_partition), encrypted_label],
                timeout=60,
            )

            child.expect("Enter passphrase.*", timeout=10)
            child.sendline(passphrase.get())

            child.expect(pexpect.EOF, timeout=30)
            child.close()

            if child.exitstatus != 0:
                return Result.err(
                    StorageError(f"Failed to open LUKS volume with exit code {child.exitstatus}")
                )

        except ImportError:
            # Fallback
            result = subprocess.run(
                ["cryptsetup", "open", str(encrypted_partition), encrypted_label],
                input=passphrase.get(),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return Result.err(StorageError(f"Failed to open LUKS volume: {result.stderr}"))
        except Exception as e:
            return Result.err(StorageError(f"Failed to open LUKS volume: {e}"))

        # Step 7: Create ext2 filesystem on encrypted volume
        mapper_device = Path(f"/dev/mapper/{encrypted_label}")
        result = subprocess.run(
            ["mkfs.ext2", "-L", encrypted_label, str(mapper_device)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Clean up: close LUKS volume
            subprocess.run(["cryptsetup", "close", encrypted_label], capture_output=True)
            return Result.err(StorageError(f"Failed to create ext2 filesystem: {result.stderr}"))

        # Step 8: Create FAT32 filesystem on public partition
        result = subprocess.run(
            ["mkfs.vfat", "-F", "32", "-n", public_label, str(public_partition)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Clean up: close LUKS volume
            subprocess.run(["cryptsetup", "close", encrypted_label], capture_output=True)
            return Result.err(StorageError(f"Failed to create FAT32 filesystem: {result.stderr}"))

        # Step 9: Close LUKS volume
        result = subprocess.run(
            ["cryptsetup", "close", encrypted_label],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return Result.err(StorageError(f"Failed to close LUKS volume: {result.stderr}"))

        # Step 10: Sync to ensure all writes complete
        subprocess.run(["sync"], capture_output=True)

        return Result.ok(
            BackupDriveInfo(
                device_path=device,
                encrypted_partition=encrypted_partition,
                public_partition=public_partition,
                encrypted_label=encrypted_label,
                public_label=public_label,
            )
        )

    def open_backup_drive_linux(
        self,
        device: Path,
        passphrase: SecureString,
    ) -> Result[MountedBackupDrive]:
        """
        Open and mount the backup drive partitions on Linux.

        This function performs the following operations (requires sudo):
        1. Open the LUKS encrypted partition
        2. Create temporary mount points
        3. Mount the encrypted partition
        4. Mount the public partition

        Args:
            device: Path to the device (e.g., /dev/sdb)
            passphrase: Passphrase for LUKS decryption

        Returns:
            Result containing MountedBackupDrive with mount point paths,
            or StorageError if any step fails.

        Note:
            Requires root/sudo privileges.
            You must call close_backup_drive_linux() when done to unmount and close LUKS.
        """
        import tempfile

        encrypted_label = "gnupg-secrets"
        encrypted_partition = Path(f"{device}1")
        public_partition = Path(f"{device}2")

        # Step 1: Open LUKS partition
        try:
            import pexpect

            child = pexpect.spawn(
                "cryptsetup",
                ["open", str(encrypted_partition), encrypted_label],
                timeout=60,
            )

            child.expect("Enter passphrase.*", timeout=10)
            child.sendline(passphrase.get())

            child.expect(pexpect.EOF, timeout=30)
            child.close()

            if child.exitstatus != 0:
                return Result.err(
                    StorageError(f"Failed to open LUKS volume with exit code {child.exitstatus}")
                )

        except ImportError:
            # Fallback
            result = subprocess.run(
                ["cryptsetup", "open", str(encrypted_partition), encrypted_label],
                input=passphrase.get(),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return Result.err(StorageError(f"Failed to open LUKS volume: {result.stderr}"))
        except Exception as e:
            return Result.err(StorageError(f"Failed to open LUKS volume: {e}"))

        # Step 2: Create temporary mount points
        encrypted_mount = Path(tempfile.mkdtemp(prefix="yubikey-encrypted-"))
        public_mount = Path(tempfile.mkdtemp(prefix="yubikey-public-"))

        # Step 3: Mount encrypted partition
        mapper_device = Path(f"/dev/mapper/{encrypted_label}")
        result = subprocess.run(
            ["mount", str(mapper_device), str(encrypted_mount)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Clean up: close LUKS and remove temp dirs
            subprocess.run(["cryptsetup", "close", encrypted_label], capture_output=True)
            encrypted_mount.rmdir()
            public_mount.rmdir()
            return Result.err(StorageError(f"Failed to mount encrypted partition: {result.stderr}"))

        # Step 4: Mount public partition
        result = subprocess.run(
            ["mount", str(public_partition), str(public_mount)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Clean up: unmount encrypted, close LUKS, remove temp dirs
            subprocess.run(["umount", str(encrypted_mount)], capture_output=True)
            subprocess.run(["cryptsetup", "close", encrypted_label], capture_output=True)
            encrypted_mount.rmdir()
            public_mount.rmdir()
            return Result.err(StorageError(f"Failed to mount public partition: {result.stderr}"))

        return Result.ok(
            MountedBackupDrive(
                encrypted_mount=encrypted_mount,
                public_mount=public_mount,
                device_path=device,
            )
        )

    def close_backup_drive_linux(
        self,
        mounted: MountedBackupDrive,
    ) -> Result[None]:
        """
        Unmount and close the backup drive partitions on Linux.

        This function performs the following operations (requires sudo):
        1. Unmount the public partition
        2. Unmount the encrypted partition
        3. Close the LUKS volume
        4. Sync to ensure all writes complete
        5. Clean up temporary mount points

        Args:
            mounted: MountedBackupDrive instance from open_backup_drive_linux()

        Returns:
            Result with None on success, or StorageError if any step fails.

        Note:
            Requires root/sudo privileges.
            Even if unmounting fails, this will attempt to clean up all resources.
        """
        encrypted_label = "gnupg-secrets"
        errors = []

        # Step 1: Unmount public partition
        result = subprocess.run(
            ["umount", str(mounted.public_mount)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            errors.append(f"Failed to unmount public partition: {result.stderr}")

        # Step 2: Unmount encrypted partition
        result = subprocess.run(
            ["umount", str(mounted.encrypted_mount)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            errors.append(f"Failed to unmount encrypted partition: {result.stderr}")

        # Step 3: Close LUKS volume
        result = subprocess.run(
            ["cryptsetup", "close", encrypted_label],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            errors.append(f"Failed to close LUKS volume: {result.stderr}")

        # Step 4: Sync
        subprocess.run(["sync"], capture_output=True)

        # Step 5: Clean up temporary mount points
        try:
            if mounted.encrypted_mount.exists():
                mounted.encrypted_mount.rmdir()
        except Exception as e:
            errors.append(f"Failed to remove encrypted mount point: {e}")

        try:
            if mounted.public_mount.exists():
                mounted.public_mount.rmdir()
        except Exception as e:
            errors.append(f"Failed to remove public mount point: {e}")

        if errors:
            return Result.err(StorageError("; ".join(errors)))

        return Result.ok(None)

    def verify_backup_drive_linux(
        self,
        device: Path,
    ) -> Result[bool]:
        """
        Verify that a device has the expected backup drive partition structure.

        This function checks:
        1. Device exists
        2. Partition 1 exists
        3. Partition 2 exists
        4. Partition 1 has a valid LUKS header

        Args:
            device: Path to the device (e.g., /dev/sdb)

        Returns:
            Result with True if verification passes, False if structure is invalid,
            or StorageError if verification cannot be performed.

        Note:
            Does not require sudo unless device permissions are restricted.
        """
        # Check device exists
        if not device.exists():
            return Result.err(StorageError(f"Device does not exist: {device}"))

        # Check partitions exist
        partition1 = Path(f"{device}1")
        partition2 = Path(f"{device}2")

        if not partition1.exists():
            return Result.ok(False)

        if not partition2.exists():
            return Result.ok(False)

        # Check LUKS header on partition 1
        result = subprocess.run(
            ["cryptsetup", "isLuks", str(partition1)],
            capture_output=True,
            text=True,
        )

        # cryptsetup isLuks returns 0 if valid LUKS header, non-zero otherwise
        if result.returncode != 0:
            return Result.ok(False)

        return Result.ok(True)
