from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")


class WorkflowState(Enum):
    UNINITIALIZED = "uninitialized"
    STORAGE_SETUP = "storage_setup"
    STORAGE_VERIFIED = "storage_verified"
    GPG_MASTER_GENERATED = "gpg_master_generated"
    GPG_SUBKEYS_GENERATED = "gpg_subkeys_generated"
    BACKUP_CREATED = "backup_created"
    BACKUP_VERIFIED = "backup_verified"
    YUBIKEY_1_PROVISIONED = "yubikey_1_provisioned"
    YUBIKEY_2_PROVISIONED = "yubikey_2_provisioned"
    MASTER_KEY_REMOVED = "master_key_removed"
    COMPLETE = "complete"


class KeyType(Enum):
    RSA4096 = "rsa4096"
    ED25519 = "ed25519"


class KeyUsage(Enum):
    CERTIFY = "certify"
    SIGN = "sign"
    ENCRYPT = "encrypt"
    AUTHENTICATE = "authenticate"


class KeySlot(Enum):
    SIGNATURE = "sig"
    ENCRYPTION = "enc"
    AUTHENTICATION = "aut"


class TouchPolicy(Enum):
    OFF = "off"
    ON = "on"
    FIXED = "fixed"
    CACHED = "cached"
    CACHED_FIXED = "cached-fixed"


@dataclass(frozen=True)
class KeyInfo:
    key_id: str
    fingerprint: str
    creation_date: datetime
    expiry_date: datetime | None
    identity: str
    key_type: KeyType


@dataclass(frozen=True)
class SubkeyInfo:
    key_id: str
    fingerprint: str
    creation_date: datetime
    expiry_date: datetime | None
    usage: KeyUsage
    key_type: KeyType
    parent_key_id: str


@dataclass(frozen=True)
class YubiKeyInfo:
    serial: str
    version: str
    form_factor: str
    has_openpgp: bool
    openpgp_version: str | None


@dataclass(frozen=True)
class DeviceInfo:
    path: Path
    name: str
    size_bytes: int
    removable: bool
    mounted: bool
    mount_point: Path | None = None


@dataclass(frozen=True)
class VolumeInfo:
    device: Path
    name: str
    uuid: str
    size_bytes: int


@dataclass(frozen=True)
class CardStatus:
    serial: str
    signature_key: str | None
    encryption_key: str | None
    authentication_key: str | None
    signature_count: int
    pin_retries: int
    admin_pin_retries: int


@dataclass(frozen=True)
class BackupVerification:
    path: Path
    files_found: list[str]
    files_missing: list[str]
    verified_at: datetime
    is_complete: bool


@dataclass(frozen=True)
class BackupDriveInfo:
    """Information about prepared backup drive partitions."""

    device_path: Path
    encrypted_partition: Path
    public_partition: Path
    encrypted_label: str
    public_label: str


@dataclass(frozen=True)
class MountedBackupDrive:
    """Information about mounted backup drive partitions."""

    encrypted_mount: Path
    public_mount: Path
    device_path: Path


class SecureString:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecureString(****)"

    def __str__(self) -> str:
        return "****"

    def __len__(self) -> int:
        return len(self._value)

    def clear(self) -> None:
        self._value = "\x00" * len(self._value)
        self._value = ""


class Result(Generic[T]):
    __slots__ = ("_value", "_error", "_is_ok")

    def __init__(self, value: T | None, error: Exception | None, is_ok: bool) -> None:
        self._value = value
        self._error = error
        self._is_ok = is_ok

    @staticmethod
    def ok(value: T) -> Result[T]:
        return Result(value, None, True)

    @staticmethod
    def err(error: Exception) -> Result[T]:
        return Result(None, error, False)

    def is_ok(self) -> bool:
        return self._is_ok

    def is_err(self) -> bool:
        return not self._is_ok

    def unwrap(self) -> T:
        if not self._is_ok:
            raise self._error if self._error else RuntimeError("Result is error but no error set")
        return self._value  # type: ignore

    def unwrap_err(self) -> Exception:
        if self._is_ok:
            raise RuntimeError("Called unwrap_err on Ok result")
        return self._error  # type: ignore

    def unwrap_or(self, default: T) -> T:
        return self._value if self._is_ok else default  # type: ignore

    def map(self, fn: Callable[[T], U]) -> Result[U]:
        if self._is_ok:
            try:
                return Result.ok(fn(self._value))  # type: ignore
            except Exception as e:
                return Result.err(e)
        return Result.err(self._error)  # type: ignore

    def and_then(self, fn: Callable[[T], Result[U]]) -> Result[U]:
        if self._is_ok:
            return fn(self._value)  # type: ignore
        return Result.err(self._error)  # type: ignore


VALID_TRANSITIONS: dict[WorkflowState, list[WorkflowState]] = {
    WorkflowState.UNINITIALIZED: [WorkflowState.STORAGE_SETUP, WorkflowState.STORAGE_VERIFIED],
    WorkflowState.STORAGE_SETUP: [WorkflowState.STORAGE_VERIFIED],
    WorkflowState.STORAGE_VERIFIED: [WorkflowState.GPG_MASTER_GENERATED],
    WorkflowState.GPG_MASTER_GENERATED: [WorkflowState.GPG_SUBKEYS_GENERATED],
    WorkflowState.GPG_SUBKEYS_GENERATED: [WorkflowState.BACKUP_CREATED],
    WorkflowState.BACKUP_CREATED: [WorkflowState.BACKUP_VERIFIED],
    WorkflowState.BACKUP_VERIFIED: [WorkflowState.YUBIKEY_1_PROVISIONED],
    WorkflowState.YUBIKEY_1_PROVISIONED: [
        WorkflowState.YUBIKEY_2_PROVISIONED,
        WorkflowState.MASTER_KEY_REMOVED,
    ],
    WorkflowState.YUBIKEY_2_PROVISIONED: [WorkflowState.MASTER_KEY_REMOVED],
    WorkflowState.MASTER_KEY_REMOVED: [WorkflowState.COMPLETE],
    WorkflowState.COMPLETE: [],
}
