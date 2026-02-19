"""YubiKey GPG initialization and management tool.

This package provides automated YubiKey GPG initialization following
the best practices from drduh/YubiKey-Guide.
"""

from .backup import (
    BackupManifest,
    FileChecksum,
    calculate_file_checksum,
    copy_gnupghome,
    copy_public_files_to_partition,
    copy_to_backup_drive,
    create_full_backup,
    generate_paperkey,
    import_from_backup,
    list_backups,
    readback_verify_backup,
    restore_from_paperkey,
    verify_backup_checksums,
    verify_backup_complete,
    verify_backup_integrity,
)
from .config import (
    HARDENED_GPG_CONF,
    generate_ssh_agent_setup_script,
    restart_gpg_agent,
    setup_all_configs,
    write_gpg_agent_conf,
    write_gpg_conf,
    write_scdaemon_conf,
)
from .diagnostics import (
    DiagnosticInfo,
    format_diagnostic_report,
    restart_gpg_components,
    run_diagnostics,
    test_card_operations,
)
from .environment import (
    CheckResult,
    EnvironmentReport,
    verify_environment,
    verify_environment_result,
)
from .errors import EnvironmentError as EnvError
from .errors import (
    ErrorCategory,
    ErrorLogger,
    GPGOperationError,
    HardwareError,
    InterruptHandler,
    RecoveryHint,
    StateError,
    UserCancelledError,
    YubiKeyInitError,
    get_recovery_hints_for_message,
    wrap_exception,
)
from .errors import PermissionError as PermError
from .errors import StorageError as StorageErr
from .gpg_ops import GPGError, GPGOperations
from .inventory import (
    DeviceEntry,
    Inventory,
    InventoryError,
    KeySlotInfo,
    OpenPGPState,
    OperationRecord,
    parse_openpgp_info,
)
from .main import run
from .prompts import (
    MockPrompts,
    PassphraseAnalysis,
    PassphraseStrength,
    PINRequirements,
    Prompts,
    analyze_passphrase,
    calculate_entropy,
)
from .safety import (
    DeviceVerificationError,
    MultiCardWarningError,
    ProtectedDeviceError,
    SafetyCheckResult,
    SafetyError,
    SafetyGuard,
    SafetyLevel,
    display_device_table,
    list_connected_devices_safely,
)
from .state_machine import InvalidTransitionError, StateMachine, WorkflowConfig, WorkflowSession
from .storage_ops import StorageError, StorageOperations
from .types import (
    BackupVerification,
    CardStatus,
    DeviceInfo,
    KeyInfo,
    KeySlot,
    KeyType,
    KeyUsage,
    Result,
    SecureString,
    SubkeyInfo,
    TouchPolicy,
    VolumeInfo,
    WorkflowState,
    YubiKeyInfo,
)
from .yubikey_ops import YubiKeyError, YubiKeyOperations, yubikey_available

__version__ = "0.2.0"

__all__ = [
    # Types
    "BackupVerification",
    "CardStatus",
    "DeviceInfo",
    "KeyInfo",
    "KeySlot",
    "KeyType",
    "KeyUsage",
    "Result",
    "SecureString",
    "SubkeyInfo",
    "TouchPolicy",
    "VolumeInfo",
    "WorkflowState",
    "YubiKeyInfo",
    # Operations
    "GPGOperations",
    "GPGError",
    "YubiKeyOperations",
    "YubiKeyError",
    "yubikey_available",
    "StorageOperations",
    "StorageError",
    # State Management
    "StateMachine",
    "WorkflowSession",
    "WorkflowConfig",
    "InvalidTransitionError",
    # Prompts
    "Prompts",
    "MockPrompts",
    "PassphraseStrength",
    "PassphraseAnalysis",
    "PINRequirements",
    "analyze_passphrase",
    "calculate_entropy",
    # Configuration
    "setup_all_configs",
    "write_gpg_conf",
    "write_gpg_agent_conf",
    "write_scdaemon_conf",
    "generate_ssh_agent_setup_script",
    "restart_gpg_agent",
    "HARDENED_GPG_CONF",
    # Environment
    "verify_environment",
    "verify_environment_result",
    "EnvironmentReport",
    "CheckResult",
    # Backup
    "create_full_backup",
    "copy_to_backup_drive",
    "copy_gnupghome",
    "copy_public_files_to_partition",
    "verify_backup_complete",
    "verify_backup_integrity",
    "verify_backup_checksums",
    "readback_verify_backup",
    "calculate_file_checksum",
    "generate_paperkey",
    "restore_from_paperkey",
    "import_from_backup",
    "list_backups",
    "BackupManifest",
    "FileChecksum",
    # Diagnostics
    "run_diagnostics",
    "format_diagnostic_report",
    "restart_gpg_components",
    "test_card_operations",
    "DiagnosticInfo",
    # Inventory
    "Inventory",
    "InventoryError",
    "DeviceEntry",
    "OpenPGPState",
    "KeySlotInfo",
    "OperationRecord",
    "parse_openpgp_info",
    # Safety
    "SafetyGuard",
    "SafetyLevel",
    "SafetyError",
    "SafetyCheckResult",
    "ProtectedDeviceError",
    "MultiCardWarningError",
    "DeviceVerificationError",
    "list_connected_devices_safely",
    "display_device_table",
    # Errors
    "YubiKeyInitError",
    "ErrorCategory",
    "RecoveryHint",
    "EnvError",
    "HardwareError",
    "GPGOperationError",
    "StorageErr",
    "PermError",
    "UserCancelledError",
    "StateError",
    "ErrorLogger",
    "InterruptHandler",
    "get_recovery_hints_for_message",
    "wrap_exception",
    # Main
    "run",
    "__version__",
]
