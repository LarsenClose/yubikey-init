# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-06

### Added

- Interactive TUI setup wizard with 10-step guided flow (`W` key from main menu)
  - Step 1: Environment verification with live system checks
  - Step 2: Identity configuration with name/email preview
  - Step 3: Passphrase setup with real-time strength analysis
  - Step 4: Key algorithm (ED25519/RSA4096) and expiry selection
  - Step 5: Backup storage setup with skip option
  - Step 6: Key generation wired to real controller operations (master key + subkeys) with live status updates
  - Step 7: Backup creation wired to real controller operations with storage-aware messaging
  - Step 8: YubiKey transfer wired to real controller provisioning with device detection and PIN validation (admin 8+, user 6+)
  - Step 9: Verification checklist with status indicators
  - Step 10: Final configuration summary
- Wizard execution engine wired to real controller operations
  - TUIController wizard execution methods: generate_master_key, generate_all_subkeys, create_backup, provision_yubikey
- WizardState dataclass for accumulating configuration across steps
- Back/Next/Cancel navigation with step-aware validation
- Project CLAUDE.md with build and architecture reference

### Fixed

- Transfer step error paths now properly reset wizard state on failure

## [0.2.1] - 2026-03-06

### Added

- `--version` flag to CLI (db554c6)
- Edge case tests for ykman/gpg interaction paths (ecd2bc8)

### Fixed

- Handle missing `ykman` binary gracefully in `_run_ykman` (8a26ec2)
- Handle missing `gpg` binary gracefully in `_run_gpg` and `transfer_key` (febb405)
- Remove PyPI publish step from release workflow (1d7903b)
- Inaccuracies in CONTRIBUTING.md and SECURITY.md (bb28b61)

### Changed

- CI: Add Dependabot auto-merge workflow (126ef75)
- CI: Bump actions/upload-artifact from 6 to 7 (de3296f)

## [0.2.0] - 2026-02-28

### Added

- Interactive TUI for device and key management (`yubikey-init manage`)
  - Device list with status indicators (keys, PIN tries, protection)
  - Key list with expiry status and YubiKey associations
  - Device detail view with reset, label, and protect actions
  - Diagnostics screen with system health checks
  - Keyboard-driven navigation
- Device inventory system with persistent labels, notes, and protection status
- Auto-unmount functionality for backup drive preparation
- Comprehensive TUI test suite (97 tests)

### Fixed

- APFS synthesized containers now filtered from removable device list
  - Checks for `Content=Apple_APFS_Container` and `APFSPhysicalStores` properties
  - Prevents duplicate entries showing both physical disk and APFS container
- Mount status detection improved for multi-partition drives
- Backup drive creation now uses proper `eraseDisk` flow instead of direct container creation (fixes error -69626)
- Subkey generation rewritten to use `--quick-add-key` instead of pexpect interactive mode
  - More reliable across different GPG versions
  - No longer depends on GPG's interactive menu structure

### Changed

- Device protection now prevents accidental resets
- Improved error messages for storage operations

## [0.1.0] - 2025-01-28

### Added

- Initial release
- Automated YubiKey GPG initialization workflow
- Support for ED25519 and RSA4096 key types
- Resumable state machine architecture
- Encrypted backup creation and verification
- Multi-key provisioning (primary and backup YubiKeys)
- Hardened GPG configuration setup
- SSH key export functionality
- Subkey renewal capability
- Educational/verbose output mode
- Comprehensive diagnostics and troubleshooting
- Cross-platform support (macOS, Linux)

### Security

- Passphrases never stored, always prompted
- PIN/PUK validation with strength requirements
- Explicit confirmation before destructive operations
- Secure secret handling with SecureString wrapper
