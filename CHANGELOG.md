# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
