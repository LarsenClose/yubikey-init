# YubiKey Initialization Tool

[![CI](https://github.com/LarsenClose/yubikey-init/actions/workflows/ci.yml/badge.svg)](https://github.com/LarsenClose/yubikey-init/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Automated YubiKey GPG initialization and management following the [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) best practices.

**New to this tool?** See the **[Getting Started Guide](GETTING_STARTED.md)** for a complete walkthrough.

## Features

- **Guided 10-step workflow**: From environment check to fully provisioned YubiKey
- **Backup-first design**: Encrypted backup created and verified before any destructive operation
- **Resumable**: Interrupt anytime with Ctrl+C, resume with `yubikey-init continue`
- **Multi-key support**: Provision primary and backup YubiKeys from the same master key
- **Safety guards**: Protected devices, PIN warnings, confirmation prompts for destructive ops
- **Interactive TUI**: Keyboard-driven interface for device and key management (`yubikey-init manage`)
- **Device inventory**: Track labels, notes, and protection status across sessions

## Installation

### From PyPI (recommended)

```bash
pip install yubikey-init
```

### From Source

```bash
git clone https://github.com/LarsenClose/yubikey-init
cd yubikey-init
uv sync
```

## Usage

```bash
# Show status dashboard (default when no command)
uv run yubikey-init

# Start a new initialization workflow
uv run yubikey-init new

# Resume an interrupted workflow
uv run yubikey-init continue

# Check current status
uv run yubikey-init status

# Run diagnostics
uv run yubikey-init doctor

# Reset workflow state (does not affect keys)
uv run yubikey-init reset
```

### Interactive Management (TUI)

```bash
# Launch the interactive terminal UI
uv run yubikey-init manage
```

The TUI provides a keyboard-driven interface for:
- Viewing and managing connected YubiKeys
- Inspecting GPG keys and their status
- Running diagnostics
- Performing device operations (reset, label, protect)

**Navigation:** `D` Devices | `K` Keys | `X` Diagnostics | `Escape` Back | `Q` Quit

### Device Management (CLI)

```bash
# List connected devices
uv run yubikey-init devices

# Show device details
uv run yubikey-init devices show <serial>

# Label a device
uv run yubikey-init devices label <serial> "Work Key"

# Reset a YubiKey (DESTRUCTIVE)
uv run yubikey-init devices reset <serial>
```

### Key Management

```bash
# List keys in keyring
uv run yubikey-init keys

# Renew expiring subkeys
uv run yubikey-init keys renew <key_id>

# Export SSH public key
uv run yubikey-init keys export-ssh
```

### Backup Operations

```bash
# Verify backup integrity
uv run yubikey-init backup verify /path/to/backup

# Restore from backup
uv run yubikey-init backup restore /path/to/backup
```

## Requirements

### System Dependencies

- `gnupg` >= 2.2
- `ykman` >= 5.0
- `pcscd` (Linux) or native smartcard support (macOS)

### macOS

```bash
brew install gnupg yubikey-manager
```

### Linux (Debian/Ubuntu)

```bash
sudo apt install gnupg2 yubikey-manager pcscd scdaemon
sudo systemctl enable pcscd
sudo systemctl start pcscd
```

## Development

### Setup

```bash
uv sync --all-extras
```

### Run Tests

```bash
# Unit tests only (fast)
uv run pytest tests/unit -v

# Integration tests (requires GPG)
uv run pytest tests/integration -v

# All tests except hardware
uv run pytest tests/unit tests/integration tests/e2e -v

# Hardware tests (requires YubiKey)
uv run pytest tests/hardware -v
```

### Type Checking

```bash
uv run mypy src/
```

### Linting

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

### Mutation Testing

```bash
uv run mutmut run
uv run mutmut results
```

## Project Structure

```
yubikey-init/
├── SPEC.md                     # Detailed specification
├── README.md                   # This file
├── GETTING_STARTED.md          # Step-by-step guide
├── pyproject.toml              # Project configuration
├── src/yubikey_init/
│   ├── __init__.py
│   ├── __main__.py             # CLI entry point
│   ├── main.py                 # Application orchestration
│   ├── state_machine.py        # Workflow state management
│   ├── gpg_ops.py              # GPG operations
│   ├── yubikey_ops.py          # YubiKey operations
│   ├── storage_ops.py          # Encrypted storage operations
│   ├── inventory.py            # Device inventory tracking
│   ├── prompts.py              # User interaction
│   ├── types.py                # Shared types
│   └── tui/                    # Terminal user interface
│       ├── app.py              # Main TUI application
│       ├── controller.py       # TUI state management
│       ├── screens/            # Screen components
│       └── widgets/            # Reusable widgets
└── tests/
    ├── conftest.py             # Shared fixtures
    ├── unit/                   # Pure logic tests (1000+)
    ├── integration/            # GPG integration tests
    ├── hardware/               # YubiKey hardware tests
    └── e2e/                    # Full workflow tests
```

## Security Model

### What Is Automated
- GPG key generation with secure parameters
- Subkey creation and configuration
- Key export and backup operations
- YubiKey provisioning and PIN setup
- Encrypted volume creation and mounting

### What Requires Human Input
- **Passphrases**: Never stored, always prompted
- **PIN/PUK selection**: User chooses, tool validates strength
- **Backup verification**: User must confirm backup readability
- **Destructive confirmations**: Explicit consent before key movement

## License

MIT License - See [LICENSE](LICENSE) file.
