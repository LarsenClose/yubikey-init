# yubikey-init

Automated YubiKey GPG initialization and management tool.

## Build & Test

```bash
uv sync --all-extras          # Install deps
uv run pytest                  # Run tests (1331 tests)
uv run pytest --cov            # With coverage (threshold: 87%)
uv run ruff check .            # Lint
uv run ruff format --check .   # Format check
uv run mypy src/yubikey_init/  # Type check (strict)
```

## Architecture

- Entry: `__main__.py` -> `main.py:run()` -> argparse subcommands
- Operations modules: `gpg_ops.py`, `yubikey_ops.py`, `storage_ops.py`, `backup.py`
- Safety/validation: `safety.py`, `prompts.py`, `environment.py`, `diagnostics.py`
- State: `state_machine.py` (resumable workflow), `inventory.py` (device tracking)
- TUI: `tui/app.py` (Textual), screens in `tui/screens/`, controller in `tui/controller.py`
- Types: `types.py` (Result monad, dataclasses), `errors.py` (error hierarchy)

## Key Conventions

- Result type for fallible operations (not exceptions)
- SecureString for sensitive data (passphrase, PIN)
- All ykman/gpg interaction goes through `_run_ykman`/`_run_gpg` wrappers
- Tests: `tests/unit/`, `tests/integration/`, `tests/e2e/`, `tests/hardware/` (marker: hardware)
- Coverage gaps in TUI screens and storage_ops are acknowledged (require hardware/Textual app)

## GitHub

- Owner: LarsenClose
- Auth: `GH_CONFIG_DIR=~/.config/gh-larsenclose gh <command>`
