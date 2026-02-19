from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from collections.abc import Generator
from pathlib import Path

import pytest

from yubikey_init import StateMachine
from yubikey_init.gpg_ops import GPGOperations
from yubikey_init.prompts import MockPrompts
from yubikey_init.yubikey_ops import yubikey_available


@pytest.fixture
def tmp_state_file(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


@pytest.fixture
def state_machine(tmp_state_file: Path) -> StateMachine:
    sm = StateMachine(tmp_state_file)
    sm.load()
    return sm


@pytest.fixture
def memory_state_machine() -> StateMachine:
    sm = StateMachine(":memory:")
    sm.load()
    return sm


def _gpg_agent_can_start() -> bool:
    """Check if gpg-agent can be started in a temp directory."""
    import tempfile
    import time

    with tempfile.TemporaryDirectory() as tmpdir:
        gnupghome = Path(tmpdir)
        (gnupghome / "gpg-agent.conf").write_text("allow-loopback-pinentry\n")
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupghome)
        try:
            # gpg-agent --daemon forks, so we need to not capture output
            # and let it run in background
            subprocess.Popen(
                ["gpg-agent", "--daemon"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait briefly for agent to start and create socket
            time.sleep(0.5)
            # Check if socket was created
            socket_path = gnupghome / "S.gpg-agent"
            started = socket_path.exists()
            # Cleanup
            subprocess.run(
                ["gpgconf", "--kill", "gpg-agent"],
                env=env,
                capture_output=True,
                timeout=5,
            )
            return started
        except Exception:
            return False


# Cache the result
_GPG_AGENT_AVAILABLE: bool | None = None


def gpg_agent_available() -> bool:
    """Check if gpg-agent can be started (cached)."""
    global _GPG_AGENT_AVAILABLE
    if _GPG_AGENT_AVAILABLE is None:
        _GPG_AGENT_AVAILABLE = _gpg_agent_can_start()
    return _GPG_AGENT_AVAILABLE


@pytest.fixture
def gpg_home(tmp_path: Path) -> Generator[Path, None, None]:
    """Create an isolated GNUPGHOME with gpg-agent configured for testing.

    Note: Uses /tmp directly instead of pytest's tmp_path because Unix domain
    sockets have a maximum path length (~104 chars on macOS). Pytest's temp
    paths are often too long for gpg-agent's socket files.
    """
    import tempfile

    # Use a short temp directory to avoid socket path length issues
    tmpdir = tempfile.mkdtemp(prefix="gpg_")
    gnupghome = Path(tmpdir)
    gnupghome.chmod(0o700)

    # Create gpg.conf with loopback pinentry mode
    gpg_conf = gnupghome / "gpg.conf"
    gpg_conf.write_text("pinentry-mode loopback\n")
    gpg_conf.chmod(0o600)

    # Create gpg-agent.conf allowing loopback pinentry
    agent_conf = gnupghome / "gpg-agent.conf"
    agent_conf.write_text("allow-loopback-pinentry\n")
    agent_conf.chmod(0o600)

    # Set environment for this fixture - must be done BEFORE starting agent
    old_gnupghome = os.environ.get("GNUPGHOME")
    os.environ["GNUPGHOME"] = str(gnupghome)

    # Create environment dict with GNUPGHOME set
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)

    # Start gpg-agent directly with --daemon flag
    # The agent must be started with the same GNUPGHOME in its environment
    import time

    try:
        subprocess.run(
            f"gpg-agent --daemon --homedir '{gnupghome}'",
            shell=True,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Wait for agent to start and create socket
        time.sleep(0.5)
    except subprocess.TimeoutExpired:
        pass  # Agent may timeout in some environments
    except Exception:
        pass  # Agent may fail in some environments, tests will skip if needed

    yield gnupghome

    # Cleanup: kill gpg-agent for this GNUPGHOME
    with contextlib.suppress(Exception):
        subprocess.run(
            ["gpgconf", "--kill", "gpg-agent"],
            env=env,
            capture_output=True,
            timeout=5,
        )

    # Restore environment
    if old_gnupghome is not None:
        os.environ["GNUPGHOME"] = old_gnupghome
    elif "GNUPGHOME" in os.environ:
        del os.environ["GNUPGHOME"]

    shutil.rmtree(gnupghome, ignore_errors=True)


@pytest.fixture
def gpg_ops(gpg_home: Path) -> GPGOperations:
    return GPGOperations(gnupghome=gpg_home)


@pytest.fixture
def mock_prompts() -> MockPrompts:
    return MockPrompts(
        passphrase="test-passphrase-secure",
        pin="654321",
        admin_pin="87654321",
        confirmations=True,
    )


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    backup = tmp_path / "backup"
    backup.mkdir()
    return backup


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "hardware: marks tests as requiring physical YubiKey")
    config.addinivalue_line("markers", "slow: marks tests as slow-running")
    config.addinivalue_line("markers", "gpg_agent: marks tests as requiring gpg-agent")


def pytest_collection_modifyitems(  # noqa: ARG001
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    skip_hardware = pytest.mark.skip(reason="No YubiKey connected")
    skip_gpg_agent = pytest.mark.skip(reason="gpg-agent cannot start in isolated environment")

    for item in items:
        if "hardware" in item.keywords and not yubikey_available():
            item.add_marker(skip_hardware)
        # Skip slow tests (which require gpg-agent) when agent isn't available
        if "slow" in item.keywords and not gpg_agent_available():
            item.add_marker(skip_gpg_agent)
