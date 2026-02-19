from __future__ import annotations

import os
import platform
from pathlib import Path

from .types import Result


class ConfigError(Exception):
    pass


# Hardened gpg.conf based on drduh/YubiKey-Guide recommendations
HARDENED_GPG_CONF = """\
# Behavior
no-emit-version
no-comments
export-options export-minimal
keyid-format 0xlong
with-fingerprint
list-options show-uid-validity
verify-options show-uid-validity

# Algorithms and ciphers
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed

# Cipher/digest used for symmetric ops
s2k-cipher-algo AES256
s2k-digest-algo SHA512
s2k-mode 3
s2k-count 65011712

# Digest algorithm for signing keys
cert-digest-algo SHA512

# Disable weak algorithms
disable-cipher-algo 3DES
disable-cipher-algo IDEA
disable-cipher-algo CAST5
disable-cipher-algo BLOWFISH

# SHA-1 is deprecated
weak-digest SHA1

# Security settings
require-cross-certification
no-symkey-cache
throw-keyids

# Keyserver (optional, uncomment if desired)
# keyserver hkps://keys.openpgp.org
# keyserver-options no-honor-keyserver-url
# keyserver-options include-revoked

# Auto-fetch keys from keyserver (optional, uncomment if desired)
# auto-key-locate keyserver
# auto-key-retrieve

# Display preferences
fixed-list-mode
charset utf-8
utf8-strings
"""

HARDENED_GPG_AGENT_CONF = """\
# Cache TTL (in seconds)
default-cache-ttl 600
max-cache-ttl 7200

# PIN entry program (platform-specific)
# pinentry-program /usr/bin/pinentry-curses

# Enable SSH support (allows gpg-agent to act as ssh-agent)
enable-ssh-support

# TTL for SSH keys
default-cache-ttl-ssh 600
max-cache-ttl-ssh 7200

# Extra socket for forwarding
# extra-socket /path/to/socket

# Grab keyboard for PIN entry (security feature)
# grab

# Log file (useful for debugging)
# log-file /tmp/gpg-agent.log
"""

SCDAEMON_CONF = """\
# Disable built-in CCID driver (use system's pcscd)
disable-ccid

# Reader port (optional, auto-detected usually)
# reader-port Yubico Yubikey

# Card timeout (seconds)
card-timeout 5

# Debug logging (useful for troubleshooting)
# debug-level basic
# log-file /tmp/scdaemon.log
"""


def get_gnupghome() -> Path:
    """Get the GnuPG home directory."""
    env_home = os.environ.get("GNUPGHOME")
    if env_home:
        return Path(env_home)
    return Path.home() / ".gnupg"


def ensure_gnupg_dir(gnupghome: Path | None = None) -> Result[Path]:
    """Ensure the GnuPG directory exists with correct permissions."""
    home = gnupghome or get_gnupghome()

    try:
        home.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions (0700)
        if platform.system() != "Windows":
            home.chmod(0o700)

        return Result.ok(home)
    except OSError as e:
        return Result.err(ConfigError(f"Could not create GnuPG directory: {e}"))


def write_gpg_conf(
    gnupghome: Path | None = None,
    content: str | None = None,
    backup_existing: bool = True,
) -> Result[Path]:
    """Write hardened gpg.conf to the GnuPG home directory."""
    home = gnupghome or get_gnupghome()
    conf_path = home / "gpg.conf"

    try:
        if backup_existing and conf_path.exists():
            backup_path = conf_path.with_suffix(".conf.bak")
            conf_path.rename(backup_path)

        conf_path.write_text(content or HARDENED_GPG_CONF)

        # Set restrictive permissions
        if platform.system() != "Windows":
            conf_path.chmod(0o600)

        return Result.ok(conf_path)
    except OSError as e:
        return Result.err(ConfigError(f"Could not write gpg.conf: {e}"))


def write_gpg_agent_conf(
    gnupghome: Path | None = None,
    content: str | None = None,
    enable_ssh: bool = True,
    backup_existing: bool = True,
) -> Result[Path]:
    """Write gpg-agent.conf to the GnuPG home directory."""
    home = gnupghome or get_gnupghome()
    conf_path = home / "gpg-agent.conf"

    final_content = content or HARDENED_GPG_AGENT_CONF

    if not enable_ssh:
        final_content = final_content.replace("enable-ssh-support", "# enable-ssh-support")

    try:
        if backup_existing and conf_path.exists():
            backup_path = conf_path.with_suffix(".conf.bak")
            conf_path.rename(backup_path)

        conf_path.write_text(final_content)

        if platform.system() != "Windows":
            conf_path.chmod(0o600)

        return Result.ok(conf_path)
    except OSError as e:
        return Result.err(ConfigError(f"Could not write gpg-agent.conf: {e}"))


def write_scdaemon_conf(
    gnupghome: Path | None = None,
    content: str | None = None,
    backup_existing: bool = True,
) -> Result[Path]:
    """Write scdaemon.conf to the GnuPG home directory."""
    home = gnupghome or get_gnupghome()
    conf_path = home / "scdaemon.conf"

    try:
        if backup_existing and conf_path.exists():
            backup_path = conf_path.with_suffix(".conf.bak")
            conf_path.rename(backup_path)

        conf_path.write_text(content or SCDAEMON_CONF)

        if platform.system() != "Windows":
            conf_path.chmod(0o600)

        return Result.ok(conf_path)
    except OSError as e:
        return Result.err(ConfigError(f"Could not write scdaemon.conf: {e}"))


def setup_all_configs(
    gnupghome: Path | None = None,
    enable_ssh: bool = True,
    backup_existing: bool = True,
) -> Result[dict[str, Path]]:
    """Set up all GnuPG configuration files with hardened settings."""
    home = gnupghome or get_gnupghome()

    # Ensure directory exists
    result = ensure_gnupg_dir(home)
    if result.is_err():
        return Result.err(result.unwrap_err())

    paths = {}

    # Write gpg.conf
    result = write_gpg_conf(home, backup_existing=backup_existing)
    if result.is_err():
        return Result.err(result.unwrap_err())
    paths["gpg.conf"] = result.unwrap()

    # Write gpg-agent.conf
    result = write_gpg_agent_conf(home, enable_ssh=enable_ssh, backup_existing=backup_existing)
    if result.is_err():
        return Result.err(result.unwrap_err())
    paths["gpg-agent.conf"] = result.unwrap()

    # Write scdaemon.conf
    result = write_scdaemon_conf(home, backup_existing=backup_existing)
    if result.is_err():
        return Result.err(result.unwrap_err())
    paths["scdaemon.conf"] = result.unwrap()

    return Result.ok(paths)


def get_ssh_auth_socket() -> Path:
    """Get the path to the GPG agent SSH auth socket."""
    system = platform.system()

    if system == "Darwin":
        # macOS
        return Path.home() / ".gnupg" / "S.gpg-agent.ssh"
    elif system == "Linux":
        # Linux - check XDG runtime dir first
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
        if runtime_dir:
            return Path(runtime_dir) / "gnupg" / "S.gpg-agent.ssh"
        return Path.home() / ".gnupg" / "S.gpg-agent.ssh"
    else:
        # Fallback
        return Path.home() / ".gnupg" / "S.gpg-agent.ssh"


def generate_ssh_agent_setup_script(shell: str = "bash") -> str:
    """Generate shell commands to use gpg-agent for SSH authentication."""
    socket_path = get_ssh_auth_socket()

    if shell in ("bash", "zsh", "sh"):
        return f"""\
# Add to ~/.bashrc or ~/.zshrc

# Use gpg-agent for SSH
export GPG_TTY=$(tty)
export SSH_AUTH_SOCK="{socket_path}"

# Start gpg-agent if not running
gpgconf --launch gpg-agent

# Refresh gpg-agent on new terminal
gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1
"""
    elif shell == "fish":
        return f"""\
# Add to ~/.config/fish/config.fish

# Use gpg-agent for SSH
set -gx GPG_TTY (tty)
set -gx SSH_AUTH_SOCK "{socket_path}"

# Start gpg-agent if not running
gpgconf --launch gpg-agent

# Refresh gpg-agent on new terminal
gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1
"""
    else:
        return f"# SSH_AUTH_SOCK={socket_path}"


def restart_gpg_agent() -> Result[None]:
    """Restart the gpg-agent."""
    import subprocess

    try:
        # Kill existing agent
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)

        # Start new agent
        subprocess.run(["gpgconf", "--launch", "gpg-agent"], check=True)

        return Result.ok(None)
    except subprocess.CalledProcessError as e:
        return Result.err(ConfigError(f"Could not restart gpg-agent: {e}"))
    except FileNotFoundError:
        return Result.err(ConfigError("gpgconf not found"))
