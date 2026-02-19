from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .types import Result


class EnvironmentError(Exception):
    pass


@dataclass
class CheckResult:
    """Result of an environment check."""

    name: str
    passed: bool
    message: str
    critical: bool = True
    fix_hint: str | None = None


@dataclass
class EnvironmentReport:
    """Complete environment verification report."""

    system: str
    checks: list[CheckResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks if c.critical)

    @property
    def critical_failures(self) -> list[CheckResult]:
        return [c for c in self.checks if c.critical and not c.passed]

    @property
    def non_critical_failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.critical and not c.passed]


def check_gpg_installed() -> CheckResult:
    """Check if GnuPG is installed and accessible."""
    gpg_path = shutil.which("gpg")
    if gpg_path:
        try:
            result = subprocess.run(
                ["gpg", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                version_line = result.stdout.split("\n")[0]
                return CheckResult(
                    name="GnuPG",
                    passed=True,
                    message=f"Found: {version_line}",
                )
        except Exception as e:
            return CheckResult(
                name="GnuPG",
                passed=False,
                message=f"Error checking gpg: {e}",
                fix_hint="Reinstall GnuPG",
            )

    return CheckResult(
        name="GnuPG",
        passed=False,
        message="gpg not found in PATH",
        fix_hint="Install GnuPG: brew install gnupg (macOS) or apt install gnupg (Debian/Ubuntu)",
    )


def check_gpg_version() -> CheckResult:
    """Check GnuPG version is >= 2.2."""
    try:
        result = subprocess.run(
            ["gpg", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            # Parse version: "gpg (GnuPG) 2.4.0"
            version_line = result.stdout.split("\n")[0]
            parts = version_line.split()
            if parts:
                version_str = parts[-1]
                version_parts = version_str.split(".")
                major = int(version_parts[0])
                minor = int(version_parts[1]) if len(version_parts) > 1 else 0

                if major > 2 or (major == 2 and minor >= 2):
                    return CheckResult(
                        name="GnuPG Version",
                        passed=True,
                        message=f"Version {version_str} (>= 2.2 required)",
                    )
                else:
                    return CheckResult(
                        name="GnuPG Version",
                        passed=False,
                        message=f"Version {version_str} is too old (>= 2.2 required)",
                        fix_hint="Upgrade GnuPG to version 2.2 or later",
                    )
    except Exception:
        pass

    return CheckResult(
        name="GnuPG Version",
        passed=False,
        message="Could not determine GnuPG version",
        fix_hint="Ensure gpg is installed correctly",
    )


def check_ykman_installed() -> CheckResult:
    """Check if ykman (YubiKey Manager) is installed."""
    ykman_path = shutil.which("ykman")
    if ykman_path:
        try:
            result = subprocess.run(
                ["ykman", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return CheckResult(
                    name="YubiKey Manager",
                    passed=True,
                    message=f"Found: ykman {result.stdout.strip()}",
                )
        except Exception:
            pass

    return CheckResult(
        name="YubiKey Manager",
        passed=False,
        message="ykman not found in PATH",
        fix_hint="Install YubiKey Manager: brew install ykman (macOS) or pip install yubikey-manager",
    )


def check_ykman_version() -> CheckResult:
    """Check ykman version is >= 5.0."""
    try:
        result = subprocess.run(
            ["ykman", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            version_str = result.stdout.strip().split()[-1]
            version_parts = version_str.split(".")
            major = int(version_parts[0])

            if major >= 5:
                return CheckResult(
                    name="ykman Version",
                    passed=True,
                    message=f"Version {version_str} (>= 5.0 required)",
                )
            else:
                return CheckResult(
                    name="ykman Version",
                    passed=False,
                    message=f"Version {version_str} is too old (>= 5.0 required)",
                    fix_hint="Upgrade ykman: pip install --upgrade yubikey-manager",
                )
    except Exception:
        pass

    return CheckResult(
        name="ykman Version",
        passed=False,
        message="Could not determine ykman version",
        critical=False,
    )


def check_pcscd_running() -> CheckResult:
    """Check if pcscd (PC/SC Smart Card Daemon) is running (Linux only)."""
    system = platform.system()

    if system == "Darwin":
        # macOS has built-in smartcard support
        return CheckResult(
            name="Smartcard Daemon",
            passed=True,
            message="macOS has built-in smartcard support",
        )

    if system == "Linux":
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "pcscd"],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip() == "active":
                return CheckResult(
                    name="pcscd",
                    passed=True,
                    message="pcscd is running",
                )
            else:
                return CheckResult(
                    name="pcscd",
                    passed=False,
                    message="pcscd is not running",
                    fix_hint="Start pcscd: sudo systemctl start pcscd && sudo systemctl enable pcscd",
                )
        except FileNotFoundError:
            # Try alternative check
            try:
                result = subprocess.run(
                    ["pgrep", "-x", "pcscd"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    return CheckResult(
                        name="pcscd",
                        passed=True,
                        message="pcscd is running",
                    )
            except Exception:
                pass

            return CheckResult(
                name="pcscd",
                passed=False,
                message="Could not verify pcscd status",
                fix_hint="Install and start pcscd: apt install pcscd && sudo systemctl start pcscd",
            )

    return CheckResult(
        name="Smartcard Daemon",
        passed=True,
        message=f"Skipped for {system}",
        critical=False,
    )


def check_scdaemon() -> CheckResult:
    """Check if scdaemon is available and can communicate with smartcards."""
    try:
        result = subprocess.run(
            ["gpg-connect-agent", "SCD GETINFO version", "/bye"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and "OK" in result.stdout:
            return CheckResult(
                name="scdaemon",
                passed=True,
                message="scdaemon is responding",
            )
        else:
            return CheckResult(
                name="scdaemon",
                passed=False,
                message="scdaemon not responding",
                fix_hint="Restart gpg-agent: gpgconf --kill gpg-agent",
                critical=False,
            )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="scdaemon",
            passed=False,
            message="scdaemon timed out",
            fix_hint="Restart gpg-agent: gpgconf --kill gpg-agent",
            critical=False,
        )
    except FileNotFoundError:
        return CheckResult(
            name="scdaemon",
            passed=False,
            message="gpg-connect-agent not found",
            fix_hint="Ensure GnuPG is properly installed",
        )


def check_yubikey_detected() -> CheckResult:
    """Check if a YubiKey is detected."""
    try:
        result = subprocess.run(
            ["ykman", "list"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = [line for line in result.stdout.strip().split("\n") if line]
            return CheckResult(
                name="YubiKey Detection",
                passed=True,
                message=f"Found {len(lines)} YubiKey(s)",
                critical=False,
            )
        else:
            return CheckResult(
                name="YubiKey Detection",
                passed=False,
                message="No YubiKey detected",
                fix_hint="Insert a YubiKey and ensure it's recognized by the system",
                critical=False,
            )
    except Exception as e:
        return CheckResult(
            name="YubiKey Detection",
            passed=False,
            message=f"Error detecting YubiKey: {e}",
            critical=False,
        )


def check_entropy() -> CheckResult:
    """Check system entropy availability (Linux only)."""
    system = platform.system()

    if system != "Linux":
        return CheckResult(
            name="Entropy",
            passed=True,
            message=f"Entropy check skipped for {system}",
            critical=False,
        )

    try:
        entropy_path = Path("/proc/sys/kernel/random/entropy_avail")
        if entropy_path.exists():
            entropy = int(entropy_path.read_text().strip())
            if entropy >= 256:
                return CheckResult(
                    name="Entropy",
                    passed=True,
                    message=f"Available entropy: {entropy} bits (>= 256 required)",
                )
            else:
                return CheckResult(
                    name="Entropy",
                    passed=False,
                    message=f"Low entropy: {entropy} bits (>= 256 recommended)",
                    fix_hint="Install rng-tools: apt install rng-tools && sudo systemctl start rng-tools",
                    critical=False,
                )
    except Exception as e:
        return CheckResult(
            name="Entropy",
            passed=True,
            message=f"Could not check entropy: {e}",
            critical=False,
        )

    return CheckResult(
        name="Entropy",
        passed=True,
        message="Entropy check not available",
        critical=False,
    )


def check_network_disabled() -> CheckResult:
    """Check if network is disabled (recommended for key generation)."""
    system = platform.system()

    try:
        if system == "Darwin":
            # Check if Wi-Fi is off
            result = subprocess.run(
                ["networksetup", "-getairportpower", "en0"],
                capture_output=True,
                text=True,
            )
            if "Off" in result.stdout:
                return CheckResult(
                    name="Network Isolation",
                    passed=True,
                    message="Wi-Fi is disabled",
                    critical=False,
                )
        elif system == "Linux":
            # Check if network interfaces are down
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
            )
            # This is a loose check - just informational
            pass

        return CheckResult(
            name="Network Isolation",
            passed=False,
            message="Network may be active (recommended to disable during key generation)",
            fix_hint="Consider disabling network: networksetup -setairportpower en0 off (macOS) or nmcli networking off (Linux)",
            critical=False,
        )
    except Exception:
        return CheckResult(
            name="Network Isolation",
            passed=False,
            message="Could not verify network status",
            critical=False,
        )


def check_pinentry() -> CheckResult:
    """Check if a pinentry program is available."""
    # Try common pinentry programs
    pinentry_programs = [
        "pinentry-mac",
        "pinentry-gnome3",
        "pinentry-gtk-2",
        "pinentry-qt",
        "pinentry-curses",
        "pinentry-tty",
        "pinentry",
    ]

    for program in pinentry_programs:
        if shutil.which(program):
            return CheckResult(
                name="Pinentry",
                passed=True,
                message=f"Found: {program}",
            )

    return CheckResult(
        name="Pinentry",
        passed=False,
        message="No pinentry program found",
        fix_hint="Install pinentry: brew install pinentry-mac (macOS) or apt install pinentry-curses (Linux)",
    )


def check_paperkey_installed() -> CheckResult:
    """Check if paperkey is installed (for physical backups)."""
    paperkey_path = shutil.which("paperkey")
    if paperkey_path:
        return CheckResult(
            name="Paperkey",
            passed=True,
            message="paperkey is available for physical backups",
            critical=False,
        )

    return CheckResult(
        name="Paperkey",
        passed=False,
        message="paperkey not installed (optional, for physical backups)",
        fix_hint="Install paperkey: brew install paperkey (macOS) or apt install paperkey (Linux)",
        critical=False,
    )


def check_cryptsetup_installed() -> CheckResult:
    """Check if cryptsetup is installed (Linux only, for LUKS)."""
    system = platform.system()

    if system == "Darwin":
        return CheckResult(
            name="Disk Encryption",
            passed=True,
            message="macOS uses FileVault/APFS encryption",
            critical=False,
        )

    if system == "Linux":
        cryptsetup_path = shutil.which("cryptsetup")
        if cryptsetup_path:
            return CheckResult(
                name="cryptsetup",
                passed=True,
                message="cryptsetup is available for LUKS encryption",
            )
        return CheckResult(
            name="cryptsetup",
            passed=False,
            message="cryptsetup not installed",
            fix_hint="Install cryptsetup: apt install cryptsetup",
        )

    return CheckResult(
        name="Disk Encryption",
        passed=True,
        message=f"Check skipped for {system}",
        critical=False,
    )


def check_live_environment() -> CheckResult:
    """Check if running in a live/ephemeral environment."""
    system = platform.system()

    if system == "Linux":
        # Check for common live environment indicators
        indicators = [
            Path("/run/live"),
            Path("/lib/live"),
            Path("/cdrom"),
        ]

        for indicator in indicators:
            if indicator.exists():
                return CheckResult(
                    name="Live Environment",
                    passed=True,
                    message="Running in a live environment (recommended)",
                    critical=False,
                )

        # Check if root filesystem is read-only or tmpfs
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    if " / " in line and ("tmpfs" in line or "squashfs" in line):
                        return CheckResult(
                            name="Live Environment",
                            passed=True,
                            message="Running in a live/ephemeral environment",
                            critical=False,
                        )
        except Exception:
            pass

    return CheckResult(
        name="Live Environment",
        passed=False,
        message="Not running in a live environment (recommended for maximum security)",
        fix_hint="Consider booting from a Debian Live USB for key generation",
        critical=False,
    )


def verify_environment(include_optional: bool = True) -> EnvironmentReport:
    """Run all environment checks and return a report."""
    report = EnvironmentReport(system=platform.system())

    # Critical checks
    report.checks.append(check_gpg_installed())
    report.checks.append(check_gpg_version())
    report.checks.append(check_ykman_installed())
    report.checks.append(check_pcscd_running())
    report.checks.append(check_pinentry())

    # Recommended checks
    if include_optional:
        report.checks.append(check_ykman_version())
        report.checks.append(check_scdaemon())
        report.checks.append(check_yubikey_detected())
        report.checks.append(check_entropy())
        report.checks.append(check_network_disabled())
        report.checks.append(check_paperkey_installed())
        report.checks.append(check_cryptsetup_installed())
        report.checks.append(check_live_environment())

    # Add warnings
    if not report.all_passed:
        report.warnings.append("Some critical checks failed. Fix these before proceeding.")

    return report


def verify_environment_result() -> Result[EnvironmentReport]:
    """Run environment verification and return as a Result."""
    report = verify_environment()

    if report.all_passed:
        return Result.ok(report)
    else:
        failures = ", ".join(c.name for c in report.critical_failures)
        return Result.err(EnvironmentError(f"Critical checks failed: {failures}"))
