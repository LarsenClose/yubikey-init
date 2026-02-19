from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .types import Result


class DiagnosticError(Exception):
    pass


@dataclass
class DiagnosticInfo:
    """Complete diagnostic information."""

    timestamp: datetime
    system_info: dict[str, Any]
    gpg_info: dict[str, Any]
    yubikey_info: dict[str, Any]
    card_info: dict[str, Any]
    agent_info: dict[str, Any]
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def get_system_info() -> dict[str, Any]:
    """Gather system information."""
    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
    }


def get_gpg_info() -> dict[str, Any]:
    """Gather GnuPG information."""
    info: dict[str, Any] = {
        "installed": False,
        "version": None,
        "home": None,
        "config_files": [],
        "agent_running": False,
    }

    # Check GPG installation
    gpg_path = shutil.which("gpg")
    if gpg_path:
        info["installed"] = True
        info["path"] = gpg_path

        # Get version
        try:
            result = subprocess.run(
                ["gpg", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                if lines:
                    info["version"] = lines[0]
                    # Parse additional info
                    for line in lines:
                        if "libgcrypt" in line.lower():
                            info["libgcrypt"] = line.strip()
        except Exception:
            pass

    # Get GNUPGHOME
    gnupghome = os.environ.get("GNUPGHOME", str(Path.home() / ".gnupg"))
    info["home"] = gnupghome

    # Check config files
    gnupg_path = Path(gnupghome)
    config_files = ["gpg.conf", "gpg-agent.conf", "scdaemon.conf", "dirmngr.conf"]
    for conf_file in config_files:
        conf_path = gnupg_path / conf_file
        if conf_path.exists():
            info["config_files"].append(str(conf_path))

    # Check if agent is running
    try:
        result = subprocess.run(
            ["gpg-connect-agent", "/bye"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        info["agent_running"] = result.returncode == 0
    except Exception:
        info["agent_running"] = False

    return info


def get_yubikey_info() -> dict[str, Any]:
    """Gather YubiKey Manager information."""
    info: dict[str, Any] = {
        "ykman_installed": False,
        "ykman_version": None,
        "devices": [],
    }

    ykman_path = shutil.which("ykman")
    if ykman_path:
        info["ykman_installed"] = True
        info["ykman_path"] = ykman_path

        # Get version
        try:
            result = subprocess.run(
                ["ykman", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                info["ykman_version"] = result.stdout.strip()
        except Exception:
            pass

        # List devices
        try:
            result = subprocess.run(
                ["ykman", "list", "--serials"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                serials = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
                for serial in serials:
                    device_info = {"serial": serial}
                    # Get device details
                    try:
                        detail_result = subprocess.run(
                            ["ykman", "--device", serial, "info"],
                            capture_output=True,
                            text=True,
                        )
                        if detail_result.returncode == 0:
                            device_info["info"] = detail_result.stdout
                    except Exception:
                        pass
                    info["devices"].append(device_info)
        except Exception:
            pass

    return info


def get_card_info() -> dict[str, Any]:
    """Gather smartcard information."""
    info: dict[str, Any] = {
        "card_present": False,
        "card_status": None,
        "reader": None,
    }

    try:
        result = subprocess.run(
            ["gpg", "--card-status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            info["card_present"] = True
            info["card_status"] = result.stdout

            # Parse reader info
            for line in result.stdout.split("\n"):
                if line.startswith("Reader"):
                    info["reader"] = line
                elif line.startswith("Application ID"):
                    info["application_id"] = line
                elif "Serial number" in line:
                    info["serial"] = line
    except subprocess.TimeoutExpired:
        info["error"] = "Card status timed out"
    except Exception as e:
        info["error"] = str(e)

    return info


def get_agent_info() -> dict[str, Any]:
    """Gather GPG agent information."""
    info: dict[str, Any] = {
        "running": False,
        "socket_path": None,
        "ssh_socket_path": None,
        "scdaemon_status": None,
    }

    # Check agent status
    try:
        result = subprocess.run(
            ["gpg-connect-agent", "GETINFO pid", "/bye"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["running"] = True
            # Parse PID
            for line in result.stdout.split("\n"):
                if line.startswith("D "):
                    info["pid"] = line[2:].strip()
    except Exception:
        pass

    # Get socket paths
    try:
        result = subprocess.run(
            ["gpgconf", "--list-dirs"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.startswith("agent-socket:"):
                    info["socket_path"] = line.split(":", 1)[1]
                elif line.startswith("agent-ssh-socket:"):
                    info["ssh_socket_path"] = line.split(":", 1)[1]
    except Exception:
        pass

    # Check scdaemon
    try:
        result = subprocess.run(
            ["gpg-connect-agent", "SCD GETINFO version", "/bye"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            info["scdaemon_status"] = "responding"
            for line in result.stdout.split("\n"):
                if line.startswith("D "):
                    info["scdaemon_version"] = line[2:].strip()
        else:
            info["scdaemon_status"] = "not responding"
    except subprocess.TimeoutExpired:
        info["scdaemon_status"] = "timed out"
    except Exception as e:
        info["scdaemon_status"] = f"error: {e}"

    return info


def analyze_issues(diagnostic: DiagnosticInfo) -> None:
    """Analyze diagnostic info and identify issues/recommendations."""
    issues = diagnostic.issues
    recommendations = diagnostic.recommendations

    # GPG issues
    if not diagnostic.gpg_info.get("installed"):
        issues.append("GnuPG is not installed")
        recommendations.append(
            "Install GnuPG: brew install gnupg (macOS) or apt install gnupg (Linux)"
        )

    if not diagnostic.gpg_info.get("agent_running"):
        issues.append("GPG agent is not running")
        recommendations.append("Start GPG agent: gpgconf --launch gpg-agent")

    # YubiKey issues
    if not diagnostic.yubikey_info.get("ykman_installed"):
        issues.append("YubiKey Manager (ykman) is not installed")
        recommendations.append("Install ykman: pip install yubikey-manager")

    if diagnostic.yubikey_info.get("ykman_installed") and not diagnostic.yubikey_info.get(
        "devices"
    ):
        issues.append("No YubiKey devices detected")
        recommendations.append("Insert a YubiKey and ensure USB connection is working")

    # Card issues
    if not diagnostic.card_info.get("card_present") and diagnostic.yubikey_info.get("devices"):
        issues.append("YubiKey detected but smartcard not accessible")
        recommendations.append("Try restarting scdaemon: gpgconf --kill scdaemon")

    # Agent issues
    if diagnostic.agent_info.get("scdaemon_status") == "timed out":
        issues.append("scdaemon is not responding (timed out)")
        recommendations.append(
            "Kill and restart agents: gpgconf --kill all && gpgconf --launch gpg-agent"
        )

    if diagnostic.agent_info.get("scdaemon_status") == "not responding":
        issues.append("scdaemon is not responding")
        recommendations.append(
            "Check scdaemon.conf configuration and restart: gpgconf --kill scdaemon"
        )

    # Platform-specific checks
    if diagnostic.system_info.get("platform") == "Linux":
        # Check pcscd on Linux
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "pcscd"],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip() != "active":
                issues.append("pcscd service is not running")
                recommendations.append("Start pcscd: sudo systemctl start pcscd")
        except Exception:
            pass


def run_diagnostics() -> DiagnosticInfo:
    """Run complete diagnostics and return results."""
    diagnostic = DiagnosticInfo(
        timestamp=datetime.now(UTC),
        system_info=get_system_info(),
        gpg_info=get_gpg_info(),
        yubikey_info=get_yubikey_info(),
        card_info=get_card_info(),
        agent_info=get_agent_info(),
    )

    analyze_issues(diagnostic)
    return diagnostic


def format_diagnostic_report(diagnostic: DiagnosticInfo) -> str:
    """Format diagnostic info as a human-readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append("YubiKey GPG Diagnostic Report")
    lines.append(f"Generated: {diagnostic.timestamp.isoformat()}")
    lines.append("=" * 60)

    # System Info
    lines.append("\n[System Information]")
    for key, value in diagnostic.system_info.items():
        lines.append(f"  {key}: {value}")

    # GPG Info
    lines.append("\n[GnuPG]")
    gpg = diagnostic.gpg_info
    lines.append(f"  Installed: {gpg.get('installed', False)}")
    if gpg.get("version"):
        lines.append(f"  Version: {gpg['version']}")
    lines.append(f"  Home: {gpg.get('home', 'unknown')}")
    lines.append(f"  Agent Running: {gpg.get('agent_running', False)}")
    if gpg.get("config_files"):
        lines.append(f"  Config Files: {', '.join(gpg['config_files'])}")

    # YubiKey Info
    lines.append("\n[YubiKey Manager]")
    yk = diagnostic.yubikey_info
    lines.append(f"  ykman Installed: {yk.get('ykman_installed', False)}")
    if yk.get("ykman_version"):
        lines.append(f"  Version: {yk['ykman_version']}")
    if yk.get("devices"):
        lines.append(f"  Devices Found: {len(yk['devices'])}")
        for device in yk["devices"]:
            lines.append(f"    - Serial: {device['serial']}")
    else:
        lines.append("  Devices Found: 0")

    # Card Info
    lines.append("\n[Smartcard]")
    card = diagnostic.card_info
    lines.append(f"  Card Present: {card.get('card_present', False)}")
    if card.get("reader"):
        lines.append(f"  {card['reader']}")
    if card.get("error"):
        lines.append(f"  Error: {card['error']}")

    # Agent Info
    lines.append("\n[GPG Agent]")
    agent = diagnostic.agent_info
    lines.append(f"  Running: {agent.get('running', False)}")
    if agent.get("pid"):
        lines.append(f"  PID: {agent['pid']}")
    if agent.get("socket_path"):
        lines.append(f"  Socket: {agent['socket_path']}")
    if agent.get("ssh_socket_path"):
        lines.append(f"  SSH Socket: {agent['ssh_socket_path']}")
    if agent.get("scdaemon_status"):
        lines.append(f"  scdaemon: {agent['scdaemon_status']}")

    # Issues
    if diagnostic.issues:
        lines.append("\n[Issues Detected]")
        for issue in diagnostic.issues:
            lines.append(f"  * {issue}")

    # Recommendations
    if diagnostic.recommendations:
        lines.append("\n[Recommendations]")
        for rec in diagnostic.recommendations:
            lines.append(f"  -> {rec}")

    if not diagnostic.issues:
        lines.append("\n[Status]")
        lines.append("  All checks passed. System appears ready for YubiKey operations.")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def restart_gpg_components() -> Result[list[str]]:
    """Restart all GPG-related components."""
    restarted = []

    try:
        # Kill all components
        subprocess.run(["gpgconf", "--kill", "all"], check=False)
        restarted.append("Killed all GPG components")

        # Launch agent
        result = subprocess.run(
            ["gpgconf", "--launch", "gpg-agent"],
            capture_output=True,
        )
        if result.returncode == 0:
            restarted.append("Started gpg-agent")

        return Result.ok(restarted)
    except Exception as e:
        return Result.err(DiagnosticError(f"Restart failed: {e}"))


def test_card_operations() -> Result[dict[str, Any]]:
    """Test basic card operations."""
    results: dict[str, Any] = {}

    # Test card status
    try:
        result = subprocess.run(
            ["gpg", "--card-status"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        results["card_status"] = result.returncode == 0
    except Exception as e:
        results["card_status"] = False
        results["card_status_error"] = str(e)

    # Test ykman access
    try:
        result = subprocess.run(
            ["ykman", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        results["ykman_list"] = result.returncode == 0
    except Exception as e:
        results["ykman_list"] = False
        results["ykman_list_error"] = str(e)

    return Result.ok(results)


def check_key_on_card(key_id: str) -> Result[dict[str, Any]]:
    """Check if a specific key is on the card."""
    results: dict[str, Any] = {
        "key_id": key_id,
        "on_card": False,
        "slots": {},
    }

    try:
        result = subprocess.run(
            ["gpg", "--card-status"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            output = result.stdout

            # Check each slot
            if "Signature key" in output:
                results["slots"]["signature"] = key_id in output
            if "Encryption key" in output:
                results["slots"]["encryption"] = key_id in output
            if "Authentication key" in output:
                results["slots"]["authentication"] = key_id in output

            results["on_card"] = any(results["slots"].values())

        return Result.ok(results)
    except Exception as e:
        return Result.err(DiagnosticError(f"Card check failed: {e}"))
