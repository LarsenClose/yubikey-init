"""Tests for diagnostics module."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from yubikey_init.diagnostics import (
    DiagnosticInfo,
    analyze_issues,
    format_diagnostic_report,
    get_agent_info,
    get_card_info,
    get_gpg_info,
    get_system_info,
    get_yubikey_info,
    restart_gpg_components,
    run_diagnostics,
)
from yubikey_init.diagnostics import (
    test_card_operations as check_card_ops,
)


class TestDiagnosticInfo:
    """Test DiagnosticInfo dataclass."""

    def test_diagnostic_info_creation(self):
        """Test creating diagnostic info."""
        info = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux"},
            gpg_info={"installed": True},
            yubikey_info={"ykman_installed": True},
            card_info={"card_present": True},
            agent_info={"running": True},
        )

        assert info.system_info["platform"] == "Linux"
        assert info.gpg_info["installed"] is True
        assert info.issues == []
        assert info.recommendations == []

    def test_diagnostic_info_with_issues(self):
        """Test diagnostic info with issues."""
        info = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={},
            yubikey_info={},
            card_info={},
            agent_info={},
            issues=["Issue 1", "Issue 2"],
            recommendations=["Fix 1"],
        )

        assert len(info.issues) == 2
        assert len(info.recommendations) == 1


class TestSystemInfo:
    """Test system info gathering."""

    def test_get_system_info(self):
        """Test getting system info."""
        info = get_system_info()

        assert "platform" in info
        assert "platform_version" in info
        assert "python_version" in info
        assert "machine" in info


class TestGPGInfo:
    """Test GPG info gathering."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_gpg_info_installed(self, mock_run, mock_which):
        """Test getting GPG info when installed."""
        mock_which.return_value = "/usr/bin/gpg"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="gpg (GnuPG) 2.4.0\nlibgcrypt 1.10.0",
        )

        info = get_gpg_info()

        assert info["installed"] is True
        assert "2.4.0" in info.get("version", "")

    @patch("shutil.which")
    def test_get_gpg_info_not_installed(self, mock_which):
        """Test getting GPG info when not installed."""
        mock_which.return_value = None

        info = get_gpg_info()

        assert info["installed"] is False


class TestYubiKeyInfo:
    """Test YubiKey info gathering."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_yubikey_info_installed(self, mock_run, mock_which):
        """Test getting YubiKey info when ykman is installed."""
        mock_which.return_value = "/usr/bin/ykman"

        def run_side_effect(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="YubiKey Manager (ykman) 5.2.0")
            elif "list" in cmd:
                return MagicMock(returncode=0, stdout="12345678\n")
            elif "info" in cmd:
                return MagicMock(returncode=0, stdout="Device info")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_yubikey_info()

        assert info["ykman_installed"] is True
        assert "5.2.0" in info.get("ykman_version", "")

    @patch("shutil.which")
    def test_get_yubikey_info_not_installed(self, mock_which):
        """Test getting YubiKey info when ykman is not installed."""
        mock_which.return_value = None

        info = get_yubikey_info()

        assert info["ykman_installed"] is False


class TestCardInfo:
    """Test card info gathering."""

    @patch("subprocess.run")
    def test_get_card_info_present(self, mock_run):
        """Test getting card info when card is present."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Reader: Yubico YubiKey\nApplication ID: 12345\n",
        )

        info = get_card_info()

        assert info["card_present"] is True
        assert "Reader" in info.get("reader", "")

    @patch("subprocess.run")
    def test_get_card_info_not_present(self, mock_run):
        """Test getting card info when no card."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No card")

        info = get_card_info()

        assert info["card_present"] is False


class TestAgentInfo:
    """Test agent info gathering."""

    @patch("subprocess.run")
    def test_get_agent_info_running(self, mock_run):
        """Test getting agent info when running."""

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                return MagicMock(returncode=0, stdout="D 12345\nOK")
            elif "--list-dirs" in cmd:
                return MagicMock(
                    returncode=0,
                    stdout="agent-socket:/tmp/gpg/S.gpg-agent\nagent-ssh-socket:/tmp/gpg/S.gpg-agent.ssh",
                )
            elif "SCD GETINFO" in str(cmd):
                return MagicMock(returncode=0, stdout="D 2.4.0\nOK")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert info["running"] is True
        assert info.get("pid") == "12345"


class TestAnalyzeIssues:
    """Test issue analysis."""

    def test_analyze_issues_gpg_not_installed(self):
        """Test that missing GPG is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": False},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={"card_present": False},
            agent_info={"running": True},
        )

        analyze_issues(diagnostic)

        assert any("GnuPG" in issue for issue in diagnostic.issues)

    def test_analyze_issues_ykman_not_installed(self):
        """Test that missing ykman is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": False},
            card_info={},
            agent_info={},
        )

        analyze_issues(diagnostic)

        assert any("ykman" in issue for issue in diagnostic.issues)

    def test_analyze_issues_no_yubikey(self):
        """Test that missing YubiKey is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={},
            agent_info={},
        )

        analyze_issues(diagnostic)

        assert any("YubiKey" in issue and "detected" in issue for issue in diagnostic.issues)


class TestRunDiagnostics:
    """Test the main run_diagnostics function."""

    @patch("yubikey_init.diagnostics.get_system_info")
    @patch("yubikey_init.diagnostics.get_gpg_info")
    @patch("yubikey_init.diagnostics.get_yubikey_info")
    @patch("yubikey_init.diagnostics.get_card_info")
    @patch("yubikey_init.diagnostics.get_agent_info")
    def test_run_diagnostics(
        self,
        mock_agent,
        mock_card,
        mock_yubikey,
        mock_gpg,
        mock_system,
    ):
        """Test running full diagnostics."""
        mock_system.return_value = {"platform": "Linux"}
        mock_gpg.return_value = {"installed": True}
        mock_yubikey.return_value = {"ykman_installed": True}
        mock_card.return_value = {"card_present": False}
        mock_agent.return_value = {"running": True}

        diagnostic = run_diagnostics()

        assert diagnostic.system_info["platform"] == "Linux"
        assert diagnostic.gpg_info["installed"] is True


class TestFormatReport:
    """Test report formatting."""

    def test_format_diagnostic_report(self):
        """Test formatting a diagnostic report."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux", "python_version": "3.11"},
            gpg_info={"installed": True, "version": "gpg 2.4.0"},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={"card_present": False},
            agent_info={"running": True},
            issues=["Test issue"],
            recommendations=["Test recommendation"],
        )

        report = format_diagnostic_report(diagnostic)

        assert "Diagnostic Report" in report
        assert "Linux" in report
        assert "Test issue" in report
        assert "Test recommendation" in report


class TestRestartComponents:
    """Test component restart functions."""

    @patch("subprocess.run")
    def test_restart_gpg_components(self, mock_run):
        """Test restarting GPG components."""
        mock_run.return_value = MagicMock(returncode=0)

        result = restart_gpg_components()

        assert result.is_ok()
        actions = result.unwrap()
        assert len(actions) > 0


class TestCardOperations:
    """Test card operation tests."""

    @patch("subprocess.run")
    def test_test_card_operations(self, mock_run):
        """Test testing card operations."""
        mock_run.return_value = MagicMock(returncode=0)

        result = check_card_ops()

        assert result.is_ok()
        results = result.unwrap()
        assert "card_status" in results
        assert "ykman_list" in results

    @patch("subprocess.run")
    def test_test_card_operations_card_exception(self, mock_run):
        """Test test_card_operations handles card status exception."""
        import subprocess

        def run_side_effect(cmd, **kwargs):
            if "--card-status" in cmd:
                raise subprocess.TimeoutExpired(cmd, 15)
            return MagicMock(returncode=0)

        mock_run.side_effect = run_side_effect

        result = check_card_ops()

        assert result.is_ok()
        results = result.unwrap()
        assert results["card_status"] is False
        assert "card_status_error" in results

    @patch("subprocess.run")
    def test_test_card_operations_ykman_exception(self, mock_run):
        """Test test_card_operations handles ykman exception."""

        def run_side_effect(cmd, **kwargs):
            if "ykman" in cmd:
                raise FileNotFoundError("ykman not found")
            return MagicMock(returncode=0)

        mock_run.side_effect = run_side_effect

        result = check_card_ops()

        assert result.is_ok()
        results = result.unwrap()
        assert results["ykman_list"] is False
        assert "ykman_list_error" in results


class TestCheckKeyOnCard:
    """Test check_key_on_card function."""

    @patch("subprocess.run")
    def test_check_key_on_card_found(self, mock_run):
        """Test check_key_on_card when key is on card."""
        from yubikey_init.diagnostics import check_key_on_card

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Signature key: ABCD1234567890EF\n"
                "Encryption key: ABCD1234567890EF\n"
                "Authentication key: ABCD1234567890EF\n"
            ),
        )

        result = check_key_on_card("ABCD1234567890EF")

        assert result.is_ok()
        results = result.unwrap()
        assert results["on_card"] is True
        assert results["slots"]["signature"] is True

    @patch("subprocess.run")
    def test_check_key_on_card_not_found(self, mock_run):
        """Test check_key_on_card when key is not on card."""
        from yubikey_init.diagnostics import check_key_on_card

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Signature key: DIFFERENT1234567\n"
                "Encryption key: DIFFERENT1234567\n"
                "Authentication key: DIFFERENT1234567\n"
            ),
        )

        result = check_key_on_card("ABCD1234567890EF")

        assert result.is_ok()
        results = result.unwrap()
        assert results["on_card"] is False

    @patch("subprocess.run")
    def test_check_key_on_card_no_card(self, mock_run):
        """Test check_key_on_card when no card present."""
        from yubikey_init.diagnostics import check_key_on_card

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No card")

        result = check_key_on_card("ABCD1234567890EF")

        assert result.is_ok()
        results = result.unwrap()
        assert results["on_card"] is False

    @patch("subprocess.run")
    def test_check_key_on_card_exception(self, mock_run):
        """Test check_key_on_card handles exception."""
        from yubikey_init.diagnostics import check_key_on_card

        mock_run.side_effect = Exception("Card error")

        result = check_key_on_card("ABCD1234567890EF")

        assert result.is_err()
        assert "Card check failed" in str(result.unwrap_err())


class TestGPGInfoExtended:
    """Extended tests for get_gpg_info."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_gpg_info_with_libgcrypt(self, mock_run, mock_which):
        """Test get_gpg_info parses libgcrypt version."""
        mock_which.return_value = "/usr/bin/gpg"

        def run_side_effect(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(
                    returncode=0,
                    stdout="gpg (GnuPG) 2.4.0\nlibgcrypt 1.10.0\nCompiled with...",
                )
            elif "/bye" in cmd:
                return MagicMock(returncode=0)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_gpg_info()

        assert info["installed"] is True
        assert "libgcrypt" in info

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_gpg_info_version_exception(self, mock_run, mock_which):
        """Test get_gpg_info handles version check exception."""
        mock_which.return_value = "/usr/bin/gpg"
        mock_run.side_effect = Exception("Command failed")

        info = get_gpg_info()

        # Should still succeed with installed=True, but no version
        assert info["installed"] is True
        assert info["version"] is None

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_gpg_info_agent_exception(self, mock_run, mock_which):
        """Test get_gpg_info handles agent check exception."""
        mock_which.return_value = "/usr/bin/gpg"

        def run_side_effect(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="gpg 2.4.0\n")
            elif "/bye" in cmd:
                raise Exception("Agent not running")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_gpg_info()

        assert info["agent_running"] is False


class TestYubiKeyInfoExtended:
    """Extended tests for get_yubikey_info."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_yubikey_info_version_exception(self, mock_run, mock_which):
        """Test get_yubikey_info handles version check exception."""
        mock_which.return_value = "/usr/bin/ykman"
        mock_run.side_effect = Exception("Command failed")

        info = get_yubikey_info()

        assert info["ykman_installed"] is True
        assert info["ykman_version"] is None

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_yubikey_info_list_exception(self, mock_run, mock_which):
        """Test get_yubikey_info handles list exception."""
        mock_which.return_value = "/usr/bin/ykman"

        def run_side_effect(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="ykman 5.0.0")
            elif "list" in cmd:
                raise Exception("List failed")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_yubikey_info()

        assert info["devices"] == []

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_yubikey_info_device_info_exception(self, mock_run, mock_which):
        """Test get_yubikey_info handles device info exception."""
        mock_which.return_value = "/usr/bin/ykman"

        def run_side_effect(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="ykman 5.0.0")
            elif "list" in cmd:
                return MagicMock(returncode=0, stdout="12345678\n")
            elif "info" in cmd:
                raise Exception("Info failed")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_yubikey_info()

        # Should still have device with serial, just no info
        assert len(info["devices"]) == 1
        assert info["devices"][0]["serial"] == "12345678"


class TestCardInfoExtended:
    """Extended tests for get_card_info."""

    @patch("subprocess.run")
    def test_get_card_info_with_serial(self, mock_run):
        """Test get_card_info parses serial number."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Reader: Yubico YubiKey\n"
                "Application ID: D2760001240103040006123456780000\n"
                "Serial number: 12345678\n"
            ),
        )

        info = get_card_info()

        assert info["card_present"] is True
        assert "Serial number" in info.get("serial", "")

    @patch("subprocess.run")
    def test_get_card_info_timeout(self, mock_run):
        """Test get_card_info handles timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("gpg", 10)

        info = get_card_info()

        assert info["card_present"] is False
        assert "timed out" in info.get("error", "")

    @patch("subprocess.run")
    def test_get_card_info_exception(self, mock_run):
        """Test get_card_info handles exception."""
        mock_run.side_effect = Exception("Card error")

        info = get_card_info()

        assert info["card_present"] is False
        assert "Card error" in info.get("error", "")


class TestAgentInfoExtended:
    """Extended tests for get_agent_info."""

    @patch("subprocess.run")
    def test_get_agent_info_scdaemon_timeout(self, mock_run):
        """Test get_agent_info handles scdaemon timeout."""
        import subprocess

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                return MagicMock(returncode=0, stdout="D 12345\nOK")
            elif "--list-dirs" in cmd:
                return MagicMock(returncode=0, stdout="")
            elif "SCD GETINFO" in str(cmd):
                raise subprocess.TimeoutExpired("gpg-connect-agent", 10)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert info["scdaemon_status"] == "timed out"

    @patch("subprocess.run")
    def test_get_agent_info_scdaemon_not_responding(self, mock_run):
        """Test get_agent_info when scdaemon not responding."""

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                return MagicMock(returncode=0, stdout="D 12345\nOK")
            elif "--list-dirs" in cmd:
                return MagicMock(returncode=0, stdout="")
            elif "SCD GETINFO" in str(cmd):
                return MagicMock(returncode=1)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert info["scdaemon_status"] == "not responding"

    @patch("subprocess.run")
    def test_get_agent_info_scdaemon_exception(self, mock_run):
        """Test get_agent_info handles scdaemon exception."""

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                return MagicMock(returncode=0, stdout="D 12345\nOK")
            elif "--list-dirs" in cmd:
                return MagicMock(returncode=0, stdout="")
            elif "SCD GETINFO" in str(cmd):
                raise Exception("scdaemon error")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert "error:" in info.get("scdaemon_status", "")

    @patch("subprocess.run")
    def test_get_agent_info_exception_on_getinfo(self, mock_run):
        """Test get_agent_info handles GETINFO exception."""

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                raise Exception("Connection failed")
            elif "--list-dirs" in cmd:
                return MagicMock(returncode=0, stdout="agent-socket:/tmp/socket")
            elif "SCD GETINFO" in str(cmd):
                return MagicMock(returncode=0, stdout="D 2.4.0")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert info["running"] is False

    @patch("subprocess.run")
    def test_get_agent_info_list_dirs_exception(self, mock_run):
        """Test get_agent_info handles list-dirs exception."""

        def run_side_effect(cmd, **kwargs):
            if "GETINFO pid" in str(cmd):
                return MagicMock(returncode=0, stdout="D 12345\nOK")
            elif "--list-dirs" in cmd:
                raise Exception("gpgconf error")
            elif "SCD GETINFO" in str(cmd):
                return MagicMock(returncode=0, stdout="D 2.4.0")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        info = get_agent_info()

        assert info["socket_path"] is None


class TestAnalyzeIssuesExtended:
    """Extended tests for analyze_issues."""

    def test_analyze_issues_card_not_accessible(self):
        """Test that card not accessible is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": [{"serial": "12345678"}]},
            card_info={"card_present": False},
            agent_info={},
        )

        analyze_issues(diagnostic)

        assert any("smartcard not accessible" in issue for issue in diagnostic.issues)

    def test_analyze_issues_scdaemon_timeout(self):
        """Test that scdaemon timeout is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={},
            agent_info={"scdaemon_status": "timed out"},
        )

        analyze_issues(diagnostic)

        assert any("timed out" in issue for issue in diagnostic.issues)

    def test_analyze_issues_scdaemon_not_responding(self):
        """Test that scdaemon not responding is flagged."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={},
            agent_info={"scdaemon_status": "not responding"},
        )

        analyze_issues(diagnostic)

        assert any("not responding" in issue for issue in diagnostic.issues)

    @patch("subprocess.run")
    def test_analyze_issues_linux_pcscd_not_active(self, mock_run):
        """Test that pcscd not running is flagged on Linux."""
        mock_run.return_value = MagicMock(returncode=0, stdout="inactive")

        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux"},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": []},
            card_info={},
            agent_info={},
        )

        analyze_issues(diagnostic)

        assert any("pcscd" in issue for issue in diagnostic.issues)


class TestFormatReportExtended:
    """Extended tests for format_diagnostic_report."""

    def test_format_report_with_devices(self):
        """Test format report shows devices."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux"},
            gpg_info={
                "installed": True,
                "version": "gpg 2.4.0",
                "home": "/home/user/.gnupg",
                "agent_running": True,
                "config_files": ["/home/user/.gnupg/gpg.conf"],
            },
            yubikey_info={
                "ykman_installed": True,
                "ykman_version": "5.0.0",
                "devices": [{"serial": "12345678"}, {"serial": "87654321"}],
            },
            card_info={
                "card_present": True,
                "reader": "Reader: Yubico YubiKey",
                "error": None,
            },
            agent_info={
                "running": True,
                "pid": "12345",
                "socket_path": "/tmp/socket",
                "ssh_socket_path": "/tmp/ssh-socket",
                "scdaemon_status": "responding",
            },
        )

        report = format_diagnostic_report(diagnostic)

        assert "12345678" in report
        assert "87654321" in report
        assert "PID: 12345" in report
        assert "SSH Socket:" in report
        assert "scdaemon: responding" in report

    def test_format_report_no_issues(self):
        """Test format report when no issues."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux"},
            gpg_info={"installed": True, "agent_running": True},
            yubikey_info={"ykman_installed": True, "devices": [{"serial": "12345"}]},
            card_info={"card_present": True},
            agent_info={"running": True},
            issues=[],
            recommendations=[],
        )

        report = format_diagnostic_report(diagnostic)

        assert "All checks passed" in report

    def test_format_report_with_card_error(self):
        """Test format report shows card error."""
        diagnostic = DiagnosticInfo(
            timestamp=datetime.now(UTC),
            system_info={"platform": "Linux"},
            gpg_info={"installed": True},
            yubikey_info={"ykman_installed": True},
            card_info={"card_present": False, "error": "Card read timeout"},
            agent_info={"running": True},
        )

        report = format_diagnostic_report(diagnostic)

        assert "Error: Card read timeout" in report


class TestRestartComponentsExtended:
    """Extended tests for restart_gpg_components."""

    @patch("subprocess.run")
    def test_restart_gpg_components_launch_fails(self, mock_run):
        """Test restart when launch fails."""

        def run_side_effect(cmd, **kwargs):
            if "--kill" in cmd:
                return MagicMock(returncode=0)
            elif "--launch" in cmd:
                return MagicMock(returncode=1)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        result = restart_gpg_components()

        assert result.is_ok()
        actions = result.unwrap()
        # Should have killed, but not started
        assert any("Killed" in a for a in actions)
        assert not any("Started" in a for a in actions)

    @patch("subprocess.run")
    def test_restart_gpg_components_exception(self, mock_run):
        """Test restart handles exception."""
        mock_run.side_effect = Exception("gpgconf not found")

        result = restart_gpg_components()

        assert result.is_err()
        assert "Restart failed" in str(result.unwrap_err())
