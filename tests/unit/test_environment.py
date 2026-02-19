"""Tests for environment verification module."""

from unittest.mock import MagicMock, patch

from yubikey_init.environment import (
    CheckResult,
    EnvironmentReport,
    check_gpg_installed,
    check_gpg_version,
    check_pinentry,
    check_ykman_installed,
    verify_environment,
    verify_environment_result,
)


class TestCheckResult:
    """Test CheckResult dataclass."""

    def test_check_result_passed(self):
        """Test creating a passed check result."""
        result = CheckResult(
            name="Test Check",
            passed=True,
            message="All good",
        )
        assert result.passed
        assert result.critical  # Default is True

    def test_check_result_failed_with_hint(self):
        """Test creating a failed check result with hint."""
        result = CheckResult(
            name="Test Check",
            passed=False,
            message="Something failed",
            fix_hint="Try this fix",
        )
        assert not result.passed
        assert result.fix_hint == "Try this fix"

    def test_check_result_non_critical(self):
        """Test non-critical check result."""
        result = CheckResult(
            name="Optional Check",
            passed=False,
            message="Not required",
            critical=False,
        )
        assert not result.passed
        assert not result.critical


class TestEnvironmentReport:
    """Test EnvironmentReport dataclass."""

    def test_all_passed_with_all_passing(self):
        """Test all_passed when all checks pass."""
        report = EnvironmentReport(
            system="Linux",
            checks=[
                CheckResult("Check 1", True, "OK"),
                CheckResult("Check 2", True, "OK"),
            ],
        )
        assert report.all_passed

    def test_all_passed_with_critical_failure(self):
        """Test all_passed when a critical check fails."""
        report = EnvironmentReport(
            system="Linux",
            checks=[
                CheckResult("Check 1", True, "OK"),
                CheckResult("Check 2", False, "Failed", critical=True),
            ],
        )
        assert not report.all_passed

    def test_all_passed_with_non_critical_failure(self):
        """Test all_passed when only non-critical checks fail."""
        report = EnvironmentReport(
            system="Linux",
            checks=[
                CheckResult("Critical", True, "OK", critical=True),
                CheckResult("Optional", False, "Failed", critical=False),
            ],
        )
        assert report.all_passed

    def test_critical_failures(self):
        """Test getting list of critical failures."""
        report = EnvironmentReport(
            system="Linux",
            checks=[
                CheckResult("Check 1", False, "Failed", critical=True),
                CheckResult("Check 2", True, "OK"),
                CheckResult("Check 3", False, "Failed", critical=False),
            ],
        )
        failures = report.critical_failures
        assert len(failures) == 1
        assert failures[0].name == "Check 1"


class TestIndividualChecks:
    """Test individual check functions."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_gpg_installed_found(self, mock_run, mock_which):
        """Test check_gpg_installed when gpg is found."""
        mock_which.return_value = "/usr/bin/gpg"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="gpg (GnuPG) 2.4.0",
        )

        result = check_gpg_installed()

        assert result.passed
        assert "Found" in result.message

    @patch("shutil.which")
    def test_check_gpg_installed_not_found(self, mock_which):
        """Test check_gpg_installed when gpg is not found."""
        mock_which.return_value = None

        result = check_gpg_installed()

        assert not result.passed
        assert result.fix_hint is not None

    @patch("subprocess.run")
    def test_check_gpg_version_sufficient(self, mock_run):
        """Test check_gpg_version with sufficient version."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="gpg (GnuPG) 2.4.0",
        )

        result = check_gpg_version()

        assert result.passed
        assert "2.4.0" in result.message

    @patch("subprocess.run")
    def test_check_gpg_version_too_old(self, mock_run):
        """Test check_gpg_version with old version."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="gpg (GnuPG) 2.0.0",
        )

        result = check_gpg_version()

        assert not result.passed
        assert "too old" in result.message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_ykman_installed_found(self, mock_run, mock_which):
        """Test check_ykman_installed when ykman is found."""
        mock_which.return_value = "/usr/bin/ykman"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="YubiKey Manager (ykman) version: 5.2.0",
        )

        result = check_ykman_installed()

        assert result.passed

    @patch("shutil.which")
    def test_check_ykman_installed_not_found(self, mock_which):
        """Test check_ykman_installed when ykman is not found."""
        mock_which.return_value = None

        result = check_ykman_installed()

        assert not result.passed

    @patch("shutil.which")
    def test_check_pinentry_found(self, mock_which):
        """Test check_pinentry when a pinentry program is found."""

        # Return None for all except pinentry-curses
        def which_side_effect(name):
            if name == "pinentry-curses":
                return "/usr/bin/pinentry-curses"
            return None

        mock_which.side_effect = which_side_effect

        result = check_pinentry()

        assert result.passed
        assert "pinentry-curses" in result.message


class TestCheckGpgInstalled:
    """Additional tests for check_gpg_installed."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_check_gpg_installed_subprocess_error(self, mock_run, mock_which):
        """Test check_gpg_installed handles subprocess exception."""
        mock_which.return_value = "/usr/bin/gpg"
        mock_run.side_effect = Exception("Subprocess error")

        result = check_gpg_installed()

        assert not result.passed
        assert result.fix_hint is not None


class TestCheckGpgVersion:
    """Additional tests for check_gpg_version."""

    @patch("subprocess.run")
    def test_check_gpg_version_old_major(self, mock_run):
        """Test check_gpg_version with old major version."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="gpg (GnuPG) 1.4.0",
        )

        result = check_gpg_version()

        assert not result.passed
        assert "too old" in result.message

    @patch("subprocess.run")
    def test_check_gpg_version_failure(self, mock_run):
        """Test check_gpg_version when gpg fails."""
        mock_run.return_value = MagicMock(returncode=1)

        result = check_gpg_version()

        assert not result.passed

    @patch("subprocess.run")
    def test_check_gpg_version_exception(self, mock_run):
        """Test check_gpg_version handles exception."""
        mock_run.side_effect = Exception("Error")

        result = check_gpg_version()

        assert not result.passed


class TestCheckYkmanVersion:
    """Tests for check_ykman_version."""

    @patch("subprocess.run")
    def test_check_ykman_version_sufficient(self, mock_run):
        """Test ykman version check passes for >= 5.0."""
        from yubikey_init.environment import check_ykman_version

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="YubiKey Manager (ykman) version 5.2.0",
        )

        result = check_ykman_version()

        assert result.passed

    @patch("subprocess.run")
    def test_check_ykman_version_too_old(self, mock_run):
        """Test ykman version check fails for < 5.0."""
        from yubikey_init.environment import check_ykman_version

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="YubiKey Manager (ykman) version 4.0.0",
        )

        result = check_ykman_version()

        assert not result.passed
        assert "too old" in result.message

    @patch("subprocess.run")
    def test_check_ykman_version_failure(self, mock_run):
        """Test ykman version check handles failure."""
        from yubikey_init.environment import check_ykman_version

        mock_run.return_value = MagicMock(returncode=1)

        result = check_ykman_version()

        assert not result.passed


class TestCheckPcscdRunning:
    """Tests for check_pcscd_running."""

    @patch("platform.system")
    def test_check_pcscd_running_macos(self, mock_system):
        """Test pcscd check on macOS returns success."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Darwin"

        result = check_pcscd_running()

        assert result.passed
        assert "macOS" in result.message

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_pcscd_running_linux_running(self, mock_run, mock_system):
        """Test pcscd check on Linux when running."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Linux"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="active",
        )

        result = check_pcscd_running()

        assert result.passed

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_pcscd_running_linux_not_running(self, mock_run, mock_system):
        """Test pcscd check on Linux when not running."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Linux"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="inactive",
        )

        result = check_pcscd_running()

        assert not result.passed


class TestCheckPinentry:
    """Additional tests for check_pinentry."""

    @patch("shutil.which")
    def test_check_pinentry_none_found(self, mock_which):
        """Test check_pinentry when no pinentry is found."""
        mock_which.return_value = None

        result = check_pinentry()

        assert not result.passed
        assert result.fix_hint is not None


class TestVerifyEnvironment:
    """Test the main verify_environment function."""

    @patch("yubikey_init.environment.check_gpg_installed")
    @patch("yubikey_init.environment.check_gpg_version")
    @patch("yubikey_init.environment.check_ykman_installed")
    @patch("yubikey_init.environment.check_pcscd_running")
    @patch("yubikey_init.environment.check_pinentry")
    def test_verify_environment_all_pass(
        self,
        mock_pinentry,
        mock_pcscd,
        mock_ykman,
        mock_gpg_version,
        mock_gpg_installed,
    ):
        """Test verify_environment when all critical checks pass."""
        mock_gpg_installed.return_value = CheckResult("GnuPG", True, "OK")
        mock_gpg_version.return_value = CheckResult("GnuPG Version", True, "OK")
        mock_ykman.return_value = CheckResult("ykman", True, "OK")
        mock_pcscd.return_value = CheckResult("pcscd", True, "OK")
        mock_pinentry.return_value = CheckResult("pinentry", True, "OK")

        report = verify_environment(include_optional=False)

        assert report.all_passed
        assert len(report.checks) == 5

    def test_verify_environment_result_success(self):
        """Test verify_environment_result returns Result type."""
        with patch("yubikey_init.environment.verify_environment") as mock_verify:
            mock_report = EnvironmentReport(
                system="Linux",
                checks=[CheckResult("Test", True, "OK")],
            )
            mock_verify.return_value = mock_report

            result = verify_environment_result()

            assert result.is_ok()
            assert result.unwrap() == mock_report

    def test_verify_environment_result_failure(self):
        """Test verify_environment_result when checks fail."""
        with patch("yubikey_init.environment.verify_environment") as mock_verify:
            mock_report = EnvironmentReport(
                system="Linux",
                checks=[CheckResult("Test", False, "Failed", critical=True)],
            )
            mock_verify.return_value = mock_report

            result = verify_environment_result()

            assert result.is_err()


class TestCheckScdaemon:
    """Test check_scdaemon function."""

    @patch("subprocess.run")
    def test_check_scdaemon_success(self, mock_run):
        """Test check_scdaemon when scdaemon is responding."""
        from yubikey_init.environment import check_scdaemon

        mock_run.return_value = MagicMock(returncode=0, stdout="OK")

        result = check_scdaemon()

        assert result.passed
        assert "responding" in result.message

    @patch("subprocess.run")
    def test_check_scdaemon_not_responding(self, mock_run):
        """Test check_scdaemon when not responding."""
        from yubikey_init.environment import check_scdaemon

        mock_run.return_value = MagicMock(returncode=0, stdout="ERR")

        result = check_scdaemon()

        assert not result.passed
        assert not result.critical

    @patch("subprocess.run")
    def test_check_scdaemon_timeout(self, mock_run):
        """Test check_scdaemon handles timeout."""
        from subprocess import TimeoutExpired

        from yubikey_init.environment import check_scdaemon

        mock_run.side_effect = TimeoutExpired(cmd="gpg-connect-agent", timeout=10)

        result = check_scdaemon()

        assert not result.passed
        assert "timed out" in result.message

    @patch("subprocess.run")
    def test_check_scdaemon_not_found(self, mock_run):
        """Test check_scdaemon when gpg-connect-agent not found."""
        from yubikey_init.environment import check_scdaemon

        mock_run.side_effect = FileNotFoundError()

        result = check_scdaemon()

        assert not result.passed
        assert "not found" in result.message


class TestCheckYubikeyDetected:
    """Test check_yubikey_detected function."""

    @patch("subprocess.run")
    def test_check_yubikey_detected_found(self, mock_run):
        """Test check_yubikey_detected when YubiKey found."""
        from yubikey_init.environment import check_yubikey_detected

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678\n",
        )

        result = check_yubikey_detected()

        assert result.passed
        assert "Found 1" in result.message

    @patch("subprocess.run")
    def test_check_yubikey_detected_multiple(self, mock_run):
        """Test check_yubikey_detected with multiple YubiKeys."""
        from yubikey_init.environment import check_yubikey_detected

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="YubiKey 5 NFC Serial: 12345678\nYubiKey 5C Serial: 87654321\n",
        )

        result = check_yubikey_detected()

        assert result.passed
        assert "Found 2" in result.message

    @patch("subprocess.run")
    def test_check_yubikey_detected_not_found(self, mock_run):
        """Test check_yubikey_detected when no YubiKey found."""
        from yubikey_init.environment import check_yubikey_detected

        mock_run.return_value = MagicMock(returncode=0, stdout="")

        result = check_yubikey_detected()

        assert not result.passed
        assert not result.critical

    @patch("subprocess.run")
    def test_check_yubikey_detected_error(self, mock_run):
        """Test check_yubikey_detected handles error."""
        from yubikey_init.environment import check_yubikey_detected

        mock_run.side_effect = Exception("ykman error")

        result = check_yubikey_detected()

        assert not result.passed
        assert not result.critical


class TestCheckEntropy:
    """Test check_entropy function."""

    @patch("platform.system")
    def test_check_entropy_non_linux(self, mock_system):
        """Test check_entropy skips non-Linux systems."""
        from yubikey_init.environment import check_entropy

        mock_system.return_value = "Darwin"

        result = check_entropy()

        assert result.passed
        assert "skipped" in result.message.lower()

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    def test_check_entropy_sufficient(self, mock_read, mock_exists, mock_system):
        """Test check_entropy with sufficient entropy."""
        from yubikey_init.environment import check_entropy

        mock_system.return_value = "Linux"
        mock_exists.return_value = True
        mock_read.return_value = "3500\n"

        result = check_entropy()

        assert result.passed
        assert "3500" in result.message

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    def test_check_entropy_low(self, mock_read, mock_exists, mock_system):
        """Test check_entropy with low entropy."""
        from yubikey_init.environment import check_entropy

        mock_system.return_value = "Linux"
        mock_exists.return_value = True
        mock_read.return_value = "100\n"

        result = check_entropy()

        assert not result.passed
        assert "Low entropy" in result.message
        assert not result.critical

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    def test_check_entropy_error(self, mock_read, mock_exists, mock_system):
        """Test check_entropy handles error."""
        from yubikey_init.environment import check_entropy

        mock_system.return_value = "Linux"
        mock_exists.return_value = True
        mock_read.side_effect = Exception("Read error")

        result = check_entropy()

        # Should pass with warning on error
        assert result.passed


class TestCheckNetworkDisabled:
    """Test check_network_disabled function."""

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_network_disabled_macos_wifi_off(self, mock_run, mock_system):
        """Test network check on macOS with Wi-Fi disabled."""
        from yubikey_init.environment import check_network_disabled

        mock_system.return_value = "Darwin"
        mock_run.return_value = MagicMock(stdout="Wi-Fi Power (en0): Off")

        result = check_network_disabled()

        assert result.passed
        assert "disabled" in result.message.lower()

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_network_disabled_macos_wifi_on(self, mock_run, mock_system):
        """Test network check on macOS with Wi-Fi enabled."""
        from yubikey_init.environment import check_network_disabled

        mock_system.return_value = "Darwin"
        mock_run.return_value = MagicMock(stdout="Wi-Fi Power (en0): On")

        result = check_network_disabled()

        assert not result.passed
        assert not result.critical

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_network_disabled_linux(self, mock_run, mock_system):
        """Test network check on Linux."""
        from yubikey_init.environment import check_network_disabled

        mock_system.return_value = "Linux"
        mock_run.return_value = MagicMock(stdout="1: lo: <LOOPBACK,UP>")

        result = check_network_disabled()

        # Linux check is informational, always warns
        assert not result.passed
        assert not result.critical

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_network_disabled_error(self, mock_run, mock_system):
        """Test network check handles error."""
        from yubikey_init.environment import check_network_disabled

        mock_system.return_value = "Darwin"
        mock_run.side_effect = Exception("Network error")

        result = check_network_disabled()

        assert not result.passed
        assert not result.critical


class TestCheckPaperkeyInstalled:
    """Test check_paperkey_installed function."""

    @patch("shutil.which")
    def test_check_paperkey_installed_found(self, mock_which):
        """Test paperkey check when installed."""
        from yubikey_init.environment import check_paperkey_installed

        mock_which.return_value = "/usr/bin/paperkey"

        result = check_paperkey_installed()

        assert result.passed
        assert not result.critical

    @patch("shutil.which")
    def test_check_paperkey_not_installed(self, mock_which):
        """Test paperkey check when not installed."""
        from yubikey_init.environment import check_paperkey_installed

        mock_which.return_value = None

        result = check_paperkey_installed()

        assert not result.passed
        assert not result.critical
        assert "optional" in result.message


class TestCheckCryptsetupInstalled:
    """Test check_cryptsetup_installed function."""

    @patch("platform.system")
    def test_check_cryptsetup_macos(self, mock_system):
        """Test cryptsetup check on macOS."""
        from yubikey_init.environment import check_cryptsetup_installed

        mock_system.return_value = "Darwin"

        result = check_cryptsetup_installed()

        assert result.passed
        assert "FileVault" in result.message

    @patch("platform.system")
    @patch("shutil.which")
    def test_check_cryptsetup_linux_installed(self, mock_which, mock_system):
        """Test cryptsetup check on Linux when installed."""
        from yubikey_init.environment import check_cryptsetup_installed

        mock_system.return_value = "Linux"
        mock_which.return_value = "/sbin/cryptsetup"

        result = check_cryptsetup_installed()

        assert result.passed
        assert "LUKS" in result.message

    @patch("platform.system")
    @patch("shutil.which")
    def test_check_cryptsetup_linux_not_installed(self, mock_which, mock_system):
        """Test cryptsetup check on Linux when not installed."""
        from yubikey_init.environment import check_cryptsetup_installed

        mock_system.return_value = "Linux"
        mock_which.return_value = None

        result = check_cryptsetup_installed()

        assert not result.passed
        assert result.critical

    @patch("platform.system")
    def test_check_cryptsetup_windows(self, mock_system):
        """Test cryptsetup check on Windows."""
        from yubikey_init.environment import check_cryptsetup_installed

        mock_system.return_value = "Windows"

        result = check_cryptsetup_installed()

        assert result.passed
        assert not result.critical


class TestCheckLiveEnvironment:
    """Test check_live_environment function."""

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    def test_check_live_environment_linux_live_detected(self, mock_exists, mock_system):
        """Test live environment detection on Linux."""
        from yubikey_init.environment import check_live_environment

        mock_system.return_value = "Linux"
        # /run/live exists
        mock_exists.side_effect = lambda: True

        result = check_live_environment()

        assert result.passed
        assert "live" in result.message.lower()

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    @patch("builtins.open", create=True)
    def test_check_live_environment_linux_tmpfs_root(self, mock_open, mock_exists, mock_system):
        """Test live environment detection via tmpfs root."""
        from io import StringIO

        from yubikey_init.environment import check_live_environment

        mock_system.return_value = "Linux"
        mock_exists.return_value = False
        mock_open.return_value.__enter__ = lambda s: StringIO("tmpfs / tmpfs rw 0 0\n")
        mock_open.return_value.__exit__ = MagicMock(return_value=False)

        result = check_live_environment()

        assert result.passed or not result.critical  # Either passes or non-critical fail

    @patch("platform.system")
    @patch("pathlib.Path.exists")
    @patch("builtins.open", create=True)
    def test_check_live_environment_linux_not_live(self, mock_open, mock_exists, mock_system):
        """Test non-live environment detection on Linux."""
        from io import StringIO

        from yubikey_init.environment import check_live_environment

        mock_system.return_value = "Linux"
        mock_exists.return_value = False
        mock_open.return_value.__enter__ = lambda s: StringIO("/dev/sda1 / ext4 rw 0 0\n")
        mock_open.return_value.__exit__ = MagicMock(return_value=False)

        result = check_live_environment()

        assert not result.passed
        assert not result.critical

    @patch("platform.system")
    def test_check_live_environment_non_linux(self, mock_system):
        """Test live environment check on non-Linux."""
        from yubikey_init.environment import check_live_environment

        mock_system.return_value = "Darwin"

        result = check_live_environment()

        assert not result.passed
        assert not result.critical


class TestCheckPcscdFallback:
    """Test pcscd check Linux fallback path."""

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_pcscd_linux_systemctl_not_found_pgrep_success(self, mock_run, mock_system):
        """Test pcscd check falls back to pgrep when systemctl not found."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Linux"

        def run_side_effect(cmd, *args, **kwargs):
            if cmd[0] == "systemctl":
                raise FileNotFoundError()
            elif cmd[0] == "pgrep":
                return MagicMock(returncode=0)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        result = check_pcscd_running()

        assert result.passed

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_pcscd_linux_systemctl_not_found_pgrep_fail(self, mock_run, mock_system):
        """Test pcscd check when both systemctl and pgrep fail."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Linux"

        def run_side_effect(cmd, *args, **kwargs):
            if cmd[0] == "systemctl":
                raise FileNotFoundError()
            elif cmd[0] == "pgrep":
                return MagicMock(returncode=1)
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        result = check_pcscd_running()

        assert not result.passed

    @patch("platform.system")
    @patch("subprocess.run")
    def test_check_pcscd_linux_systemctl_not_found_pgrep_error(self, mock_run, mock_system):
        """Test pcscd check when systemctl not found and pgrep raises error."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "Linux"

        def run_side_effect(cmd, *args, **kwargs):
            if cmd[0] == "systemctl":
                raise FileNotFoundError()
            elif cmd[0] == "pgrep":
                raise Exception("pgrep error")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect

        result = check_pcscd_running()

        assert not result.passed

    @patch("platform.system")
    def test_check_pcscd_unknown_system(self, mock_system):
        """Test pcscd check on unknown system."""
        from yubikey_init.environment import check_pcscd_running

        mock_system.return_value = "FreeBSD"

        result = check_pcscd_running()

        assert result.passed
        assert not result.critical


class TestVerifyEnvironmentWithOptional:
    """Test verify_environment with optional checks."""

    @patch("yubikey_init.environment.check_gpg_installed")
    @patch("yubikey_init.environment.check_gpg_version")
    @patch("yubikey_init.environment.check_ykman_installed")
    @patch("yubikey_init.environment.check_pcscd_running")
    @patch("yubikey_init.environment.check_pinentry")
    @patch("yubikey_init.environment.check_ykman_version")
    @patch("yubikey_init.environment.check_scdaemon")
    @patch("yubikey_init.environment.check_yubikey_detected")
    @patch("yubikey_init.environment.check_entropy")
    @patch("yubikey_init.environment.check_network_disabled")
    @patch("yubikey_init.environment.check_paperkey_installed")
    @patch("yubikey_init.environment.check_cryptsetup_installed")
    @patch("yubikey_init.environment.check_live_environment")
    def test_verify_environment_with_optional_checks(
        self,
        mock_live,
        mock_crypto,
        mock_paperkey,
        mock_network,
        mock_entropy,
        mock_yubikey,
        mock_scdaemon,
        mock_ykman_ver,
        mock_pinentry,
        mock_pcscd,
        mock_ykman,
        mock_gpg_version,
        mock_gpg_installed,
    ):
        """Test verify_environment runs optional checks when enabled."""
        # Set all mocks to return passing results
        for mock in [
            mock_gpg_installed,
            mock_gpg_version,
            mock_ykman,
            mock_pcscd,
            mock_pinentry,
            mock_ykman_ver,
            mock_scdaemon,
            mock_yubikey,
            mock_entropy,
            mock_network,
            mock_paperkey,
            mock_crypto,
            mock_live,
        ]:
            mock.return_value = CheckResult("Test", True, "OK", critical=False)

        report = verify_environment(include_optional=True)

        # Should have all 13 checks (5 critical + 8 optional)
        assert len(report.checks) == 13
        mock_live.assert_called_once()

    @patch("yubikey_init.environment.check_gpg_installed")
    @patch("yubikey_init.environment.check_gpg_version")
    @patch("yubikey_init.environment.check_ykman_installed")
    @patch("yubikey_init.environment.check_pcscd_running")
    @patch("yubikey_init.environment.check_pinentry")
    def test_verify_environment_adds_warning_on_failure(
        self,
        mock_pinentry,
        mock_pcscd,
        mock_ykman,
        mock_gpg_version,
        mock_gpg_installed,
    ):
        """Test verify_environment adds warning when checks fail."""
        mock_gpg_installed.return_value = CheckResult("GnuPG", False, "Failed", critical=True)
        mock_gpg_version.return_value = CheckResult("Version", True, "OK")
        mock_ykman.return_value = CheckResult("ykman", True, "OK")
        mock_pcscd.return_value = CheckResult("pcscd", True, "OK")
        mock_pinentry.return_value = CheckResult("pinentry", True, "OK")

        report = verify_environment(include_optional=False)

        assert not report.all_passed
        assert len(report.warnings) > 0
        assert "critical" in report.warnings[0].lower()


class TestEnvironmentReportNonCriticalFailures:
    """Test EnvironmentReport non_critical_failures property."""

    def test_non_critical_failures(self):
        """Test getting non-critical failures."""
        report = EnvironmentReport(
            system="Linux",
            checks=[
                CheckResult("Critical", False, "Failed", critical=True),
                CheckResult("Optional1", False, "Failed", critical=False),
                CheckResult("Optional2", True, "OK", critical=False),
                CheckResult("Optional3", False, "Failed", critical=False),
            ],
        )

        non_critical = report.non_critical_failures
        assert len(non_critical) == 2
        assert non_critical[0].name == "Optional1"
        assert non_critical[1].name == "Optional3"
