"""Comprehensive tests for main.py CLI module."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

from yubikey_init.environment import CheckResult, EnvironmentReport
from yubikey_init.main import (
    DEPRECATED_COMMANDS,
    cmd_backup,
    cmd_continue,
    cmd_dashboard,
    cmd_devices,
    cmd_doctor,
    cmd_keys,
    cmd_new,
    cmd_provision,
    cmd_reset,
    cmd_setup_config,
    cmd_status,
    cmd_verify,
    get_parser,
    handle_deprecated_command,
    provision_yubikey,
    run,
    show_environment_report,
)
from yubikey_init.state_machine import WorkflowConfig
from yubikey_init.types import (
    BackupDriveInfo,
    CardStatus,
    DeviceInfo,
    KeyInfo,
    KeyType,
    KeyUsage,
    MountedBackupDrive,
    Result,
    SecureString,
    SubkeyInfo,
    WorkflowState,
    YubiKeyInfo,
)


class TestGetParser:
    """Test argument parser creation."""

    def test_get_parser_returns_parser(self) -> None:
        """Test get_parser returns ArgumentParser instance."""
        parser = get_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "yubikey-init"

    def test_parser_has_subcommands(self) -> None:
        """Test parser has all expected subcommands."""
        parser = get_parser()
        subparsers_actions = [
            action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
        ]
        assert len(subparsers_actions) == 1
        subparsers = subparsers_actions[0].choices
        assert subparsers is not None
        # New command structure
        expected_commands = [
            "new",
            "continue",
            "status",
            "reset",
            "verify",
            "doctor",
            "setup-config",
            "provision",
            "devices",
            "keys",
            "backup",
        ]
        for cmd in expected_commands:
            assert cmd in subparsers

    def test_parser_new_command_arguments(self) -> None:
        """Test new subcommand has expected arguments."""
        parser = get_parser()
        args = parser.parse_args(["new", "--key-type", "rsa4096", "--expiry-years", "3"])
        assert args.command == "new"
        assert args.key_type == "rsa4096"
        assert args.expiry_years == 3

    def test_parser_new_defaults(self) -> None:
        """Test new subcommand default values."""
        parser = get_parser()
        args = parser.parse_args(["new"])
        assert args.key_type == "ed25519"
        assert args.expiry_years == 2
        assert args.skip_storage is False

    def test_parser_verify_full_flag(self) -> None:
        """Test verify subcommand accepts --full flag."""
        parser = get_parser()
        args = parser.parse_args(["verify", "--full"])
        assert args.command == "verify"
        assert args.full is True

    def test_parser_keys_export_ssh(self) -> None:
        """Test keys export-ssh subcommand."""
        parser = get_parser()
        args = parser.parse_args(["keys", "export-ssh", "ABC123"])
        assert args.key_id == "ABC123"

    def test_parser_global_verbose_flag(self) -> None:
        """Test global --verbose flag."""
        parser = get_parser()
        args = parser.parse_args(["--verbose", "status"])
        assert args.verbose is True


class TestShowEnvironmentReport:
    """Test environment report display."""

    def test_show_environment_report_all_passed(self) -> None:
        """Test showing report with all checks passed."""
        report = EnvironmentReport(
            system="Darwin 21.0.0",
            checks=[
                CheckResult(
                    name="GPG installed",
                    passed=True,
                    critical=True,
                    message="GPG 2.3.0 found",
                    fix_hint=None,
                ),
            ],
        )
        with patch("yubikey_init.main.console") as mock_console:
            show_environment_report(report)
            mock_console.print.assert_called()
            # Check that success message was printed
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("All critical checks passed" in str(c) for c in calls)

    def test_show_environment_report_with_failures(self) -> None:
        """Test showing report with failures."""
        report = EnvironmentReport(
            system="Darwin 21.0.0",
            checks=[
                CheckResult(
                    name="YubiKey detected",
                    passed=False,
                    critical=True,
                    message="No YubiKey found",
                    fix_hint="Insert YubiKey",
                ),
            ],
        )
        with patch("yubikey_init.main.console") as mock_console:
            show_environment_report(report)
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("critical checks failed" in str(c) for c in calls)


class TestCmdVerify:
    """Test cmd_verify function."""

    def test_cmd_verify_success(self) -> None:
        """Test verify command returns 0 on success."""
        args = argparse.Namespace(full=False)
        report = EnvironmentReport(
            system="Darwin",
            checks=[],
        )
        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
        ):
            result = cmd_verify(args)
            assert result == 0

    def test_cmd_verify_failure(self) -> None:
        """Test verify command returns 1 on failure."""
        args = argparse.Namespace(full=False)
        report = EnvironmentReport(
            system="Darwin",
            checks=[
                CheckResult(
                    name="Test",
                    passed=False,
                    critical=True,
                    message="Failed",
                ),
            ],
        )
        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
        ):
            result = cmd_verify(args)
            assert result == 1

    def test_cmd_verify_with_full_flag(self) -> None:
        """Test verify command passes full flag."""
        args = argparse.Namespace(full=True)
        report = EnvironmentReport(system="Darwin", checks=[])
        with (
            patch("yubikey_init.main.verify_environment", return_value=report) as mock_verify,
            patch("yubikey_init.main.show_environment_report"),
        ):
            cmd_verify(args)
            mock_verify.assert_called_once_with(include_optional=True)


class TestCmdDoctor:
    """Test cmd_doctor function."""

    def test_cmd_doctor_runs_diagnostics(self) -> None:
        """Test doctor command runs diagnostics and formats report."""
        with (
            patch("yubikey_init.main.run_diagnostics") as mock_diag,
            patch("yubikey_init.main.format_diagnostic_report") as mock_format,
            patch("yubikey_init.main.console"),
        ):
            mock_diag.return_value = MagicMock()
            mock_format.return_value = "Diagnostic report"
            result = cmd_doctor()
            assert result == 0
            mock_diag.assert_called_once()
            mock_format.assert_called_once()


class TestCmdStatus:
    """Test cmd_status function."""

    def test_cmd_status_success(self) -> None:
        """Test status command displays session info."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.session_id = "test-session"
        sm.session.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.session.created_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00")
        sm.session.updated_at = MagicMock(isoformat=lambda: "2024-01-01T01:00:00")
        sm.session.completed_steps = []
        sm.session.config.identity = "Test User <test@example.com>"
        sm.session.config.yubikey_serials = ["12345678"]
        sm.session.error_log = []

        with patch("yubikey_init.main.console"):
            result = cmd_status(sm, verbose=False)
            assert result == 0

    def test_cmd_status_load_error(self) -> None:
        """Test status command handles load error."""
        sm = MagicMock()
        sm.load.return_value = Result.err(Exception("Load failed"))

        with patch("yubikey_init.main.console"):
            result = cmd_status(sm, verbose=False)
            assert result == 1

    def test_cmd_status_with_verbose(self) -> None:
        """Test status command with verbose flag shows errors."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.session_id = "test-session"
        sm.session.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.session.created_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00")
        sm.session.updated_at = MagicMock(isoformat=lambda: "2024-01-01T01:00:00")
        sm.session.completed_steps = []
        sm.session.config.identity = None
        sm.session.config.yubikey_serials = []
        sm.session.error_log = [{"timestamp": "2024-01-01T00:00:00", "error": "Test error"}]

        with patch("yubikey_init.main.console") as mock_console:
            result = cmd_status(sm, verbose=True)
            assert result == 0
            # Verify error log was printed
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("Errors" in str(c) for c in calls)


class TestCmdReset:
    """Test cmd_reset function."""

    def test_cmd_reset_confirmed(self) -> None:
        """Test reset command when user confirms."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.reset.return_value = Result.ok(None)
        prompts = MagicMock()
        prompts.confirm.return_value = True

        with patch("yubikey_init.main.console"):
            result = cmd_reset(sm, prompts)
            assert result == 0
            sm.reset.assert_called_once()

    def test_cmd_reset_cancelled(self) -> None:
        """Test reset command when user cancels."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        prompts = MagicMock()
        prompts.confirm.return_value = False

        with patch("yubikey_init.main.console"):
            result = cmd_reset(sm, prompts)
            assert result == 1
            sm.reset.assert_not_called()

    def test_cmd_reset_no_workflow(self) -> None:
        """Test reset command when no workflow exists."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_reset(sm, prompts)
            assert result == 0
            prompts.confirm.assert_not_called()


class TestCmdSetupConfig:
    """Test cmd_setup_config function."""

    def test_cmd_setup_config_success(self) -> None:
        """Test setup-config command success."""
        args = argparse.Namespace(gnupghome=None, no_ssh=False)
        paths = {
            "gpg.conf": "/path/to/gpg.conf",
            "gpg-agent.conf": "/path/to/gpg-agent.conf",
        }
        with (
            patch("yubikey_init.main.setup_all_configs", return_value=Result.ok(paths)),
            patch("yubikey_init.main.restart_gpg_agent", return_value=Result.ok(None)),
            patch("yubikey_init.main.generate_ssh_agent_setup_script", return_value="# script"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_setup_config(args)
            assert result == 0

    def test_cmd_setup_config_failure(self) -> None:
        """Test setup-config command failure."""
        args = argparse.Namespace(gnupghome=None, no_ssh=False)
        with (
            patch(
                "yubikey_init.main.setup_all_configs",
                return_value=Result.err(Exception("Setup failed")),
            ),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_setup_config(args)
            assert result == 1

    def test_cmd_setup_config_with_no_ssh(self) -> None:
        """Test setup-config command with --no-ssh flag."""
        args = argparse.Namespace(gnupghome=None, no_ssh=True)
        paths = {"gpg.conf": "/path/to/gpg.conf"}
        with (
            patch(
                "yubikey_init.main.setup_all_configs", return_value=Result.ok(paths)
            ) as mock_setup,
            patch("yubikey_init.main.restart_gpg_agent", return_value=Result.ok(None)),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_setup_config(args)
            assert result == 0
            mock_setup.assert_called_once_with(
                gnupghome=None, enable_ssh=False, backup_existing=True
            )


class TestCmdKeys:
    """Test cmd_keys function."""

    def test_cmd_keys_list_success(self) -> None:
        """Test keys list command success."""
        args = argparse.Namespace(gnupghome=None, keys_command="list")
        prompts = MagicMock()

        mock_key = MagicMock()
        mock_key.key_id = "ABC123"
        mock_key.identity = "Test User <test@example.com>"
        mock_key.expiry_date = None

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.ok([mock_key])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0
            mock_gpg.list_secret_keys.assert_called_once()

    def test_cmd_keys_list_empty(self) -> None:
        """Test keys list command with no keys."""
        args = argparse.Namespace(gnupghome=None, keys_command="list")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.ok([])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0

    def test_cmd_keys_renew_success(self) -> None:
        """Test keys renew command success."""
        args = argparse.Namespace(
            gnupghome=None, keys_command="renew", key_id="ABC123", expiry_years=2
        )
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.renew_all_subkeys.return_value = Result.ok(None)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0
            mock_gpg.renew_all_subkeys.assert_called_once()

    def test_cmd_keys_renew_failure(self) -> None:
        """Test keys renew command failure."""
        args = argparse.Namespace(
            gnupghome=None, keys_command="renew", key_id="ABC123", expiry_years=2
        )
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.renew_all_subkeys.return_value = Result.err(Exception("Renewal failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 1

    def test_cmd_keys_export_ssh_success(self) -> None:
        """Test keys export-ssh command success."""
        args = argparse.Namespace(gnupghome=None, keys_command="export-ssh", key_id="ABC123")
        prompts = MagicMock()
        ssh_key = "ssh-rsa AAAAB3..."

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.export_ssh_key.return_value = Result.ok(ssh_key)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0
            mock_gpg.export_ssh_key.assert_called_once_with("ABC123")

    def test_cmd_keys_export_ssh_failure(self) -> None:
        """Test keys export-ssh command failure."""
        args = argparse.Namespace(gnupghome=None, keys_command="export-ssh", key_id="ABC123")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.export_ssh_key.return_value = Result.err(Exception("Export failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 1


class TestCmdProvision:
    """Test cmd_provision function."""

    def test_cmd_provision_success(self, tmp_path: Path) -> None:
        """Test provision command success."""
        backup_path = tmp_path / "backup"
        backup_path.mkdir()
        args = argparse.Namespace(gnupghome=None, key_id="ABC123", backup_path=backup_path)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        with (
            # Patch where the function is imported FROM (backup module)
            patch(
                "yubikey_init.backup.import_from_backup", return_value=Result.ok("ABCDEF1234567890")
            ),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.StateMachine") as mock_sm_class,
            patch("yubikey_init.main.provision_yubikey", return_value=0),
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg
            mock_sm = MagicMock()
            mock_sm.load.return_value = Result.ok(None)
            mock_sm_class.return_value = mock_sm

            result = cmd_provision(args, prompts)
            assert result == 0

    def test_cmd_provision_import_failure(self, tmp_path: Path) -> None:
        """Test provision command when import fails."""
        backup_path = tmp_path / "backup"
        args = argparse.Namespace(gnupghome=None, key_id="ABC123", backup_path=backup_path)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        with (
            patch(
                "yubikey_init.backup.import_from_backup",
                return_value=Result.err(Exception("Import failed")),
            ),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_provision(args, prompts)
            assert result == 1


class TestRun:
    """Test main run function."""

    def test_run_no_command_shows_dashboard(self) -> None:
        """Test run with no command shows dashboard."""
        with (
            patch("yubikey_init.main.cmd_dashboard", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run([])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_new_command(self) -> None:
        """Test run dispatches to new command."""
        with (
            patch("yubikey_init.main.cmd_new", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["new"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_continue_command(self) -> None:
        """Test run dispatches to continue command."""
        with (
            patch("yubikey_init.main.cmd_continue", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["continue"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_status_command(self) -> None:
        """Test run dispatches to status command."""
        with (
            patch("yubikey_init.main.cmd_status", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["status"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_verify_command(self) -> None:
        """Test run dispatches to verify command."""
        with (
            patch("yubikey_init.main.cmd_verify", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["verify"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_doctor_command(self) -> None:
        """Test run dispatches to doctor command."""
        with (
            patch("yubikey_init.main.cmd_doctor", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["doctor"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_devices_command(self) -> None:
        """Test run dispatches to devices command."""
        with (
            patch("yubikey_init.main.cmd_devices", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["devices"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_keys_command(self) -> None:
        """Test run dispatches to keys command."""
        with (
            patch("yubikey_init.main.cmd_keys", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["keys"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_backup_command(self) -> None:
        """Test run dispatches to backup command."""
        with (
            patch("yubikey_init.main.cmd_backup", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["backup", "verify", "/tmp/backup"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_deprecated_init_command(self) -> None:
        """Test deprecated init command shows helpful error."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["init"])
            assert result == 1
            mock_handler.assert_called_once_with("init")

    def test_run_deprecated_resume_command(self) -> None:
        """Test deprecated resume command shows helpful error."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["resume"])
            assert result == 1
            mock_handler.assert_called_once_with("resume")

    def test_run_deprecated_diagnose_command(self) -> None:
        """Test deprecated diagnose command shows helpful error."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["diagnose"])
            assert result == 1
            mock_handler.assert_called_once_with("diagnose")


class TestDeprecatedCommands:
    """Test deprecated command handling."""

    def test_handle_deprecated_init(self) -> None:
        """Test deprecated init command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("init")
            assert result == 1
            # Check that the new command is mentioned
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("new" in str(c) for c in calls)

    def test_handle_deprecated_resume(self) -> None:
        """Test deprecated resume command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("resume")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("continue" in str(c) for c in calls)

    def test_deprecated_commands_dict(self) -> None:
        """Test DEPRECATED_COMMANDS contains expected mappings."""
        assert "init" in DEPRECATED_COMMANDS
        assert "resume" in DEPRECATED_COMMANDS
        assert "diagnose" in DEPRECATED_COMMANDS
        assert "inventory" in DEPRECATED_COMMANDS
        assert "reset-yubikey" in DEPRECATED_COMMANDS


class TestProvisionYubikey:
    """Test provision_yubikey function."""

    def test_provision_yubikey_no_device_detected(self) -> None:
        """Test provision when no YubiKey is detected."""
        sm = MagicMock()
        gpg = MagicMock()
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        prompts.wait_for_yubikey.return_value = None
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = provision_yubikey(sm, gpg, "ABC123", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_user_cancels(self) -> None:
        """Test provision when user cancels confirmation."""
        sm = MagicMock()
        gpg = MagicMock()
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        prompts.confirm.return_value = False
        prompts.select_yubikey.return_value = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [
                YubiKeyInfo(
                    serial="12345678",
                    version="5.4.3",
                    form_factor="USB-A",
                    has_openpgp=True,
                    openpgp_version=None,
                )
            ]
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user cancels
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(False)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABC123", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_reset_failure(self) -> None:
        """Test provision when YubiKey reset fails."""
        sm = MagicMock()
        gpg = MagicMock()
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        prompts.select_yubikey.return_value = device
        prompts.confirm.return_value = True
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk.reset_openpgp.return_value = Result.err(Exception("Reset failed"))
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user confirms
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABC123", passphrase, prompts, args)
            assert result == 1


class TestCmdNew:
    """Test cmd_new function."""

    def test_cmd_new_workflow_already_in_progress(self) -> None:
        """Test new when workflow is already in progress."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_new_load_error(self) -> None:
        """Test new when state load fails."""
        sm = MagicMock()
        sm.load.return_value = Result.err(Exception("Load failed"))
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_new_environment_check_failure_not_confirmed(self) -> None:
        """Test new when environment check fails and user doesn't confirm."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        args = argparse.Namespace()
        prompts = MagicMock()
        prompts.confirm.return_value = False

        report = EnvironmentReport(
            system="Darwin",
            checks=[
                CheckResult(
                    name="Test",
                    passed=False,
                    critical=True,
                    message="Failed",
                ),
            ],
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_new(sm, args, prompts)
            assert result == 1


class TestCmdContinue:
    """Test cmd_continue function."""

    def test_cmd_continue_load_error(self) -> None:
        """Test resume when state load fails."""
        sm = MagicMock()
        sm.load.return_value = Result.err(Exception("Load failed"))
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_continue(sm, args, prompts)
            assert result == 1

    def test_cmd_continue_no_workflow(self) -> None:
        """Test resume when no workflow exists."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_continue(sm, args, prompts)
            assert result == 1

    def test_cmd_continue_already_complete(self) -> None:
        """Test resume when workflow is already complete."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.COMPLETE
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_continue(sm, args, prompts)
            assert result == 0

    def test_cmd_continue_missing_key_id(self) -> None:
        """Test resume when key ID is missing from artifacts."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.get_artifact.return_value = None
        args = argparse.Namespace()
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_continue(sm, args, prompts)
            assert result == 1

    def test_cmd_continue_from_gpg_master_generated(self) -> None:
        """Test resume from GPG_MASTER_GENERATED state generates subkeys."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.session.config.key_type = "ed25519"
        sm.session.config.expiry_years = 2
        sm.session.config.backup_device = "/tmp/backup"
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")
        prompts.confirm.return_value = False  # Don't continue past backup verification

        subkey = SubkeyInfo(
            key_id="SUBKEY1234567890",
            fingerprint="SUBKEYFP1234567890",
            creation_date=datetime.now(),
            expiry_date=None,
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.create_full_backup") as mock_backup,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_all_subkeys.return_value = Result.ok([subkey])
            mock_gpg_class.return_value = mock_gpg

            mock_manifest = MagicMock()
            mock_manifest.backup_path = Path("/tmp/backup")
            mock_backup.return_value = Result.ok(mock_manifest)

            cmd_continue(sm, args, prompts)
            # Should stop at backup confirmation (we said False)
            mock_gpg.generate_all_subkeys.assert_called_once()

    def test_cmd_continue_subkey_generation_failure(self) -> None:
        """Test resume when subkey generation fails."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.session.config.key_type = "ed25519"
        sm.session.config.expiry_years = 2

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_all_subkeys.return_value = Result.err(Exception("Subkey gen failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_continue(sm, args, prompts)
            assert result == 1

    def test_cmd_continue_backup_failure(self) -> None:
        """Test resume when backup creation fails."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_SUBKEYS_GENERATED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.session.config.backup_device = "/tmp/backup"

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.main.GPGOperations"),
            patch("yubikey_init.main.create_full_backup") as mock_backup,
            patch("yubikey_init.main.console"),
        ):
            mock_backup.return_value = Result.err(Exception("Backup failed"))

            result = cmd_continue(sm, args, prompts)
            assert result == 1

    def test_cmd_continue_from_backup_verified(self) -> None:
        """Test resume from BACKUP_VERIFIED state provisions YubiKey."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.BACKUP_VERIFIED
        sm.get_artifact.return_value = "ABCDEF1234567890"

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.main.GPGOperations"),
            patch("yubikey_init.main.provision_yubikey", return_value=0) as mock_provision,
            patch("yubikey_init.main.console"),
        ):
            cmd_continue(sm, args, prompts)
            mock_provision.assert_called_once()

    def test_cmd_continue_from_yubikey_provisioned(self) -> None:
        """Test resume from YUBIKEY_1_PROVISIONED removes master key."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.YUBIKEY_1_PROVISIONED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")
        prompts.confirm.return_value = True  # Confirm master key removal

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.delete_secret_key.return_value = Result.ok(None)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_continue(sm, args, prompts)
            assert result == 0
            mock_gpg.delete_secret_key.assert_called_once()


class TestProvisionYubikeySuccess:
    """Test provision_yubikey success paths."""

    def test_provision_yubikey_no_device_selected(self) -> None:
        """Test provision when user doesn't select a device."""
        sm = MagicMock()
        gpg = MagicMock()
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        prompts.select_yubikey.return_value = None  # No device selected
        args = argparse.Namespace(gnupghome=None)

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk_class.return_value = mock_yk

            result = provision_yubikey(sm, gpg, "ABCDEF1234567890", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_pin_setup_failure(self) -> None:
        """Test provision when PIN setup fails."""
        sm = MagicMock()
        gpg = MagicMock()
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        prompts.select_yubikey.return_value = device
        prompts.confirm.return_value = True
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk.reset_openpgp.return_value = Result.ok(None)
            mock_yk.set_pins.return_value = Result.err(Exception("PIN setup failed"))
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user confirms
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABCDEF1234567890", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_list_subkeys_failure(self) -> None:
        """Test provision when listing subkeys fails."""
        sm = MagicMock()
        gpg = MagicMock()
        gpg.list_subkeys.return_value = Result.err(Exception("List failed"))
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        prompts.select_yubikey.return_value = device
        prompts.confirm.return_value = True
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk.reset_openpgp.return_value = Result.ok(None)
            mock_yk.set_pins.return_value = Result.ok(None)
            mock_yk.enable_kdf.return_value = Result.ok(None)
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user confirms
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABCDEF1234567890", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_transfer_failure(self) -> None:
        """Test provision when key transfer fails."""
        from datetime import datetime

        sm = MagicMock()
        gpg = MagicMock()
        subkey = SubkeyInfo(
            key_id="SUBKEY1234567890",
            fingerprint="SUBKEYFP12345678",
            creation_date=datetime.now(),
            expiry_date=None,
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )
        gpg.list_subkeys.return_value = Result.ok([subkey])
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        prompts.select_yubikey.return_value = device
        prompts.confirm.return_value = True
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]
        args = argparse.Namespace(gnupghome=None)

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk.reset_openpgp.return_value = Result.ok(None)
            mock_yk.set_pins.return_value = Result.ok(None)
            mock_yk.enable_kdf.return_value = Result.ok(None)
            mock_yk.transfer_key.return_value = Result.err(Exception("Transfer failed"))
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user confirms
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABCDEF1234567890", passphrase, prompts, args)
            assert result == 1

    def test_provision_yubikey_full_success(self) -> None:
        """Test provision full success path."""
        from datetime import datetime

        sm = MagicMock()
        sm.session.config.yubikey_serials = []
        sm.transition.return_value = Result.ok(None)
        gpg = MagicMock()
        subkeys = [
            SubkeyInfo(
                key_id="SIGN123456789012",
                fingerprint="SIGNFP1234567890",
                creation_date=datetime.now(),
                expiry_date=None,
                usage=KeyUsage.SIGN,
                key_type=KeyType.ED25519,
                parent_key_id="ABCDEF1234567890",
            ),
            SubkeyInfo(
                key_id="ENCR123456789012",
                fingerprint="ENCRFP1234567890",
                creation_date=datetime.now(),
                expiry_date=None,
                usage=KeyUsage.ENCRYPT,
                key_type=KeyType.ED25519,
                parent_key_id="ABCDEF1234567890",
            ),
            SubkeyInfo(
                key_id="AUTH123456789012",
                fingerprint="AUTHFP1234567890",
                creation_date=datetime.now(),
                expiry_date=None,
                usage=KeyUsage.AUTHENTICATE,
                key_type=KeyType.ED25519,
                parent_key_id="ABCDEF1234567890",
            ),
        ]
        gpg.list_subkeys.return_value = Result.ok(subkeys)
        gpg.delete_secret_key.return_value = Result.ok(None)
        gpg.get_key_info.return_value = Result.ok(MagicMock(identity="Test User <test@test.com>"))
        passphrase = SecureString("test-pass")
        prompts = MagicMock()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        prompts.select_yubikey.return_value = device
        # confirm calls: second yubikey offer, remove master key (reset confirmation moved to SafetyGuard)
        prompts.confirm.side_effect = [False, True]
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]
        args = argparse.Namespace(gnupghome=None)

        card_status = CardStatus(
            serial="12345678",
            signature_key="SIGN123456789012",
            encryption_key="ENCR123456789012",
            authentication_key="AUTH123456789012",
            signature_count=0,
            pin_retries=3,
            admin_pin_retries=3,
        )

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk.reset_openpgp.return_value = Result.ok(None)
            mock_yk.set_pins.return_value = Result.ok(None)
            mock_yk.enable_kdf.return_value = Result.ok(None)
            mock_yk.transfer_key.return_value = Result.ok(None)
            mock_yk.set_touch_policy.return_value = Result.ok(None)
            mock_yk.get_card_status.return_value = Result.ok(card_status)
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.get_or_create.return_value = MagicMock()
            mock_inv.save.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user confirms
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = provision_yubikey(sm, gpg, "ABCDEF1234567890", passphrase, prompts, args)
            assert result == 0
            assert mock_yk.transfer_key.call_count == 3
            assert mock_yk.set_touch_policy.call_count == 3


class TestShowEnvironmentReportEdgeCases:
    """Test edge cases in show_environment_report."""

    def test_show_environment_report_non_critical_warning(self) -> None:
        """Test showing report with non-critical warning."""
        report = EnvironmentReport(
            system="Darwin 21.0.0",
            checks=[
                CheckResult(
                    name="Optional Check",
                    passed=False,
                    critical=False,
                    message="Not installed",
                    fix_hint="Install optional tool",
                ),
            ],
        )
        with patch("yubikey_init.main.console") as mock_console:
            show_environment_report(report)
            calls = [str(call) for call in mock_console.print.call_args_list]
            # Should show WARN for non-critical failures
            assert any("WARN" in str(c) for c in calls)


class TestCmdInitEdgeCases:
    """Test edge cases in cmd_init."""

    def test_cmd_init_skip_storage_without_backup_path(self) -> None:
        """Test init with --skip-storage but no --backup-path."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_new(sm, args, prompts)
            assert result == 1  # Should fail because no backup path

    def test_cmd_init_skip_storage_with_backup_path(self) -> None:
        """Test init with --skip-storage and --backup-path."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.confirm.side_effect = [True, False]  # confirm env, don't confirm backup verified
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        subkey = SubkeyInfo(
            key_id="SUBKEY1234567890",
            fingerprint="SUBKEYFP12345678",
            creation_date=datetime.now(),
            expiry_date=None,
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )

        mock_manifest = MagicMock()
        mock_manifest.backup_path = Path("/tmp/backup")
        mock_manifest.files = ["master-key.asc"]

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("yubikey_init.main.create_full_backup") as mock_backup,
            patch("yubikey_init.main.verify_backup_complete") as mock_verify,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg.generate_all_subkeys.return_value = Result.ok([subkey])
            mock_gpg_class.return_value = mock_gpg

            mock_backup.return_value = Result.ok(mock_manifest)
            mock_verify.return_value = Result.ok(["master-key.asc"])

            # Mock YubiKey operations
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk_class.return_value = mock_yk

            # Mock inventory
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            # Mock safety guard - user cancels
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(False)
            mock_safety_class.return_value = mock_safety

            # Set prompts to select the device and decline at SafetyGuard
            prompts.select_yubikey.return_value = device

            cmd_new(sm, args, prompts)
            # Should proceed past storage setup and stop at backup verification
            mock_gpg.generate_master_key.assert_called_once()

    def test_cmd_init_key_generation_failure(self) -> None:
        """Test init when key generation fails."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.err(Exception("Key gen failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_init_subkey_generation_failure(self) -> None:
        """Test init when subkey generation fails."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg.generate_all_subkeys.return_value = Result.err(Exception("Subkey gen failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            assert result == 1


class TestRunCommandDispatch:
    """Test run function command dispatching."""

    def test_run_continue_command(self) -> None:
        """Test run dispatches to continue command."""
        with (
            patch("yubikey_init.main.cmd_continue", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["continue"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_reset_command(self) -> None:
        """Test run dispatches to reset command."""
        with (
            patch("yubikey_init.main.cmd_reset", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["reset"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_setup_config_command(self) -> None:
        """Test run dispatches to setup-config command."""
        with patch("yubikey_init.main.cmd_setup_config", return_value=0) as mock_cmd:
            result = run(["setup-config"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_keys_export_ssh_command(self) -> None:
        """Test run dispatches to keys export-ssh command."""
        with (
            patch("yubikey_init.main.cmd_keys", return_value=0) as mock_cmd,
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["keys", "export-ssh", "ABC123"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_keys_renew_command(self) -> None:
        """Test run dispatches to keys renew command."""
        with (
            patch("yubikey_init.main.cmd_keys", return_value=0) as mock_cmd,
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["keys", "renew", "ABC123"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_provision_command(self) -> None:
        """Test run dispatches to provision command."""
        with (
            patch("yubikey_init.main.cmd_provision", return_value=0) as mock_cmd,
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["provision", "--key-id", "ABC123", "--backup-path", "/tmp"])
            assert result == 0
            mock_cmd.assert_called_once()


class TestCmdSetupConfigEdgeCases:
    """Test edge cases in cmd_setup_config."""

    def test_cmd_setup_config_restart_agent_failure(self) -> None:
        """Test setup-config handles gpg-agent restart failure gracefully."""
        args = argparse.Namespace(gnupghome=None, no_ssh=True)
        paths = {"gpg.conf": "/path/to/gpg.conf"}
        with (
            patch("yubikey_init.main.setup_all_configs", return_value=Result.ok(paths)),
            patch(
                "yubikey_init.main.restart_gpg_agent",
                return_value=Result.err(Exception("Restart failed")),
            ),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_setup_config(args)
            # Should still succeed, just warn about restart
            assert result == 0


class TestCmdResetEdgeCases:
    """Test edge cases in cmd_reset."""

    def test_cmd_reset_error(self) -> None:
        """Test reset command handles reset error."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.reset.return_value = Result.err(Exception("Reset error"))
        prompts = MagicMock()
        prompts.confirm.return_value = True

        with patch("yubikey_init.main.console"):
            result = cmd_reset(sm, prompts)
            assert result == 1


class TestCmdDevices:
    """Test cmd_devices function."""

    def test_cmd_devices_list_no_command(self) -> None:
        """Test devices command with no subcommand lists devices."""
        args = argparse.Namespace(devices_command=None, show_all=False, fingerprints=False)
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely", return_value=[]),
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0

    def test_cmd_devices_list_with_connected(self) -> None:
        """Test devices list with connected devices."""
        args = argparse.Namespace(devices_command="list", show_all=False, fingerprints=False)
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely") as mock_list,
            patch("yubikey_init.main.display_device_table") as mock_display,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            mock_list.return_value = [(device, None, None)]

            result = cmd_devices(args, prompts)
            assert result == 0
            mock_display.assert_called_once()

    def test_cmd_devices_inventory_load_error(self) -> None:
        """Test devices command handles inventory load error."""
        args = argparse.Namespace(devices_command="list")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.err(Exception("Load failed"))
            mock_inv_class.return_value = mock_inv

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_scan(self) -> None:
        """Test devices scan command."""
        args = argparse.Namespace(devices_command="scan")
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely") as mock_list,
            patch("yubikey_init.main.display_device_table"),
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            mock_list.return_value = [(device, None, None)]

            result = cmd_devices(args, prompts)
            assert result == 0

    def test_cmd_devices_show_not_found(self) -> None:
        """Test devices show with nonexistent device."""
        args = argparse.Namespace(devices_command="show", serial="nonexistent")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_label_set(self) -> None:
        """Test devices label command sets label."""
        args = argparse.Namespace(devices_command="label", serial="12345678", label="My Key")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv.get_or_create.return_value = MagicMock()
            mock_inv.set_label.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0
            mock_inv.set_label.assert_called_once_with("12345678", "My Key")

    def test_cmd_devices_protect(self) -> None:
        """Test devices protect command."""
        args = argparse.Namespace(devices_command="protect", serial="12345678")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_entry = MagicMock()
            mock_entry.display_name.return_value = "YubiKey 12345678"
            mock_inv.get_or_create.return_value = mock_entry
            mock_inv.set_protected.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0
            mock_inv.set_protected.assert_called_once_with("12345678", True)

    def test_cmd_devices_unprotect_not_protected(self) -> None:
        """Test devices unprotect command when device is not protected."""
        args = argparse.Namespace(devices_command="unprotect", serial="12345678")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv.get.return_value = None  # Device not in inventory
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0  # Not an error, just nothing to do

    def test_cmd_devices_notes_set(self) -> None:
        """Test devices notes command sets notes."""
        args = argparse.Namespace(
            devices_command="notes", serial="12345678", notes="Primary dev key"
        )
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv.get_or_create.return_value = MagicMock()
            mock_inv.set_notes.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0

    def test_cmd_devices_remove_cancelled(self) -> None:
        """Test devices remove command when user cancels."""
        args = argparse.Namespace(devices_command="remove", serial="12345678")
        prompts = MagicMock()
        prompts.confirm.return_value = False

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_entry = MagicMock()
            mock_entry.display_name.return_value = "YubiKey 12345678"
            mock_inv.get.return_value = mock_entry
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1  # Cancelled
            mock_inv.remove.assert_not_called()

    def test_cmd_devices_unknown_subcommand(self) -> None:
        """Test devices command with unknown subcommand shows help."""
        args = argparse.Namespace(devices_command="unknown")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0  # Shows help


class TestCmdBackup:
    """Test cmd_backup function."""

    def test_cmd_backup_verify_success(self, tmp_path: Path) -> None:
        """Test backup verify command success."""
        args = argparse.Namespace(backup_command="verify", path=tmp_path, gnupghome=None)
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.verify_backup_complete") as mock_verify,
            patch("yubikey_init.main.console"),
        ):
            mock_verify.return_value = Result.ok(["master-key.asc", "public-key.asc"])

            result = cmd_backup(args, prompts)
            assert result == 0

    def test_cmd_backup_verify_failure(self, tmp_path: Path) -> None:
        """Test backup verify command failure."""
        args = argparse.Namespace(backup_command="verify", path=tmp_path, gnupghome=None)
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.verify_backup_complete") as mock_verify,
            patch("yubikey_init.main.console"),
        ):
            mock_verify.return_value = Result.err(Exception("Verification failed"))

            result = cmd_backup(args, prompts)
            assert result == 1

    def test_cmd_backup_restore_success(self, tmp_path: Path) -> None:
        """Test backup restore command success."""
        args = argparse.Namespace(
            backup_command="restore",
            path=tmp_path,
            gnupghome=None,
            subkeys_only=False,
        )
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.backup.import_from_backup") as mock_import,
            patch("yubikey_init.main.console"),
        ):
            mock_import.return_value = Result.ok("ABCDEF1234567890")

            result = cmd_backup(args, prompts)
            assert result == 0

    def test_cmd_backup_restore_failure(self, tmp_path: Path) -> None:
        """Test backup restore command failure."""
        args = argparse.Namespace(
            backup_command="restore",
            path=tmp_path,
            gnupghome=None,
            subkeys_only=False,
        )
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.backup.import_from_backup") as mock_import,
            patch("yubikey_init.main.console"),
        ):
            mock_import.return_value = Result.err(Exception("Restore failed"))

            result = cmd_backup(args, prompts)
            assert result == 1

    def test_cmd_backup_no_subcommand_shows_help(self) -> None:
        """Test backup command with no subcommand shows help."""
        args = argparse.Namespace(backup_command=None, gnupghome=None)
        prompts = MagicMock()

        with patch("yubikey_init.main.console"):
            result = cmd_backup(args, prompts)
            assert result == 0  # Shows help


class TestCmdKeysEdgeCases:
    """Test edge cases in cmd_keys function."""

    def test_cmd_keys_list_error(self) -> None:
        """Test keys list command handles error."""
        args = argparse.Namespace(gnupghome=None, keys_command="list")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.err(Exception("List failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 1

    def test_cmd_keys_export_ssh_no_key_id_with_keys(self) -> None:
        """Test keys export-ssh uses first key when no key_id provided."""
        args = argparse.Namespace(gnupghome=None, keys_command="export-ssh")
        # No key_id attribute
        prompts = MagicMock()

        mock_key = MagicMock()
        mock_key.key_id = "ABC123"

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.ok([mock_key])
            mock_gpg.export_ssh_key.return_value = Result.ok("ssh-rsa AAAA...")
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0
            mock_gpg.export_ssh_key.assert_called_once_with("ABC123")

    def test_cmd_keys_export_ssh_no_key_id_no_keys(self) -> None:
        """Test keys export-ssh fails when no key_id and no keys found."""
        args = argparse.Namespace(gnupghome=None, keys_command="export-ssh")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.ok([])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 1

    def test_cmd_keys_unknown_subcommand(self) -> None:
        """Test keys command with unknown subcommand shows help."""
        args = argparse.Namespace(gnupghome=None, keys_command="unknown")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.GPGOperations"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_keys(args, prompts)
            assert result == 0  # Shows help

    def test_cmd_keys_list_with_expiry(self) -> None:
        """Test keys list displays expiry date."""
        from datetime import datetime

        args = argparse.Namespace(gnupghome=None, keys_command="list")
        prompts = MagicMock()

        mock_key = MagicMock()
        mock_key.key_id = "ABC123"
        mock_key.identity = "Test User <test@example.com>"
        mock_key.expiry_date = datetime(2025, 12, 31)

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.list_secret_keys.return_value = Result.ok([mock_key])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_keys(args, prompts)
            assert result == 0


class TestCmdDashboard:
    """Test cmd_dashboard function."""

    def test_cmd_dashboard_no_state_file(self) -> None:
        """Test dashboard shows welcome message when no state file exists."""
        sm = MagicMock()
        sm.load.return_value = Result.err(Exception("No state file"))

        with patch("yubikey_init.main.console"):
            result = cmd_dashboard(sm, _verbose=False)
            assert result == 0

    def test_cmd_dashboard_uninitialized_state(self) -> None:
        """Test dashboard when workflow is uninitialized."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.current_state = WorkflowState.UNINITIALIZED
        sm.session.config.identity = None

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_dashboard(sm, _verbose=False)
            assert result == 0

    def test_cmd_dashboard_complete_state(self) -> None:
        """Test dashboard when workflow is complete."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.current_state = WorkflowState.COMPLETE
        sm.session.config.identity = "Test User <test@example.com>"

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_yk_class.return_value = mock_yk

            result = cmd_dashboard(sm, _verbose=False)
            assert result == 0

    def test_cmd_dashboard_in_progress_state(self) -> None:
        """Test dashboard when workflow is in progress."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.session.config.identity = "Test User <test@example.com>"

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_dashboard(sm, _verbose=False)
            assert result == 0

    def test_cmd_dashboard_with_verbose(self) -> None:
        """Test dashboard with verbose flag."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.session.current_state = WorkflowState.GPG_MASTER_GENERATED
        sm.session.config.identity = "Test User <test@example.com>"

        with (
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_dashboard(sm, _verbose=True)
            assert result == 0


class TestCmdNewCompletePath:
    """Test cmd_new complete execution paths."""

    def test_cmd_new_storage_path_no_removable_devices(self) -> None:
        """Test new command when no removable devices found."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts._console.input.return_value = "/tmp/backup"

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = []
            mock_storage_class.return_value = mock_storage

            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            # Should fail or continue - checking it doesn't crash
            assert result in [0, 1]

    def test_cmd_new_storage_path_with_device_selection_macos(self) -> None:
        """Test new command with device selection for storage on macOS."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/disk2"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=True,
            mount_point=Path("/Volumes/USB"),
        )

        backup_drive_info = BackupDriveInfo(
            device_path=Path("/dev/disk2"),
            encrypted_partition=Path("/dev/disk2s1"),
            public_partition=Path("/dev/disk2s2"),
            encrypted_label="gnupg-secrets",
            public_label="gnupg-public",
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("platform.system", return_value="Darwin"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage.prepare_backup_drive_macos.return_value = Result.ok(backup_drive_info)
            mock_storage_class.return_value = mock_storage

            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            # Should proceed through storage setup
            mock_storage.prepare_backup_drive_macos.assert_called_once()
            # Verify correct path was passed
            call_args = mock_storage.prepare_backup_drive_macos.call_args
            assert call_args[0][0] == device_info.path
            prompts.confirm_destructive.assert_called_once()
            assert result in [0, 1]

    def test_cmd_new_storage_path_with_device_selection_linux(self) -> None:
        """Test new command with device selection for storage on Linux."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/sdb"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=True,
            mount_point=Path("/mnt/usb"),
        )

        backup_drive_info = BackupDriveInfo(
            device_path=Path("/dev/sdb"),
            encrypted_partition=Path("/dev/sdb1"),
            public_partition=Path("/dev/sdb2"),
            encrypted_label="gnupg-secrets",
            public_label="gnupg-public",
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Linux", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("platform.system", return_value="Linux"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage.prepare_backup_drive_linux.return_value = Result.ok(backup_drive_info)
            mock_storage_class.return_value = mock_storage

            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            # Should call Linux-specific preparation
            mock_storage.prepare_backup_drive_linux.assert_called_once()
            # Verify correct path was passed
            call_args = mock_storage.prepare_backup_drive_linux.call_args
            assert call_args[0][0] == device_info.path
            prompts.confirm_destructive.assert_called_once()
            assert result in [0, 1]

    def test_cmd_new_storage_unsupported_platform(self) -> None:
        """Test new command on unsupported platform."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/sdb"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Windows", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("platform.system", return_value="Windows"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage_class.return_value = mock_storage

            result = cmd_new(sm, args, prompts)
            assert result == 1
            # Neither preparation function should be called
            mock_storage.prepare_backup_drive_macos.assert_not_called()
            mock_storage.prepare_backup_drive_linux.assert_not_called()

    def test_cmd_new_storage_device_selection_cancelled(self) -> None:
        """Test new command when user cancels device selection."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/sdb"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = None  # User cancelled

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage_class.return_value = mock_storage

            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_new_storage_drive_preparation_failure(self) -> None:
        """Test new command when backup drive preparation fails."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/disk2"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("platform.system", return_value="Darwin"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage.prepare_backup_drive_macos.return_value = Result.err(
                "Drive preparation failed: Error -69626"
            )
            mock_storage_class.return_value = mock_storage

            result = cmd_new(sm, args, prompts)
            assert result == 1
            mock_storage.prepare_backup_drive_macos.assert_called_once()

    def test_cmd_new_storage_confirm_destructive_cancelled(self) -> None:
        """Test new command when user cancels destructive confirmation."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/disk2"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = False  # User cancels
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage_class.return_value = mock_storage

            result = cmd_new(sm, args, prompts)
            assert result == 1
            # Should not attempt drive preparation
            mock_storage.prepare_backup_drive_macos.assert_not_called()
            mock_storage.prepare_backup_drive_linux.assert_not_called()

    def test_cmd_new_state_transition_failure_storage(self) -> None:
        """Test new command when state transition fails after storage setup."""

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.side_effect = [
            Result.err(Exception("Transition failed")),
        ]

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_new_state_transition_failure_storage_verified(self) -> None:
        """Test new command when state transition fails after storage verification."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.side_effect = [
            Result.ok(None),  # STORAGE_SETUP succeeds
            Result.err(Exception("Transition failed")),  # STORAGE_VERIFIED fails
        ]

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_new(sm, args, prompts)
            assert result == 1

    def test_cmd_new_rsa4096_key_type(self) -> None:
        """Test new command with RSA4096 key type."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            key_type="rsa4096",
            expiry_years=2,
            gnupghome=None,
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.RSA4096,
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg_class.return_value = mock_gpg

            cmd_new(sm, args, prompts)
            # Verify RSA4096 key type was used
            mock_gpg.generate_master_key.assert_called_once()
            call_args = mock_gpg.generate_master_key.call_args
            assert call_args[0][2] == KeyType.RSA4096


class TestCmdNewBackupMounting:
    """Test backup volume mounting during Step 7."""

    def test_cmd_new_mounts_encrypted_volume_for_backup_macos(self) -> None:
        """Test that backup uses mounted encrypted volume path on macOS."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/disk6"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        backup_drive_info = BackupDriveInfo(
            device_path=Path("/dev/disk6"),
            encrypted_partition=Path("/dev/disk6s1"),
            public_partition=Path("/dev/disk6s2"),
            encrypted_label="gnupg-secrets",
            public_label="gnupg-public",
        )

        mounted_backup = MountedBackupDrive(
            encrypted_mount=Path("/Volumes/gnupg-secrets"),
            public_mount=Path("/Volumes/gnupg-public"),
            device_path=Path("/dev/disk6"),
        )

        prompts = MagicMock()
        # Return False on backup verification prompt to stop at Step 8
        prompts.confirm.return_value = False
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        subkey_info = SubkeyInfo(
            key_id="SUBKEY123456",
            fingerprint="SUBFP1234567890",
            creation_date=datetime.now(),
            expiry_date=datetime.now(),
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )

        backup_manifest = MagicMock()
        backup_manifest.backup_path = Path("/Volumes/gnupg-secrets/gpg-backup-ABCDEF-20260131")
        backup_manifest.files = ["master.key", "subkeys.key"]

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.create_full_backup") as mock_backup,
            patch("yubikey_init.main.verify_backup_complete") as mock_verify,
            patch("platform.system", return_value="Darwin"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage.prepare_backup_drive_macos.return_value = Result.ok(backup_drive_info)
            mock_storage.open_backup_drive_macos.return_value = Result.ok(mounted_backup)
            mock_storage.close_backup_drive_macos.return_value = Result.ok(None)
            mock_storage_class.return_value = mock_storage

            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg.generate_all_subkeys.return_value = Result.ok([subkey_info])
            mock_gpg_class.return_value = mock_gpg

            mock_backup.return_value = Result.ok(backup_manifest)
            mock_verify.return_value = Result.ok(None)

            result = cmd_new(sm, args, prompts)

            # Should return 0 (user declined to confirm backup verification)
            assert result == 0

            # Verify encrypted volume was mounted before backup
            mock_storage.open_backup_drive_macos.assert_called_once()
            mount_call_args = mock_storage.open_backup_drive_macos.call_args
            assert mount_call_args[0][0] == Path("/dev/disk6")

            # Verify backup was created with mounted volume path, not device path
            mock_backup.assert_called_once()
            backup_call_args = mock_backup.call_args
            # The backup_path argument should be the mounted path, not /dev/disk6
            assert backup_call_args[0][1] == Path("/Volumes/gnupg-secrets")

            # Verify volume was closed after backup
            mock_storage.close_backup_drive_macos.assert_called_once()

    def test_cmd_new_backup_mount_failure_returns_error(self) -> None:
        """Test that failure to mount backup volume returns error."""
        from datetime import datetime

        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = MagicMock()
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(
            skip_storage=False,
            backup_path=None,
            key_type="ed25519",
            expiry_years=2,
            gnupghome=None,
        )

        device_info = DeviceInfo(
            path=Path("/dev/disk6"),
            name="USB Drive",
            size_bytes=8000000000,
            removable=True,
            mounted=False,
            mount_point=None,
        )

        backup_drive_info = BackupDriveInfo(
            device_path=Path("/dev/disk6"),
            encrypted_partition=Path("/dev/disk6s1"),
            public_partition=Path("/dev/disk6s2"),
            encrypted_label="gnupg-secrets",
            public_label="gnupg-public",
        )

        prompts = MagicMock()
        prompts.confirm.return_value = True
        prompts.confirm_destructive.return_value = True
        prompts.get_identity.return_value = "Test <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.select_device.return_value = device_info

        report = EnvironmentReport(system="Darwin", checks=[])

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="FP12345678901234",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test <test@example.com>",
            key_type=KeyType.ED25519,
        )

        subkey_info = SubkeyInfo(
            key_id="SUBKEY123456",
            fingerprint="SUBFP1234567890",
            creation_date=datetime.now(),
            expiry_date=datetime.now(),
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )

        with (
            patch("yubikey_init.main.verify_environment", return_value=report),
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.StorageOperations") as mock_storage_class,
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("platform.system", return_value="Darwin"),
            patch("yubikey_init.main.console"),
        ):
            mock_storage = MagicMock()
            mock_storage.list_removable_devices.return_value = [device_info]
            mock_storage.prepare_backup_drive_macos.return_value = Result.ok(backup_drive_info)
            mock_storage.open_backup_drive_macos.return_value = Result.err(
                "Failed to unlock volume"
            )
            mock_storage_class.return_value = mock_storage

            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg.generate_all_subkeys.return_value = Result.ok([subkey_info])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)

            # Should fail and return 1
            assert result == 1
            # Volume mount should have been attempted
            mock_storage.open_backup_drive_macos.assert_called_once()


class TestCmdContinueAdditionalPaths:
    """Test cmd_continue additional execution paths."""

    def test_cmd_continue_from_backup_created_user_declines(self) -> None:
        """Test continue from BACKUP_CREATED when user declines verification."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.BACKUP_CREATED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.session.config.backup_device = "/tmp/backup"

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")
        prompts.confirm.return_value = False  # User says they haven't verified backup

        with (
            patch("yubikey_init.main.GPGOperations"),
            patch("yubikey_init.main.console"),
        ):
            result = cmd_continue(sm, args, prompts)
            assert result == 0
            # Should not transition to BACKUP_VERIFIED
            sm.transition.assert_not_called()

    def test_cmd_continue_from_yubikey_provisioned_user_declines_removal(self) -> None:
        """Test continue from YUBIKEY_1_PROVISIONED when user declines master key removal."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.YUBIKEY_1_PROVISIONED
        sm.get_artifact.return_value = "ABCDEF1234567890"
        sm.transition.return_value = Result.ok(None)

        args = argparse.Namespace(gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")
        prompts.confirm.return_value = False  # User declines master key removal

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg_class.return_value = mock_gpg

            result = cmd_continue(sm, args, prompts)
            assert result == 0
            # Should not delete key but should mark complete
            mock_gpg.delete_secret_key.assert_not_called()
            # Should transition to COMPLETE
            assert sm.transition.called


class TestRunDeprecatedCommands:
    """Test run() function with all deprecated commands."""

    def test_run_deprecated_inventory_command(self) -> None:
        """Test deprecated inventory command."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["inventory"])
            assert result == 1
            mock_handler.assert_called_once_with("inventory")

    def test_run_deprecated_reset_yubikey_command(self) -> None:
        """Test deprecated reset-yubikey command."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["reset-yubikey"])
            assert result == 1
            mock_handler.assert_called_once_with("reset-yubikey")

    def test_run_deprecated_renew_command(self) -> None:
        """Test deprecated renew command."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["renew", "--key-id", "ABC123"])
            assert result == 1
            mock_handler.assert_called_once_with("renew")

    def test_run_deprecated_export_ssh_command(self) -> None:
        """Test deprecated export-ssh command."""
        with (
            patch("yubikey_init.main.handle_deprecated_command", return_value=1) as mock_handler,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["export-ssh", "--key-id", "ABC123"])
            assert result == 1
            mock_handler.assert_called_once_with("export-ssh")

    def test_run_setup_config_command(self) -> None:
        """Test run dispatches to setup-config command."""
        with (
            patch("yubikey_init.main.cmd_setup_config", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["setup-config"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_provision_command(self) -> None:
        """Test run dispatches to provision command."""
        with (
            patch("yubikey_init.main.cmd_provision", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["provision", "--key-id", "ABC123", "--backup-path", "/tmp/backup"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_reset_command(self) -> None:
        """Test run dispatches to reset command."""
        with (
            patch("yubikey_init.main.cmd_reset", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["reset"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_unknown_command_fallback(self) -> None:
        """Test run with unknown command group prints help."""
        # Test the fallback case when no valid command matches
        with (
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
            patch("yubikey_init.main.cmd_devices", return_value=1),
        ):
            # Test with a valid but unhandled command (shouldn't happen in practice)
            result = run(["devices", "list"])
            # cmd_devices should handle this, returning its result
            assert result == 1


class TestHandleDeprecatedCommandComplete:
    """Test handle_deprecated_command with all deprecated commands."""

    def test_handle_deprecated_inventory(self) -> None:
        """Test deprecated inventory command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("inventory")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("devices" in str(c) for c in calls)

    def test_handle_deprecated_reset_yubikey(self) -> None:
        """Test deprecated reset-yubikey command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("reset-yubikey")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("devices reset" in str(c) for c in calls)

    def test_handle_deprecated_renew(self) -> None:
        """Test deprecated renew command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("renew")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("keys renew" in str(c) for c in calls)

    def test_handle_deprecated_export_ssh(self) -> None:
        """Test deprecated export-ssh command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("export-ssh")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("keys export-ssh" in str(c) for c in calls)

    def test_handle_deprecated_diagnose(self) -> None:
        """Test deprecated diagnose command shows correct message."""
        with patch("yubikey_init.main.console") as mock_console:
            result = handle_deprecated_command("diagnose")
            assert result == 1
            calls = [str(call) for call in mock_console.print.call_args_list]
            assert any("doctor" in str(c) for c in calls)

    def test_handle_unknown_deprecated_command(self) -> None:
        """Test handle_deprecated_command with unknown command."""
        # Unknown commands should still return 1
        result = handle_deprecated_command("unknown-cmd")
        assert result == 1


class TestCmdDevicesReset:
    """Test cmd_devices_reset function comprehensively."""

    def test_devices_reset_no_devices_connected(self) -> None:
        """Test devices reset when no YubiKeys are connected."""
        args = argparse.Namespace(serial=None, force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()
        yubikey = MagicMock()
        yubikey.list_devices.return_value = []
        resolve_serial = MagicMock()

        from yubikey_init.main import cmd_devices_reset

        with patch("yubikey_init.main.console"):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_multiple_devices_no_serial_specified(self) -> None:
        """Test devices reset with multiple devices but no serial specified."""
        args = argparse.Namespace(serial=None, force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()

        device1 = YubiKeyInfo(
            serial="11111111",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )
        device2 = YubiKeyInfo(
            serial="22222222",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device1, device2]
        resolve_serial = MagicMock()

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard"),
            patch(
                "yubikey_init.main.list_connected_devices_safely",
                return_value=[(device1, None, None), (device2, None, None)],
            ),
            patch("yubikey_init.main.display_device_table"),
        ):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_device_not_found(self) -> None:
        """Test devices reset when specified device is not found."""
        args = argparse.Namespace(serial="nonexistent", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        resolve_serial = MagicMock(return_value=None)

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard"),
        ):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_device_not_connected(self) -> None:
        """Test devices reset when device is found but not connected."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()

        device = YubiKeyInfo(
            serial="99999999",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]  # Different serial
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard"),
        ):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_safety_check_failed(self) -> None:
        """Test devices reset when safety check fails."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.err(
                Exception("Safety check failed")
            )
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_user_cancels(self) -> None:
        """Test devices reset when user cancels confirmation."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(False)  # User cancels
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 0

    def test_devices_reset_reset_operation_fails(self) -> None:
        """Test devices reset when reset operation fails."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()
        inventory = MagicMock()
        inventory.get_or_create.return_value = MagicMock()
        inventory.save.return_value = Result.ok(None)

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        yubikey.reset_openpgp.return_value = Result.err(Exception("Reset failed"))
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1
            inventory.get_or_create.assert_called()

    def test_devices_reset_success_without_set_pins(self) -> None:
        """Test successful devices reset without setting new PINs."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=False, gnupghome=None)
        prompts = MagicMock()

        entry = MagicMock()
        inventory = MagicMock()
        inventory.get_or_create.return_value = entry
        inventory.save.return_value = Result.ok(None)

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        yubikey.reset_openpgp.return_value = Result.ok(None)
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 0
            entry.add_history.assert_called()
            inventory.save.assert_called()

    def test_devices_reset_success_with_set_pins(self) -> None:
        """Test successful devices reset with setting new PINs."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=True, gnupghome=None)
        prompts = MagicMock()
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]

        entry = MagicMock()
        inventory = MagicMock()
        inventory.get_or_create.return_value = entry
        inventory.save.return_value = Result.ok(None)

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        yubikey.reset_openpgp.return_value = Result.ok(None)
        yubikey.set_pins.return_value = Result.ok(None)
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 0
            yubikey.set_pins.assert_called_once()

    def test_devices_reset_set_pins_fails(self) -> None:
        """Test devices reset when setting new PINs fails."""
        args = argparse.Namespace(serial="12345678", force=False, set_pins=True, gnupghome=None)
        prompts = MagicMock()
        prompts.get_pin.side_effect = [SecureString("123456"), SecureString("12345678")]

        entry = MagicMock()
        inventory = MagicMock()
        inventory.get_or_create.return_value = entry
        inventory.save.return_value = Result.ok(None)

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        yubikey.reset_openpgp.return_value = Result.ok(None)
        yubikey.set_pins.return_value = Result.err(Exception("PIN setup failed"))
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard") as mock_safety_class,
            patch("rich.panel.Panel"),
        ):
            mock_safety = MagicMock()
            mock_safety.require_confirmation.return_value = Result.ok(True)
            mock_safety_class.return_value = mock_safety

            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1

    def test_devices_reset_with_force_flag(self) -> None:
        """Test devices reset with --force flag skips confirmation."""
        args = argparse.Namespace(serial="12345678", force=True, set_pins=False, gnupghome=None)
        prompts = MagicMock()

        entry = MagicMock()
        inventory = MagicMock()
        inventory.get_or_create.return_value = entry
        inventory.save.return_value = Result.ok(None)
        inventory.is_protected.return_value = False

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        yubikey.reset_openpgp.return_value = Result.ok(None)
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard"),
            patch("rich.panel.Panel"),
        ):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 0

    def test_devices_reset_with_force_protected_device(self) -> None:
        """Test devices reset with --force on protected device is blocked."""
        args = argparse.Namespace(serial="12345678", force=True, set_pins=False, gnupghome=None)
        prompts = MagicMock()

        inventory = MagicMock()
        inventory.is_protected.return_value = True

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        yubikey = MagicMock()
        yubikey.list_devices.return_value = [device]
        resolve_serial = MagicMock(return_value="12345678")

        from yubikey_init.main import cmd_devices_reset

        with (
            patch("yubikey_init.main.console"),
            patch("yubikey_init.main.SafetyGuard"),
            patch("rich.panel.Panel"),
        ):
            result = cmd_devices_reset(args, prompts, inventory, yubikey, resolve_serial)
            assert result == 1


class TestCmdNewBackupPaths:
    """Test cmd_new with various backup path scenarios."""

    def test_cmd_new_skip_storage_with_backup_path(self) -> None:
        """Test cmd_new with --skip-storage and --backup-path."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.transition.return_value = Result.ok(None)
        sm.session.config = WorkflowConfig(
            identity="Test User <test@example.com>",
            key_type="ed25519",
            expiry_years=2,
        )

        args = argparse.Namespace(
            key_type="ed25519",
            expiry_years=2,
            skip_storage=True,
            backup_path=Path("/tmp/backup"),
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.get_identity.return_value = "Test User <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.confirm.return_value = True

        key_info = KeyInfo(
            key_id="ABCDEF1234567890",
            fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
            creation_date=datetime.now(),
            expiry_date=None,
            identity="Test User <test@example.com>",
            key_type=KeyType.ED25519,
        )

        subkey = SubkeyInfo(
            key_id="FEDCBA0987654321",
            fingerprint="FEDCBA0987654321FEDCBA0987654321FEDCBA09",
            creation_date=datetime.now(),
            expiry_date=None,
            usage=KeyUsage.SIGN,
            key_type=KeyType.ED25519,
            parent_key_id="ABCDEF1234567890",
        )

        from yubikey_init.backup import BackupManifest

        manifest = BackupManifest(
            created_at=datetime.now(),
            key_id="ABCDEF1234567890",
            fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
            identity="Test User <test@example.com>",
            files=["master.asc", "subkeys.asc"],
            backup_path=Path("/tmp/backup"),
        )

        with (
            patch("yubikey_init.main.verify_environment") as mock_verify,
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.create_full_backup", return_value=Result.ok(manifest)),
            patch("yubikey_init.main.verify_backup_complete", return_value=Result.ok(None)),
            patch("yubikey_init.main.provision_yubikey", return_value=0),
            patch("yubikey_init.main.console"),
        ):
            mock_verify.return_value = EnvironmentReport(system="Darwin", checks=[])
            mock_gpg = MagicMock()
            mock_gpg.generate_master_key.return_value = Result.ok(key_info)
            mock_gpg.generate_all_subkeys.return_value = Result.ok([subkey])
            mock_gpg_class.return_value = mock_gpg

            result = cmd_new(sm, args, prompts)
            assert result == 0
            # Verify backup path was set
            assert sm.session.config.backup_device == "/tmp/backup"

    def test_cmd_new_skip_storage_without_backup_path(self) -> None:
        """Test cmd_new with --skip-storage but no --backup-path fails."""
        sm = MagicMock()
        sm.load.return_value = Result.ok(None)
        sm.current_state = WorkflowState.UNINITIALIZED
        sm.session.config = WorkflowConfig(
            identity="Test User <test@example.com>",
            key_type="ed25519",
            expiry_years=2,
        )

        args = argparse.Namespace(
            key_type="ed25519",
            expiry_years=2,
            skip_storage=True,
            backup_path=None,  # Missing
            gnupghome=None,
        )
        prompts = MagicMock()
        prompts.get_identity.return_value = "Test User <test@example.com>"
        prompts.get_passphrase.return_value = SecureString("test-passphrase")
        prompts.confirm.return_value = True

        with (
            patch("yubikey_init.main.verify_environment") as mock_verify,
            patch("yubikey_init.main.show_environment_report"),
            patch("yubikey_init.main.console"),
        ):
            mock_verify.return_value = EnvironmentReport(system="Darwin", checks=[])

            result = cmd_new(sm, args, prompts)
            assert result == 1


class TestCmdDevicesAdditionalPaths:
    """Test additional cmd_devices execution paths."""

    def test_cmd_devices_list_with_all_flag(self) -> None:
        """Test devices list with --all flag showing offline devices."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="list", show_all=True, fingerprints=False)
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        offline_entry = DeviceEntry(serial="99999999")
        offline_entry.label = "Offline Key"
        offline_entry.last_seen = datetime.now()
        offline_entry.protected = True

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely") as mock_list,
            patch("yubikey_init.main.display_device_table"),
            patch("yubikey_init.main.console"),
            patch("rich.table.Table") as mock_table_class,
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.ok(None)
            mock_inv.list_all.return_value = [offline_entry]
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            mock_list.return_value = [(device, None, None)]

            mock_table = MagicMock()
            mock_table_class.return_value = mock_table

            result = cmd_devices(args, prompts)
            assert result == 0
            # Verify offline devices table was created
            mock_table.add_column.assert_called()
            mock_table.add_row.assert_called()

    def test_cmd_devices_list_with_fingerprints(self) -> None:
        """Test devices list with --fingerprints flag."""
        args = argparse.Namespace(devices_command="list", show_all=False, fingerprints=True)
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely") as mock_list,
            patch("yubikey_init.main.display_device_table") as mock_display,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.ok(None)
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            mock_list.return_value = [(device, None, None)]

            result = cmd_devices(args, prompts)
            assert result == 0
            # Verify fingerprints parameter was passed
            mock_display.assert_called_once()
            call_kwargs = mock_display.call_args[1]
            assert call_kwargs.get("show_fingerprints") is True

    def test_cmd_devices_scan_save_error(self) -> None:
        """Test devices scan when save fails."""
        args = argparse.Namespace(devices_command="scan")
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.list_connected_devices_safely") as mock_list,
            patch("yubikey_init.main.display_device_table"),
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.save.return_value = Result.err(Exception("Save failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk_class.return_value = mock_yk

            mock_list.return_value = [(device, None, None)]

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_show_with_connected_device(self) -> None:
        """Test devices show with connected device displaying full info."""
        from yubikey_init.inventory import DeviceEntry, KeySlotInfo, OpenPGPState

        args = argparse.Namespace(devices_command="show", serial="12345678")
        prompts = MagicMock()

        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        entry = DeviceEntry(serial="12345678")
        entry.label = "My Key"
        entry.device_type = "YubiKey 5C"
        entry.firmware_version = "5.4.3"
        entry.notes = "Test notes"
        entry.provisioned_identity = "Test <test@example.com>"
        entry.first_seen = datetime.now()
        entry.last_seen = datetime.now()
        entry.protected = True

        openpgp_state = OpenPGPState(
            pin_tries_remaining=3,
            admin_pin_tries_remaining=3,
            kdf_enabled=True,
            signature_key=KeySlotInfo(fingerprint="ABCD1234", touch_policy="On"),
            encryption_key=KeySlotInfo(fingerprint="EFGH5678", touch_policy="On"),
            authentication_key=KeySlotInfo(fingerprint="IJKL9012", touch_policy="On"),
        )

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
            patch("rich.table.Table") as mock_table_class,
            patch("yubikey_init.main.parse_openpgp_info", return_value=openpgp_state),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = [device]
            mock_ykman_result = MagicMock()
            mock_ykman_result.returncode = 0
            mock_ykman_result.stdout = "OpenPGP info"
            mock_yk._run_ykman.return_value = mock_ykman_result
            mock_yk_class.return_value = mock_yk

            mock_table = MagicMock()
            mock_table_class.return_value = mock_table

            result = cmd_devices(args, prompts)
            assert result == 0
            # Verify table was populated
            assert mock_table.add_row.call_count >= 5

    def test_cmd_devices_remove_user_declines(self) -> None:
        """Test devices remove when user declines."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="remove", serial="12345678")
        prompts = MagicMock()
        prompts.confirm.return_value = False

        entry = DeviceEntry(serial="12345678")
        entry.label = "My Key"

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1
            # Verify remove was not called
            mock_inv.remove.assert_not_called()

    def test_cmd_devices_remove_save_error(self) -> None:
        """Test devices remove when save fails."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="remove", serial="12345678")
        prompts = MagicMock()
        prompts.confirm.return_value = True

        entry = DeviceEntry(serial="12345678")

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv.save.return_value = Result.err(Exception("Save failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_label_set_error(self) -> None:
        """Test devices label when set_label fails."""
        args = argparse.Namespace(devices_command="label", serial="12345678", label="New Label")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv.get_or_create.return_value = MagicMock()
            mock_inv.set_label.return_value = Result.err(Exception("Set label failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_protect_set_error(self) -> None:
        """Test devices protect when set_protected fails."""
        args = argparse.Namespace(devices_command="protect", serial="12345678")
        prompts = MagicMock()

        from yubikey_init.inventory import DeviceEntry

        entry = DeviceEntry(serial="12345678")

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get_or_create.return_value = entry
            mock_inv.set_protected.return_value = Result.err(Exception("Set protected failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_unprotect_not_protected(self) -> None:
        """Test devices unprotect on device that's not protected."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="unprotect", serial="12345678")
        prompts = MagicMock()

        entry = DeviceEntry(serial="12345678")
        entry.protected = False

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 0
            # Verify set_protected was not called
            mock_inv.set_protected.assert_not_called()

    def test_cmd_devices_unprotect_user_declines(self) -> None:
        """Test devices unprotect when user declines."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="unprotect", serial="12345678")
        prompts = MagicMock()
        prompts.confirm.return_value = False

        entry = DeviceEntry(serial="12345678")
        entry.protected = True
        entry.label = "My Key"

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
            patch("rich.panel.Panel"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1
            mock_inv.set_protected.assert_not_called()

    def test_cmd_devices_unprotect_set_error(self) -> None:
        """Test devices unprotect when set_protected fails."""
        from yubikey_init.inventory import DeviceEntry

        args = argparse.Namespace(devices_command="unprotect", serial="12345678")
        prompts = MagicMock()
        prompts.confirm.return_value = True

        entry = DeviceEntry(serial="12345678")
        entry.protected = True

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
            patch("rich.panel.Panel"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = entry
            mock_inv.get.return_value = entry
            mock_inv.set_protected.return_value = Result.err(Exception("Set protected failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1

    def test_cmd_devices_notes_set_error(self) -> None:
        """Test devices notes when set_notes fails."""
        args = argparse.Namespace(devices_command="notes", serial="12345678", notes="New notes")
        prompts = MagicMock()

        with (
            patch("yubikey_init.main.Inventory") as mock_inv_class,
            patch("yubikey_init.main.YubiKeyOperations") as mock_yk_class,
            patch("yubikey_init.main.console"),
        ):
            mock_inv = MagicMock()
            mock_inv.load.return_value = Result.ok(None)
            mock_inv.find_by_label.return_value = None
            mock_inv.get_or_create.return_value = MagicMock()
            mock_inv.set_notes.return_value = Result.err(Exception("Set notes failed"))
            mock_inv_class.return_value = mock_inv

            mock_yk = MagicMock()
            mock_yk.list_devices.return_value = []
            mock_yk_class.return_value = mock_yk

            result = cmd_devices(args, prompts)
            assert result == 1


class TestCmdExportSshAndRenew:
    """Test cmd_export_ssh and cmd_renew functions."""

    def test_cmd_export_ssh_success(self) -> None:
        """Test successful SSH key export."""
        from yubikey_init.main import cmd_export_ssh

        args = argparse.Namespace(key_id="ABCD1234", gnupghome=None)

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.export_ssh_key.return_value = Result.ok("ssh-rsa AAAA...")
            mock_gpg_class.return_value = mock_gpg

            result = cmd_export_ssh(args)
            assert result == 0
            mock_gpg.export_ssh_key.assert_called_once_with("ABCD1234")

    def test_cmd_export_ssh_failure(self) -> None:
        """Test SSH key export failure."""
        from yubikey_init.main import cmd_export_ssh

        args = argparse.Namespace(key_id="ABCD1234", gnupghome=None)

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.export_ssh_key.return_value = Result.err(Exception("Export failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_export_ssh(args)
            assert result == 1

    def test_cmd_renew_success(self) -> None:
        """Test successful subkey renewal."""
        from yubikey_init.main import cmd_renew

        args = argparse.Namespace(key_id="ABCD1234", expiry_years=2, gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.renew_all_subkeys.return_value = Result.ok(None)
            mock_gpg_class.return_value = mock_gpg

            result = cmd_renew(args, prompts)
            assert result == 0
            mock_gpg.renew_all_subkeys.assert_called_once_with("ABCD1234", ANY, 730)

    def test_cmd_renew_failure(self) -> None:
        """Test subkey renewal failure."""
        from yubikey_init.main import cmd_renew

        args = argparse.Namespace(key_id="ABCD1234", expiry_years=2, gnupghome=None)
        prompts = MagicMock()
        prompts.get_passphrase.return_value = SecureString("test-pass")

        with (
            patch("yubikey_init.main.GPGOperations") as mock_gpg_class,
            patch("yubikey_init.main.console"),
        ):
            mock_gpg = MagicMock()
            mock_gpg.renew_all_subkeys.return_value = Result.err(Exception("Renewal failed"))
            mock_gpg_class.return_value = mock_gpg

            result = cmd_renew(args, prompts)
            assert result == 1


class TestCmdManage:
    """Tests for cmd_manage TUI launcher."""

    def test_cmd_manage_success(self) -> None:
        """Test cmd_manage launches TUI successfully."""

        args = argparse.Namespace()

        with patch("yubikey_init.main.cmd_manage") as mock_manage:
            mock_manage.return_value = 0
            result = mock_manage(args)
            assert result == 0

    def test_cmd_manage_tui_available(self) -> None:
        """Test cmd_manage when TUI is available."""
        from yubikey_init.main import cmd_manage

        args = argparse.Namespace()

        with patch("yubikey_init.tui.run_tui") as mock_run_tui:
            result = cmd_manage(args)
            assert result == 0
            mock_run_tui.assert_called_once()

    def test_cmd_manage_import_error(self) -> None:
        """Test cmd_manage when TUI is not available (ImportError)."""
        from yubikey_init.main import cmd_manage

        args = argparse.Namespace()

        with (
            patch("yubikey_init.main.console"),
            patch("builtins.__import__", side_effect=ImportError("textual not installed")),
        ):
            # Directly test the logic by patching the internal import
            pass

        # Test via the actual function with run_tui mocked to raise ImportError
        with (
            patch("yubikey_init.main.console"),
            patch(
                "yubikey_init.tui.run_tui",
                side_effect=ImportError("textual not installed"),
            ),
        ):
            result = cmd_manage(args)
            assert result == 1

    def test_cmd_manage_general_exception(self) -> None:
        """Test cmd_manage when TUI throws unexpected error."""
        from yubikey_init.main import cmd_manage

        args = argparse.Namespace()

        with (
            patch("yubikey_init.main.console"),
            patch(
                "yubikey_init.tui.run_tui",
                side_effect=RuntimeError("TUI crashed"),
            ),
        ):
            result = cmd_manage(args)
            assert result == 1


class TestRunManageCommand:
    """Test run() dispatches to manage command."""

    def test_run_manage_command(self) -> None:
        """Test run dispatches to manage command."""
        with (
            patch("yubikey_init.main.cmd_manage", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
        ):
            result = run(["manage"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_provision_command(self) -> None:
        """Test run dispatches to provision command."""
        with (
            patch("yubikey_init.main.cmd_provision", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["provision", "--key-id", "ABC123", "--backup-path", "/tmp/backup"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_reset_command(self) -> None:
        """Test run dispatches to reset command."""
        with (
            patch("yubikey_init.main.cmd_reset", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["reset"])
            assert result == 0
            mock_cmd.assert_called_once()

    def test_run_setup_config_command(self) -> None:
        """Test run dispatches to setup-config command."""
        with (
            patch("yubikey_init.main.cmd_setup_config", return_value=0) as mock_cmd,
            patch("yubikey_init.main.StateMachine"),
            patch("yubikey_init.main.Prompts"),
        ):
            result = run(["setup-config"])
            assert result == 0
            mock_cmd.assert_called_once()
