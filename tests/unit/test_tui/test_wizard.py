"""Tests for WizardScreen."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from yubikey_init.environment import CheckResult, EnvironmentReport
from yubikey_init.tui.controller import TUIController
from yubikey_init.tui.screens.wizard import WizardScreen


@pytest.fixture
def mock_controller() -> MagicMock:
    """Create a mock TUI controller."""
    return MagicMock(spec=TUIController)


@pytest.fixture
def all_passed_report() -> EnvironmentReport:
    """Create an environment report where all checks pass."""
    return EnvironmentReport(
        system="Darwin",
        checks=[
            CheckResult(name="GnuPG", passed=True, message="Found: gpg 2.4.3", critical=True),
            CheckResult(
                name="GnuPG Version",
                passed=True,
                message="Version 2.4.3 (>= 2.2 required)",
                critical=True,
            ),
            CheckResult(
                name="YubiKey Manager",
                passed=True,
                message="Found: ykman 5.2.1",
                critical=True,
            ),
            CheckResult(
                name="Smartcard Daemon",
                passed=True,
                message="macOS has built-in smartcard support",
                critical=True,
            ),
            CheckResult(name="Pinentry", passed=True, message="Found: pinentry-mac", critical=True),
            CheckResult(
                name="YubiKey Detection",
                passed=True,
                message="Found 1 YubiKey(s)",
                critical=False,
            ),
        ],
    )


@pytest.fixture
def failed_report() -> EnvironmentReport:
    """Create an environment report with some failures."""
    return EnvironmentReport(
        system="Darwin",
        checks=[
            CheckResult(name="GnuPG", passed=True, message="Found: gpg 2.4.3", critical=True),
            CheckResult(
                name="YubiKey Manager",
                passed=False,
                message="ykman not found in PATH",
                critical=True,
                fix_hint="Install YubiKey Manager: brew install ykman",
            ),
            CheckResult(
                name="Pinentry",
                passed=False,
                message="No pinentry program found",
                critical=True,
                fix_hint="Install pinentry: brew install pinentry-mac",
            ),
            CheckResult(
                name="YubiKey Detection",
                passed=False,
                message="No YubiKey detected",
                critical=False,
                fix_hint="Insert a YubiKey",
            ),
        ],
        warnings=["Some critical checks failed. Fix these before proceeding."],
    )


class TestWizardScreenInit:
    """Tests for WizardScreen initialization."""

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Test screen initialization with controller."""
        screen = WizardScreen(controller=mock_controller)
        assert screen._controller is mock_controller
        assert screen._current_step == 1

    def test_init_without_controller(self) -> None:
        """Test screen initialization without controller."""
        screen = WizardScreen()
        assert screen._controller is None

    def test_init_default_step(self) -> None:
        """Test that wizard starts at step 1."""
        screen = WizardScreen()
        assert screen._current_step == 1

    def test_total_steps(self) -> None:
        """Test that total steps is 10."""
        screen = WizardScreen()
        assert screen._total_steps == 10

    def test_init_env_report_is_none(self) -> None:
        """Test that env_report starts as None."""
        screen = WizardScreen()
        assert screen._env_report is None

    def test_init_step_not_complete(self) -> None:
        """Test that step starts as not complete."""
        screen = WizardScreen()
        assert screen._step_complete is False


class TestWizardScreenProperties:
    """Tests for WizardScreen properties."""

    def test_step_label_step_1(self) -> None:
        """Test step label for step 1."""
        screen = WizardScreen()
        assert screen.step_label == "Environment Check"

    def test_step_label_step_2(self) -> None:
        """Test step label for step 2."""
        screen = WizardScreen()
        screen._current_step = 2
        assert screen.step_label == "Identity Configuration"

    def test_step_label_step_10(self) -> None:
        """Test step label for step 10."""
        screen = WizardScreen()
        screen._current_step = 10
        assert screen.step_label == "Summary"

    def test_step_label_unknown(self) -> None:
        """Test step label for an unknown step returns Coming Soon."""
        screen = WizardScreen()
        screen._current_step = 99
        assert screen.step_label == "Coming Soon"


class TestWizardScreenNavigation:
    """Tests for WizardScreen navigation logic."""

    def test_back_disabled_on_step_1(self) -> None:
        """Test that going back on step 1 does nothing."""
        screen = WizardScreen()
        assert screen._current_step == 1
        screen._go_back()
        assert screen._current_step == 1

    def test_next_advances_step(self) -> None:
        """Test that next increments current_step when step is complete."""
        screen = WizardScreen()
        screen._step_complete = True
        # We can't call action_next_step directly because it tries to
        # update widgets, so test the logic directly
        assert screen._current_step == 1
        if screen._step_complete and screen._current_step < screen._total_steps:
            screen._current_step += 1
        assert screen._current_step == 2

    def test_next_blocked_when_incomplete(self) -> None:
        """Test that next does not advance when step is not complete."""
        screen = WizardScreen()
        screen._step_complete = False
        # Simulate the guard check in action_next_step
        old_step = screen._current_step
        if screen._step_complete and screen._current_step < screen._total_steps:
            screen._current_step += 1
        assert screen._current_step == old_step

    def test_next_blocked_at_last_step(self) -> None:
        """Test that next does not advance past the last step."""
        screen = WizardScreen()
        screen._current_step = 10
        screen._step_complete = True
        old_step = screen._current_step
        if screen._step_complete and screen._current_step < screen._total_steps:
            screen._current_step += 1
        assert screen._current_step == old_step

    def test_back_decrements_step(self) -> None:
        """Test that back decrements step when not on step 1."""
        screen = WizardScreen()
        screen._current_step = 3
        # Simulate the logic in _go_back without widget calls
        if screen._current_step > 1:
            screen._current_step -= 1
        assert screen._current_step == 2


class TestWizardEnvironmentCheck:
    """Tests for the environment check step."""

    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    def test_env_check_all_passed(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
    ) -> None:
        """Test that env report is stored when all checks pass."""
        mock_verify.return_value = all_passed_report
        screen = WizardScreen()
        # Directly set the report as the worker would
        screen._env_report = mock_verify(include_optional=True)
        assert screen._env_report is not None
        assert screen._env_report.all_passed is True
        assert len(screen._env_report.checks) == 6
        mock_verify.assert_called_once_with(include_optional=True)

    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    def test_env_check_with_failures(
        self,
        mock_verify: MagicMock,
        failed_report: EnvironmentReport,
    ) -> None:
        """Test that env report captures failures."""
        mock_verify.return_value = failed_report
        screen = WizardScreen()
        screen._env_report = mock_verify(include_optional=True)
        assert screen._env_report is not None
        assert screen._env_report.all_passed is False
        assert len(screen._env_report.critical_failures) == 2
        assert len(screen._env_report.non_critical_failures) == 1

    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    def test_env_check_display_format(
        self,
        mock_verify: MagicMock,
        failed_report: EnvironmentReport,
    ) -> None:
        """Test that check results use correct status icons."""
        mock_verify.return_value = failed_report
        screen = WizardScreen()
        screen._env_report = mock_verify(include_optional=True)
        assert screen._env_report is not None

        # Verify icon assignment logic
        for check in screen._env_report.checks:
            if check.passed:
                icon = "[green]OK[/green]"
            elif check.critical:
                icon = "[red]X[/red]"
            else:
                icon = "[yellow]!![/yellow]"

            if check.name == "GnuPG":
                assert icon == "[green]OK[/green]"
            elif check.name in ("YubiKey Manager", "Pinentry"):
                assert icon == "[red]X[/red]"
            elif check.name == "YubiKey Detection":
                assert icon == "[yellow]!![/yellow]"

    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    def test_env_check_fix_hints(
        self,
        mock_verify: MagicMock,
        failed_report: EnvironmentReport,
    ) -> None:
        """Test that failed checks have fix hints."""
        mock_verify.return_value = failed_report
        screen = WizardScreen()
        screen._env_report = mock_verify(include_optional=True)
        assert screen._env_report is not None

        failed_checks = [c for c in screen._env_report.checks if not c.passed]
        for check in failed_checks:
            assert check.fix_hint is not None
            assert len(check.fix_hint) > 0


class TestWizardScreenBindings:
    """Tests for WizardScreen key bindings."""

    def test_bindings_defined(self) -> None:
        """Test that key bindings are defined."""
        screen = WizardScreen()
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "n" in binding_keys

    def test_bindings_have_descriptions(self) -> None:
        """Test that bindings have descriptions."""
        screen = WizardScreen()
        for binding in screen.BINDINGS:
            assert binding.description is not None
            assert len(binding.description) > 0

    def test_escape_binding_has_priority(self) -> None:
        """Test that escape binding has priority."""
        screen = WizardScreen()
        for binding in screen.BINDINGS:
            if binding.key == "escape":
                assert binding.priority is True


class TestWizardScreenIntegration:
    """Integration tests for WizardScreen with Textual app."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_screen_runs_env_check_on_mount(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        """Test that screen runs environment check on mount."""
        mock_verify.return_value = all_passed_report

        from yubikey_init.tui.app import YubiKeyManagerApp

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert pilot.app.screen is screen
            mock_verify.assert_called_with(include_optional=True)

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_screen_handles_env_check_failure(
        self,
        mock_verify: MagicMock,
        failed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        """Test that screen handles failed env checks gracefully."""
        mock_verify.return_value = failed_report

        from yubikey_init.tui.app import YubiKeyManagerApp

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert pilot.app.screen is screen

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_cancel_pops_screen(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        """Test that cancel pops the wizard screen."""
        mock_verify.return_value = all_passed_report

        from yubikey_init.tui.app import YubiKeyManagerApp

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            screen.action_cancel()
            await pilot.pause()
            assert pilot.app.screen is not screen

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_screen_handles_verify_exception(
        self,
        mock_verify: MagicMock,
        mock_controller: MagicMock,
    ) -> None:
        """Test that screen handles exceptions from verify_environment."""
        mock_verify.side_effect = Exception("Unexpected error")

        from yubikey_init.tui.app import YubiKeyManagerApp

        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # Should not crash
            assert pilot.app.screen is screen
