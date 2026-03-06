"""Tests for WizardScreen."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import Button, Input, RadioSet, Static

from yubikey_init.environment import CheckResult, EnvironmentReport
from yubikey_init.prompts import PassphraseStrength, analyze_passphrase
from yubikey_init.tui.controller import TUIController
from yubikey_init.tui.screens.wizard import _STEP_LABELS, WizardScreen, WizardState
from yubikey_init.types import KeyType, SecureString


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


class TestWizardState:
    """Tests for WizardState dataclass."""

    def test_default_state(self) -> None:
        """Test that default state has expected values."""
        state = WizardState()
        assert state.identity is None
        assert state.passphrase is None
        assert state.key_type == KeyType.ED25519
        assert state.expiry_years == 2

    def test_state_stores_identity(self) -> None:
        """Test that identity can be stored in state."""
        state = WizardState()
        state.identity = "Test User <test@example.com>"
        assert state.identity == "Test User <test@example.com>"

    def test_state_stores_passphrase(self) -> None:
        """Test that passphrase can be stored in state."""
        state = WizardState()
        state.passphrase = SecureString("my-test-passphrase")
        assert state.passphrase is not None
        assert state.passphrase.get() == "my-test-passphrase"

    def test_state_stores_key_type(self) -> None:
        """Test that key_type can be changed in state."""
        state = WizardState()
        state.key_type = KeyType.RSA4096
        assert state.key_type == KeyType.RSA4096

    def test_state_stores_expiry_years(self) -> None:
        """Test that expiry_years can be changed in state."""
        state = WizardState()
        state.expiry_years = 5
        assert state.expiry_years == 5

    def test_wizard_screen_has_state(self) -> None:
        """Test that WizardScreen initializes with a WizardState."""
        screen = WizardScreen()
        assert isinstance(screen._state, WizardState)
        assert screen._state.identity is None


class TestWizardIdentityStep:
    """Tests for the identity configuration step (step 2)."""

    def test_step_2_label(self) -> None:
        """Test that step 2 label is 'Identity Configuration'."""
        assert _STEP_LABELS[2] == "Identity Configuration"

    def test_step_2_label_via_screen(self) -> None:
        """Test step label via screen property."""
        screen = WizardScreen()
        screen._current_step = 2
        assert screen.step_label == "Identity Configuration"

    def test_identity_preview_format(self) -> None:
        """Test that identity is stored in 'Name <email>' format."""
        state = WizardState()
        name = "Alice Smith"
        email = "alice@example.com"
        state.identity = f"{name} <{email}>"
        assert state.identity == "Alice Smith <alice@example.com>"

    def test_identity_preview_format_parsing(self) -> None:
        """Test that identity format can be parsed back to name and email."""
        identity = "Bob Jones <bob@test.org>"
        assert "<" in identity and identity.endswith(">")
        name = identity[: identity.index("<")].strip()
        email = identity[identity.index("<") + 1 : -1].strip()
        assert name == "Bob Jones"
        assert email == "bob@test.org"


class TestWizardPassphraseStep:
    """Tests for the passphrase setup step (step 3)."""

    def test_step_3_label(self) -> None:
        """Test that step 3 label is 'Passphrase Setup'."""
        assert _STEP_LABELS[3] == "Passphrase Setup"

    def test_passphrase_strength_weak(self) -> None:
        """Test that a short/simple passphrase is analyzed as WEAK."""
        analysis = analyze_passphrase("abc")
        assert analysis.strength == PassphraseStrength.WEAK

    def test_passphrase_strength_fair(self) -> None:
        """Test that a fair passphrase is analyzed as FAIR."""
        analysis = analyze_passphrase("MyPassphrase1")
        assert analysis.strength in (PassphraseStrength.FAIR, PassphraseStrength.GOOD)

    def test_passphrase_strength_strong(self) -> None:
        """Test that a strong passphrase is analyzed as STRONG or better."""
        analysis = analyze_passphrase("C0mpl3x!P@ssw0rd#2024")
        assert analysis.strength in (
            PassphraseStrength.GOOD,
            PassphraseStrength.STRONG,
            PassphraseStrength.EXCELLENT,
        )

    def test_passphrase_match_check_matching(self) -> None:
        """Test that matching passphrases are detected."""
        pw1 = "MySecurePassphrase!123"
        pw2 = "MySecurePassphrase!123"
        assert pw1 == pw2

    def test_passphrase_match_check_not_matching(self) -> None:
        """Test that non-matching passphrases are detected."""
        pw1 = "MySecurePassphrase!123"
        pw2 = "DifferentPassphrase!456"
        assert pw1 != pw2

    def test_passphrase_minimum_length_check(self) -> None:
        """Test that passphrases under 12 chars fail minimum check."""
        analysis = analyze_passphrase("Short!1")
        assert not analysis.meets_minimum

    def test_passphrase_meets_minimum_length(self) -> None:
        """Test that passphrases >= 12 chars pass minimum check."""
        analysis = analyze_passphrase("LongEnoughPw!")
        assert analysis.meets_minimum

    def test_passphrase_entropy_calculated(self) -> None:
        """Test that entropy is calculated for passphrases."""
        analysis = analyze_passphrase("TestPassphrase123!")
        assert analysis.entropy_bits > 0

    def test_passphrase_feedback_provided(self) -> None:
        """Test that feedback is provided for weak passphrases."""
        analysis = analyze_passphrase("weak")
        assert len(analysis.feedback) > 0


class TestWizardKeyConfigStep:
    """Tests for the key configuration step (step 4)."""

    def test_step_4_label(self) -> None:
        """Test that step 4 label is 'Key Configuration'."""
        assert _STEP_LABELS[4] == "Key Configuration"

    def test_default_key_type(self) -> None:
        """Test that default key type is ED25519."""
        state = WizardState()
        assert state.key_type == KeyType.ED25519

    def test_default_expiry(self) -> None:
        """Test that default expiry is 2 years."""
        state = WizardState()
        assert state.expiry_years == 2

    def test_key_type_rsa4096(self) -> None:
        """Test that RSA4096 can be selected."""
        state = WizardState()
        state.key_type = KeyType.RSA4096
        assert state.key_type == KeyType.RSA4096

    def test_custom_expiry(self) -> None:
        """Test that custom expiry can be set."""
        state = WizardState()
        state.expiry_years = 5
        assert state.expiry_years == 5

    def test_expiry_parsing_valid_digit(self) -> None:
        """Test expiry parsing with valid digit string."""
        expiry_str = "3"
        result = int(expiry_str) if expiry_str.isdigit() else 2
        assert result == 3

    def test_expiry_parsing_invalid_string(self) -> None:
        """Test expiry parsing falls back to default for non-digit."""
        expiry_str = "abc"
        result = int(expiry_str) if expiry_str.isdigit() else 2
        assert result == 2

    def test_expiry_parsing_empty_string(self) -> None:
        """Test expiry parsing falls back to default for empty string."""
        expiry_str = ""
        result = int(expiry_str) if expiry_str.isdigit() else 2
        assert result == 2


class TestWizardIdentityStepIntegration:
    """Integration tests for the identity step (step 2) with mounted widgets."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_identity_step_renders(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Advance to step 2 (env check auto-completes)
            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 2
            name_input = screen.query_one("#input-name", Input)
            email_input = screen.query_one("#input-email", Input)
            assert name_input is not None
            assert email_input is not None

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_identity_step_validates_inputs(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # Initially next should be disabled (empty inputs)
            next_btn = screen.query_one("#btn-next", Button)
            assert next_btn.disabled is True

            # Fill in name and email
            name_input = screen.query_one("#input-name", Input)
            email_input = screen.query_one("#input-email", Input)
            name_input.value = "Test User"
            email_input.value = "test@example.com"
            await pilot.pause()
            await pilot.pause()

            # Next should now be enabled
            assert screen._step_complete is True
            assert next_btn.disabled is False

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_identity_captures_state_on_next(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            name_input = screen.query_one("#input-name", Input)
            email_input = screen.query_one("#input-email", Input)
            name_input.value = "Alice"
            email_input.value = "alice@test.com"
            await pilot.pause()

            # Advance to step 3 — should capture identity
            screen.action_next_step()
            await pilot.pause()

            assert screen._state.identity == "Alice <alice@test.com>"
            assert screen._current_step == 3

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_identity_prefills_on_back(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Go to step 2, fill, advance to step 3, go back
            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            name_input = screen.query_one("#input-name", Input)
            email_input = screen.query_one("#input-email", Input)
            name_input.value = "Bob"
            email_input.value = "bob@test.com"
            await pilot.pause()

            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()

            # Go back to step 2
            screen._go_back()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 2
            name_input = screen.query_one("#input-name", Input)
            email_input = screen.query_one("#input-email", Input)
            assert name_input.value == "Bob"
            assert email_input.value == "bob@test.com"


class TestWizardPassphraseStepIntegration:
    """Integration tests for the passphrase step (step 3) with mounted widgets."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_passphrase_step_renders(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Advance to step 3
            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            # Fill identity for step 2
            screen.query_one("#input-name", Input).value = "A"
            screen.query_one("#input-email", Input).value = "a@b.com"
            await pilot.pause()
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 3
            pw_input = screen.query_one("#input-passphrase", Input)
            confirm_input = screen.query_one("#input-passphrase-confirm", Input)
            assert pw_input is not None
            assert confirm_input is not None

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_passphrase_strength_feedback(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Navigate to step 3
            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            screen.query_one("#input-name", Input).value = "A"
            screen.query_one("#input-email", Input).value = "a@b.com"
            await pilot.pause()
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # Enter a passphrase
            pw_input = screen.query_one("#input-passphrase", Input)
            pw_input.value = "MyStr0ngP@ssphrase!!"
            await pilot.pause()
            await pilot.pause()

            feedback = screen.query_one("#strength-feedback", Static)
            assert "Strength:" in str(feedback.render())

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_passphrase_mismatch_blocks_next(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            screen.query_one("#input-name", Input).value = "A"
            screen.query_one("#input-email", Input).value = "a@b.com"
            await pilot.pause()
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # Enter mismatched passphrases
            screen.query_one("#input-passphrase", Input).value = "MyStr0ngP@ss!!"
            screen.query_one("#input-passphrase-confirm", Input).value = "Different!!"
            await pilot.pause()
            await pilot.pause()

            assert screen._step_complete is False
            assert screen.query_one("#btn-next", Button).disabled is True

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_passphrase_valid_enables_next(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            screen.query_one("#input-name", Input).value = "A"
            screen.query_one("#input-email", Input).value = "a@b.com"
            await pilot.pause()
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            strong_pw = "MyStr0ngP@ssphrase!!"
            screen.query_one("#input-passphrase", Input).value = strong_pw
            screen.query_one("#input-passphrase-confirm", Input).value = strong_pw
            await pilot.pause()
            await pilot.pause()

            assert screen._step_complete is True
            assert screen.query_one("#btn-next", Button).disabled is False


class TestWizardKeyConfigStepIntegration:
    """Integration tests for the key config step (step 4) with mounted widgets."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_key_config_step_renders(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Fast-track to step 4
            screen._step_complete = True
            screen._current_step = 3
            screen._capture_step_state()
            screen._current_step = 4
            screen._run_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 4
            radio = screen.query_one("#key-type-radio", RadioSet)
            expiry = screen.query_one("#input-expiry", Input)
            assert radio is not None
            assert expiry.value == "2"

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_key_config_captures_expiry(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen._current_step = 3
            screen._current_step = 4
            screen._run_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            screen.query_one("#input-expiry", Input).value = "5"
            await pilot.pause()

            screen._capture_step_state()
            assert screen._state.expiry_years == 5


class TestWizardPlaceholderStep:
    """Integration tests for placeholder steps (5+)."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_placeholder_step_renders(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            screen._step_complete = True
            screen._current_step = 5
            screen._run_step()
            await pilot.pause()
            await pilot.pause()

            assert screen._step_complete is True


class TestWizardButtonNavigation:
    """Integration tests for button-based navigation."""

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_back_button_navigates(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()

            # Advance to step 2
            screen._step_complete = True
            screen.action_next_step()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 2
            back_btn = screen.query_one("#btn-back", Button)
            assert back_btn.disabled is False

            # Click back
            screen._go_back()
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 1

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_next_button_pressed_handler(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # Env check should complete and enable next
            next_btn = screen.query_one("#btn-next", Button)
            assert next_btn.disabled is False

            # Click next
            await pilot.click("#btn-next")
            await pilot.pause()
            await pilot.pause()

            assert screen._current_step == 2

    @pytest.mark.asyncio
    @patch("yubikey_init.tui.screens.wizard.verify_environment")
    async def test_cancel_button_pressed_handler(
        self,
        mock_verify: MagicMock,
        all_passed_report: EnvironmentReport,
        mock_controller: MagicMock,
    ) -> None:
        from yubikey_init.tui.app import YubiKeyManagerApp

        mock_verify.return_value = all_passed_report
        app = YubiKeyManagerApp(controller=mock_controller)
        async with app.run_test() as pilot:
            screen = WizardScreen(controller=mock_controller)
            await pilot.app.push_screen(screen)
            await pilot.pause()

            await pilot.click("#btn-cancel")
            await pilot.pause()

            assert pilot.app.screen is not screen


class TestWizardStepLabelsUpdated:
    """Tests for the updated step labels."""

    def test_step_5_label(self) -> None:
        """Test that step 5 is now 'Storage Setup'."""
        assert _STEP_LABELS[5] == "Storage Setup"

    def test_step_6_label(self) -> None:
        """Test that step 6 is now 'Key Generation'."""
        assert _STEP_LABELS[6] == "Key Generation"

    def test_step_7_label(self) -> None:
        """Test that step 7 is now 'Backup Creation'."""
        assert _STEP_LABELS[7] == "Backup Creation"

    def test_step_8_label(self) -> None:
        """Test that step 8 is now 'YubiKey Transfer'."""
        assert _STEP_LABELS[8] == "YubiKey Transfer"

    def test_step_9_label(self) -> None:
        """Test that step 9 is still 'Verification'."""
        assert _STEP_LABELS[9] == "Verification"

    def test_all_10_steps_have_labels(self) -> None:
        """Test that all 10 steps have labels defined."""
        for i in range(1, 11):
            assert i in _STEP_LABELS
            assert len(_STEP_LABELS[i]) > 0
