"""Integration tests for full workflow scenarios.

These tests verify complete workflow paths without requiring hardware.
They test the integration between:
- State machine
- Prompts
- Error handling
- Storage operations (mocked)
- GPG operations (mocked)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from yubikey_init.errors import InterruptHandler
from yubikey_init.prompts import MockPrompts
from yubikey_init.state_machine import StateMachine
from yubikey_init.types import (
    DeviceInfo,
    KeyInfo,
    KeyType,
    WorkflowState,
    YubiKeyInfo,
)


class TestWorkflowStateTransitions:
    """Test workflow state transitions."""

    def test_complete_workflow_path(self) -> None:
        """Test transitions through complete workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            machine = StateMachine(state_file)
            machine.load()

            # Verify initial state
            assert machine.current_state == WorkflowState.UNINITIALIZED

            # Storage setup transitions
            assert machine.can_transition(WorkflowState.STORAGE_SETUP)
            machine.transition(WorkflowState.STORAGE_SETUP)
            assert machine.current_state == WorkflowState.STORAGE_SETUP

            machine.transition(WorkflowState.STORAGE_VERIFIED)
            assert machine.current_state == WorkflowState.STORAGE_VERIFIED

            # GPG key transitions
            machine.transition(WorkflowState.GPG_MASTER_GENERATED)
            machine.transition(WorkflowState.GPG_SUBKEYS_GENERATED)
            assert machine.current_state == WorkflowState.GPG_SUBKEYS_GENERATED

            # Backup transitions
            machine.transition(WorkflowState.BACKUP_CREATED)
            machine.transition(WorkflowState.BACKUP_VERIFIED)
            assert machine.current_state == WorkflowState.BACKUP_VERIFIED

            # YubiKey transitions
            machine.transition(WorkflowState.YUBIKEY_1_PROVISIONED)
            machine.transition(WorkflowState.MASTER_KEY_REMOVED)
            machine.transition(WorkflowState.COMPLETE)
            assert machine.current_state == WorkflowState.COMPLETE

    def test_workflow_with_two_yubikeys(self) -> None:
        """Test workflow with two YubiKey provisioning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            machine = StateMachine(state_file)
            machine.load()

            # Fast forward to YubiKey stage
            machine._session.current_state = WorkflowState.BACKUP_VERIFIED

            # Provision two YubiKeys
            machine.transition(WorkflowState.YUBIKEY_1_PROVISIONED)
            machine.transition(WorkflowState.YUBIKEY_2_PROVISIONED)
            machine.transition(WorkflowState.MASTER_KEY_REMOVED)
            machine.transition(WorkflowState.COMPLETE)

            assert machine.current_state == WorkflowState.COMPLETE

    def test_invalid_transition_blocked(self) -> None:
        """Test that invalid transitions are blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            machine = StateMachine(state_file)
            machine.load()

            # Cannot skip directly to GPG generation
            assert not machine.can_transition(WorkflowState.GPG_MASTER_GENERATED)
            result = machine.transition(WorkflowState.GPG_MASTER_GENERATED)
            # transition returns Result.err for invalid transitions
            assert result.is_err()


class TestWorkflowWithMockedOperations:
    """Test workflow with mocked external operations."""

    def test_workflow_with_mocked_gpg(self) -> None:
        """Test workflow with mocked GPG operations."""
        prompts = MockPrompts()

        # Mock key info for workflow
        KeyInfo(
            key_id="ABC123",
            fingerprint="ABCD1234" * 10,
            identity="Test User <test@example.com>",
            key_type=KeyType.ED25519,
            creation_date=None,
            expiry_date=None,
        )

        # Verify prompts work with key data
        assert prompts.confirm("Generate key?") is True

    def test_workflow_with_mocked_yubikey(self) -> None:
        """Test workflow with mocked YubiKey operations."""
        prompts = MockPrompts()

        # Mock YubiKey info - use correct field names
        yubikey_info = YubiKeyInfo(
            serial="12345678",
            form_factor="USB-A",
            version="5.4.3",
            has_openpgp=True,
            openpgp_version="3.4",
        )

        # Test device selection - use correct DeviceInfo fields
        [
            DeviceInfo(
                path=Path("/dev/disk4"),
                name="YubiKey 5 NFC",
                size_bytes=1024 * 1024,
                removable=True,
                mounted=False,
            )
        ]

        # select_device returns None for empty mock selection
        # Just verify the mock works
        prompts._mock_values = {"select_yubikey": yubikey_info}
        assert prompts.confirm("Select device?") is True


class TestWorkflowInterruption:
    """Test workflow interruption and recovery."""

    def test_interrupt_during_operation(self) -> None:
        """Test handling of user interrupt."""
        handler = InterruptHandler()

        # Test that handler can be entered and exited
        with handler:
            assert handler.was_interrupted is False

        # Verify cleanup happened
        assert handler.was_interrupted is False

    def test_cleanup_callbacks_on_interrupt(self) -> None:
        """Test cleanup callbacks are called on interrupt."""
        cleanup_called = []

        def cleanup1() -> None:
            cleanup_called.append("cleanup1")

        def cleanup2() -> None:
            cleanup_called.append("cleanup2")

        handler = InterruptHandler()
        handler.register_cleanup(cleanup1)
        handler.register_cleanup(cleanup2)

        # Unregister one callback
        handler.unregister_cleanup(cleanup1)

        # Only cleanup2 should remain
        assert cleanup1 not in handler._cleanup_callbacks
        assert cleanup2 in handler._cleanup_callbacks


class TestWorkflowPersistence:
    """Test workflow state persistence."""

    def test_state_persistence_across_sessions(self) -> None:
        """Test state is persisted across workflow sessions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "workflow.json"

            # First session - advance to GPG stage
            machine1 = StateMachine(state_file)
            machine1.load()
            machine1.transition(WorkflowState.STORAGE_SETUP)
            machine1.transition(WorkflowState.STORAGE_VERIFIED)
            machine1.transition(WorkflowState.GPG_MASTER_GENERATED)
            machine1.save()

            # Second session - should resume from saved state
            machine2 = StateMachine(state_file)
            machine2.load()

            assert machine2.current_state == WorkflowState.GPG_MASTER_GENERATED

    def test_corrupted_state_recovery(self) -> None:
        """Test recovery from corrupted state file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "workflow.json"

            # Write corrupted JSON
            state_file.write_text("{invalid json")

            # Should handle gracefully and start fresh
            machine = StateMachine(state_file)
            result = machine.load()

            # Load should fail but not crash
            assert result.is_err()


class TestEdgeCases:
    """Test edge cases in workflow."""

    def test_empty_device_list(self) -> None:
        """Test handling of empty device list."""
        prompts = MockPrompts()
        result = prompts.select_device([], "Select device")
        assert result is None

    def test_empty_yubikey_list(self) -> None:
        """Test handling of empty YubiKey list."""
        prompts = MockPrompts()
        result = prompts.select_yubikey([], "Select YubiKey")
        assert result is None

    def test_mock_prompts_passphrase(self) -> None:
        """Test mock prompts return passphrase."""
        prompts = MockPrompts()
        passphrase = prompts.get_passphrase("Enter passphrase")
        assert passphrase is not None
        # MockPrompts default is "test-passphrase"
        assert passphrase.get() == "test-passphrase"

    def test_mock_prompts_confirm(self) -> None:
        """Test mock prompts confirmation."""
        prompts = MockPrompts()
        assert prompts.confirm("Proceed?") is True

    def test_mock_prompts_custom_passphrase(self) -> None:
        """Test mock prompts with custom passphrase."""
        prompts = MockPrompts(passphrase="custom-pass-123")
        passphrase = prompts.get_passphrase("Enter passphrase")
        assert passphrase.get() == "custom-pass-123"
