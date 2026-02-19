from __future__ import annotations

from pathlib import Path

from yubikey_init import InvalidTransitionError, StateMachine, WorkflowState


class TestStateMachineBasics:
    def test_initial_state_is_uninitialized(self, memory_state_machine: StateMachine) -> None:
        assert memory_state_machine.current_state == WorkflowState.UNINITIALIZED

    def test_load_creates_new_session(self, memory_state_machine: StateMachine) -> None:
        session = memory_state_machine.session
        assert session.session_id is not None
        assert session.version == "1.0.0"

    def test_session_has_uuid(self, memory_state_machine: StateMachine) -> None:
        session = memory_state_machine.session
        assert len(session.session_id) == 36


class TestStateMachineTransitions:
    def test_can_transition_to_valid_state(self, memory_state_machine: StateMachine) -> None:
        assert memory_state_machine.can_transition(WorkflowState.STORAGE_SETUP)
        assert memory_state_machine.can_transition(WorkflowState.STORAGE_VERIFIED)

    def test_cannot_transition_to_invalid_state(self, memory_state_machine: StateMachine) -> None:
        assert not memory_state_machine.can_transition(WorkflowState.COMPLETE)
        assert not memory_state_machine.can_transition(WorkflowState.BACKUP_VERIFIED)

    def test_transition_updates_state(self, memory_state_machine: StateMachine) -> None:
        result = memory_state_machine.transition(WorkflowState.STORAGE_SETUP)
        assert result.is_ok()
        assert memory_state_machine.current_state == WorkflowState.STORAGE_SETUP

    def test_transition_records_step(self, memory_state_machine: StateMachine) -> None:
        memory_state_machine.transition(WorkflowState.STORAGE_SETUP)
        assert len(memory_state_machine.session.completed_steps) == 1
        assert memory_state_machine.session.completed_steps[0].state == WorkflowState.STORAGE_SETUP

    def test_transition_stores_artifacts(self, memory_state_machine: StateMachine) -> None:
        artifacts = {"key_id": "0x1234", "fingerprint": "ABCD"}
        memory_state_machine.transition(WorkflowState.STORAGE_SETUP, artifacts)
        step = memory_state_machine.session.completed_steps[0]
        assert step.artifacts == artifacts

    def test_invalid_transition_returns_error(self, memory_state_machine: StateMachine) -> None:
        result = memory_state_machine.transition(WorkflowState.COMPLETE)
        assert result.is_err()
        assert isinstance(result.unwrap_err(), InvalidTransitionError)

    def test_invalid_transition_does_not_change_state(
        self, memory_state_machine: StateMachine
    ) -> None:
        memory_state_machine.transition(WorkflowState.COMPLETE)
        assert memory_state_machine.current_state == WorkflowState.UNINITIALIZED


class TestStateMachineFullWorkflow:
    def test_valid_workflow_sequence(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine

        assert sm.transition(WorkflowState.STORAGE_SETUP).is_ok()
        assert sm.transition(WorkflowState.STORAGE_VERIFIED).is_ok()
        assert sm.transition(WorkflowState.GPG_MASTER_GENERATED).is_ok()
        assert sm.transition(WorkflowState.GPG_SUBKEYS_GENERATED).is_ok()
        assert sm.transition(WorkflowState.BACKUP_CREATED).is_ok()
        assert sm.transition(WorkflowState.BACKUP_VERIFIED).is_ok()
        assert sm.transition(WorkflowState.YUBIKEY_1_PROVISIONED).is_ok()
        assert sm.transition(WorkflowState.MASTER_KEY_REMOVED).is_ok()
        assert sm.transition(WorkflowState.COMPLETE).is_ok()

        assert sm.current_state == WorkflowState.COMPLETE
        assert len(sm.session.completed_steps) == 9

    def test_workflow_with_two_yubikeys(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine

        sm.transition(WorkflowState.STORAGE_SETUP)
        sm.transition(WorkflowState.STORAGE_VERIFIED)
        sm.transition(WorkflowState.GPG_MASTER_GENERATED)
        sm.transition(WorkflowState.GPG_SUBKEYS_GENERATED)
        sm.transition(WorkflowState.BACKUP_CREATED)
        sm.transition(WorkflowState.BACKUP_VERIFIED)
        sm.transition(WorkflowState.YUBIKEY_1_PROVISIONED)
        assert sm.transition(WorkflowState.YUBIKEY_2_PROVISIONED).is_ok()
        sm.transition(WorkflowState.MASTER_KEY_REMOVED)
        sm.transition(WorkflowState.COMPLETE)

        assert sm.current_state == WorkflowState.COMPLETE


class TestStateMachineRollback:
    def test_rollback_to_previous_state(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine
        sm.transition(WorkflowState.STORAGE_SETUP)
        sm.transition(WorkflowState.STORAGE_VERIFIED)
        sm.transition(WorkflowState.GPG_MASTER_GENERATED)

        result = sm.rollback(WorkflowState.STORAGE_VERIFIED)

        assert result.is_ok()
        assert sm.current_state == WorkflowState.STORAGE_VERIFIED
        assert len(sm.session.completed_steps) == 2

    def test_rollback_to_unreached_state_fails(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine
        sm.transition(WorkflowState.STORAGE_SETUP)

        result = sm.rollback(WorkflowState.BACKUP_VERIFIED)

        assert result.is_err()
        assert "never reached" in str(result.unwrap_err()).lower()


class TestStateMachinePersistence:
    def test_save_and_load(self, tmp_state_file: Path) -> None:
        sm1 = StateMachine(tmp_state_file)
        sm1.load()
        sm1.transition(WorkflowState.STORAGE_SETUP, {"device": "/dev/sda"})

        sm2 = StateMachine(tmp_state_file)
        result = sm2.load()

        assert result.is_ok()
        assert sm2.current_state == WorkflowState.STORAGE_SETUP
        assert sm2.session.session_id == sm1.session.session_id

    def test_load_nonexistent_creates_new(self, tmp_path: Path) -> None:
        state_file = tmp_path / "nonexistent" / "state.json"
        sm = StateMachine(state_file)
        result = sm.load()

        assert result.is_ok()
        assert sm.current_state == WorkflowState.UNINITIALIZED

    def test_artifacts_persist(self, tmp_state_file: Path) -> None:
        sm1 = StateMachine(tmp_state_file)
        sm1.load()
        sm1.transition(WorkflowState.STORAGE_SETUP, {"key": "value"})

        sm2 = StateMachine(tmp_state_file)
        sm2.load()

        artifact = sm2.get_artifact(WorkflowState.STORAGE_SETUP, "key")
        assert artifact == "value"


class TestStateMachineArtifacts:
    def test_get_artifact_returns_value(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine
        sm.transition(WorkflowState.STORAGE_SETUP, {"key_id": "0x1234"})

        assert sm.get_artifact(WorkflowState.STORAGE_SETUP, "key_id") == "0x1234"

    def test_get_artifact_returns_none_for_missing(
        self, memory_state_machine: StateMachine
    ) -> None:
        sm = memory_state_machine
        sm.transition(WorkflowState.STORAGE_SETUP, {})

        assert sm.get_artifact(WorkflowState.STORAGE_SETUP, "nonexistent") is None

    def test_get_artifact_returns_none_for_unreached_state(
        self, memory_state_machine: StateMachine
    ) -> None:
        sm = memory_state_machine
        assert sm.get_artifact(WorkflowState.BACKUP_VERIFIED, "key") is None


class TestStateMachineReset:
    def test_reset_clears_state(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine
        sm.transition(WorkflowState.STORAGE_SETUP)
        sm.transition(WorkflowState.STORAGE_VERIFIED)

        result = sm.reset()

        assert result.is_ok()
        assert sm.current_state == WorkflowState.UNINITIALIZED
        assert len(sm.session.completed_steps) == 0


class TestStateMachineErrorLogging:
    def test_log_error_records_error(self, memory_state_machine: StateMachine) -> None:
        sm = memory_state_machine
        error = ValueError("test error")

        sm.log_error(error, context="testing")

        assert len(sm.session.error_log) == 1
        assert sm.session.error_log[0]["error"] == "test error"
        assert sm.session.error_log[0]["error_type"] == "ValueError"
        assert sm.session.error_log[0]["context"] == "testing"
