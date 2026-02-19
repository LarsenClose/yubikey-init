from __future__ import annotations

from pathlib import Path

import pytest

from yubikey_init import StateMachine, WorkflowState
from yubikey_init.gpg_ops import GPGOperations
from yubikey_init.prompts import MockPrompts


@pytest.mark.slow
class TestFullWorkflowWithMockPrompts:
    def test_workflow_to_backup_verified(
        self,
        gpg_home: Path,
        tmp_path: Path,
        mock_prompts: MockPrompts,
    ) -> None:
        state_file = tmp_path / "state.json"
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()

        sm = StateMachine(state_file)
        sm.load()
        gpg = GPGOperations(gnupghome=gpg_home)

        sm.transition(WorkflowState.STORAGE_SETUP, {"backup_path": str(backup_dir)})
        sm.transition(WorkflowState.STORAGE_VERIFIED)

        passphrase = mock_prompts.get_passphrase("Master key passphrase", confirm=True)
        result = gpg.generate_master_key(
            identity="E2E Test <e2e@example.com>",
            passphrase=passphrase,
        )
        assert result.is_ok()
        key = result.unwrap()

        sm.transition(
            WorkflowState.GPG_MASTER_GENERATED,
            {
                "key_id": key.key_id,
                "fingerprint": key.fingerprint,
            },
        )

        assert sm.current_state == WorkflowState.GPG_MASTER_GENERATED
        assert gpg.verify_key_exists(key.key_id, secret=True)

    def test_workflow_resume_from_saved_state(
        self,
        gpg_home: Path,
        tmp_path: Path,
    ) -> None:
        state_file = tmp_path / "state.json"

        sm1 = StateMachine(state_file)
        sm1.load()
        sm1.session.config.identity = "Resume Test <resume@example.com>"
        sm1.transition(WorkflowState.STORAGE_SETUP)
        sm1.transition(WorkflowState.STORAGE_VERIFIED)

        sm2 = StateMachine(state_file)
        sm2.load()

        assert sm2.current_state == WorkflowState.STORAGE_VERIFIED
        assert sm2.session.config.identity == "Resume Test <resume@example.com>"
        assert sm2.can_transition(WorkflowState.GPG_MASTER_GENERATED)


class TestWorkflowErrorRecovery:
    def test_rollback_after_failed_operation(
        self,
        tmp_path: Path,
    ) -> None:
        state_file = tmp_path / "state.json"

        sm = StateMachine(state_file)
        sm.load()

        sm.transition(WorkflowState.STORAGE_SETUP)
        sm.transition(WorkflowState.STORAGE_VERIFIED)
        sm.transition(WorkflowState.GPG_MASTER_GENERATED)

        sm.log_error(RuntimeError("Simulated failure"), context="subkey generation")
        result = sm.rollback(WorkflowState.STORAGE_VERIFIED)

        assert result.is_ok()
        assert sm.current_state == WorkflowState.STORAGE_VERIFIED
        assert len(sm.session.error_log) == 1
