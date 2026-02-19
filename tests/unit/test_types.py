from __future__ import annotations

import pytest

from yubikey_init import (
    Result,
    SecureString,
    WorkflowState,
)
from yubikey_init.types import VALID_TRANSITIONS


class TestResult:
    def test_ok_is_ok(self) -> None:
        result: Result[int] = Result.ok(42)
        assert result.is_ok()
        assert not result.is_err()

    def test_err_is_err(self) -> None:
        result: Result[int] = Result.err(ValueError("test"))
        assert result.is_err()
        assert not result.is_ok()

    def test_unwrap_ok(self) -> None:
        result = Result.ok(42)
        assert result.unwrap() == 42

    def test_unwrap_err_raises(self) -> None:
        result: Result[int] = Result.err(ValueError("test error"))
        with pytest.raises(ValueError, match="test error"):
            result.unwrap()

    def test_unwrap_or_returns_value_on_ok(self) -> None:
        result = Result.ok(42)
        assert result.unwrap_or(0) == 42

    def test_unwrap_or_returns_default_on_err(self) -> None:
        result: Result[int] = Result.err(ValueError("test"))
        assert result.unwrap_or(0) == 0

    def test_unwrap_err_returns_error(self) -> None:
        err = ValueError("test")
        result: Result[int] = Result.err(err)
        assert result.unwrap_err() is err

    def test_unwrap_err_raises_on_ok(self) -> None:
        result = Result.ok(42)
        with pytest.raises(RuntimeError):
            result.unwrap_err()

    def test_map_transforms_ok(self) -> None:
        result = Result.ok(42)
        mapped = result.map(lambda x: x * 2)
        assert mapped.is_ok()
        assert mapped.unwrap() == 84

    def test_map_propagates_err(self) -> None:
        result: Result[int] = Result.err(ValueError("test"))
        mapped = result.map(lambda x: x * 2)
        assert mapped.is_err()

    def test_map_catches_exception(self) -> None:
        result = Result.ok(42)
        mapped = result.map(lambda x: 1 / 0)
        assert mapped.is_err()
        assert isinstance(mapped.unwrap_err(), ZeroDivisionError)

    def test_and_then_chains_ok(self) -> None:
        result = Result.ok(42)
        chained = result.and_then(lambda x: Result.ok(x * 2))
        assert chained.is_ok()
        assert chained.unwrap() == 84

    def test_and_then_propagates_err(self) -> None:
        result: Result[int] = Result.err(ValueError("first"))
        chained = result.and_then(lambda x: Result.ok(x * 2))
        assert chained.is_err()


class TestSecureString:
    def test_get_returns_value(self) -> None:
        ss = SecureString("secret")
        assert ss.get() == "secret"

    def test_str_masks_value(self) -> None:
        ss = SecureString("secret")
        assert str(ss) == "****"
        assert "secret" not in str(ss)

    def test_repr_masks_value(self) -> None:
        ss = SecureString("secret")
        assert repr(ss) == "SecureString(****)"
        assert "secret" not in repr(ss)

    def test_len_returns_actual_length(self) -> None:
        ss = SecureString("secret")
        assert len(ss) == 6

    def test_clear_zeros_value(self) -> None:
        ss = SecureString("secret")
        ss.clear()
        assert ss.get() == ""


class TestWorkflowState:
    def test_all_states_have_transitions_defined(self) -> None:
        for state in WorkflowState:
            assert state in VALID_TRANSITIONS

    def test_complete_has_no_transitions(self) -> None:
        assert VALID_TRANSITIONS[WorkflowState.COMPLETE] == []

    def test_uninitialized_can_transition_to_storage(self) -> None:
        valid = VALID_TRANSITIONS[WorkflowState.UNINITIALIZED]
        assert WorkflowState.STORAGE_SETUP in valid
        assert WorkflowState.STORAGE_VERIFIED in valid
