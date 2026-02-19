from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .types import VALID_TRANSITIONS, Result, WorkflowState


class InvalidTransitionError(Exception):
    pass


class StateLoadError(Exception):
    pass


@dataclass
class CompletedStep:
    state: WorkflowState
    completed_at: datetime
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "completed_at": self.completed_at.isoformat(),
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompletedStep:
        return cls(
            state=WorkflowState(data["state"]),
            completed_at=datetime.fromisoformat(data["completed_at"]),
            artifacts=data.get("artifacts", {}),
        )


@dataclass
class WorkflowConfig:
    identity: str = ""
    key_type: str = "ed25519"
    expiry_years: int = 2
    backup_device: str = ""
    yubikey_serials: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkflowConfig:
        return cls(**data)


@dataclass
class WorkflowSession:
    version: str = "1.0.0"
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    current_state: WorkflowState = WorkflowState.UNINITIALIZED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    config: WorkflowConfig = field(default_factory=WorkflowConfig)
    completed_steps: list[CompletedStep] = field(default_factory=list)
    error_log: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "session_id": self.session_id,
            "current_state": self.current_state.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "config": self.config.to_dict(),
            "completed_steps": [step.to_dict() for step in self.completed_steps],
            "error_log": self.error_log,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkflowSession:
        return cls(
            version=data["version"],
            session_id=data["session_id"],
            current_state=WorkflowState(data["current_state"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            config=WorkflowConfig.from_dict(data["config"]),
            completed_steps=[CompletedStep.from_dict(s) for s in data.get("completed_steps", [])],
            error_log=data.get("error_log", []),
        )


class StateMachine:
    def __init__(self, state_path: Path | str) -> None:
        if state_path == ":memory:":
            self._state_path: Path | None = None
        else:
            self._state_path = Path(state_path)
        self._session: WorkflowSession | None = None

    @property
    def session(self) -> WorkflowSession:
        if self._session is None:
            self._session = WorkflowSession()
        return self._session

    @property
    def current_state(self) -> WorkflowState:
        return self.session.current_state

    def load(self) -> Result[WorkflowSession]:
        if self._state_path is None:
            self._session = WorkflowSession()
            return Result.ok(self._session)

        if not self._state_path.exists():
            self._session = WorkflowSession()
            return Result.ok(self._session)

        try:
            data = json.loads(self._state_path.read_text())
            self._session = WorkflowSession.from_dict(data)
            return Result.ok(self._session)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return Result.err(StateLoadError(f"Failed to load state: {e}"))

    def save(self) -> Result[None]:
        if self._state_path is None:
            return Result.ok(None)

        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(self.session.to_dict(), indent=2))
            return Result.ok(None)
        except OSError as e:
            return Result.err(e)

    def can_transition(self, to_state: WorkflowState) -> bool:
        valid_next = VALID_TRANSITIONS.get(self.current_state, [])
        return to_state in valid_next

    def transition(
        self, to_state: WorkflowState, artifacts: dict[str, Any] | None = None
    ) -> Result[None]:
        if not self.can_transition(to_state):
            return Result.err(
                InvalidTransitionError(
                    f"Invalid transition from {self.current_state.value} to {to_state.value}"
                )
            )

        now = datetime.now(UTC)
        step = CompletedStep(
            state=to_state,
            completed_at=now,
            artifacts=artifacts or {},
        )

        self.session.completed_steps.append(step)
        self.session.current_state = to_state
        self.session.updated_at = now

        return self.save()

    def rollback(self, to_state: WorkflowState) -> Result[None]:
        target_index = -1
        for i, step in enumerate(self.session.completed_steps):
            if step.state == to_state:
                target_index = i
                break

        if target_index == -1:
            return Result.err(
                InvalidTransitionError(f"Cannot rollback to {to_state.value}: state never reached")
            )

        self.session.completed_steps = self.session.completed_steps[: target_index + 1]
        self.session.current_state = to_state
        self.session.updated_at = datetime.now(UTC)

        return self.save()

    def log_error(self, error: Exception, context: str = "") -> None:
        self.session.error_log.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "error": str(error),
                "error_type": type(error).__name__,
                "context": context,
                "state": self.current_state.value,
            }
        )
        self.save()

    def get_artifact(self, state: WorkflowState, key: str) -> Any | None:
        for step in self.session.completed_steps:
            if step.state == state:
                return step.artifacts.get(key)
        return None

    def reset(self) -> Result[None]:
        self._session = WorkflowSession()
        return self.save()
