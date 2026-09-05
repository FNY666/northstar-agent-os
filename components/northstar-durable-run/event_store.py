"""Append-only local event history and checkpoint support for durable runs."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from durable_contract import (
    EventContract,
    RunContract,
    StepContract,
    assert_transition,
    can_transition,
)

CHECKPOINT_SCHEMA_VERSION = "northstar.checkpoint.v1"
_CHECKPOINT_FIELDS = {"schema_version", "run_id", "sequence", "state", "state_digest"}
_RUN_EVENT_PREFIX = "run."
_STEP_EVENT_PREFIX = "step."


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _read_lines(path: Path) -> list[EventContract]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError("event history could not be read") from error
    events: list[EventContract] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise ValueError(f"event history contains blank line {line_number}")
        try:
            value = json.loads(line)
            events.append(EventContract.from_dict(value))
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError(
                f"event history contains an invalid event at line {line_number}"
            ) from error
    return events


def _stream_identity(events: list[EventContract]) -> dict[str, str] | None:
    if not events:
        return None
    first = events[0]
    identity = {
        "task_id": first.task_id,
        "thread_id": first.thread_id,
        "run_id": first.run_id,
        "trace_id": first.trace_id,
    }
    for event in events[1:]:
        for field, expected in identity.items():
            if getattr(event, field) != expected:
                raise ValueError(f"event {field} does not match event stream")
    return identity


def _apply_event(
    event: EventContract,
    *,
    identity: dict[str, str] | None,
    state: dict[str, Any],
) -> None:
    if identity is not None:
        for field, expected in identity.items():
            if getattr(event, field) != expected:
                raise ValueError(f"event {field} does not match event stream")

    if event.event_type == "checkpoint.created":
        if state["status"] not in {"running", "waiting"}:
            raise ValueError("checkpoint requires an active run")
        return

    if event.event_type.startswith(_RUN_EVENT_PREFIX):
        if event.step_id != "__run__":
            raise ValueError("run lifecycle events must use the __run__ step")
        current = state["status"]
        if current == "planned" and event.event_type == "run.created":
            if event.sequence != 1:
                raise ValueError("run.created must be the first event")
        else:
            assert_transition(current, event.status)
        state["status"] = event.status
        return

    if event.event_type.startswith(_STEP_EVENT_PREFIX):
        if event.step_id == "__run__":
            raise ValueError("step lifecycle events require a real step_id")
        current = state["steps"].get(event.step_id, {}).get("status", "planned")
        if event.event_type == "step.planned":
            if current != "planned":
                raise ValueError("step.planned may only create a planned step")
        else:
            assert_transition(current, event.status)
        state["steps"][event.step_id] = {
            "status": event.status,
            "sequence": event.sequence,
        }
        return

    raise ValueError("event type is not supported")


def _derive(events: list[EventContract]) -> dict[str, Any]:
    if not events:
        raise ValueError("run has no event history")
    identity = _stream_identity(events)
    assert identity is not None
    state: dict[str, Any] = {
        **identity,
        "status": "planned",
        "sequence": 0,
        "steps": {},
    }
    expected_sequence = 1
    for event in events:
        if event.sequence != expected_sequence:
            raise ValueError("event sequence is not contiguous")
        _apply_event(event, identity=identity, state=state)
        state["sequence"] = event.sequence
        expected_sequence += 1
    return state


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("checkpoint could not be read") from error
    if not isinstance(value, dict):
        raise ValueError("checkpoint must be an object")
    return value


class EventStore:
    """Persist one durable run's validated, append-only event history."""

    def __init__(self, path: str | Path):
        self._path = Path(path).absolute()
        self._checkpoint_path = self._path.with_name(
            self._path.name + ".checkpoint.json"
        )

    def _events(self) -> list[EventContract]:
        events = _read_lines(self._path)
        _derive(events) if events else None
        return events

    def append_event(self, event: EventContract) -> EventContract:
        if not isinstance(event, EventContract):
            raise ValueError("event must be an EventContract")
        events = self._events()
        identity = _stream_identity(events)
        if identity is not None:
            for field, expected in identity.items():
                if getattr(event, field) != expected:
                    raise ValueError(f"event {field} does not match event stream")

        for existing in events:
            if existing.idempotency_key == event.idempotency_key:
                if existing.canonical_json() == event.canonical_json():
                    return existing
                raise ValueError("idempotency key conflicts with existing event")
            if existing.event_id == event.event_id:
                raise ValueError("event_id conflicts with existing event")

        expected_sequence = len(events) + 1
        if event.sequence != expected_sequence:
            raise ValueError("event sequence must be the next contiguous sequence")
        candidate = events + [event]
        _derive(candidate)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = _canonical_json(event.to_dict()) + b"\n"
        try:
            with self._path.open("ab") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise ValueError("event could not be appended") from error
        return event

    def read_history(self, run_id: str) -> list[EventContract]:
        events = self._events()
        if events and events[0].run_id != run_id:
            raise ValueError("requested run_id does not match event history")
        return events

    def derive_state(self, run_id: str) -> dict[str, Any]:
        events = self.read_history(run_id)
        return _derive(events)

    def replay(self, run_id: str) -> dict[str, Any]:
        return self.derive_state(run_id)

    def create_checkpoint(self, run_id: str) -> dict[str, Any]:
        state = self.derive_state(run_id)
        checkpoint = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "run_id": run_id,
            "sequence": state["sequence"],
            "state": state,
            "state_digest": _digest(state),
        }
        self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=self._checkpoint_path.name + ".",
            dir=str(self._checkpoint_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(checkpoint, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._checkpoint_path)
        except OSError as error:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ValueError("checkpoint could not be persisted") from error
        return checkpoint

    def _validate_checkpoint(
        self, run_id: str, checkpoint: Any, current: dict[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(checkpoint, dict):
            raise ValueError("checkpoint must be an object")
        if set(checkpoint) != _CHECKPOINT_FIELDS:
            raise ValueError("checkpoint has unknown or missing fields")
        if checkpoint["schema_version"] != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("checkpoint schema_version is invalid")
        if checkpoint["run_id"] != run_id:
            raise ValueError("checkpoint run_id does not match")
        sequence = checkpoint["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
            raise ValueError("checkpoint sequence is invalid")
        state = checkpoint["state"]
        if not isinstance(state, dict):
            raise ValueError("checkpoint state is invalid")
        if state.get("run_id") != run_id:
            raise ValueError("checkpoint state run_id does not match")
        if checkpoint["state_digest"] != _digest(state):
            raise ValueError("checkpoint state digest is invalid")
        if sequence != current["sequence"]:
            raise ValueError("checkpoint is stale relative to event history")
        if state != current:
            raise ValueError("checkpoint state does not match event history")
        return state

    def restore(
        self, run_id: str, *, checkpoint: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        current = self.derive_state(run_id)
        if checkpoint is None:
            if not self._checkpoint_path.exists():
                raise ValueError("no checkpoint exists for run")
            checkpoint = _read_json_object(self._checkpoint_path)
        return self._validate_checkpoint(run_id, checkpoint, current)
