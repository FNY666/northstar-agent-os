"""A small local durable runner for the Northstar vertical slice.

This runner intentionally executes only caller-registered Python step functions
inside the test fixture. It is not a sandbox, scheduler, or production worker.
Its purpose is to prove lifecycle, lease, checkpoint, resume, cancellation, and
idempotent step boundaries before adding broader execution surfaces.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from durable_contract import (
    RunContract,
    assert_transition,
    can_transition,
)
from event_store import EventStore

_ID_RE = re.compile(r"^[^\s/\\]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_MAX_INPUT_BYTES = 256_000
_PRIVATE_MODE = 0o700


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("step input must be JSON serializable") from error


def _digest(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{field} is invalid")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _require_scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("scope_snapshot must be a list")
    if len(value) > 64:
        raise ValueError("scope_snapshot has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for scope in value:
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
            raise ValueError("scope_snapshot contains an invalid scope")
        if scope in seen:
            raise ValueError("scope_snapshot contains a duplicate scope")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _require_postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("expected_postconditions must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for name in value:
        normalized = _require_id(name, "expected_postcondition")
        if normalized in seen:
            raise ValueError("expected_postconditions contains a duplicate")
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


@dataclass(frozen=True)
class StepPlan:
    step_id: str
    input_payload: dict[str, Any]
    scope_snapshot: tuple[str, ...] | list[str]
    expected_postconditions: tuple[str, ...] | list[str]
    action: Callable[[str], dict[str, Any]]

    def __post_init__(self) -> None:
        _require_id(self.step_id, "step_id")
        if not isinstance(self.input_payload, dict):
            raise ValueError("input_payload must be an object")
        if len(_canonical_json(self.input_payload)) > _MAX_INPUT_BYTES:
            raise ValueError("step input exceeds the maximum size")
        object.__setattr__(self, "scope_snapshot", _require_scopes(self.scope_snapshot))
        object.__setattr__(
            self,
            "expected_postconditions",
            _require_postconditions(self.expected_postconditions),
        )
        if not callable(self.action):
            raise ValueError("step action must be callable")

    @property
    def input_digest(self) -> str:
        return _digest(self.input_payload)


class LeaseManager:
    """A single-owner, expiring local lease persisted as strict JSON."""

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()

    def _read(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("lease file is invalid") from error
        if not isinstance(value, dict) or set(value) != {"owner_id", "expires_at"}:
            raise ValueError("lease file has unknown or missing fields")
        _require_id(value.get("owner_id"), "lease owner_id")
        expires_at = value.get("expires_at")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
            raise ValueError("lease expires_at is invalid")
        return value

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=self.path.name + ".", dir=str(self.path.parent)
        )
        try:
            os.fchmod(fd, _PRIVATE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as error:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ValueError("lease could not be persisted") from error

    def acquire(self, owner_id: str, *, now: int, ttl_seconds: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        current = self._read()
        if current is not None and now < current["expires_at"]:
            raise ValueError("lease is held by another active owner")
        lease = {"owner_id": owner_id, "expires_at": now + ttl_seconds}
        self._write(lease)
        return lease

    def assert_valid(self, owner_id: str, *, now: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        current = self._read()
        if current is None:
            raise ValueError("lease does not exist")
        if current["owner_id"] != owner_id:
            raise ValueError("lease owner does not match")
        if now >= current["expires_at"]:
            raise ValueError("lease has expired")
        return current

    def heartbeat(self, owner_id: str, *, now: int, ttl_seconds: int) -> dict[str, Any]:
        self.assert_valid(owner_id, now=now)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        lease = {"owner_id": owner_id, "expires_at": now + ttl_seconds}
        self._write(lease)
        return lease

    def release(self, owner_id: str) -> None:
        current = self._read()
        if current is None:
            return
        if current["owner_id"] != owner_id:
            raise ValueError("lease owner does not match")
        try:
            self.path.unlink()
        except FileNotFoundError:
            return
        except OSError as error:
            raise ValueError("lease could not be released") from error


class DurableRunner:
    """Execute planned local steps with durable event and lease boundaries."""

    def __init__(
        self,
        run: RunContract,
        store: EventStore,
        *,
        lease_path: str | Path,
        lease_ttl_seconds: int = 60,
    ):
        if not isinstance(run, RunContract):
            raise ValueError("run must be a RunContract")
        if not isinstance(lease_ttl_seconds, int) or isinstance(lease_ttl_seconds, bool) or lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be a positive integer")
        self.run = run
        self.store = store
        self.lease = LeaseManager(lease_path)
        self.lease_ttl_seconds = lease_ttl_seconds

    def _event(
        self,
        *,
        event_id: str,
        sequence: int,
        event_type: str,
        status: str,
        step_id: str,
        idempotency_key: str,
        occurred_at: int,
        payload_digest: str,
    ):
        from durable_contract import EventContract

        return EventContract.from_dict(
            {
                "schema_version": "northstar.durable-event.v1",
                "event_id": event_id,
                "task_id": self.run.task_id,
                "thread_id": self.run.thread_id,
                "run_id": self.run.run_id,
                "step_id": step_id,
                "sequence": sequence,
                "event_type": event_type,
                "status": status,
                "occurred_at": occurred_at,
                "idempotency_key": idempotency_key,
                "trace_id": self.run.trace_id,
                "payload_digest": payload_digest,
            }
        )

    def _append(
        self,
        *,
        event_type: str,
        status: str,
        step_id: str,
        idempotency_key: str,
        now: int,
        payload: Any,
    ) -> None:
        history = self.store.read_history(self.run.run_id)
        event = self._event(
            event_id=f"event-{len(history) + 1:06d}",
            sequence=len(history) + 1,
            event_type=event_type,
            status=status,
            step_id=step_id,
            idempotency_key=idempotency_key,
            occurred_at=now,
            payload_digest=_digest(payload),
        )
        self.store.append_event(event)

    def prepare(self, *, owner_id: str, now: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        history = self.store.read_history(self.run.run_id)
        if not history:
            self._append(
                event_type="run.created",
                status="planned",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-created",
                now=now,
                payload=self.run.to_dict(),
            )
        return self.store.derive_state(self.run.run_id)

    def _ensure_execution_lease(self, owner_id: str, *, now: int) -> None:
        if self.lease.path.exists():
            self.lease.assert_valid(owner_id, now=now)
        else:
            self.lease.acquire(
                owner_id, now=now, ttl_seconds=self.lease_ttl_seconds
            )

    def _append_run_started(self, *, now: int) -> None:
        state = self.store.derive_state(self.run.run_id)
        if state["status"] == "planned":
            self._append(
                event_type="run.started",
                status="running",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-started",
                now=now,
                payload={"status": "running"},
            )
        elif state["status"] == "waiting":
            self._append(
                event_type="run.started",
                status="running",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-resumed-{state['sequence'] + 1}",
                now=now,
                payload={"status": "running"},
            )

    def cancel(self, *, owner_id: str, now: int) -> dict[str, Any]:
        state = self.prepare(owner_id=owner_id, now=now)
        if state["status"] in {"finished", "failed", "cancelled"}:
            return state
        self._append(
            event_type="run.cancelled",
            status="cancelled",
            step_id="__run__",
            idempotency_key=f"{self.run.run_id}-cancelled-{state['sequence'] + 1}",
            now=now,
            payload={"status": "cancelled"},
        )
        return self.store.derive_state(self.run.run_id)

    def execute(
        self,
        plans: list[StepPlan],
        *,
        owner_id: str,
        now: int,
        finalize: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(plans, list):
            raise ValueError("plans must be a list")
        if len({plan.step_id for plan in plans}) != len(plans):
            raise ValueError("step plans must have unique step IDs")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        if now >= self.run.deadline_at:
            raise ValueError("run deadline has expired")
        state = self.prepare(owner_id=owner_id, now=now)
        if state["status"] == "cancelled":
            return state
        if state["status"] == "finished":
            return state
        if state["status"] == "failed":
            raise ValueError("run has already failed")

        self._ensure_execution_lease(owner_id, now=now)
        try:
            self._append_run_started(now=now)
            for plan in plans:
                state = self.store.derive_state(self.run.run_id)
                step_state = state["steps"].get(plan.step_id)
                if step_state is not None and step_state["status"] == "finished":
                    continue
                if step_state is None:
                    self._append(
                        event_type="step.planned",
                        status="planned",
                        step_id=plan.step_id,
                        idempotency_key=f"{self.run.run_id}-{plan.step_id}-planned",
                        now=now,
                        payload={
                            "input_digest": plan.input_digest,
                            "scope_snapshot": list(plan.scope_snapshot),
                            "expected_postconditions": list(plan.expected_postconditions),
                        },
                    )
                    step_state = {"status": "planned"}
                if step_state["status"] == "failed":
                    raise ValueError(f"step {plan.step_id} has already failed")
                if step_state["status"] == "planned":
                    self._append(
                        event_type="step.started",
                        status="running",
                        step_id=plan.step_id,
                        idempotency_key=f"{self.run.run_id}-{plan.step_id}-started",
                        now=now,
                        payload={"input_digest": plan.input_digest},
                    )
                action_key = f"{self.run.run_id}:{plan.step_id}:attempt-1"
                try:
                    output = plan.action(action_key)
                    if not isinstance(output, dict):
                        raise ValueError("step action must return an object")
                except KeyboardInterrupt:
                    raise
                except BaseException:
                    raise
                self._append(
                    event_type="step.finished",
                    status="finished",
                    step_id=plan.step_id,
                    idempotency_key=f"{self.run.run_id}-{plan.step_id}-finished",
                    now=now,
                    payload={"output_digest": _digest(output)},
                )
                self._append(
                    event_type="checkpoint.created",
                    status="running",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-checkpoint-{plan.step_id}",
                    now=now,
                    payload=self.store.derive_state(self.run.run_id),
                )
                self.store.create_checkpoint(self.run.run_id)

            state = self.store.derive_state(self.run.run_id)
            if finalize and state["status"] == "running":
                self._append(
                    event_type="run.finished",
                    status="finished",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-finished",
                    now=now,
                    payload={"status": "finished"},
                )
                self.store.create_checkpoint(self.run.run_id)
            return self.store.derive_state(self.run.run_id)
        except KeyboardInterrupt:
            raise
        except Exception as error:
            state = self.store.derive_state(self.run.run_id)
            active_step = next(
                (
                    step_id
                    for step_id, details in state["steps"].items()
                    if details["status"] == "running"
                ),
                None,
            )
            if active_step is not None:
                self._append(
                    event_type="step.failed",
                    status="failed",
                    step_id=active_step,
                    idempotency_key=f"{self.run.run_id}-{active_step}-failed",
                    now=now,
                    payload={"error_class": error.__class__.__name__},
                )
            if self.store.derive_state(self.run.run_id)["status"] == "running":
                self._append(
                    event_type="run.failed",
                    status="failed",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-failed",
                    now=now,
                    payload={"error_class": error.__class__.__name__},
                )
            return self.store.derive_state(self.run.run_id)
        finally:
            self.lease.release(owner_id)
