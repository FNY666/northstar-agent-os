"""BPMN engine: process deployment and task-completion bookkeeping.

Research motivation: Camunda/Zeebe-style BPMN engines separate the
*process definition* (the deployed BPMN model) from *process instances*
(running executions) and *tasks* (work items claimed and completed by
workers). The engine never executes business logic itself -- it books
the declared lifecycle: definition deployed, instance started, task
completed. This module is the deterministic single-host bookkeeping of
that shape, not a workflow runtime: it observes no worker, runs no
process code, and cannot prove a booked task was actually performed.

Public API:

- ``BPMNEngine()`` -- mutable, RLock-guarded ledger.
  - ``deploy(definition_id, bpmn_digest, seq, tasks=())`` ->
    frozen ``DeploymentRecord``: registers a process definition with
    its ordered task list (``(task_id, task_kind)`` pairs).
  - ``start(instance_id, definition_id, seq)`` -> frozen
    ``StartRecord``: opens a process instance against a deployed
    definition.
  - ``task(instance_id, task_id, seq, outcome="completed")`` ->
    frozen ``TaskRecord``: books a host-declared task outcome. When
    the last pending task of an instance closes, a frozen
    ``CompletionRecord`` is booked and the instance turns terminal.
  - ``instance(instance_id)`` / ``instance_ids()`` /
    ``deployment(definition_id)`` / ``pending_tasks(instance_id)`` /
    ``stats()`` / ``audit_log()`` -- pure read views; consume no seq.
- ``bpmn_engine_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"bpmn.deployed"``,
  ``"bpmn.started"``, ``"bpmn.task-completed"``,
  ``"bpmn.completed"``, ``"bpmn.rejected"``.

Process models are pinned by ``sha256:`` digest only -- raw BPMN XML
never enters a record or crosses the audit boundary. Task outcomes are
pinned vocabulary (``"completed"``/``"skipped"``); the module cannot
prove the declared work happened.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* deployments, starts and task
  completions; it observes no worker and executes no task code.
- A ``TaskRecord`` is a decision, not proof: the task moves only if
  the host performs and reports the work.
- Instance completion is structural (all tasks booked terminal), not
  semantic: it says nothing about the business outcome.

Version pin: ``bpmn-engine.v1`` / schema pin
``northstar.bpmn-engine.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # sibling canonical-JSON helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover
    _cj = None  # type: ignore

#: Module version.
BPMN_ENGINE_VERSION = "bpmn-engine.v1"

#: Schema pin for records produced by this module.
BPMN_ENGINE_SCHEMA = "northstar.bpmn-engine.v1"

#: Audit record format pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned audit kinds.
KIND_DEPLOYED = "bpmn.deployed"
KIND_STARTED = "bpmn.started"
KIND_TASK_COMPLETED = "bpmn.task-completed"
KIND_COMPLETED = "bpmn.completed"
KIND_REJECTED = "bpmn.rejected"

_KINDS = frozenset(
    {KIND_DEPLOYED, KIND_STARTED, KIND_TASK_COMPLETED, KIND_COMPLETED, KIND_REJECTED}
)

#: Digest prefix and safe integer bound.
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64
_MAX_INT = 2**53 - 1

#: Max ids/chars guardrails.
_MAX_ID_LEN = 256
_MAX_TASKS = 1024

#: Pinned task kinds (BPMN task families).
_TASK_KINDS = frozenset({"user", "service", "manual", "script"})

#: Pinned task outcomes.
_OUTCOMES = frozenset({"completed", "skipped"})

#: Instance states.
_STATE_ACTIVE = "active"
_STATE_COMPLETED = "completed"


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class BPMNEngineError(Exception):
    """Base class for BPMN engine errors."""


class BadDefinitionError(BPMNEngineError):
    """The process definition id or its digest is malformed."""


class DuplicateDefinitionError(BPMNEngineError):
    """The definition id is already deployed."""


class UnknownDefinitionError(BPMNEngineError):
    """The definition id is not deployed."""


class BadTaskSpecError(BPMNEngineError):
    """A task spec (id or kind) in a deployment is malformed."""


class BadInstanceError(BPMNEngineError):
    """The process instance id is malformed."""


class DuplicateInstanceError(BPMNEngineError):
    """The instance id is already started."""


class UnknownInstanceError(BPMNEngineError):
    """The instance id is not started."""


class UnknownTaskError(BPMNEngineError):
    """The task id is not part of the instance's definition."""


class TaskStateError(BPMNEngineError):
    """The task or instance is not in a state that allows the action."""


class BadOutcomeError(BPMNEngineError):
    """The task outcome is not in the pinned vocabulary."""


class SeqOrderError(BPMNEngineError):
    """Caller seq did not strictly increase."""


class AuditKindError(BPMNEngineError):
    """Unknown audit kind for bpmn_engine_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BPMNEngineError(f"{what} must be str, got {type(value).__name__}")
    if not value.strip():
        raise BPMNEngineError(f"{what} must be non-empty")
    if len(value) > _MAX_ID_LEN:
        raise BPMNEngineError(f"{what} exceeds {_MAX_ID_LEN} chars")
    return value


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDefinitionError(
            f"bpmn_digest must be str, got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadDefinitionError("bpmn_digest must be 'sha256:' + 64 hex chars")
    hexpart = digest[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDefinitionError("bpmn_digest hex part is not lowercase hex")
    return digest


def _check_tasks(tasks: Any) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(tasks, (tuple, list)):
        raise BadTaskSpecError("tasks must be a tuple/list of (task_id, task_kind)")
    if len(tasks) > _MAX_TASKS:
        raise BadTaskSpecError(f"tasks exceeds {_MAX_TASKS}")
    seen: set = set()
    out = []
    for entry in tasks:
        if (
            not isinstance(entry, (tuple, list))
            or len(entry) != 2
        ):
            raise BadTaskSpecError("each task must be a (task_id, task_kind) pair")
        task_id, task_kind = entry
        task_id = _check_id(task_id, "task_id")
        if isinstance(task_kind, bool) or not isinstance(task_kind, str):
            raise BadTaskSpecError("task_kind must be str")
        if task_kind not in _TASK_KINDS:
            raise BadTaskSpecError(f"task_kind {task_kind!r} not in {_TASK_KINDS}")
        if task_id in seen:
            raise BadTaskSpecError(f"duplicate task_id {task_id!r}")
        seen.add(task_id)
        out.append((task_id, task_kind))
    return tuple(out)


def _check_outcome(outcome: Any) -> str:
    if isinstance(outcome, bool) or not isinstance(outcome, str):
        raise BadOutcomeError(f"outcome must be str, got {type(outcome).__name__}")
    if outcome not in _OUTCOMES:
        raise BadOutcomeError(f"outcome {outcome!r} not in {_OUTCOMES}")
    return outcome


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise BPMNEngineError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise BPMNEngineError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise BPMNEngineError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([BPMN_ENGINE_VERSION, *parts])
    ).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentRecord:
    """Frozen record of a deployed process definition."""

    definition_id: str
    bpmn_digest: str
    tasks: Tuple[Tuple[str, str], ...]
    seq: int
    digest: str
    schema: str = BPMN_ENGINE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("deploy", self.definition_id, self.bpmn_digest,
                              [list(t) for t in self.tasks], self.seq)
        except BPMNEngineError:
            return False
        return (
            recomputed == self.digest and self.schema == BPMN_ENGINE_SCHEMA
        )


@dataclass(frozen=True)
class StartRecord:
    """Frozen record of a started process instance."""

    instance_id: str
    definition_id: str
    seq: int
    digest: str
    schema: str = BPMN_ENGINE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("start", self.instance_id, self.definition_id, self.seq)
        except BPMNEngineError:
            return False
        return (
            recomputed == self.digest and self.schema == BPMN_ENGINE_SCHEMA
        )


@dataclass(frozen=True)
class TaskRecord:
    """Frozen record of a host-declared task outcome."""

    instance_id: str
    task_id: str
    task_kind: str
    outcome: str
    seq: int
    digest: str
    schema: str = BPMN_ENGINE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "task", self.instance_id, self.task_id, self.task_kind,
                self.outcome, self.seq,
            )
        except BPMNEngineError:
            return False
        return (
            recomputed == self.digest and self.schema == BPMN_ENGINE_SCHEMA
        )


@dataclass(frozen=True)
class CompletionRecord:
    """Frozen record of an instance whose tasks are all terminal."""

    instance_id: str
    definition_id: str
    seq: int
    digest: str
    schema: str = BPMN_ENGINE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("complete", self.instance_id, self.definition_id, self.seq)
        except BPMNEngineError:
            return False
        return (
            recomputed == self.digest and self.schema == BPMN_ENGINE_SCHEMA
        )


@dataclass(frozen=True)
class InstanceView:
    """Pure read view of one process instance's state."""

    instance_id: str
    definition_id: str
    state: str
    completed_tasks: Tuple[str, ...]
    pending_tasks: Tuple[str, ...]
    schema: str = BPMN_ENGINE_SCHEMA


@dataclass(frozen=True)
class EngineStats:
    """Pure read view of ledger-wide counters."""

    definitions: int
    instances: int
    completed_instances: int
    tasks_completed: int
    schema: str = BPMN_ENGINE_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def bpmn_engine_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the BPMN engine.

    Raw BPMN XML never crosses the audit boundary: ``detail`` may carry
    digests, ids, kinds, outcomes and counts -- never ``bpmn_xml``,
    ``payload``, ``xml``, ``bytes``, ``value`` or ``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"bpmn_xml", "payload", "xml", "bytes", "value", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": BPMN_ENGINE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class BPMNEngine:
    """Deterministic BPMN deployment/instance/task bookkeeping (single-host).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). Read views are pure:
    seq shape is validated, never consumed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._definitions: Dict[str, Dict[str, Any]] = {}
        self._instances: Dict[str, Dict[str, Any]] = {}
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(
        self, seq: int, reason: str, instance_id: str = "", definition_id: str = ""
    ) -> Dict[str, Any]:
        row = bpmn_engine_audit_event(
            KIND_REJECTED,
            {"reason": reason, "instance_id": instance_id, "definition_id": definition_id},
            seq,
        )
        self._audit.append(row)
        return row

    # -- mutations ----------------------------------------------------------

    def deploy(
        self,
        definition_id: str,
        bpmn_digest: str,
        seq: int,
        tasks: Tuple[Tuple[str, str], ...] = (),
    ) -> DeploymentRecord:
        """Register a process definition with its task list."""
        with self._lock:
            seq = self._claim(seq)
            try:
                definition_id = _check_id(definition_id, "definition_id")
            except BPMNEngineError as exc:
                self._reject(seq, str(exc))
                raise BadDefinitionError(str(exc)) from exc
            if definition_id in self._definitions:
                self._reject(seq, "duplicate definition", definition_id=definition_id)
                raise DuplicateDefinitionError(
                    f"definition {definition_id!r} already deployed"
                )
            try:
                bpmn_digest = _check_digest(bpmn_digest)
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), definition_id=definition_id)
                raise BadDefinitionError(str(exc)) from exc
            try:
                tasks = _check_tasks(tasks)
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), definition_id=definition_id)
                raise BadTaskSpecError(str(exc)) from exc
            record = DeploymentRecord(
                definition_id=definition_id,
                bpmn_digest=bpmn_digest,
                tasks=tasks,
                seq=seq,
                digest=_pin(
                    "deploy", definition_id, bpmn_digest,
                    [list(t) for t in tasks], seq,
                ),
            )
            self._definitions[definition_id] = {
                "bpmn_digest": bpmn_digest,
                "tasks": tasks,
            }
            self._audit.append(
                bpmn_engine_audit_event(
                    KIND_DEPLOYED,
                    {
                        "definition_id": definition_id,
                        "task_count": len(tasks),
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    def start(
        self, instance_id: str, definition_id: str, seq: int
    ) -> StartRecord:
        """Open a process instance against a deployed definition."""
        with self._lock:
            seq = self._claim(seq)
            try:
                instance_id = _check_id(instance_id, "instance_id")
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), instance_id=instance_id)
                raise BadInstanceError(str(exc)) from exc
            if instance_id in self._instances:
                self._reject(seq, "duplicate instance", instance_id=instance_id)
                raise DuplicateInstanceError(
                    f"instance {instance_id!r} already started"
                )
            try:
                definition_id = _check_id(definition_id, "definition_id")
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), instance_id=instance_id)
                raise UnknownDefinitionError(str(exc)) from exc
            definition = self._definitions.get(definition_id)
            if definition is None:
                self._reject(
                    seq, "unknown definition",
                    instance_id=instance_id, definition_id=definition_id,
                )
                raise UnknownDefinitionError(
                    f"definition {definition_id!r} not deployed"
                )
            record = StartRecord(
                instance_id=instance_id,
                definition_id=definition_id,
                seq=seq,
                digest=_pin("start", instance_id, definition_id, seq),
            )
            self._instances[instance_id] = {
                "definition_id": definition_id,
                "state": _STATE_ACTIVE,
                "done": {},
                "start_seq": seq,
            }
            self._audit.append(
                bpmn_engine_audit_event(
                    KIND_STARTED,
                    {
                        "instance_id": instance_id,
                        "definition_id": definition_id,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    def task(
        self,
        instance_id: str,
        task_id: str,
        seq: int,
        outcome: str = "completed",
    ) -> TaskRecord:
        """Book a host-declared task outcome for an active instance.

        Returns the booked ``TaskRecord``; when the last pending task
        of the instance closes, a ``CompletionRecord`` is booked and
        audited alongside (reachable via ``audit_log()``).
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                instance_id = _check_id(instance_id, "instance_id")
                task_id = _check_id(task_id, "task_id")
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), instance_id=instance_id)
                raise BadInstanceError(str(exc)) from exc
            entry = self._instances.get(instance_id)
            if entry is None:
                self._reject(seq, "unknown instance", instance_id=instance_id)
                raise UnknownInstanceError(
                    f"instance {instance_id!r} not started"
                )
            if entry["state"] == _STATE_COMPLETED:
                self._reject(seq, "instance terminal", instance_id=instance_id)
                raise TaskStateError(
                    f"instance {instance_id!r} already completed"
                )
            tasks = dict(self._definitions[entry["definition_id"]]["tasks"])
            if task_id not in tasks:
                self._reject(seq, "unknown task", instance_id=instance_id)
                raise UnknownTaskError(
                    f"task {task_id!r} not in definition {entry['definition_id']!r}"
                )
            if task_id in entry["done"]:
                self._reject(seq, "task already terminal", instance_id=instance_id)
                raise TaskStateError(
                    f"task {task_id!r} already booked for {instance_id!r}"
                )
            try:
                outcome = _check_outcome(outcome)
            except BPMNEngineError as exc:
                self._reject(seq, str(exc), instance_id=instance_id)
                raise BadOutcomeError(str(exc)) from exc
            task_kind = tasks[task_id]
            record = TaskRecord(
                instance_id=instance_id,
                task_id=task_id,
                task_kind=task_kind,
                outcome=outcome,
                seq=seq,
                digest=_pin("task", instance_id, task_id, task_kind, outcome, seq),
            )
            entry["done"][task_id] = record
            self._audit.append(
                bpmn_engine_audit_event(
                    KIND_TASK_COMPLETED,
                    {
                        "instance_id": instance_id,
                        "task_id": task_id,
                        "task_kind": task_kind,
                        "outcome": outcome,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            if len(entry["done"]) == len(tasks):
                entry["state"] = _STATE_COMPLETED
                completion = CompletionRecord(
                    instance_id=instance_id,
                    definition_id=entry["definition_id"],
                    seq=seq,
                    digest=_pin(
                        "complete", instance_id, entry["definition_id"], seq
                    ),
                )
                self._audit.append(
                    bpmn_engine_audit_event(
                        KIND_COMPLETED,
                        {
                            "instance_id": instance_id,
                            "definition_id": entry["definition_id"],
                            "task_count": len(tasks),
                            "digest": completion.digest,
                        },
                        seq,
                    )
                )
            return record

    # -- pure views ----------------------------------------------------------

    def deployment_spec(
        self, definition_id: str
    ) -> Optional[Tuple[str, Tuple[Tuple[str, str], ...]]]:
        """Declared ``(bpmn_digest, tasks)`` for a definition id, or None."""
        definition_id = _check_id(definition_id, "definition_id")
        with self._lock:
            entry = self._definitions.get(definition_id)
            if entry is None:
                return None
            return (entry["bpmn_digest"], entry["tasks"])

    def instance(self, instance_id: str) -> Optional[InstanceView]:
        """State of one process instance, or None if never started."""
        instance_id = _check_id(instance_id, "instance_id")
        with self._lock:
            entry = self._instances.get(instance_id)
            if entry is None:
                return None
            tasks = dict(self._definitions[entry["definition_id"]]["tasks"])
            done = tuple(sorted(entry["done"]))
            pending = tuple(sorted(t for t in tasks if t not in entry["done"]))
            return InstanceView(
                instance_id=instance_id,
                definition_id=entry["definition_id"],
                state=entry["state"],
                completed_tasks=done,
                pending_tasks=pending,
            )

    def instance_ids(self) -> Tuple[str, ...]:
        """Ids of started instances, sorted."""
        with self._lock:
            return tuple(sorted(self._instances))

    def definition_ids(self) -> Tuple[str, ...]:
        """Ids of deployed definitions, sorted."""
        with self._lock:
            return tuple(sorted(self._definitions))

    def pending_tasks(self, instance_id: str) -> Tuple[str, ...]:
        """Sorted pending task ids for an active instance."""
        view = self.instance(instance_id)
        if view is None:
            raise UnknownInstanceError(f"instance {instance_id!r} not started")
        return view.pending_tasks

    def stats(self) -> EngineStats:
        """Ledger-wide counters."""
        with self._lock:
            completed = sum(
                1 for e in self._instances.values() if e["state"] == _STATE_COMPLETED
            )
            tasks_done = sum(len(e["done"]) for e in self._instances.values())
            return EngineStats(
                definitions=len(self._definitions),
                instances=len(self._instances),
                completed_instances=completed,
                tasks_completed=tasks_done,
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The audit rows booked so far."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check."""
    engine = BPMNEngine()
    rec = engine.deploy(
        "proc-1",
        "sha256:" + "ab" * 32,
        1,
        (("approve", "user"), ("charge", "service")),
    )
    assert rec.verify(), "deployment verify"
    start = engine.start("inst-1", "proc-1", 2)
    assert start.verify(), "start verify"
    t1 = engine.task("inst-1", "approve", 3)
    assert t1.verify() and t1.task_kind == "user"
    view = engine.instance("inst-1")
    assert view is not None and view.state == "active"
    assert view.pending_tasks == ("charge",)
    t2 = engine.task("inst-1", "charge", 4, outcome="skipped")
    assert t2.verify() and t2.outcome == "skipped"
    view = engine.instance("inst-1")
    assert view is not None and view.state == "completed"
    stats = engine.stats()
    assert stats.definitions == 1 and stats.instances == 1
    assert stats.completed_instances == 1 and stats.tasks_completed == 2
    kinds = [row["kind"] for row in engine.audit_log()]
    assert kinds == [
        "bpmn.deployed",
        "bpmn.started",
        "bpmn.task-completed",
        "bpmn.task-completed",
        "bpmn.completed",
    ], kinds
    print(
        "bpmn-engine OK: deploy, start, task, complete, pins, audit"
    )


if __name__ == "__main__":
    main()
