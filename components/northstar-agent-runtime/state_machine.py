"""Finite state machine bookkeeping: declared states, guarded transitions.

A run of a deterministic finite state machine -- idle -> running ->
paused -> running -> done -- is recorded here as a ledger of *declared*
facts. This module is the *bookkeeping* half of the FSM contract (the
execution half -- whatever the states *do* -- is the host's):

- :meth:`StateMachine.add_machine` registers a machine behind an
  ``initial_state``.
- :meth:`StateMachine.add_transition` declares one legal edge
  ``(from_state, event) -> to_state``, optionally behind a named guard.
- :meth:`StateMachine.transition` fires one event: the guard (if any) is
  evaluated against a host-supplied ``context`` mapping, and on success
  the machine moves to the target state. A blocked guard or an
  undeclared edge is refused **fail-closed** -- the seq is consumed and
  a ``state-machine.rejected`` audit row is booked.
- :meth:`StateMachine.guard` is the pure read companion: it reports
  whether an event *would* be allowed from the current state, as data.
- :meth:`StateMachine.reset` returns a machine to its initial state.

Guards are host-registered callables ``context -> bool`` (see
:meth:`StateMachine.register_guard`). The module *books* the verdict it
computed; it cannot prove the predicate was true -- a lying predicate
is the host's lie, pinned for auditors.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall clock anywhere), ``RLock``-guarded, fail-closed
taxonomy, stdlib-only plus the shared ``canonical_json`` try/except
fallback, type-tagged ``sha256:`` digest pins, ``audit.ndjson/1``
events. Raw ``context`` mappings never cross the audit boundary.

Honest scope: this module books *declared* topology and host-reported
outcomes. It cannot prove a state was semantically reached, cannot
verify guard predicates, and cannot prevent a host from ignoring a
booked transition. A ``TransitionRecord`` proves only that the ledger
advanced from ``from_state`` to ``to_state`` on the recorded seq.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Version pin for this module's record shape.
STATE_MACHINE_VERSION = "state-machine.v1"

#: Schema pin carried by records and audit events.
STATE_MACHINE_SCHEMA = "northstar.state-machine.v1"

#: Domain separation prefix for digest pins.
_DIGEST_DOMAIN = b"northstar-state-machine.v1:"

#: Audit event kinds.
KIND_MACHINE_ADDED = "machine-added"
KIND_TRANSITION_DEFINED = "transition-defined"
KIND_TRANSITIONED = "transitioned"
KIND_RESET = "reset"
KIND_REJECTED = "rejected"

_AUDIT_KINDS = frozenset(
    {
        KIND_MACHINE_ADDED,
        KIND_TRANSITION_DEFINED,
        KIND_TRANSITIONED,
        KIND_RESET,
        KIND_REJECTED,
    }
)


class StateMachineError(Exception):
    """Base error: any state-machine contract violation."""


class BadMachineError(StateMachineError):
    """Malformed machine id or state name."""


class DuplicateMachineError(StateMachineError):
    """A machine id was registered twice (ids are never recycled)."""


class UnknownMachineError(StateMachineError):
    """A mutation or read named an unregistered machine."""


class BadStateError(StateMachineError):
    """A state name was malformed."""


class BadEventError(StateMachineError):
    """An event name was malformed."""


class DuplicateTransitionError(StateMachineError):
    """An edge for (from_state, event) was already declared."""


class UnknownTransitionError(StateMachineError):
    """No edge is declared for (from_state, event)."""


class GuardBlockedError(StateMachineError):
    """The guard for the edge evaluated False: transition refused."""


class BadGuardError(StateMachineError):
    """A guard name or predicate was malformed."""


class UnknownGuardError(StateMachineError):
    """A transition named a guard that was never registered."""


class SeqOrderError(StateMachineError):
    """A seq was not a strictly increasing int (or was a bool)."""


class AuditKindError(StateMachineError):
    """The audit builder was asked for an unknown kind."""


def _check_text(value: object, name: str) -> str:
    """Validate a name field: str (never bool), non-empty, no whitespace."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    if len(value) > 256:
        raise ValueError(f"{name} must be <= 256 chars")
    stripped = value.strip()
    if stripped != value or not value:
        raise ValueError(f"{name} must not have leading/trailing whitespace")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_context(value: object) -> Mapping[str, Any]:
    """Validate a guard context: a mapping with str keys (never audited)."""
    if not isinstance(value, Mapping):
        raise TypeError(
            f"context must be a Mapping, got {type(value).__name__}"
        )
    for key in value:
        if isinstance(key, bool) or not isinstance(key, str):
            raise TypeError("context keys must be str")
    return value


def _digest_of(tag: bytes, payload: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _DIGEST_DOMAIN + tag + jcs_canonical_json(payload)
    ).hexdigest()


@dataclass(frozen=True)
class MachineRecord:
    """A registered machine and its initial state."""

    machine_id: str
    initial_state: str
    seq: int
    digest: str = field(compare=True)
    version: str = STATE_MACHINE_VERSION
    schema: str = STATE_MACHINE_SCHEMA

    @staticmethod
    def build(machine_id: str, initial_state: str, seq: int) -> "MachineRecord":
        payload = {
            "machine_id": machine_id,
            "initial_state": initial_state,
            "seq": seq,
        }
        return MachineRecord(
            machine_id=machine_id,
            initial_state=initial_state,
            seq=seq,
            digest=_digest_of(b"machine:", payload),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            b"machine:",
            {
                "machine_id": self.machine_id,
                "initial_state": self.initial_state,
                "seq": self.seq,
            },
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "machine",
            "machine_id": self.machine_id,
            "initial_state": self.initial_state,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TransitionDefRecord:
    """One declared edge: (from_state, event) -> to_state, maybe guarded."""

    machine_id: str
    from_state: str
    event: str
    to_state: str
    guard_name: str
    seq: int
    digest: str = field(compare=True)
    version: str = STATE_MACHINE_VERSION
    schema: str = STATE_MACHINE_SCHEMA

    @staticmethod
    def build(
        machine_id: str,
        from_state: str,
        event: str,
        to_state: str,
        guard_name: str,
        seq: int,
    ) -> "TransitionDefRecord":
        payload = {
            "machine_id": machine_id,
            "from_state": from_state,
            "event": event,
            "to_state": to_state,
            "guard_name": guard_name,
            "seq": seq,
        }
        return TransitionDefRecord(
            machine_id=machine_id,
            from_state=from_state,
            event=event,
            to_state=to_state,
            guard_name=guard_name,
            seq=seq,
            digest=_digest_of(b"transition-def:", payload),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            b"transition-def:",
            {
                "machine_id": self.machine_id,
                "from_state": self.from_state,
                "event": self.event,
                "to_state": self.to_state,
                "guard_name": self.guard_name,
                "seq": self.seq,
            },
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "transition-def",
            "machine_id": self.machine_id,
            "from_state": self.from_state,
            "event": self.event,
            "to_state": self.to_state,
            "guard_name": self.guard_name,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TransitionRecord:
    """One fired edge: the ledger advanced from -> to on the recorded seq."""

    machine_id: str
    event: str
    from_state: str
    to_state: str
    seq: int
    digest: str = field(compare=True)
    version: str = STATE_MACHINE_VERSION
    schema: str = STATE_MACHINE_SCHEMA

    @staticmethod
    def build(
        machine_id: str,
        event: str,
        from_state: str,
        to_state: str,
        seq: int,
    ) -> "TransitionRecord":
        payload = {
            "machine_id": machine_id,
            "event": event,
            "from_state": from_state,
            "to_state": to_state,
            "seq": seq,
        }
        return TransitionRecord(
            machine_id=machine_id,
            event=event,
            from_state=from_state,
            to_state=to_state,
            seq=seq,
            digest=_digest_of(b"transition:", payload),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            b"transition:",
            {
                "machine_id": self.machine_id,
                "event": self.event,
                "from_state": self.from_state,
                "to_state": self.to_state,
                "seq": self.seq,
            },
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "transition",
            "machine_id": self.machine_id,
            "event": self.event,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class GuardVerdict:
    """Pure read verdict: would ``event`` be allowed from the current state?

    ``allowed`` is data, never raised: ``reason`` is one of ``"ok"``,
    ``"no-edge"`` (no declared transition for this event), or
    ``"guard-blocked"`` (the guard predicate returned False).
    """

    machine_id: str
    event: str
    from_state: str
    allowed: bool
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "guard-verdict",
            "machine_id": self.machine_id,
            "event": self.event,
            "from_state": self.from_state,
            "allowed": self.allowed,
            "reason": self.reason,
            "version": STATE_MACHINE_VERSION,
            "schema": STATE_MACHINE_SCHEMA,
        }


@dataclass(frozen=True)
class StateView:
    """Pure read view of a machine's current state."""

    machine_id: str
    state: str
    transitions_fired: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "state-view",
            "machine_id": self.machine_id,
            "state": self.state,
            "transitions_fired": self.transitions_fired,
            "version": STATE_MACHINE_VERSION,
            "schema": STATE_MACHINE_SCHEMA,
        }


@dataclass(frozen=True)
class ResetRecord:
    """A machine returned to its initial state."""

    machine_id: str
    from_state: str
    to_state: str
    seq: int
    digest: str = field(compare=True)
    version: str = STATE_MACHINE_VERSION
    schema: str = STATE_MACHINE_SCHEMA

    @staticmethod
    def build(
        machine_id: str, from_state: str, to_state: str, seq: int
    ) -> "ResetRecord":
        payload = {
            "machine_id": machine_id,
            "from_state": from_state,
            "to_state": to_state,
            "seq": seq,
        }
        return ResetRecord(
            machine_id=machine_id,
            from_state=from_state,
            to_state=to_state,
            seq=seq,
            digest=_digest_of(b"reset:", payload),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            b"reset:",
            {
                "machine_id": self.machine_id,
                "from_state": self.from_state,
                "to_state": self.to_state,
                "seq": self.seq,
            },
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": "reset",
            "machine_id": self.machine_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


def state_machine_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape a state-machine fact as an ``audit.ndjson/1`` record.

    Only ids, state/event names, guard *names* (never predicate code),
    and digest pins cross the audit boundary -- raw ``context`` mappings
    are banned (they are host data, never evidence).
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise TypeError("detail must be a Mapping")
    for banned in ("context", "predicate", "payload", "raw", "value"):
        if banned in detail:
            raise StateMachineError(
                f"key {banned!r} is banned from the audit boundary"
            )
    record: Dict[str, Any] = {
        "audit": "audit.ndjson/1",
        "kind": f"state-machine.{kind}",
        "seq": seq,
        "version": STATE_MACHINE_VERSION,
        "schema": STATE_MACHINE_SCHEMA,
    }
    record.update({k: v for k, v in detail.items()})
    return record


class StateMachine:
    """Deterministic single-host finite state machine ledger.

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position) and book a
    ``state-machine.rejected`` audit row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # machine_id -> MachineRecord; machine_id -> current state.
        self._machines: Dict[str, MachineRecord] = {}
        self._current: Dict[str, str] = {}
        # (machine_id, from_state, event) -> TransitionDefRecord.
        self._edges: Dict[Tuple[str, str, str], TransitionDefRecord] = {}
        # guard name -> host predicate (context -> bool).
        self._guards: Dict[str, Callable[[Mapping[str, Any]], bool]] = {}
        # machine_id -> ordered fired TransitionRecords.
        self._history: Dict[str, List[TransitionRecord]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _consume_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(state_machine_audit_event(kind, detail, seq))

    def _reject_locked(
        self, seq: int, error: StateMachineError, **detail: Any
    ) -> None:
        row = {"error": type(error).__name__, "message": str(error)}
        row.update(detail)
        self._emit(KIND_REJECTED, row, seq)
        raise error

    def _check_machine_id(self, value: object) -> str:
        try:
            return _check_text(value, "machine_id")
        except (TypeError, ValueError) as exc:
            raise BadMachineError(str(exc)) from exc

    def _check_state(self, value: object) -> str:
        try:
            return _check_text(value, "state")
        except (TypeError, ValueError) as exc:
            raise BadStateError(str(exc)) from exc

    def _check_event(self, value: object) -> str:
        try:
            return _check_text(value, "event")
        except (TypeError, ValueError) as exc:
            raise BadEventError(str(exc)) from exc

    def _lookup_machine_locked(self, machine_id: str) -> MachineRecord:
        try:
            return self._machines[machine_id]
        except KeyError:
            raise UnknownMachineError(
                f"machine_id {machine_id!r} is not registered"
            ) from None

    # -- public --------------------------------------------------------

    def register_guard(
        self, name: str, predicate: Callable[[Mapping[str, Any]], bool]
    ) -> None:
        """Register a named guard predicate (host-supplied, GIGO).

        The predicate receives the transition ``context`` mapping and
        returns a bool. Registration is a pure registry write: no seq
        is consumed and no audit row is written -- the *verdicts* are
        what get audited, not the predicate.
        """
        with self._lock:
            name = _check_text(name, "guard name")
            if not callable(predicate):
                raise BadGuardError("predicate must be callable")
            self._guards[name] = predicate

    def add_machine(
        self, machine_id: str, initial_state: str, seq: int
    ) -> MachineRecord:
        """Register a machine behind an initial state.

        Ids are never recycled: re-registering raises
        ``DuplicateMachineError`` fail-closed.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                machine_id = self._check_machine_id(machine_id)
                initial_state = self._check_state(initial_state)
                if machine_id in self._machines:
                    raise DuplicateMachineError(
                        f"machine_id {machine_id!r} already registered"
                    )
            except StateMachineError as exc:
                if consumed:
                    self._reject_locked(seq, exc, machine_id=str(machine_id))
                raise
            record = MachineRecord.build(machine_id, initial_state, seq)
            self._machines[machine_id] = record
            self._current[machine_id] = initial_state
            self._history[machine_id] = []
            self._emit(
                KIND_MACHINE_ADDED,
                {
                    "machine_id": machine_id,
                    "initial_state": initial_state,
                    "digest": record.digest,
                },
                seq,
            )
            return record

    def add_transition(
        self,
        machine_id: str,
        from_state: str,
        event: str,
        to_state: str,
        seq: int,
        guard_name: str = "",
    ) -> TransitionDefRecord:
        """Declare one legal edge ``(from_state, event) -> to_state``.

        ``guard_name`` names a predicate registered with
        :meth:`register_guard`; ``""`` means unconditional. Naming an
        unregistered guard raises ``UnknownGuardError`` fail-closed.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                machine_id = self._check_machine_id(machine_id)
                self._lookup_machine_locked(machine_id)
                from_state = self._check_state(from_state)
                event = self._check_event(event)
                to_state = self._check_state(to_state)
                if not isinstance(guard_name, str):
                    raise BadGuardError("guard_name must be str")
                if guard_name and guard_name not in self._guards:
                    raise UnknownGuardError(
                        f"guard {guard_name!r} is not registered"
                    )
                key = (machine_id, from_state, event)
                if key in self._edges:
                    raise DuplicateTransitionError(
                        f"edge ({from_state!r}, {event!r}) already declared"
                    )
            except StateMachineError as exc:
                if consumed:
                    self._reject_locked(
                        seq, exc, machine_id=str(machine_id)
                    )
                raise
            record = TransitionDefRecord.build(
                machine_id, from_state, event, to_state, guard_name, seq
            )
            self._edges[(machine_id, from_state, event)] = record
            self._emit(
                KIND_TRANSITION_DEFINED,
                {
                    "machine_id": machine_id,
                    "from_state": from_state,
                    "event": event,
                    "to_state": to_state,
                    "guard_name": guard_name,
                    "digest": record.digest,
                },
                seq,
            )
            return record

    def guard(
        self,
        machine_id: str,
        event: str,
        seq: int,
        context: Optional[Mapping[str, Any]] = None,
    ) -> GuardVerdict:
        """Would ``event`` fire from the current state? Verdict as data.

        Pure read: the seq shape is validated but never consumed, and no
        audit row is written.
        """
        with self._lock:
            seq = _check_seq(seq)  # validated, not consumed
            machine_id = self._check_machine_id(machine_id)
            event = self._check_event(event)
            self._lookup_machine_locked(machine_id)
            ctx = _check_context(context or {})
            current = self._current[machine_id]
            edge = self._edges.get((machine_id, current, event))
            if edge is None:
                return GuardVerdict(
                    machine_id, event, current, False, "no-edge"
                )
            if edge.guard_name:
                try:
                    ok = bool(self._guards[edge.guard_name](ctx))
                except Exception:
                    ok = False
                if not ok:
                    return GuardVerdict(
                        machine_id, event, current, False, "guard-blocked"
                    )
            return GuardVerdict(machine_id, event, current, True, "ok")

    def transition(
        self,
        machine_id: str,
        event: str,
        seq: int,
        context: Optional[Mapping[str, Any]] = None,
    ) -> TransitionRecord:
        """Fire one event from the current state.

        An undeclared edge raises ``UnknownTransitionError``; a guard
        that evaluates False (or raises) raises ``GuardBlockedError``.
        Both are fail-closed: the seq is consumed and a rejected audit
        row is booked.
        """
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                machine_id = self._check_machine_id(machine_id)
                event = self._check_event(event)
                self._lookup_machine_locked(machine_id)
                ctx = _check_context(context or {})
                current = self._current[machine_id]
                edge = self._edges.get((machine_id, current, event))
                if edge is None:
                    raise UnknownTransitionError(
                        f"no edge for ({current!r}, {event!r})"
                    )
                if edge.guard_name:
                    try:
                        ok = bool(self._guards[edge.guard_name](ctx))
                    except Exception:
                        ok = False
                    if not ok:
                        raise GuardBlockedError(
                            f"guard {edge.guard_name!r} blocked "
                            f"({current!r}, {event!r})"
                        )
            except StateMachineError as exc:
                if consumed:
                    self._reject_locked(
                        seq, exc, machine_id=str(machine_id)
                    )
                raise
            record = TransitionRecord.build(
                machine_id, event, current, edge.to_state, seq
            )
            self._current[machine_id] = edge.to_state
            self._history[machine_id].append(record)
            self._emit(
                KIND_TRANSITIONED,
                {
                    "machine_id": machine_id,
                    "event": event,
                    "from_state": current,
                    "to_state": edge.to_state,
                    "digest": record.digest,
                },
                seq,
            )
            return record

    def state(self, machine_id: str, seq: int) -> StateView:
        """Current state of a machine. Pure read: seq validated, not consumed."""
        with self._lock:
            seq = _check_seq(seq)  # validated, not consumed
            machine_id = self._check_machine_id(machine_id)
            self._lookup_machine_locked(machine_id)
            return StateView(
                machine_id=machine_id,
                state=self._current[machine_id],
                transitions_fired=len(self._history[machine_id]),
            )

    def history(self, machine_id: str) -> Tuple[TransitionRecord, ...]:
        """Ordered fired transitions. Pure read."""
        with self._lock:
            machine_id = self._check_machine_id(machine_id)
            self._lookup_machine_locked(machine_id)
            return tuple(self._history[machine_id])

    def reset(self, machine_id: str, seq: int) -> ResetRecord:
        """Return a machine to its initial state."""
        with self._lock:
            consumed = False
            try:
                seq = self._consume_seq(seq)
                consumed = True
                machine_id = self._check_machine_id(machine_id)
                machine = self._lookup_machine_locked(machine_id)
            except StateMachineError as exc:
                if consumed:
                    self._reject_locked(seq, exc, machine_id=str(machine_id))
                raise
            current = self._current[machine_id]
            record = ResetRecord.build(
                machine_id, current, machine.initial_state, seq
            )
            self._current[machine_id] = machine.initial_state
            self._emit(
                KIND_RESET,
                {
                    "machine_id": machine_id,
                    "from_state": current,
                    "to_state": machine.initial_state,
                    "digest": record.digest,
                },
                seq,
            )
            return record

    def machine_ids(self) -> Tuple[str, ...]:
        """Registered machine ids, sorted. Pure read."""
        with self._lock:
            return tuple(sorted(self._machines))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Booked audit rows, oldest first. Pure read."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    sm = StateMachine()
    sm.add_machine("job", "idle", seq=0)
    sm.add_transition("job", "idle", "start", "running", seq=1)
    sm.add_transition("job", "running", "pause", "paused", seq=2)
    sm.add_transition("job", "paused", "resume", "running", seq=3)
    sm.add_transition("job", "running", "finish", "done", seq=4)

    # Guarded edge: finish requires the context flag.
    sm.register_guard("approved", lambda ctx: bool(ctx.get("approved")))
    sm.add_transition("job", "paused", "finish", "done", seq=5,
                      guard_name="approved")

    view = sm.state("job", seq=5)
    assert view.state == "idle", view
    assert sm.guard("job", "start", seq=5).allowed is True
    assert sm.guard("job", "pause", seq=5).reason == "no-edge"

    rec = sm.transition("job", "start", seq=6)
    assert (rec.from_state, rec.to_state) == ("idle", "running"), rec
    assert rec.verify()

    # Guard blocks without the flag; passes with it.
    sm.transition("job", "pause", seq=7)
    blocked = sm.guard("job", "finish", seq=8)
    assert blocked.allowed is False and blocked.reason == "guard-blocked"
    try:
        sm.transition("job", "finish", seq=8)
    except GuardBlockedError:
        pass
    else:  # pragma: no cover
        raise AssertionError("guard should have blocked")
    rec = sm.transition("job", "finish", seq=9, context={"approved": True})
    assert rec.to_state == "done", rec
    assert len(sm.history("job")) == 3

    sm.reset("job", seq=10)
    assert sm.state("job", seq=10).state == "idle"
    print("state-machine OK: declare, guard, transition, reset, audit")


if __name__ == "__main__":
    main()
