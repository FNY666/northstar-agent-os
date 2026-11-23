"""Event sourcing: append-only event log with replay for auditability.

Research motivation: event sourcing separates *what happened* (an immutable,
ordered stream of events) from *what is* (derived state). For an agent
runtime the event stream is the ground truth an auditor can replay; any
derived view can be rebuilt deterministically from the log, so disputes
about "what did the agent see/do" reduce to disputes about the log itself.

Public API:

- ``Event`` -- frozen record: ``event_id`` (unique audit identifier),
  ``event_type`` (routing key for reducers), ``payload`` (canonicalizable
  mapping), ``seq`` (caller-supplied int ordering, no wall-clock), and a
  ``sha256:`` digest pin over the canonical event body chained to the
  previous head (tamper-evidence).
- ``EventStore`` -- append-only store. ``append(event)`` enforces strictly
  increasing seqs and hash-chain continuity (fail-closed on out-of-order,
  replayed, or re-chained events). ``events()`` / ``events_since(seq)`` /
  ``events_of_type(event_type)`` provide deterministic views;
  ``verify_chain()`` re-checks the whole chain.
- ``replay(events, handlers, initial=None)`` -- folds events in seq order
  through caller-supplied reducers ``(state, payload) -> state`` to rebuild
  derived state. Unknown event types raise ``ReplayError`` (fail closed --
  a replay that silently drops events would certify a lie).
- ``SnapshotRecord`` -- frozen pin of derived state at an event seq:
  ``EventStore.snapshot(state)`` books one through the current head
  (fail-closed on empty store, duplicate ``at_seq`` refused);
  ``replay_from(snapshot, handlers)`` / ``replay_from_latest(handlers)``
  rebuild state by folding only the events *after* the snapshot --
  snapshots accelerate replay but never replace the log.

Honest scope:

- This is the log-and-replay layer, not a database: no persistence (the
  host owns durability), no concurrency control beyond a lock for
  append-order atomicity.
- Snapshots pin *host-declared* derived state at a chain head; the module
  cannot verify the state equals what replay would actually produce --
  a lying snapshot is a host lie, pinned for the auditor to spot.
- The hash chain proves *internal consistency* of the log the host hands
  back -- it cannot prove the host didn't withhold a prefix (that needs an
  external head anchor, the host's job).
- Payloads must be JCS-canonicalizable (str/int/float/bool/None/list/dict
  with str keys). Non-canonicalizable values are rejected at construction
  so an event can always be pinned and replayed deterministically.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
EVENT_SOURCING_VERSION = "event-sourcing.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.event-sourcing.v1"

#: Genesis head digest: the chain anchor before the first event.
GENESIS_HEAD = "sha256:" + "0" * 64


class EventSourcingError(Exception):
    """Base error for the event-sourcing layer (programming errors)."""


class OutOfOrderAppend(EventSourcingError):
    """Raised when an append breaks seq monotonicity or chain continuity."""


class ReplayError(EventSourcingError):
    """Raised when replay cannot proceed deterministically."""


class SnapshotError(EventSourcingError):
    """Raised when a snapshot cannot be booked (empty store, bad state)."""


class DuplicateSnapshotError(SnapshotError):
    """Raised when a snapshot already exists at the same event seq."""


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_payload(value: object) -> Dict[str, Any]:
    """Validate a payload: mapping with str keys, canonicalizable."""
    if not isinstance(value, Mapping):
        raise TypeError(f"payload must be a mapping, got {type(value).__name__}")
    for key in value.keys():
        if not isinstance(key, str):
            raise TypeError("payload keys must be str")
    try:
        jcs_canonical_json(dict(value))
    except Exception as exc:
        raise TypeError(f"payload is not canonicalizable: {exc}") from exc
    return dict(value)


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:<64 hex>`` digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{name} must look like 'sha256:<64 hex>'")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} hex part must be lowercase hex")
    return value


_MAX_SAFE_INT = 2**53 - 1


def _check_snapshot_state(value: object) -> Any:
    """Validate derived snapshot state: JCS-canonicalizable, safe numbers.

    Accepts str/int/float/bool/None/list/tuple/dict (dict keys must be
    str). ``bool`` is not ``int`` here -- it canonicalizes separately.
    ``|int| >= 2**53`` and non-finite floats are refused so the digest
    pin is always reproducible. Returns a normalized copy (tuples become
    lists, mappings become plain dicts) so the frozen record cannot alias
    a caller-mutated object.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise SnapshotError("int state outside safe range")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise SnapshotError("non-finite float state refused")
        return value
    if isinstance(value, (list, tuple)):
        return [_check_snapshot_state(item) for item in value]
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for key in value.keys():
            if not isinstance(key, str):
                raise SnapshotError("state dict keys must be str")
            out[key] = _check_snapshot_state(value[key])
        return out
    raise SnapshotError(
        f"state must be str/int/float/bool/None/list/dict, "
        f"got {type(value).__name__}"
    )


@dataclass(frozen=True)
class Event:
    """One immutable fact in the log.

    The digest pins the canonical body ``(event_id, event_type, payload,
    seq, prev_head)`` so every event commits to the chain that came before
    it. ``prev_head`` of the first event is ``GENESIS_HEAD``.
    """

    event_id: str
    event_type: str
    payload: Dict[str, Any]
    seq: int
    prev_head: str
    digest: str

    def __init__(self, event_id: object, event_type: object, payload: object,
                 seq: object, prev_head: object = GENESIS_HEAD) -> None:
        event_id = _check_text(event_id, "event_id")
        event_type = _check_text(event_type, "event_type")
        payload = _check_payload(payload)
        seq = _check_seq(seq)
        prev_head = _check_digest(prev_head, "prev_head")
        body = {
            "event_id": event_id,
            "event_type": event_type,
            "payload": payload,
            "seq": seq,
            "prev_head": prev_head,
        }
        digest = "sha256:" + jcs_sha256_hex(body)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "prev_head", prev_head)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe view with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "seq": self.seq,
            "prev_head": self.prev_head,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Recompute the digest; True iff this event is internally intact."""
        body = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "seq": self.seq,
            "prev_head": self.prev_head,
        }
        expected = "sha256:" + jcs_sha256_hex(body)
        return _constant_time_eq(self.digest, expected)


def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison for digest checks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0


class EventStore:
    """Append-only, hash-chained event log.

    Appends are atomic under a lock. Seq numbers must be strictly
    increasing (no rewrites, no replays); each event's ``prev_head`` must
    equal the store's current head. Violations raise ``OutOfOrderAppend``
    and append nothing.
    """

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._by_id: Dict[str, Event] = {}
        self._snapshots: Dict[int, SnapshotRecord] = {}
        self._lock = threading.Lock()

    def append(self, event: Event) -> Event:
        """Append one event; fail closed on ordering/chain violations."""
        if not isinstance(event, Event):
            raise TypeError(f"expected Event, got {type(event).__name__}")
        with self._lock:
            if event.event_id in self._by_id:
                raise OutOfOrderAppend(
                    f"duplicate event_id: {event.event_id!r}")
            if self._events:
                last = self._events[-1]
                if event.seq <= last.seq:
                    raise OutOfOrderAppend(
                        f"seq {event.seq} not after last seq {last.seq}")
                if event.prev_head != last.digest:
                    raise OutOfOrderAppend(
                        "prev_head does not match current head")
            else:
                if event.seq != 0 and self._events == [] and event.prev_head != GENESIS_HEAD:
                    # First event must chain from genesis; seq may start
                    # anywhere the caller chooses (>= 0).
                    raise OutOfOrderAppend("first event must chain GENESIS_HEAD")
                if event.prev_head != GENESIS_HEAD:
                    raise OutOfOrderAppend("first event must chain GENESIS_HEAD")
            self._events.append(event)
            self._by_id[event.event_id] = event
            return event

    def head(self) -> str:
        """Current head digest (GENESIS_HEAD when empty)."""
        with self._lock:
            if not self._events:
                return GENESIS_HEAD
            return self._events[-1].digest

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def events(self) -> tuple[Event, ...]:
        """All events in append (seq) order."""
        with self._lock:
            return tuple(self._events)

    def events_since(self, seq: int) -> tuple[Event, ...]:
        """Events with ``event.seq > seq``, in order."""
        _check_seq(seq)
        with self._lock:
            return tuple(e for e in self._events if e.seq > seq)

    def events_of_type(self, event_type: str) -> tuple[Event, ...]:
        """Events of one type, in append order."""
        _check_text(event_type, "event_type")
        with self._lock:
            return tuple(e for e in self._events if e.event_type == event_type)

    def get(self, event_id: str) -> Event:
        """Fetch by id; KeyError on unknown id."""
        _check_text(event_id, "event_id")
        with self._lock:
            return self._by_id[event_id]

    def verify_chain(self) -> bool:
        """Re-verify every event digest and every chain link."""
        with self._lock:
            prev = GENESIS_HEAD
            for event in self._events:
                if not event.verify():
                    return False
                if event.prev_head != prev:
                    return False
                prev = event.digest
            return True

    def snapshot(self, state: Any) -> SnapshotRecord:
        """Book a snapshot of derived state through the current head.

        ``at_seq`` is the seq of the last appended event. Fail closed on
        an empty store (nothing to pin) and on a duplicate ``at_seq`` (a
        booked snapshot is never overwritten).
        """
        with self._lock:
            if not self._events:
                raise SnapshotError("cannot snapshot an empty store")
            at_seq = self._events[-1].seq
            head = self._events[-1].digest
            if at_seq in self._snapshots:
                raise DuplicateSnapshotError(
                    f"snapshot already booked at seq {at_seq}")
            record = SnapshotRecord(at_seq, state, head)
            self._snapshots[at_seq] = record
            return record

    def snapshots(self) -> tuple[SnapshotRecord, ...]:
        """All booked snapshots, ordered by ``at_seq``."""
        with self._lock:
            return tuple(self._snapshots[seq]
                         for seq in sorted(self._snapshots))

    def latest_snapshot(self) -> Any:
        """The snapshot with the greatest ``at_seq``, or None."""
        with self._lock:
            if not self._snapshots:
                return None
            return self._snapshots[max(self._snapshots)]

    def replay_from(self, snapshot: SnapshotRecord,
                    handlers: Mapping[str, Callable[[Any, Mapping[str, Any]],
                                                   Any]]) -> Any:
        """Rebuild state from a booked snapshot, folding later events.

        Only events with ``event.seq > snapshot.at_seq`` are folded, with
        ``snapshot.state`` as the initial value. The snapshot must be one
        this store booked (unknown, stale, or tampered records raise
        ``SnapshotError``).
        """
        if not isinstance(snapshot, SnapshotRecord):
            raise TypeError(
                f"expected SnapshotRecord, got {type(snapshot).__name__}")
        with self._lock:
            stored = self._snapshots.get(snapshot.at_seq)
            if stored is None or stored != snapshot:
                raise SnapshotError(
                    "snapshot is not booked by this store")
            later = [e for e in self._events if e.seq > snapshot.at_seq]
        return replay(later, handlers, initial=snapshot.state)

    def replay_from_latest(self, handlers: Mapping[
            str, Callable[[Any, Mapping[str, Any]], Any]]) -> Any:
        """Replay from the latest booked snapshot (fail closed if none)."""
        snapshot = self.latest_snapshot()
        if snapshot is None:
            raise SnapshotError("no snapshots booked")
        return self.replay_from(snapshot, handlers)


def replay(events: Sequence[Event],
           handlers: Mapping[str, Callable[[Any, Mapping[str, Any]], Any]],
           initial: Any = None) -> Any:
    """Fold events through reducers to rebuild derived state.

    Events are applied in ascending ``seq`` order (input order is
    normalized, not trusted). Each event's type must have a handler;
    unknown types raise ``ReplayError`` -- a replay that silently drops
    events would certify an incomplete history. Duplicate seqs raise
    ``ReplayError``. A handler that raises propagates unchanged (the
    reducer's own failure, never converted).
    """
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise TypeError("events must be a sequence of Event")
    if not isinstance(handlers, Mapping):
        raise TypeError("handlers must be a mapping of event_type -> reducer")
    ordered = list(events)
    for event in ordered:
        if not isinstance(event, Event):
            raise TypeError(
                f"expected Event, got {type(event).__name__}")
    ordered.sort(key=lambda e: e.seq)
    seen: set[int] = set()
    for event in ordered:
        if event.seq in seen:
            raise ReplayError(f"duplicate seq in replay input: {event.seq}")
        seen.add(event.seq)
    state = initial
    for event in ordered:
        try:
            handler = handlers[event.event_type]
        except KeyError:
            raise ReplayError(
                f"no handler for event_type {event.event_type!r}") from None
        if not callable(handler):
            raise TypeError(
                f"handler for {event.event_type!r} is not callable")
        state = handler(state, event.payload)
    return state


@dataclass(frozen=True)
class SnapshotRecord:
    """One pinned snapshot of derived state at an event seq.

    ``at_seq`` is the last event seq the snapshot covers; ``state`` is the
    host-declared derived state at that point; ``head_digest`` is the
    store's chain head when the snapshot was booked, so an auditor can
    confirm the snapshot covers the same history the log shows.
    ``state_digest`` pins the canonical ``(at_seq, state, head_digest)``
    body (tamper-evident). Snapshots are keyed by ``at_seq`` inside a
    store and never overwritten.
    """

    at_seq: int
    state: Any
    state_digest: str
    head_digest: str

    def __init__(self, at_seq: object, state: object,
                 head_digest: object) -> None:
        at_seq = _check_seq(at_seq, "at_seq")
        state = _check_snapshot_state(state)
        head_digest = _check_digest(head_digest, "head_digest")
        digest = "sha256:" + jcs_sha256_hex({
            "at_seq": at_seq,
            "state": state,
            "head_digest": head_digest,
        })
        object.__setattr__(self, "at_seq", at_seq)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "state_digest", digest)
        object.__setattr__(self, "head_digest", head_digest)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe view with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "kind": "snapshot",
            "at_seq": self.at_seq,
            "state": self.state,
            "state_digest": self.state_digest,
            "head_digest": self.head_digest,
        }

    def verify(self) -> bool:
        """Recompute the pin; True iff this record is internally intact."""
        expected = "sha256:" + jcs_sha256_hex({
            "at_seq": self.at_seq,
            "state": self.state,
            "head_digest": self.head_digest,
        })
        return _constant_time_eq(self.state_digest, expected)


def snapshot_audit_event(snapshot: SnapshotRecord, seq: int) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a booked snapshot."""
    if not isinstance(snapshot, SnapshotRecord):
        raise TypeError(f"expected SnapshotRecord, got {type(snapshot).__name__}")
    _check_seq(seq, "seq")
    return {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "outcome": "snapshotted",
        "snapshot_at_seq": snapshot.at_seq,
        "state_digest": snapshot.state_digest,
        "head_digest": snapshot.head_digest,
        "audit_seq": seq,
    }


def event_audit_event(event: Event, outcome: str, seq: int) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for an event-store action."""
    if not isinstance(event, Event):
        raise TypeError(f"expected Event, got {type(event).__name__}")
    if outcome not in ("appended", "replayed", "rejected"):
        raise ValueError(f"unknown outcome: {outcome!r}")
    _check_seq(seq, "seq")
    return {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "outcome": outcome,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "event_seq": event.seq,
        "event_digest": event.digest,
        "audit_seq": seq,
    }


def main() -> None:
    """Self-check: append, chain, views, replay, fail-closed edges."""
    store = EventStore()
    assert store.head() == GENESIS_HEAD
    assert len(store) == 0

    e0 = Event("e0", "account.opened", {"owner": "alice", "balance": 0}, 0)
    e1 = Event("e1", "funds.deposited",
               {"amount": 100}, 1, prev_head=e0.digest)
    e2 = Event("e2", "funds.withdrawn",
               {"amount": 30}, 2, prev_head=e1.digest)
    store.append(e0)
    store.append(e1)
    store.append(e2)
    assert len(store) == 3
    assert store.head() == e2.digest
    assert store.verify_chain()
    assert [e.event_id for e in store.events_since(0)] == ["e1", "e2"]
    assert [e.event_id for e in store.events_of_type("funds.deposited")] == ["e1"]
    assert store.get("e1") is e1

    def opened(state: Any, payload: Mapping[str, Any]) -> Any:
        return {"owner": payload["owner"], "balance": payload["balance"]}

    def deposited(state: Any, payload: Mapping[str, Any]) -> Any:
        return {**state, "balance": state["balance"] + payload["amount"]}

    def withdrawn(state: Any, payload: Mapping[str, Any]) -> Any:
        return {**state, "balance": state["balance"] - payload["amount"]}

    handlers = {
        "account.opened": opened,
        "funds.deposited": deposited,
        "funds.withdrawn": withdrawn,
    }
    # Replay works even from shuffled input; duplicate seqs fail closed.
    state = replay([e2, e0, e1], handlers)
    assert state == {"owner": "alice", "balance": 70}, state
    try:
        replay([e0, e1, e1], handlers)
    except ReplayError:
        pass
    else:
        raise AssertionError("duplicate seq must raise")
    try:
        replay([Event("ex", "unknown.type", {}, 9, prev_head=e2.digest)],
               handlers)
    except ReplayError:
        pass
    else:
        raise AssertionError("unknown type must raise")

    # Fail-closed appends: replay of an id, non-monotonic seq, broken chain.
    for bad in (
        lambda: store.append(e1),
        lambda: store.append(Event("e3", "x", {}, 1, prev_head=e2.digest)),
        lambda: store.append(Event("e3", "x", {}, 3, prev_head=e0.digest)),
    ):
        try:
            bad()
        except OutOfOrderAppend:
            pass
        else:
            raise AssertionError("bad append must raise OutOfOrderAppend")
    assert len(store) == 3  # nothing appended

    # Constructor validation.
    for bad in (
        lambda: Event("", "t", {}, 0),
        lambda: Event("id", "", {}, 0),
        lambda: Event("id", "t", "not-a-mapping", 0),
        lambda: Event("id", "t", {1: "x"}, 0),
        lambda: Event("id", "t", {}, -1),
        lambda: Event("id", "t", {}, True),
        lambda: Event("id", "t", {"f": object()}, 0),
    ):
        try:
            bad()
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("bad Event must raise")

    audit = event_audit_event(e0, "appended", 7)
    assert audit["audit_seq"] == 7 and audit["event_id"] == "e0"

    # Snapshots: pin derived state, replay only the tail.
    store2 = EventStore()
    store2.append(e0)
    store2.append(e1)
    partial = replay(store2.events(), handlers)
    assert partial == {"owner": "alice", "balance": 100}, partial
    snap = store2.snapshot(partial)
    assert snap.at_seq == 1 and snap.head_digest == store2.head()
    assert snap.verify()
    assert store2.latest_snapshot() == snap
    assert [s.at_seq for s in store2.snapshots()] == [1]
    # A new event arrives after the snapshot; replay_from folds only it.
    store2.append(e2)
    resumed = store2.replay_from(snap, handlers)
    assert resumed == state, resumed
    assert store2.replay_from_latest(handlers) == state
    saudit = snapshot_audit_event(snap, 8)
    assert saudit["outcome"] == "snapshotted"
    assert saudit["snapshot_at_seq"] == 1
    # A snapshot at a newer at_seq is allowed; the same at_seq is not.
    snap2 = store2.snapshot(state)
    assert [s.at_seq for s in store2.snapshots()] == [1, 2]
    assert snap2.verify()
    try:
        store2.snapshot(state)
    except DuplicateSnapshotError:
        pass
    else:
        raise AssertionError("duplicate snapshot must raise")
    try:
        store2.replay_from(snap, {"nope": lambda s, p: s})
    except ReplayError:
        pass
    else:
        raise AssertionError("replay with missing handler must raise")
    try:
        EventStore().snapshot({})
    except SnapshotError:
        pass
    else:
        raise AssertionError("empty-store snapshot must raise")
    print("event-sourcing OK: append, chain, views, replay, snapshot, fail-closed")


if __name__ == "__main__":
    main()
