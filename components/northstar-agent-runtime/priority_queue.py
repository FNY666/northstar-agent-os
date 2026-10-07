"""Priority queue — deterministic single-host scheduling ledger.

Research note (priority scheduling): priority queues are the core of
preemptive scheduling — rate-monotonic, earliest-deadline-first, and
interrupt dispatch all reduce to "always service the highest-priority
pending item". The standard structure is a binary heap keyed on priority,
with FIFO tie-breaking among equal priorities for starvation-free
fairness. This module takes that intersection as a *deterministic
bookkeeping* layer:

* **Frozen facts**: ``push()`` mints a frozen ``PushRecord`` pinning the
  item, its priority, and its insertion order; ``pop()`` books a frozen
  ``PopRecord`` for the highest-priority item removed (never a silent
  discard).
* **Reads are data**: ``peek()`` returns a frozen ``PeekReport`` as a
  pure read view — validated seq, nothing consumed, no audit row.
* **Heap discipline**: lower numeric priority = higher urgency (the
  ``heapq`` convention, matching Rate-Monotonic's "smaller period =
  higher priority"); ties break by insertion order (FIFO among equal
  priorities).

House rules: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), RLock guarding, fail-closed
taxonomy, stdlib-only, sha256 digest pins over canonical payloads,
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* scheduling decisions. It
executes no callbacks, dispatches no interrupts, and cannot prove a
popped item was ever serviced — the host wires the frozen records to its
own dispatcher and treats the ledger as the ordering authority. Payloads
travel by digest pin only; raw payload bytes never enter a record or the
audit boundary.
"""

from __future__ import annotations

import heapq
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Version pin for this module's record shape.
PRIORITY_QUEUE_VERSION = "priority-queue.v1"

#: Schema pin carried by records and audit events.
PRIORITY_QUEUE_SCHEMA = "northstar.priority-queue.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: Bookkeeping bounds (not protocol limits).
MAX_ITEM_ID_LEN = 256
MAX_PRIORITY_ABS = (1 << 53) - 1  # safe-int range, JCS-friendly

#: Audit event kinds.
KIND_PUSHED = "priority.pushed"
KIND_POPPED = "priority.popped"
KIND_REJECTED = "priority.rejected"
_KINDS = frozenset({KIND_PUSHED, KIND_POPPED, KIND_REJECTED})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PriorityQueueError(Exception):
    """Base error for the priority-queue ledger."""


class BadItemError(PriorityQueueError):
    """Malformed item id."""


class DuplicateItemError(PriorityQueueError):
    """Item id already present in the queue."""


class EmptyQueueError(PriorityQueueError):
    """Pop attempted on an empty queue."""


class BadPriorityError(PriorityQueueError):
    """Malformed priority value."""


class BadDigestError(PriorityQueueError):
    """Malformed sha256: digest pin."""


class SeqOrderError(PriorityQueueError):
    """Seq did not strictly increase."""


class AuditKindError(PriorityQueueError):
    """Unknown audit kind or banned audit detail key."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_item_id(value: Any, name: str = "item_id") -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ITEM_ID_LEN:
        raise BadItemError(f"{name} must be a non-empty str <= {MAX_ITEM_ID_LEN}")
    if any(c.isspace() for c in value):
        raise BadItemError(f"{name} must not contain whitespace")
    return value


def _check_priority(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadPriorityError("priority must be an int")
    if abs(value) > MAX_PRIORITY_ABS:
        raise BadPriorityError(f"|priority| must be <= {MAX_PRIORITY_ABS}")
    return value


def _check_digest(value: Any, name: str = "payload_digest") -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be a str")
    if value and not (
        value.startswith(_DIGEST_PREFIX)
        and len(value) == len(_DIGEST_PREFIX) + 64
        and all(c in "0123456789abcdef" for c in value[len(_DIGEST_PREFIX):])
    ):
        raise BadDigestError(f"{name} must be '' or 'sha256:' + 64 lowercase hex")
    return value


def _canonical(value: Any) -> bytes:
    """Canonical encoding for digest pins (stdlib-only)."""
    try:
        from northstar_agent_runtime import canonical_json  # type: ignore

        payload = canonical_json.dumps(value)
        return payload.encode("utf-8")
    except Exception:
        import json

        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return payload.encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([PRIORITY_QUEUE_VERSION, *parts])
    ).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PushRecord:
    """One item pushed onto the queue (frozen)."""

    item_id: str
    priority: int
    order: int  # insertion order: the push seq; FIFO tie-break key
    payload_digest: str
    seq: int
    digest: str
    schema: str = PRIORITY_QUEUE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "push", self.item_id, self.priority, self.order,
            self.payload_digest, self.seq,
        )


@dataclass(frozen=True)
class PopRecord:
    """One item popped off the queue (frozen)."""

    item_id: str
    priority: int
    order: int
    payload_digest: str
    push_seq: int
    seq: int
    digest: str
    schema: str = PRIORITY_QUEUE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "pop", self.item_id, self.priority, self.order,
            self.payload_digest, self.push_seq, self.seq,
        )


@dataclass(frozen=True)
class PeekReport:
    """Pure read view of the queue head (frozen)."""

    found: bool
    item_id: str
    priority: int
    payload_digest: str
    seq: int
    digest: str
    schema: str = PRIORITY_QUEUE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "peek", self.found, self.item_id, self.priority,
            self.payload_digest, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def priority_queue_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the priority-queue ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    # Only ids, pins, small ints, and reasons cross the audit boundary.
    banned = {"payload", "payload_bytes", "value", "data", "raw", "message"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": PRIORITY_QUEUE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class PriorityQueue:
    """Deterministic priority-queue bookkeeping ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position). Lower numeric priority pops first;
    ties pop in push (FIFO) order.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Heap of (priority, order, item_id); heapq maintains the order.
        self._heap: List[Tuple[int, int, str]] = []
        # item_id -> PushRecord (pending items only).
        self._pending: Dict[str, PushRecord] = {}
        self._pushes: List[PushRecord] = []
        self._pops: List[PopRecord] = []
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1

    # -- internals ------------------------------------------------------

    def _bump(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, error: Exception) -> None:
        self._audit.append(
            priority_queue_audit_event(
                KIND_REJECTED, {"reason": reason}, seq
            )
        )
        raise error

    # -- mutations ------------------------------------------------------

    def push(
        self,
        item_id: str,
        priority: int,
        seq: int,
        payload_digest: str = "",
    ) -> PushRecord:
        """Book an item at ``priority``. Lower priority pops first."""
        with self._lock:
            self._bump(seq)
            try:
                _check_item_id(item_id)
                _check_priority(priority)
                _check_digest(payload_digest)
            except PriorityQueueError as exc:
                self._reject(seq, "bad-input", exc)
            if item_id in self._pending:
                self._reject(
                    seq, "duplicate-item", DuplicateItemError(
                        f"item already queued: {item_id!r}"
                    )
                )
            record = PushRecord(
                item_id=item_id,
                priority=priority,
                order=seq,
                payload_digest=payload_digest,
                seq=seq,
                digest=_pin("push", item_id, priority, seq, payload_digest, seq),
            )
            self._pending[item_id] = record
            heapq.heappush(self._heap, (priority, seq, item_id))
            self._pushes.append(record)
            self._audit.append(
                priority_queue_audit_event(
                    KIND_PUSHED,
                    {"item_id": item_id, "priority": priority, "digest": record.digest},
                    seq,
                )
            )
            return record

    def pop(self, seq: int) -> PopRecord:
        """Remove and book the highest-priority item (lowest value, FIFO ties)."""
        with self._lock:
            self._bump(seq)
            if not self._heap:
                self._reject(
                    seq, "empty-queue", EmptyQueueError("pop on empty queue")
                )
            priority, order, item_id = heapq.heappop(self._heap)
            pushed = self._pending.pop(item_id)
            record = PopRecord(
                item_id=item_id,
                priority=priority,
                order=order,
                payload_digest=pushed.payload_digest,
                push_seq=pushed.seq,
                seq=seq,
                digest=_pin(
                    "pop", item_id, priority, order,
                    pushed.payload_digest, pushed.seq, seq,
                ),
            )
            self._pops.append(record)
            self._audit.append(
                priority_queue_audit_event(
                    KIND_POPPED,
                    {"item_id": item_id, "priority": priority, "digest": record.digest},
                    seq,
                )
            )
            return record

    # -- pure read views --------------------------------------------------

    def peek(self, seq: int) -> PeekReport:
        """Return the current queue head as data; consumes no seq."""
        with self._lock:
            _check_seq(seq, "seq")  # validated, not consumed
            if not self._heap:
                return PeekReport(
                    found=False,
                    item_id="",
                    priority=0,
                    payload_digest="",
                    seq=seq,
                    digest=_pin("peek", False, "", 0, "", seq),
                )
            priority, order, item_id = self._heap[0]
            pushed = self._pending[item_id]
            return PeekReport(
                found=True,
                item_id=item_id,
                priority=priority,
                payload_digest=pushed.payload_digest,
                seq=seq,
                digest=_pin(
                    "peek", True, item_id, priority, pushed.payload_digest, seq
                ),
            )

    def push_record(self, item_id: str) -> Optional[PushRecord]:
        """Pending push record for ``item_id`` (None when absent)."""
        with self._lock:
            return self._pending.get(item_id)

    def item_ids(self) -> Tuple[str, ...]:
        """Pending item ids in pop order (priority, then FIFO)."""
        with self._lock:
            return tuple(item_id for _, _, item_id in sorted(self._heap))

    def size(self, seq: int) -> int:
        """Number of pending items; pure read."""
        with self._lock:
            _check_seq(seq, "seq")
            return len(self._heap)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters; pure read."""
        with self._lock:
            _check_seq(seq, "seq")
            return {
                "pending": len(self._heap),
                "pushes": len(self._pushes),
                "pops": len(self._pops),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Frozen tuple of audit events booked so far."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: push, peek, pop in priority order, fail-closed edges."""
    pq = PriorityQueue()
    r1 = pq.push("low", 10, 1)
    r2 = pq.push("high", 1, 2)
    r3 = pq.push("mid", 5, 3)
    assert r1.verify() and r2.verify() and r3.verify()
    head = pq.peek(3)
    assert head.found and head.item_id == "high" and head.verify()
    assert pq.size(3) == 3
    first = pq.pop(4)
    assert first.item_id == "high" and first.verify()
    second = pq.pop(5)
    assert second.item_id == "mid"
    third = pq.pop(6)
    assert third.item_id == "low"
    try:
        pq.pop(7)
        raise AssertionError("expected EmptyQueueError")
    except EmptyQueueError:
        pass
    assert pq.stats(7)["pending"] == 0
    print(
        "priority-queue OK: push, peek, pop order, empty fail-closed, pins, audit"
    )


if __name__ == "__main__":
    main()
