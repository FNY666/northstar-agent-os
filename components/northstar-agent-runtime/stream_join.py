"""Stream-stream temporal joins.

Research motivation: an agent fleet emits *event streams* -- tool-call
records from one host, approval records from another, audit segments from
a third -- with logical timestamps but no shared wall clock. Answering
"which events go together" is a *stream-stream join* problem. This module
is the network-free, deterministic mechanical half of that: given two
host-reported event sets it computes the join pairs under three temporal
policies, so the correlation step can be replayed bit-identically for
audit.

Public API:

- ``StreamEvent`` -- frozen record: ``event_id``, ``key``, ``timestamp``
  (caller-supplied logical time, an int), ``payload`` (a mapping). All
  validation is fail-closed.
- ``JoinedPair`` -- frozen record for one joined pair, with a
  ``sha256:`` digest pin binding both event ids, the key, and both
  timestamps.
- ``StreamJoin`` -- holds a left and a right event set. ``add_left`` /
  ``add_right`` ingest events (duplicate ``event_id`` on one side is
  rejected fail-closed). Join policies:
  - ``join()`` -- inner join: pairs with equal ``key`` *and* equal
    ``timestamp``.
  - ``windowed_join(window_size)`` -- tumbling windows: events share
    ``window_id = timestamp // window_size`` and equal ``key``.
  - ``interval_join(lower_bound, upper_bound)`` -- Flink-style interval
    join: left event ``l`` pairs with right event ``r`` when the keys
    match and ``l.timestamp + lower_bound <= r.timestamp <=
    l.timestamp + upper_bound``.
- ``stream_join_audit_event(kind, seq)`` -- ``audit.ndjson/1``-shaped
  record, fixed kind vocabulary: ``"left-ingested"`` /
  ``"right-ingested"`` / ``"joined"`` / ``"windowed-joined"`` /
  ``"interval-joined"``.

Honest scope:

- This module correlates *host-reported* events. It cannot observe
  events the host never reports, and a timestamp it was given is taken
  at face value -- this module does not and cannot detect clock skew,
  delayed delivery, or host-rewritten timestamps.
- Join output is sorted by ``(left_id, right_id)`` and is fully
  deterministic for identical inputs; determinism does not mean the
  inputs were complete.
- ``JoinedPair`` pins identity (which events paired under which rule),
  never truth: a joined pair is "these two records correlated by the
  rule", not "these two real-world facts belonged together".
- Timestamps are logical caller-supplied ints. This module never reads
  a clock.

Version pin: ``stream-join.v1`` / schema pin ``northstar.stream-join.v1``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Mapping, Tuple

#: Module version.
STREAM_JOIN_VERSION = "stream-join.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.stream-join.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "left-ingested",
        "right-ingested",
        "joined",
        "windowed-joined",
        "interval-joined",
    }
)

_MAX_TS = 2**63 - 1
_MAX_ID_LEN = 1024


def _check_id(event_id: object, label: str) -> str:
    if isinstance(event_id, bool) or not isinstance(event_id, str):
        raise TypeError(f"{label} must be str, got {type(event_id).__name__}")
    if not event_id:
        raise ValueError(f"{label} must be non-empty")
    if len(event_id) > _MAX_ID_LEN:
        raise ValueError(f"{label} exceeds {_MAX_ID_LEN} chars")
    return event_id


def _check_key(key: object) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise TypeError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must be non-empty")
    if len(key) > _MAX_ID_LEN:
        raise ValueError(f"key exceeds {_MAX_ID_LEN} chars")
    return key


def _check_ts(timestamp: object, label: str = "timestamp") -> int:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise TypeError(f"{label} must be int, got {type(timestamp).__name__}")
    if timestamp < 0:
        raise ValueError(f"{label} must be non-negative")
    if timestamp > _MAX_TS:
        raise ValueError(f"{label} exceeds {_MAX_TS}")
    return timestamp


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


@dataclass(frozen=True)
class StreamEvent:
    """One host-reported stream event.

    ``payload`` is copied and frozen into a sorted tuple of items at
    construction; it is opaque to the join logic (only ``key`` and
    ``timestamp`` participate).
    """

    event_id: str
    key: str
    timestamp: int
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        _check_id(self.event_id, "event_id")
        _check_key(self.key)
        _check_ts(self.timestamp)
        if not isinstance(self.payload, Mapping):
            raise TypeError(
                f"payload must be a Mapping, got {type(self.payload).__name__}"
            )
        # Copy so later caller mutation cannot move a pinned digest.
        clean: Dict[str, object] = {}
        for k, v in self.payload.items():
            if isinstance(k, bool) or not isinstance(k, str):
                raise TypeError(
                    f"payload key must be str, got {type(k).__name__}"
                )
            clean[k] = v
        object.__setattr__(
            self, "payload", tuple(sorted(clean.items(), key=lambda kv: kv[0]))
        )

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "event_id": self.event_id,
            "key": self.key,
            "timestamp": self.timestamp,
            "payload": dict(self.payload),
        }


def _pin_pair(left_id: str, right_id: str, key: str, left_ts: int, right_ts: int) -> str:
    body = "\x1f".join([STREAM_JOIN_VERSION, left_id, right_id, key, str(left_ts), str(right_ts)])
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class JoinedPair:
    """One join output: the two paired events plus a digest pin.

    The pin binds (left_id, right_id, key, left_ts, right_ts), so a
    verifier can re-derive it from the two input events without
    re-running the join.
    """

    left_id: str
    right_id: str
    key: str
    left_timestamp: int
    right_timestamp: int
    digest: str

    def __post_init__(self) -> None:
        _check_id(self.left_id, "left_id")
        _check_id(self.right_id, "right_id")
        _check_key(self.key)
        _check_ts(self.left_timestamp, "left_timestamp")
        _check_ts(self.right_timestamp, "right_timestamp")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise ValueError("digest must be a sha256: pin")

    def verify(self, left: "StreamEvent", right: "StreamEvent") -> bool:
        """Re-derive the pin from the two source events."""
        if left.event_id != self.left_id or right.event_id != self.right_id:
            return False
        if left.key != self.key or right.key != self.key:
            return False
        return (
            _pin_pair(
                left.event_id,
                right.event_id,
                left.key,
                left.timestamp,
                right.timestamp,
            )
            == self.digest
        )

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "left_id": self.left_id,
            "right_id": self.right_id,
            "key": self.key,
            "left_timestamp": self.left_timestamp,
            "right_timestamp": self.right_timestamp,
            "digest": self.digest,
        }


def _make_pair(left: StreamEvent, right: StreamEvent) -> JoinedPair:
    return JoinedPair(
        left_id=left.event_id,
        right_id=right.event_id,
        key=left.key,
        left_timestamp=left.timestamp,
        right_timestamp=right.timestamp,
        digest=_pin_pair(
            left.event_id, right.event_id, left.key, left.timestamp, right.timestamp
        ),
    )


class StreamJoin:
    """Holds two event sets and computes temporal joins between them.

    Mutable ingest, deterministic pure join views. Duplicate
    ``event_id`` on the same side is rejected (fail-closed) so the two
    sides stay well-formed event sets rather than multisets.
    """

    def __init__(self) -> None:
        self._left: Dict[str, StreamEvent] = {}
        self._right: Dict[str, StreamEvent] = {}

    def _ingest(self, store: Dict[str, StreamEvent], event: StreamEvent) -> None:
        if not isinstance(event, StreamEvent):
            raise TypeError(
                f"event must be StreamEvent, got {type(event).__name__}"
            )
        if event.event_id in store:
            raise ValueError(f"duplicate event_id {event.event_id!r}")
        store[event.event_id] = event

    def add_left(self, event: StreamEvent) -> None:
        """Ingest one left-stream event."""
        self._ingest(self._left, event)

    def add_right(self, event: StreamEvent) -> None:
        """Ingest one right-stream event."""
        self._ingest(self._right, event)

    def left(self) -> Tuple[StreamEvent, ...]:
        """Left events, sorted by event_id (deterministic)."""
        return tuple(self._left[k] for k in sorted(self._left))

    def right(self) -> Tuple[StreamEvent, ...]:
        """Right events, sorted by event_id (deterministic)."""
        return tuple(self._right[k] for k in sorted(self._right))

    def join(self) -> Tuple[JoinedPair, ...]:
        """Inner join: equal ``key`` and equal ``timestamp``.

        Returns pairs sorted by ``(left_id, right_id)``.
        """
        out: List[JoinedPair] = []
        for l in self.left():
            for r in self.right():
                if l.key == r.key and l.timestamp == r.timestamp:
                    out.append(_make_pair(l, r))
        out.sort(key=lambda p: (p.left_id, p.right_id))
        return tuple(out)

    def windowed_join(self, window_size: int) -> Tuple[JoinedPair, ...]:
        """Tumbling-window join.

        ``window_id = timestamp // window_size``; pairs share the same
        window and the same ``key``. ``window_size`` must be a positive
        int. Returns pairs sorted by ``(left_id, right_id)``.
        """
        if isinstance(window_size, bool) or not isinstance(window_size, int):
            raise TypeError(
                f"window_size must be int, got {type(window_size).__name__}"
            )
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        if window_size > _MAX_TS:
            raise ValueError("window_size is unreasonably large")
        out: List[JoinedPair] = []
        for l in self.left():
            for r in self.right():
                if l.key != r.key:
                    continue
                if l.timestamp // window_size == r.timestamp // window_size:
                    out.append(_make_pair(l, r))
        out.sort(key=lambda p: (p.left_id, p.right_id))
        return tuple(out)

    def interval_join(
        self, lower_bound: int, upper_bound: int
    ) -> Tuple[JoinedPair, ...]:
        """Flink-style interval join.

        Left event ``l`` pairs with right event ``r`` when the keys
        match and ``l.timestamp + lower_bound <= r.timestamp <=
        l.timestamp + upper_bound``. Bounds may be negative (right event
        before left) but ``lower_bound`` must not exceed
        ``upper_bound``. Returns pairs sorted by ``(left_id, right_id)``.
        """
        if isinstance(lower_bound, bool) or not isinstance(lower_bound, int):
            raise TypeError(
                f"lower_bound must be int, got {type(lower_bound).__name__}"
            )
        if isinstance(upper_bound, bool) or not isinstance(upper_bound, int):
            raise TypeError(
                f"upper_bound must be int, got {type(upper_bound).__name__}"
            )
        if lower_bound > upper_bound:
            raise ValueError(
                "lower_bound must not exceed upper_bound"
            )
        out: List[JoinedPair] = []
        for l in self.left():
            lo = l.timestamp + lower_bound
            hi = l.timestamp + upper_bound
            for r in self.right():
                if l.key != r.key:
                    continue
                if lo <= r.timestamp <= hi:
                    out.append(_make_pair(l, r))
        out.sort(key=lambda p: (p.left_id, p.right_id))
        return tuple(out)


def stream_join_audit_event(kind: str, seq: int, *, count: int = 0) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a join operation.

    ``kind`` is one of ``"left-ingested"`` / ``"right-ingested"`` /
    ``"joined"`` / ``"windowed-joined"`` / ``"interval-joined"``.
    ``count`` is the number of events ingested or pairs produced.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    if isinstance(count, bool) or not isinstance(count, int):
        raise TypeError(f"count must be int, got {type(count).__name__}")
    if count < 0:
        raise ValueError("count must be non-negative")
    return {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "count": count,
        "seq": _check_seq(seq),
    }


def main() -> None:
    """Self-check: exact join, windowed join, and interval join."""
    sj = StreamJoin()
    sj.add_left(StreamEvent(event_id="l1", key="k", timestamp=10, payload={"v": 1}))
    sj.add_left(StreamEvent(event_id="l2", key="k", timestamp=25, payload={}))
    sj.add_right(StreamEvent(event_id="r1", key="k", timestamp=10, payload={}))
    sj.add_right(StreamEvent(event_id="r2", key="k", timestamp=29, payload={}))
    sj.add_right(StreamEvent(event_id="r3", key="other", timestamp=10, payload={}))

    exact = sj.join()
    assert len(exact) == 1 and exact[0].left_id == "l1" and exact[0].right_id == "r1"
    assert exact[0].verify(
        StreamEvent(event_id="l1", key="k", timestamp=10, payload={"v": 1}),
        StreamEvent(event_id="r1", key="k", timestamp=10, payload={}),
    ), "digest pin must re-derive from the source events"

    windowed = sj.windowed_join(10)  # windows [10,20) and [20,30) and [30,40)
    ids = {(p.left_id, p.right_id) for p in windowed}
    assert ids == {("l1", "r1"), ("l2", "r2")}, ids

    interval = sj.interval_join(-5, 5)
    ids = {(p.left_id, p.right_id) for p in interval}
    assert ids == {("l1", "r1"), ("l2", "r2")}, ids

    strict = sj.interval_join(0, 0)
    assert {(p.left_id, p.right_id) for p in strict} == {("l1", "r1")}

    print("stream-join OK: exact, windowed, interval")
    print("audit:", stream_join_audit_event("joined", 1, count=1)["kind"])


if __name__ == "__main__":
    main()
