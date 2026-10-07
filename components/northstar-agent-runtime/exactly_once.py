"""Exactly-once processor: dedup ledger plus checkpoint/recovery for ordered streams.

A producer emits events with opaque ``event_id`` values over an ordered
stream (caller-supplied int seqs, no wall-clock). ``ExactlyOnce.process``
runs the host's handler exactly once per event_id: the first sight executes
the handler and pins the result; any redelivery with the same event_id and
the same payload is a replay and returns the cached outcome without
re-running the handler.

Payload binding (the load-bearing rule): an event_id is bound to the payload
digest it was first processed with. A redelivery presenting the *same*
event_id with a *different* payload raises ``PayloadMismatchError``
fail-closed -- returning the old cached result for a different logical
event would be silently wrong, and the id binding alone cannot tell the
two apart.

Stream ordering: a *new* event must arrive with a strictly increasing seq
(a redelivery carries whatever seq it likes and does not move the
high-water mark). This keeps the dedup ledger consistent with a single
ordered upstream; out-of-order new events raise ``EventOrderError``
fail-closed instead of being silently pinned under a misleading seq.

``checkpoint(seq)`` mints a frozen ``Checkpoint`` that pins the full
processed set (not just a digest): ``recover(checkpoint)`` restores exactly
the pinned snapshot, verifying the digest pin before trusting it. Anything
processed *after* the checkpoint was taken is lost on crash -- checkpointing
before the host commits downstream is the host's job.

House style: frozen dataclasses, no wall-clock (caller-supplied int seqs),
fail-closed validation (``TypeError``/``ValueError``/domain errors on
malformed input), stdlib-only, deterministic, version and schema pins,
``main()`` self-check.

Honest scope: this is a *host-reported* processing ledger. It records that
a handler was invoked for an event_id and what digest the result had; it
cannot prove the handler's real-world side effects happened exactly once,
and it cannot see events the host never reports. A replay hit means "this
event_id was already processed here", never "the world changed exactly
once". Dedup is only as good as event_id uniqueness upstream. Payloads and
results are pinned by ``sha256:`` digests of canonical JSON; values that
are not JSON-canonicalizable (NaN/inf, non-str dict keys, arbitrary
objects) are rejected fail-closed rather than hashed ambiguously.
Integral floats above 2**53 lose precision through ``json.dumps`` and can
pin to the same digest as a different integer -- the same JCS caveat
documented in ``secure_aggregation``; hosts with such values must
normalize to exact ints or fixed-width hex before handing them over.

Version pin: exactly-once.v1
Schema pin: northstar.exactly-once.v1
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Callable, Optional

EXACTLY_ONCE_VERSION = "exactly-once.v1"
SCHEMA_PIN = "northstar.exactly-once.v1"

_MAX_EVENT_ID_LEN = 1024

_AUDIT_KINDS = (
    "processed",
    "replay",
    "checkpointed",
    "recovered",
    "rejected",
)


class ExactlyOnceError(Exception):
    """Base class for exactly-once processor errors."""


class PayloadMismatchError(ExactlyOnceError):
    """Raised when a known event_id is redelivered with a different payload.

    The event_id is bound to the payload digest it was first processed
    with; a different payload under the same id is a producer bug or a
    confused caller, and returning the old cached outcome would be
    silently wrong.
    """


class ResultNotCanonicalError(ExactlyOnceError):
    """Raised when the handler returns a non-JSON-canonicalizable result.

    The event is *not* recorded as processed: pinning a digest we cannot
    canonicalize would be dishonest, so the caller must fix the handler
    and redeliver (which will re-run the handler exactly once).
    """


class CheckpointIntegrityError(ExactlyOnceError):
    """Raised when a checkpoint's digest pin does not match its snapshot.

    ``recover`` refuses to restore a checkpoint it cannot verify -- a
    tampered or corrupted snapshot is never loaded into the ledger.
    """


class EventOrderError(ExactlyOnceError):
    """Raised when a new event's seq is not strictly increasing.

    Exactly-once processing is defined over an ordered stream; a new
    event with a stale seq would be pinned under a misleading position.
    Redeliveries (known event_ids) are not subject to this rule.
    """


def _require_event_id(event_id: Any) -> str:
    if isinstance(event_id, bool) or not isinstance(event_id, str):
        raise TypeError(f"event_id must be a str, got {type(event_id).__name__}")
    if not event_id:
        raise ValueError("event_id must be non-empty")
    if len(event_id) > _MAX_EVENT_ID_LEN:
        raise ValueError(f"event_id must be at most {_MAX_EVENT_ID_LEN} chars")
    return event_id


def _require_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        raise ValueError(f"{name} must look like 'sha256:' + 64 hex chars")
    hexpart = value[len("sha256:") :]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} hex part must be lowercase hex")
    return value


def _require_handler(handler: Any) -> Callable[[Any], Any]:
    if not callable(handler):
        raise TypeError(f"handler must be callable, got {type(handler).__name__}")
    return handler


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting; rejects non-canonicalizable input."""
    if value is None or isinstance(value, bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TypeError("payload/result must not contain NaN or infinity")
    elif isinstance(value, str):
        pass
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str for canonicalization")
            _canonical(v)
    else:
        raise TypeError(
            f"value of type {type(value).__name__} is not JSON-canonicalizable"
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _event_id_digest(event_id: str) -> str:
    return "sha256:" + hashlib.sha256(event_id.encode("utf-8")).hexdigest()


def _events_digest(entries: tuple["ProcessedEntry", ...]) -> str:
    body = [
        [e.event_id, e.payload_digest, e.result_digest, e.first_seq]
        for e in entries
    ]
    return "sha256:" + hashlib.sha256(
        json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ProcessedEntry:
    """One pinned processed event (frozen)."""

    event_id: str
    payload_digest: str
    result_digest: str
    first_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_event_id(self.event_id)
        _require_digest(self.payload_digest, "payload_digest")
        _require_digest(self.result_digest, "result_digest")
        _require_seq(self.first_seq)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "payload_digest": self.payload_digest,
            "result_digest": self.result_digest,
            "first_seq": self.first_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ProcessOutcome:
    """Result of ``ExactlyOnce.process`` (frozen).

    ``hit`` is False when the handler ran (first sight), True on a
    redelivery. ``result`` is the handler's result -- on a replay it is
    the *cached* first result, never re-computed.
    """

    hit: bool
    event_id: str
    payload_digest: str
    result_digest: str
    result: Any
    first_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.hit, bool):
            raise TypeError("hit must be a bool")
        _require_event_id(self.event_id)
        _require_digest(self.payload_digest, "payload_digest")
        _require_digest(self.result_digest, "result_digest")
        _require_seq(self.first_seq)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "hit": self.hit,
            "event_id": self.event_id,
            "payload_digest": self.payload_digest,
            "result_digest": self.result_digest,
            "first_seq": self.first_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Checkpoint:
    """A pinned snapshot of the processed set (frozen).

    ``snapshot`` carries the full processed entries in first-seen order,
    so ``recover`` restores exactly the pinned state. ``events_digest``
    is the integrity pin over the snapshot; ``recover`` recomputes it
    and refuses to load a mismatching snapshot.
    """

    checkpoint_seq: int
    processed_count: int
    events_digest: str
    snapshot: tuple
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_seq(self.checkpoint_seq)
        if isinstance(self.processed_count, bool) or not isinstance(
            self.processed_count, int
        ):
            raise TypeError("processed_count must be an int")
        if self.processed_count < 0:
            raise ValueError("processed_count must be non-negative")
        _require_digest(self.events_digest, "events_digest")
        if not isinstance(self.snapshot, tuple):
            raise TypeError("snapshot must be a tuple")
        for entry in self.snapshot:
            if not isinstance(entry, ProcessedEntry):
                raise TypeError("snapshot entries must be ProcessedEntry")
        if len(self.snapshot) != self.processed_count:
            raise ValueError("processed_count must equal len(snapshot)")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "checkpoint_seq": self.checkpoint_seq,
            "processed_count": self.processed_count,
            "events_digest": self.events_digest,
            "snapshot": [e.as_dict() for e in self.snapshot],
            "schema": self.schema,
        }


class ExactlyOnce:
    """In-memory exactly-once processing ledger over caller-supplied event_ids.

    ``process(event_id, payload, handler, seq)``: runs ``handler(payload)``
    on first sight of ``event_id`` (new events need a strictly increasing
    ``seq``); a redelivery with the same payload returns the cached outcome
    with ``hit=True`` and never re-runs the handler. A redelivery with a
    different payload raises ``PayloadMismatchError``.

    ``checkpoint(seq)`` pins the processed set into a ``Checkpoint``;
    ``ExactlyOnce.recover(checkpoint)`` builds a fresh processor from a
    verified snapshot. Persistence across restarts is the host's job --
    this ledger is in-memory by design.
    """

    def __init__(self) -> None:
        self._records: dict[str, ProcessedEntry] = {}
        self._results: dict[str, Any] = {}
        self._last_seq: int = -1

    def process(
        self,
        event_id: str,
        payload: Any,
        handler: Callable[[Any], Any],
        seq: int,
    ) -> ProcessOutcome:
        _require_event_id(event_id)
        _require_seq(seq)
        payload_digest = _digest(payload)
        _require_handler(handler)

        existing = self._records.get(event_id)
        if existing is not None:
            if existing.payload_digest != payload_digest:
                raise PayloadMismatchError(
                    f"event_id {event_id!r} already processed with a "
                    "different payload"
                )
            return ProcessOutcome(
                hit=True,
                event_id=event_id,
                payload_digest=existing.payload_digest,
                result_digest=existing.result_digest,
                result=self._results[event_id],
                first_seq=existing.first_seq,
            )

        if seq <= self._last_seq:
            raise EventOrderError(
                f"new event {event_id!r} has seq {seq} not greater than "
                f"last processed seq {self._last_seq}"
            )

        result = handler(payload)
        try:
            result_digest = _digest(result)
        except TypeError as exc:
            raise ResultNotCanonicalError(
                f"handler result for event {event_id!r} is not canonicalizable: "
                f"{exc}"
            ) from exc

        entry = ProcessedEntry(
            event_id=event_id,
            payload_digest=payload_digest,
            result_digest=result_digest,
            first_seq=seq,
        )
        self._records[event_id] = entry
        self._results[event_id] = result
        self._last_seq = seq
        return ProcessOutcome(
            hit=False,
            event_id=event_id,
            payload_digest=payload_digest,
            result_digest=result_digest,
            result=result,
            first_seq=seq,
        )

    def checkpoint(self, seq: int) -> Checkpoint:
        """Mint a frozen checkpoint pinning the full processed set."""
        _require_seq(seq)
        snapshot = tuple(self._records.values())
        return Checkpoint(
            checkpoint_seq=seq,
            processed_count=len(snapshot),
            events_digest=_events_digest(snapshot),
            snapshot=snapshot,
        )

    @classmethod
    def recover(cls, checkpoint: Checkpoint) -> "ExactlyOnce":
        """Build a processor from a verified checkpoint snapshot.

        The digest pin is recomputed from the snapshot before anything is
        loaded; a tampered snapshot raises ``CheckpointIntegrityError``
        and nothing is restored.

        The checkpoint pins *digests*, not result values: after recovery
        a redelivery of an already-checkpointed event returns ``hit=True``
        with the pinned ``result_digest`` but ``result=None`` -- the value
        was not pinned and is not invented. Hosts that need value-level
        replay across restarts must keep their own result cache.
        """
        if not isinstance(checkpoint, Checkpoint):
            raise TypeError(
                f"checkpoint must be a Checkpoint, got {type(checkpoint).__name__}"
            )
        if _events_digest(checkpoint.snapshot) != checkpoint.events_digest:
            raise CheckpointIntegrityError(
                "checkpoint digest pin does not match its snapshot"
            )
        proc = cls()
        last = -1
        for entry in checkpoint.snapshot:
            proc._records[entry.event_id] = entry
            proc._results[entry.event_id] = None
            if entry.first_seq > last:
                last = entry.first_seq
        proc._last_seq = last
        return proc

    def seen(self, event_id: str) -> bool:
        """True if ``event_id`` has been processed."""
        _require_event_id(event_id)
        return event_id in self._records

    def processed_count(self) -> int:
        return len(self._records)

    @property
    def last_seq(self) -> int:
        """Highest first-sight seq processed so far (-1 when empty)."""
        return self._last_seq

    def entries(self) -> tuple[ProcessedEntry, ...]:
        """Processed entries in first-seen order (deterministic)."""
        return tuple(self._records.values())

    def head_digest(self) -> str:
        """Digest pin over the whole processed set."""
        return _events_digest(self.entries())

    def lookup(self, event_id: str) -> Optional[ProcessedEntry]:
        """Return the pinned entry for ``event_id``, or None."""
        _require_event_id(event_id)
        return self._records.get(event_id)

    def __len__(self) -> int:
        return len(self._records)


def exactly_once_audit_event(
    kind: str,
    seq: int,
    event_id: Optional[str] = None,
    outcome: Optional[ProcessOutcome] = None,
    checkpoint: Optional[Checkpoint] = None,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for an exactly-once step.

    ``kind`` is one of ``processed`` / ``replay`` / ``checkpointed`` /
    ``recovered`` / ``rejected``. The raw event_id is never emitted --
    only its digest -- so an id that embeds sensitive context does not
    leak through the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _require_seq(seq)
    if event_id is not None:
        _require_event_id(event_id)
    if outcome is not None and not isinstance(outcome, ProcessOutcome):
        raise TypeError("outcome must be a ProcessOutcome")
    if checkpoint is not None and not isinstance(checkpoint, Checkpoint):
        raise TypeError("checkpoint must be a Checkpoint")
    record = {
        "event": f"exactly-once-{kind}",
        "event_id_digest": (
            _event_id_digest(event_id) if event_id is not None else None
        ),
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if outcome is not None:
        record["hit"] = outcome.hit
        record["payload_digest"] = outcome.payload_digest
        record["result_digest"] = outcome.result_digest
        record["first_seq"] = outcome.first_seq
    if checkpoint is not None:
        record["processed_count"] = checkpoint.processed_count
        record["events_digest"] = checkpoint.events_digest
        record["checkpoint_seq"] = checkpoint.checkpoint_seq
    return record


def main() -> None:
    proc = ExactlyOnce()
    calls = []

    def handler(payload):
        calls.append(payload)
        return {"doubled": payload["n"] * 2}

    first = proc.process("evt-1", {"n": 21}, handler, seq=0)
    assert not first.hit and first.result == {"doubled": 42}
    replay = proc.process("evt-1", {"n": 21}, handler, seq=0)
    assert replay.hit and replay.result == {"doubled": 42}
    assert calls == [{"n": 21}], "handler must run exactly once"
    try:
        proc.process("evt-1", {"n": 22}, handler, seq=1)
    except PayloadMismatchError:
        pass
    else:
        raise AssertionError("payload mismatch should raise")
    try:
        proc.process("evt-2", {"n": 1}, handler, seq=0)
    except EventOrderError:
        pass
    else:
        raise AssertionError("non-increasing seq should raise")
    proc.process("evt-2", {"n": 1}, handler, seq=1)
    assert proc.processed_count() == 2

    cp = proc.checkpoint(seq=5)
    assert cp.processed_count == 2
    revived = ExactlyOnce.recover(cp)
    assert revived.processed_count() == 2 and revived.seen("evt-1")
    assert revived.head_digest() == proc.head_digest()

    tampered = Checkpoint(
        checkpoint_seq=cp.checkpoint_seq,
        processed_count=cp.processed_count,
        events_digest="sha256:" + "00" * 32,
        snapshot=cp.snapshot,
    )
    try:
        ExactlyOnce.recover(tampered)
    except CheckpointIntegrityError:
        pass
    else:
        raise AssertionError("tampered checkpoint should raise")

    ev = exactly_once_audit_event("processed", seq=7, event_id="evt-1", outcome=first)
    assert ev["event"] == "exactly-once-processed" and ev["audit_seq"] == 7
    assert "evt-1" not in str(ev)
    print("exactly-once OK: process, replay-hit, order, checkpoint, recover")


if __name__ == "__main__":
    main()
