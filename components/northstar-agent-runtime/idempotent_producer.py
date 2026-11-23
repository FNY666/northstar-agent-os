"""Idempotent producer: Kafka-style exactly-once send bookkeeping.

Research motivation: Kafka's idempotent producer
(``enable.idempotence=true``, KIP-98) assigns a monotonically increasing
sequence number to every record on each partition. The broker tracks
``<PID, partition, sequence>`` and dedupes:

- ``producer_seq == last_seq + 1`` -- new record, appended;
- ``producer_seq <= last_seq`` -- duplicate of an already-appended
  record, acknowledged but *not* re-appended (dedupe as data);
- ``producer_seq > last_seq + 1`` -- gap (a lost message) -- the broker
  fails the batch with ``OutOfOrderSequenceException`` (fatal).

This module books that broker-side decision deterministically on a
single host. It performs no networking and stores no payload bytes --
values are pinned by ``sha256:`` digest only. The producer-side
sequence assignment and the broker-side dedupe share one ledger (as in
the batch-39 siblings), so a test can drive the full
assign -> send -> retry -> dedupe cycle without a wire.

Public API:

- ``IdempotentProducer(producer_id)`` -- mutable, RLock-guarded ledger.
  - ``send(topic, partition, producer_seq, payload_digest, seq)`` ->
    frozen ``SendRecord``: books one send. ``producer_seq`` is the
    producer-assigned per-partition sequence number. Verdict is data
    (``"appended"`` / ``"duplicate"``); a gap raises
    ``OutOfOrderError`` fail-closed.
  - ``sequence(topic, partition, seq)`` -> frozen ``SequenceView``:
    pure read view of the next assignable producer sequence number
    (``last_seq + 1``); validates the seq shape, consumes nothing,
    writes no audit row.
  - ``dedupe(topic, partition, producer_seq, seq)`` -> frozen
    ``DedupeVerdict``: pure read view answering what ``send`` would
    decide for this sequence number -- ``"new"``, ``"duplicate"`` or
    ``"out-of-order"`` -- as data, without booking anything.
- ``idempotent_producer_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"idempotent-producer.sent"``,
  ``"idempotent-producer.deduplicated"``,
  ``"idempotent-producer.rejected"``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq and book a ``rejected`` row;
bool/negative/rewind refused without consuming), RLock-guarded,
fail-closed taxonomy, stdlib-only (``canonical_json`` sibling helper
behind the standard try/except fallback).

Honest scope:

- This module books *declared* sends; it observes no broker and cannot
  prove a record was actually persisted -- producer honesty is GIGO at
  the host boundary.
- A ``"duplicate"`` verdict is a ledger decision that the send must not
  be re-appended; the host still has to honor it.
- Sequence numbers are host-declared; the module cannot detect a
  producer that reuses a PID with a reset counter.

Version pin: ``idempotent-producer.v1`` / schema pin
``northstar.idempotent-producer.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
IDEMPOTENT_PRODUCER_VERSION = "idempotent-producer.v1"

#: Schema pin carried by records and audit events.
IDEMPOTENT_PRODUCER_SCHEMA = "northstar.idempotent-producer.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_SENT = "idempotent-producer.sent"
KIND_DEDUPLICATED = "idempotent-producer.deduplicated"
KIND_REJECTED = "idempotent-producer.rejected"
_KINDS = frozenset({KIND_SENT, KIND_DEDUPLICATED, KIND_REJECTED})

#: Keys that must never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {"payload", "payload_bytes", "value", "value_bytes", "raw", "body", "data"}
)

_MAX_INT = 2**53 - 1
_MAX_PARTITION = 1023
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64

VERDICT_APPENDED = "appended"
VERDICT_DUPLICATE = "duplicate"
_VERDICTS = frozenset({VERDICT_APPENDED, VERDICT_DUPLICATE})

DEDUP_NEW = "new"
DEDUP_DUPLICATE = "duplicate"
DEDUP_OUT_OF_ORDER = "out-of-order"
_DEDUP_VERDICTS = frozenset({DEDUP_NEW, DEDUP_DUPLICATE, DEDUP_OUT_OF_ORDER})


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class IdempotentProducerError(Exception):
    """Base class for all idempotent-producer errors."""


class BadTopicError(IdempotentProducerError):
    """Topic is not a non-empty str (or exceeds length limits)."""


class BadPartitionError(IdempotentProducerError):
    """Partition is not an int in [0, 1023] (bool refused)."""


class BadProducerSeqError(IdempotentProducerError):
    """Producer sequence number is not a non-negative int (bool refused)."""


class BadDigestError(IdempotentProducerError):
    """Payload digest is not a well-formed 'sha256:' + 64 hex pin."""


class OutOfOrderError(IdempotentProducerError):
    """Producer seq jumps past last_seq + 1 -- a gap, fail-closed."""


class SeqOrderError(IdempotentProducerError):
    """Ledger seq is not a strictly increasing int (bool refused)."""


class AuditKindError(IdempotentProducerError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Canonical helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding for digest pins."""
    if _cj is not None:
        return _cj.jcs_dumps(obj).encode("utf-8")  # type: ignore[attr-defined]
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pin(tag: str, obj: Any) -> str:
    """Type-tagged sha256 digest pin."""
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x00" + _canonical(obj)
    ).hexdigest()


def _check_topic(topic: Any) -> str:
    if isinstance(topic, bool) or not isinstance(topic, str):
        raise BadTopicError(f"topic must be a non-empty str, got {type(topic).__name__}")
    if not topic or len(topic) > 256:
        raise BadTopicError("topic must be 1..256 chars")
    return topic


def _check_partition(partition: Any) -> int:
    if isinstance(partition, bool) or not isinstance(partition, int):
        raise BadPartitionError(
            f"partition must be an int in [0, {_MAX_PARTITION}], "
            f"got {type(partition).__name__}"
        )
    if partition < 0 or partition > _MAX_PARTITION:
        raise BadPartitionError(
            f"partition must be in [0, {_MAX_PARTITION}], got {partition}"
        )
    return partition


def _check_producer_seq(producer_seq: Any) -> int:
    if isinstance(producer_seq, bool) or not isinstance(producer_seq, int):
        raise BadProducerSeqError(
            f"producer_seq must be a non-negative int, got {type(producer_seq).__name__}"
        )
    if producer_seq < 0 or producer_seq > _MAX_INT:
        raise BadProducerSeqError(
            f"producer_seq must be in [0, {_MAX_INT}], got {producer_seq}"
        )
    return producer_seq


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"payload_digest must be a 'sha256:' + 64 hex pin, "
            f"got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadDigestError("payload_digest must be 'sha256:' + 64 hex chars")
    try:
        int(digest[len(_DIGEST_PREFIX):], 16)
    except ValueError:
        raise BadDigestError("payload_digest hex part is not valid hex")
    return digest


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SendRecord:
    """One booked send: the broker-side verdict as data."""

    send_id: str
    topic: str
    partition: int
    producer_seq: int
    payload_digest: str
    verdict: str  # "appended" | "duplicate"
    digest: str
    version: str = IDEMPOTENT_PRODUCER_VERSION
    schema: str = IDEMPOTENT_PRODUCER_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on tamper."""
        body = {
            "send_id": self.send_id,
            "topic": self.topic,
            "partition": self.partition,
            "producer_seq": self.producer_seq,
            "payload_digest": self.payload_digest,
            "verdict": self.verdict,
        }
        return self.digest == _pin("send-record", body)


@dataclass(frozen=True)
class SequenceView:
    """Pure read view: the next assignable producer sequence number."""

    topic: str
    partition: int
    next_seq: int
    version: str = IDEMPOTENT_PRODUCER_VERSION
    schema: str = IDEMPOTENT_PRODUCER_SCHEMA


@dataclass(frozen=True)
class DedupeVerdict:
    """Pure read view: what send() would decide, as data."""

    topic: str
    partition: int
    producer_seq: int
    verdict: str  # "new" | "duplicate" | "out-of-order"
    version: str = IDEMPOTENT_PRODUCER_VERSION
    schema: str = IDEMPOTENT_PRODUCER_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def idempotent_producer_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for this module."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError(f"audit seq must be a positive int, got {seq!r}")
    clean = {k: v for k, v in detail.items() if k not in _BANNED_AUDIT_KEYS}
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": clean,
        "module": IDEMPOTENT_PRODUCER_VERSION,
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class IdempotentProducer:
    """Kafka-shaped idempotent send bookkeeping (single-host, deterministic)."""

    def __init__(self, producer_id: str) -> None:
        if isinstance(producer_id, bool) or not isinstance(producer_id, str):
            raise BadTopicError(
                f"producer_id must be a non-empty str, got {type(producer_id).__name__}"
            )
        if not producer_id or len(producer_id) > 256:
            raise BadTopicError("producer_id must be 1..256 chars")
        self._producer_id = producer_id
        self._lock = threading.RLock()
        self._seq = 0  # ledger seq, strictly increasing on mutations
        # (topic, partition) -> {"last": int, "appended": int}
        self._partitions: Dict[Tuple[str, int], Dict[str, int]] = {}
        self._send_counter = 0
        self._audit: list = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: Any) -> None:
        """Validate and consume a ledger seq; rewinds raise bare."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
        if seq <= 0:
            raise SeqOrderError(f"seq must be positive, got {seq}")
        if seq <= self._seq:
            raise SeqOrderError(f"seq must be strictly increasing, got {seq}")
        self._seq = seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(idempotent_producer_audit_event(kind, detail, seq))

    def _fail(self, seq: int, exc: IdempotentProducerError, **detail: Any) -> None:
        """Book a rejection row, then raise the specific error."""
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _state(self, topic: str, partition: int) -> Dict[str, int]:
        key = (topic, partition)
        state = self._partitions.get(key)
        if state is None:
            state = {"last": -1, "appended": 0}
            self._partitions[key] = state
        return state

    # -- mutations ------------------------------------------------------

    def send(
        self,
        topic: str,
        partition: int,
        producer_seq: int,
        payload_digest: str,
        seq: int,
    ) -> SendRecord:
        """Book one send; verdict is data, gaps raise fail-closed."""
        with self._lock:
            self._claim_seq(seq)
            try:
                topic = _check_topic(topic)
                partition = _check_partition(partition)
                producer_seq = _check_producer_seq(producer_seq)
                payload_digest = _check_digest(payload_digest)
            except IdempotentProducerError as exc:
                self._fail(seq, exc)
            state = self._state(topic, partition)
            last = state["last"]
            if producer_seq > last + 1:
                self._fail(
                    seq,
                    OutOfOrderError(
                        f"producer_seq {producer_seq} jumps past expected {last + 1}"
                    ),
                    topic=topic,
                    partition=partition,
                    producer_seq=producer_seq,
                    expected=last + 1,
                )
            self._send_counter += 1
            send_id = f"send-{self._send_counter}"
            if producer_seq == last + 1:
                state["last"] = producer_seq
                state["appended"] += 1
                verdict = VERDICT_APPENDED
                self._emit(
                    KIND_SENT,
                    seq,
                    send_id=send_id,
                    topic=topic,
                    partition=partition,
                    producer_seq=producer_seq,
                    payload_digest=payload_digest,
                )
            else:  # producer_seq <= last: duplicate of an appended record
                verdict = VERDICT_DUPLICATE
                self._emit(
                    KIND_DEDUPLICATED,
                    seq,
                    send_id=send_id,
                    topic=topic,
                    partition=partition,
                    producer_seq=producer_seq,
                    payload_digest=payload_digest,
                )
            body = {
                "send_id": send_id,
                "topic": topic,
                "partition": partition,
                "producer_seq": producer_seq,
                "payload_digest": payload_digest,
                "verdict": verdict,
            }
            return SendRecord(digest=_pin("send-record", body), **body)

    # -- pure read views ------------------------------------------------

    def _read_seq_shape(self, seq: Any) -> None:
        """Validate seq shape on reads; never consumes."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError(f"seq must be a positive int, got {seq!r}")

    def sequence(self, topic: str, partition: int, seq: int) -> SequenceView:
        """Next assignable producer sequence number (pure read)."""
        with self._lock:
            self._read_seq_shape(seq)
            topic = _check_topic(topic)
            partition = _check_partition(partition)
            state = self._state(topic, partition)
            return SequenceView(
                topic=topic, partition=partition, next_seq=state["last"] + 1
            )

    def dedupe(
        self, topic: str, partition: int, producer_seq: int, seq: int
    ) -> DedupeVerdict:
        """What send() would decide for this seq number, as data (pure read)."""
        with self._lock:
            self._read_seq_shape(seq)
            topic = _check_topic(topic)
            partition = _check_partition(partition)
            producer_seq = _check_producer_seq(producer_seq)
            state = self._state(topic, partition)
            last = state["last"]
            if producer_seq == last + 1:
                verdict = DEDUP_NEW
            elif producer_seq <= last:
                verdict = DEDUP_DUPLICATE
            else:
                verdict = DEDUP_OUT_OF_ORDER
            return DedupeVerdict(
                topic=topic,
                partition=partition,
                producer_seq=producer_seq,
                verdict=verdict,
            )

    # -- views ----------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Aggregate ledger stats (pure read)."""
        with self._lock:
            return {
                "producer_id": self._producer_id,
                "partitions": len(self._partitions),
                "sends": self._send_counter,
                "appended": sum(s["appended"] for s in self._partitions.values()),
                "version": IDEMPOTENT_PRODUCER_VERSION,
                "schema": IDEMPOTENT_PRODUCER_SCHEMA,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Booked audit events (pure read)."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: assign -> send -> retry -> dedupe."""
    prod = IdempotentProducer("pid-1")
    digest = _pin("value", "hello")
    first = prod.sequence("orders", 0, 1)
    assert first.next_seq == 0
    rec = prod.send("orders", 0, 0, digest, 2)
    assert rec.verdict == "appended" and rec.verify()
    assert prod.sequence("orders", 0, 3).next_seq == 1
    # retry of the same record -> deduped, not re-appended
    dup = prod.send("orders", 0, 0, digest, 4)
    assert dup.verdict == "duplicate" and dup.verify()
    assert prod.stats()["appended"] == 1
    # gap -> fail-closed
    try:
        prod.send("orders", 0, 5, digest, 5)
    except OutOfOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected OutOfOrderError")
    # pure-read dedupe preview
    verdict = prod.dedupe("orders", 0, 1, 6)
    assert verdict.verdict == "new"
    print("idempotent-producer OK: send, dedupe, sequence, fail-closed")


if __name__ == "__main__":
    main()
