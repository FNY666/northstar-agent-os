"""Dead letter queue: failed-message lifecycle bookkeeping.

Research motivation: in Amazon SQS, RabbitMQ and Kafka a *dead letter
queue* absorbs messages that exhaust their delivery budget -- too many
failed processing attempts, a malformed payload, a crashed consumer.
The broker books the failure, moves the message aside, and lets an
operator retry it later or discard it deliberately. This module books
that lifecycle deterministically: enqueue on failure, bounded retries,
terminal discard. It executes no work and delivers no message -- the
host owns the main queue, the redelivery timers, and the actual
reprocessing.

Public API:

- ``DeadLetterQueue(max_retries=3)`` -- mutable, RLock-guarded ledger.
  - ``enqueue(msg_id, payload_digest, seq, reason="")`` -> frozen
    ``EnqueueRecord``: books a failed message into the DLQ
    (``attempts`` starts at 1).
  - ``retry(msg_id, seq)`` -> frozen ``RetryRecord``: declares one
    reprocessing attempt (``attempts`` increments as data). When
    ``attempts`` would exceed ``max_retries``, raises
    ``MaxRetriesExceededError`` fail-closed and marks the message
    terminal -- only ``discard()`` may still act on it.
  - ``discard(msg_id, seq, reason="")`` -> frozen ``DiscardRecord``:
    terminal removal; the id is retired and may never be re-enqueued.
  - ``message(msg_id)`` / ``pending()`` / ``stats()`` / ``audit_log()`` --
    pure read views; consume no seq.
- ``dead_letter_queue_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"dead-letter.enqueued"``,
  ``"dead-letter.retried"``, ``"dead-letter.discarded"``,
  ``"dead-letter.rejected"``.

Payloads are pinned by ``sha256:`` digest only -- raw bytes never enter
a record or cross the audit boundary. Failure reasons are host-declared
data; the module cannot prove a message is actually poison.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* failures, retries and discards; it
  observes no queue, crashes no consumer, and cannot prove a booked
  retry was actually reprocessed by the host.
- A ``RetryRecord`` is a decision, not a redelivery: the message moves
  only if the host acts on it.
- ``max_retries`` bounds the booked attempts; whether the *main* queue
  agrees is the host's problem, not this ledger's.

Version pin: ``dead-letter-queue.v1`` / schema pin
``northstar.dead-letter-queue.v1``.
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
DEAD_LETTER_QUEUE_VERSION = "dead-letter-queue.v1"

#: Schema pin carried by records and audit events.
DEAD_LETTER_QUEUE_SCHEMA = "northstar.dead-letter-queue.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ENQUEUED = "dead-letter.enqueued"
KIND_RETRIED = "dead-letter.retried"
KIND_DISCARDED = "dead-letter.discarded"
KIND_REJECTED = "dead-letter.rejected"
_KINDS = frozenset(
    {KIND_ENQUEUED, KIND_RETRIED, KIND_DISCARDED, KIND_REJECTED}
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64

#: Terminal message states: nothing further may be booked for these.
_STATE_ACTIVE = "active"
_STATE_TERMINAL = "terminal"
_STATES = frozenset({_STATE_ACTIVE, _STATE_TERMINAL})


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class DeadLetterQueueError(Exception):
    """Base class for all dead-letter-queue errors."""


class BadMessageError(DeadLetterQueueError):
    """msg_id is not a non-empty str."""


class BadDigestError(DeadLetterQueueError):
    """payload_digest is not a well-formed sha256: pin."""


class BadReasonError(DeadLetterQueueError):
    """reason is not a str (or exceeds the length cap)."""


class DuplicateMessageError(DeadLetterQueueError):
    """msg_id is already booked (active or retired)."""


class UnknownMessageError(DeadLetterQueueError):
    """msg_id is not in the ledger."""


class TerminalMessageError(DeadLetterQueueError):
    """The message is terminal; only discard() may act on it."""


class MaxRetriesExceededError(DeadLetterQueueError):
    """The retry would exceed the configured max_retries budget."""


class BadConfigError(DeadLetterQueueError):
    """max_retries is not a positive int."""


class SeqOrderError(DeadLetterQueueError):
    """Caller seq did not strictly increase."""


class AuditKindError(DeadLetterQueueError):
    """Unknown audit kind for dead_letter_queue_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_msg_id(msg_id: Any) -> str:
    if isinstance(msg_id, bool) or not isinstance(msg_id, str):
        raise BadMessageError(
            f"msg_id must be str, got {type(msg_id).__name__}"
        )
    if not msg_id.strip():
        raise BadMessageError("msg_id must be non-empty")
    if len(msg_id) > 256:
        raise BadMessageError("msg_id exceeds 256 chars")
    return msg_id


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"payload_digest must be str, got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadDigestError(
            "payload_digest must be 'sha256:' + 64 hex chars"
        )
    hexpart = digest[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError("payload_digest hex part is not lowercase hex")
    return digest


def _check_reason(reason: Any) -> str:
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise BadReasonError(
            f"reason must be str, got {type(reason).__name__}"
        )
    if len(reason) > 1024:
        raise BadReasonError("reason exceeds 1024 chars")
    return reason


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
                raise DeadLetterQueueError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DeadLetterQueueError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DeadLetterQueueError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([DEAD_LETTER_QUEUE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnqueueRecord:
    """Booked arrival of a failed message in the DLQ.

    ``attempts`` starts at 1: the failure that brought it here is
    already counted. The payload is pinned by digest only -- raw bytes
    never enter a record.
    """

    msg_id: str
    payload_digest: str
    reason: str
    attempts: int
    max_retries: int
    state: str
    digest: str
    seq: int
    schema: str = DEAD_LETTER_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "enqueue",
                self.msg_id,
                self.payload_digest,
                self.reason,
                self.attempts,
                self.max_retries,
                self.state,
                self.seq,
            )
        except DeadLetterQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == DEAD_LETTER_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class RetryRecord:
    """Booked retry decision: the host may reprocess this message.

    ``attempts`` is the new attempt count (the failed attempt plus each
    booked retry). Booking only -- the retry happens iff the host acts
    on it.
    """

    msg_id: str
    attempts: int
    max_retries: int
    digest: str
    seq: int
    schema: str = DEAD_LETTER_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "retry",
                self.msg_id,
                self.attempts,
                self.max_retries,
                self.seq,
            )
        except DeadLetterQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == DEAD_LETTER_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class DiscardRecord:
    """Terminal removal of a dead-lettered message.

    The ``msg_id`` is retired by this record and may never be
    re-enqueued -- a reappearing message is a new message with a new id.
    """

    msg_id: str
    reason: str
    digest: str
    seq: int
    schema: str = DEAD_LETTER_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "discard", self.msg_id, self.reason, self.seq
            )
        except DeadLetterQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == DEAD_LETTER_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class MessageView:
    """Pure read view of one message's DLQ state."""

    msg_id: str
    payload_digest: str
    attempts: int
    max_retries: int
    state: str
    schema: str = DEAD_LETTER_QUEUE_SCHEMA


@dataclass(frozen=True)
class QueueStats:
    """Pure read view of ledger-wide counters."""

    active: int
    terminal: int
    discarded: int
    enqueued: int
    retried: int
    schema: str = DEAD_LETTER_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def dead_letter_queue_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the dead letter queue.

    Raw payloads never cross the audit boundary: ``detail`` may carry
    digests, ids, reasons, attempts and counts -- never ``payload`` or
    ``payload_bytes``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"payload", "payload_bytes", "value", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DEAD_LETTER_QUEUE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class DeadLetterQueue:
    """Deterministic dead-letter-queue bookkeeping (single-host).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). Read views
    (``message``, ``pending``, ``stats``, ``audit_log``) are pure:
    seq shape is validated, never consumed.
    """

    def __init__(self, max_retries: int = 3) -> None:
        if isinstance(max_retries, bool) or not isinstance(
            max_retries, int
        ):
            raise BadConfigError("max_retries must be int")
        if max_retries < 1 or max_retries > 64:
            raise BadConfigError("max_retries must be in [1, 64]")
        self._max_retries = max_retries
        self._lock = threading.RLock()
        self._last_seq = -1
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        self._enqueues: list = []
        self._retries: list = []
        self._discards: list = []
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

    def _reject(self, seq: int, reason: str, msg_id: str = "") -> Dict[str, Any]:
        row = dead_letter_queue_audit_event(
            KIND_REJECTED, {"reason": reason, "msg_id": msg_id}, seq
        )
        self._audit.append(row)
        return row

    # -- pure views --------------------------------------------------------

    def message(self, msg_id: str) -> Optional[MessageView]:
        """State of one message, or None if never enqueued."""
        msg_id = _check_msg_id(msg_id)
        with self._lock:
            entry = self._entries.get(msg_id)
            if entry is None:
                return None
            return MessageView(
                msg_id=msg_id,
                payload_digest=entry["payload_digest"],
                attempts=entry["attempts"],
                max_retries=self._max_retries,
                state=entry["state"],
            )

    def pending(self) -> Tuple[str, ...]:
        """Ids of active (non-terminal, non-discarded) messages."""
        with self._lock:
            return tuple(
                sorted(
                    mid
                    for mid, e in self._entries.items()
                    if e["state"] == _STATE_ACTIVE
                )
            )

    def stats(self) -> QueueStats:
        with self._lock:
            active = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_ACTIVE
            )
            terminal = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_TERMINAL
            )
            return QueueStats(
                active=active,
                terminal=terminal,
                discarded=len(self._discards),
                enqueued=len(self._enqueues),
                retried=len(self._retries),
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations ---------------------------------------------------------

    def enqueue(
        self, msg_id: str, payload_digest: str, seq: int, reason: str = ""
    ) -> EnqueueRecord:
        """Book a failed message into the DLQ.

        The failure that brought it here counts as attempt 1. Ids are
        never recycled: re-enqueueing an active or retired id raises
        ``DuplicateMessageError`` fail-closed. Failed mutations consume
        their seq.
        """
        with self._lock:
            self._claim(seq)
            try:
                msg_id = _check_msg_id(msg_id)
                payload_digest = _check_digest(payload_digest)
                reason = _check_reason(reason)
                if msg_id in self._entries or msg_id in self._retired:
                    raise DuplicateMessageError(
                        f"msg_id already booked: {msg_id}"
                    )
            except DeadLetterQueueError as exc:
                self._reject(
                    seq,
                    type(exc).__name__,
                    msg_id if isinstance(msg_id, str) else "",
                )
                raise
            record = EnqueueRecord(
                msg_id=msg_id,
                payload_digest=payload_digest,
                reason=reason,
                attempts=1,
                max_retries=self._max_retries,
                state=_STATE_ACTIVE,
                digest=_pin(
                    "enqueue",
                    msg_id,
                    payload_digest,
                    reason,
                    1,
                    self._max_retries,
                    _STATE_ACTIVE,
                    seq,
                ),
                seq=seq,
            )
            self._entries[msg_id] = {
                "payload_digest": payload_digest,
                "reason": reason,
                "attempts": 1,
                "state": _STATE_ACTIVE,
            }
            self._enqueues.append(record)
            self._audit.append(
                dead_letter_queue_audit_event(
                    KIND_ENQUEUED,
                    {
                        "msg_id": msg_id,
                        "payload_digest": payload_digest,
                        "reason": reason,
                        "attempts": 1,
                    },
                    seq,
                )
            )
            return record

    def retry(self, msg_id: str, seq: int) -> RetryRecord:
        """Book one reprocessing attempt for an active message.

        ``attempts`` increments as data. When the new count would exceed
        ``max_retries`` the message is marked terminal and
        ``MaxRetriesExceededError`` is raised fail-closed -- from then on
        only ``discard()`` may act on it.
        """
        with self._lock:
            self._claim(seq)
            try:
                msg_id = _check_msg_id(msg_id)
                entry = self._entries.get(msg_id)
                if entry is None:
                    raise UnknownMessageError(
                        f"unknown msg_id: {msg_id}"
                    )
                if entry["state"] == _STATE_TERMINAL:
                    raise TerminalMessageError(
                        f"message is terminal: {msg_id}"
                    )
                new_attempts = entry["attempts"] + 1
                if new_attempts > self._max_retries:
                    entry["state"] = _STATE_TERMINAL
                    raise MaxRetriesExceededError(
                        f"max_retries={self._max_retries} exceeded "
                        f"for {msg_id}"
                    )
            except DeadLetterQueueError as exc:
                self._reject(seq, type(exc).__name__, msg_id)
                raise
            record = RetryRecord(
                msg_id=msg_id,
                attempts=new_attempts,
                max_retries=self._max_retries,
                digest=_pin(
                    "retry", msg_id, new_attempts, self._max_retries, seq
                ),
                seq=seq,
            )
            entry["attempts"] = new_attempts
            self._retries.append(record)
            self._audit.append(
                dead_letter_queue_audit_event(
                    KIND_RETRIED,
                    {
                        "msg_id": msg_id,
                        "attempts": new_attempts,
                        "max_retries": self._max_retries,
                    },
                    seq,
                )
            )
            return record

    def discard(
        self, msg_id: str, seq: int, reason: str = ""
    ) -> DiscardRecord:
        """Terminally remove a dead-lettered message.

        Retires the id: it may never be re-enqueued. Discard may act on
        active *and* terminal messages; unknown ids fail closed.
        """
        with self._lock:
            self._claim(seq)
            try:
                msg_id = _check_msg_id(msg_id)
                reason = _check_reason(reason)
                entry = self._entries.get(msg_id)
                if entry is None:
                    raise UnknownMessageError(
                        f"unknown msg_id: {msg_id}"
                    )
            except DeadLetterQueueError as exc:
                self._reject(
                    seq,
                    type(exc).__name__,
                    msg_id if isinstance(msg_id, str) else "",
                )
                raise
            record = DiscardRecord(
                msg_id=msg_id,
                reason=reason,
                digest=_pin("discard", msg_id, reason, seq),
                seq=seq,
            )
            del self._entries[msg_id]
            self._retired.add(msg_id)
            self._discards.append(record)
            self._audit.append(
                dead_letter_queue_audit_event(
                    KIND_DISCARDED,
                    {"msg_id": msg_id, "reason": reason},
                    seq,
                )
            )
            return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: enqueue, retry to terminal, discard."""
    import json as _json  # noqa: F401  (stdlib-only demonstration)

    dlq = DeadLetterQueue(max_retries=2)
    digest = "sha256:" + "ab" * 32
    dlq.enqueue("m-1", digest, 1, "worker crashed")
    view = dlq.message("m-1")
    assert view is not None and view.attempts == 1
    rec = dlq.retry("m-1", 2)
    assert rec.attempts == 2 and rec.verify()
    try:
        dlq.retry("m-1", 3)
        raise AssertionError("expected MaxRetriesExceededError")
    except MaxRetriesExceededError:
        pass
    view = dlq.message("m-1")
    assert view is not None and view.state == _STATE_TERMINAL
    disc = dlq.discard("m-1", 4, "poison payload")
    assert disc.verify()
    assert dlq.pending() == ()
    stats = dlq.stats()
    assert (stats.enqueued, stats.retried, stats.discarded) == (1, 1, 1)
    print(
        "dead-letter-queue OK: enqueue, retry, terminal, discard, audit"
    )


if __name__ == "__main__":
    main()
