"""Dead-letter queue interface (poison-message handling, simulated).

Research motivation: in any at-least-once messaging fabric, some
messages never succeed. Transient faults (a downstream blip, a lock
timeout) clear on retry; *poison* messages never clear -- a
malformed payload, a schema violation, a handler that deterministically
throws. Without a dead-letter queue, a poison message loops forever:
consumed, failed, redelivered, failed again, starving the queue behind
it (the classic "poison message head-of-line block" in SQS, Kafka DLQ
topics, RabbitMQ dead-letter exchanges, Azure Service Bus DLQs).

This module is the *bookkeeping* half of that shape, pinned so the
runtime's messaging plumbing speaks one dialect:

- ``DeadLetter`` -- owns the quarantine registry. ``quarantine()``
  admits a failed message, ``retry()`` requeues one for another
  attempt with an attempt budget, ``inspect()`` reports the full
  failure history without mutating it.
- ``classify_failure(reason)`` -- deterministic transient-vs-permanent
  rules over the failure reason string (documented heuristics, not
  a truth oracle).
- ``dead_letter_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``quarantined`` / ``retried`` / ``retry-exhausted`` / ``inspected``
  / ``discarded``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``message_id`` must be a non-empty ``str``; duplicating an already
  quarantined id is refused (history is never silently overwritten).
- ``payload`` must be JSON-canonicalizable (it is digested); NaN/inf
  floats and non-str mapping keys are refused.
- ``failure_reason`` must be a non-empty ``str``; ``attempts`` must be
  an int (not bool) >= 0; caller seqs are ints (not bool) >= 0.
- ``retry()`` past ``max_retries`` raises ``RetryExhaustedError`` --
  the message is then classified *poison* and stays quarantined until
  an operator discards it.
- ``discard()`` is refused for a message that is still retryable:
  only poison messages may be discarded, and only after they have
  been ``inspect()``ed at least once (operator review is recorded).
- Unknown ``message_id`` on ``retry``/``inspect``/``discard`` raises
  ``UnknownMessageError``.

Honest scope:

- This module books *host-reported* failures. It cannot verify that
  the payload it quarantines is the payload that actually failed, nor
  that a retried message was really redelivered to the consumer.
  A host that lies about attempts gets a lying ledger.
- ``classify_failure`` matches documented reason patterns; an
  unknown reason is classified ``TRANSIENT`` (retry-friendly) because
  over-quarantining on ignorance drops work that might succeed.
  Classification is a routing hint, never a proof of root cause.
- In-memory only: pair with the durable audit writer if quarantine
  records must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
DEAD_LETTER_VERSION = "dead-letter.v1"

#: Schema pin carried by records and audit events.
DEAD_LETTER_SCHEMA = "northstar.dead-letter.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Failure classes produced by classify_failure().
TRANSIENT = "transient"
PERMANENT = "permanent"
_FAILURE_CLASSES = (TRANSIENT, PERMANENT)

#: Audit event kinds.
KIND_QUARANTINED = "quarantined"
KIND_RETRIED = "retried"
KIND_RETRY_EXHAUSTED = "retry-exhausted"
KIND_INSPECTED = "inspected"
KIND_DISCARDED = "discarded"
_KINDS = (
    KIND_QUARANTINED,
    KIND_RETRIED,
    KIND_RETRY_EXHAUSTED,
    KIND_INSPECTED,
    KIND_DISCARDED,
)

# Reason patterns that indicate a deterministic (poison) failure.
_PERMANENT_MARKERS = (
    "schema", "validation", "malformed", "unparseable", "deserialization",
    "poison", "unsupported", "invalid", "constraint", "assertion",
)

# Reason patterns that indicate a transient fault.
_TRANSIENT_MARKERS = (
    "timeout", "timed out", "unavailable", "connection", "throttl",
    "overload", "deadlock", "retryable", "temporary", "ratelimit",
    "rate limit", "backpressure", "busy",
)


class DeadLetterError(Exception):
    """Base error for the dead-letter queue (programming errors)."""


class UnknownMessageError(DeadLetterError):
    """Raised when a message_id is not in the quarantine registry."""


class DuplicateMessageError(DeadLetterError):
    """Raised when a message_id is quarantined twice."""


class RetryExhaustedError(DeadLetterError):
    """Raised when retry() is called past max_retries (poison)."""


class PrematureDiscardError(DeadLetterError):
    """Raised when discard() is called before the message is poison."""


class UnreviewedDiscardError(DeadLetterError):
    """Raised when discard() is called on a poison message not yet inspected."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise DeadLetterError(f"seq must be an int >= 0, got {seq!r}")
    return seq


def _check_message_id(message_id: Any) -> str:
    if not isinstance(message_id, str) or not message_id:
        raise DeadLetterError(
            f"message_id must be a non-empty str, got {message_id!r}")
    return message_id


def _check_attempts(attempts: Any) -> int:
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
        raise DeadLetterError(
            f"attempts must be an int >= 0, got {attempts!r}")
    return attempts


def _check_payload(payload: Any) -> None:
    # Must be JSON-canonicalizable (digested at quarantine time).
    try:
        jcs_canonical_json(payload)
    except Exception as exc:
        raise DeadLetterError(
            f"payload must be JSON-canonicalizable: {exc}") from exc


def _digest_pin(body: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(body))


@dataclass(frozen=True)
class QuarantinedMessage:
    """One quarantined message: pinned, immutable."""

    version: str
    schema: str
    message_id: str
    payload_digest: str
    failure_reason: str
    failure_class: str
    attempts: int
    quarantined_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "message_id": self.message_id,
            "payload_digest": self.payload_digest,
            "failure_reason": self.failure_reason,
            "failure_class": self.failure_class,
            "attempts": self.attempts,
            "quarantined_seq": self.quarantined_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetryTicket:
    """A requeue ticket for one more delivery attempt."""

    version: str
    schema: str
    message_id: str
    payload_digest: str
    attempt_number: int
    remaining_attempts: int
    issued_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "message_id": self.message_id,
            "payload_digest": self.payload_digest,
            "attempt_number": self.attempt_number,
            "remaining_attempts": self.remaining_attempts,
            "issued_seq": self.issued_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class InspectionReport:
    """Full failure history for one quarantined message (read-only)."""

    version: str
    schema: str
    message_id: str
    payload_digest: str
    failure_reason: str
    failure_class: str
    attempts: int
    max_retries: int
    retry_events: int
    is_poison: bool
    was_reviewed: bool
    quarantined_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "message_id": self.message_id,
            "payload_digest": self.payload_digest,
            "failure_reason": self.failure_reason,
            "failure_class": self.failure_class,
            "attempts": self.attempts,
            "max_retries": self.max_retries,
            "retry_events": self.retry_events,
            "is_poison": self.is_poison,
            "was_reviewed": self.was_reviewed,
            "quarantined_seq": self.quarantined_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DiscardRecord:
    """Proof that a poison message was reviewed and discarded."""

    version: str
    schema: str
    message_id: str
    payload_digest: str
    attempts: int
    discarded_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "message_id": self.message_id,
            "payload_digest": self.payload_digest,
            "attempts": self.attempts,
            "discarded_seq": self.discarded_seq,
            "digest": self.digest,
        }


def classify_failure(reason: str) -> str:
    """Classify a failure reason as ``transient`` or ``permanent``.

    Deterministic, documented heuristics: reasons matching known
    deterministic-failure markers (schema/validation/malformed/...)
    are ``permanent``; reasons matching known transient markers
    (timeout/unavailable/throttled/...) are ``transient``. Anything
    else defaults to ``transient`` (retry-friendly; unknown faults
    might clear).
    """
    if not isinstance(reason, str) or not reason:
        raise DeadLetterError(
            f"reason must be a non-empty str, got {reason!r}")
    lowered = reason.lower()
    for marker in _PERMANENT_MARKERS:
        if marker in lowered:
            return PERMANENT
    for marker in _TRANSIENT_MARKERS:
        if marker in lowered:
            return TRANSIENT
    return TRANSIENT  # default: retry-friendly


class DeadLetter:
    """Dead-letter queue: quarantine registry + retry budget."""

    def __init__(self, max_retries: int = 3) -> None:
        if (isinstance(max_retries, bool) or not isinstance(max_retries, int)
                or max_retries < 1):
            raise DeadLetterError(
                f"max_retries must be an int >= 1, got {max_retries!r}")
        self._max_retries = max_retries
        self._lock = threading.RLock()
        # message_id -> {"message": QuarantinedMessage, "retries": int,
        #                 "reviewed": bool, "discarded": Optional[DiscardRecord]}
        self._registry: dict[str, dict] = {}
        self._seq_high = -1

    # -- views ------------------------------------------------------

    @property
    def max_retries(self) -> int:
        return self._max_retries

    def size(self) -> int:
        """Number of messages currently quarantined (not discarded)."""
        with self._lock:
            return sum(1 for r in self._registry.values()
                       if r["discarded"] is None)

    def quarantined_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(m for m, r in self._registry.items()
                                if r["discarded"] is None))

    def poisoned_ids(self) -> Tuple[str, ...]:
        """Ids whose retry budget is exhausted (or classified permanent)."""
        with self._lock:
            return tuple(sorted(
                m for m, r in self._registry.items()
                if r["discarded"] is None and self._is_poison(r)))

    def _is_poison(self, record: dict) -> bool:
        msg: QuarantinedMessage = record["message"]
        return (record["retries"] >= self._max_retries
                or msg.failure_class == PERMANENT)

    # -- operations -------------------------------------------------

    def quarantine(self, message_id: str, payload: Any, failure_reason: str,
                   attempts: int, seq: int) -> QuarantinedMessage:
        """Admit a failed message to the quarantine registry."""
        message_id = _check_message_id(message_id)
        _check_payload(payload)
        if not isinstance(failure_reason, str) or not failure_reason:
            raise DeadLetterError(
                f"failure_reason must be a non-empty str, got {failure_reason!r}")
        attempts = _check_attempts(attempts)
        seq = _check_seq(seq)
        with self._lock:
            existing = self._registry.get(message_id)
            if existing is not None and existing["discarded"] is None:
                raise DuplicateMessageError(
                    f"message already quarantined: {message_id!r}")
            if seq <= self._seq_high:
                raise DeadLetterError(
                    f"seq must strictly increase (high={self._seq_high}), got {seq}")
            self._seq_high = seq
            payload_digest = _digest_pin({"payload": payload})
            failure_class = classify_failure(failure_reason)
            body = {
                "version": DEAD_LETTER_VERSION,
                "schema": DEAD_LETTER_SCHEMA,
                "message_id": message_id,
                "payload_digest": payload_digest,
                "failure_reason": failure_reason,
                "failure_class": failure_class,
                "attempts": attempts,
                "quarantined_seq": seq,
            }
            digest = _digest_pin(body)
            message = QuarantinedMessage(digest=digest, **body)
            self._registry[message_id] = {
                "message": message,
                "retries": 0,
                "reviewed": False,
                "discarded": None,
            }
            return message

    def retry(self, message_id: str, seq: int) -> RetryTicket:
        """Issue one more delivery attempt; raises past max_retries."""
        message_id = _check_message_id(message_id)
        seq = _check_seq(seq)
        with self._lock:
            record = self._registry.get(message_id)
            if record is None or record["discarded"] is not None:
                raise UnknownMessageError(
                    f"unknown quarantined message: {message_id!r}")
            if seq <= self._seq_high:
                raise DeadLetterError(
                    f"seq must strictly increase (high={self._seq_high}), got {seq}")
            msg: QuarantinedMessage = record["message"]
            if record["retries"] >= self._max_retries:
                self._seq_high = seq
                raise RetryExhaustedError(
                    f"retry budget exhausted for {message_id!r}: "
                    f"message is poison")
            record["retries"] += 1
            self._seq_high = seq
            attempt_number = msg.attempts + record["retries"]
            body = {
                "version": DEAD_LETTER_VERSION,
                "schema": DEAD_LETTER_SCHEMA,
                "message_id": message_id,
                "payload_digest": msg.payload_digest,
                "attempt_number": attempt_number,
                "remaining_attempts": self._max_retries - record["retries"],
                "issued_seq": seq,
            }
            digest = _digest_pin(body)
            return RetryTicket(digest=digest, **body)

    def inspect(self, message_id: str) -> InspectionReport:
        """Read-only failure history; marks the message as reviewed."""
        message_id = _check_message_id(message_id)
        with self._lock:
            record = self._registry.get(message_id)
            if record is None or record["discarded"] is not None:
                raise UnknownMessageError(
                    f"unknown quarantined message: {message_id!r}")
            record["reviewed"] = True
            msg: QuarantinedMessage = record["message"]
            body = {
                "version": DEAD_LETTER_VERSION,
                "schema": DEAD_LETTER_SCHEMA,
                "message_id": message_id,
                "payload_digest": msg.payload_digest,
                "failure_reason": msg.failure_reason,
                "failure_class": msg.failure_class,
                "attempts": msg.attempts + record["retries"],
                "max_retries": self._max_retries,
                "retry_events": record["retries"],
                "is_poison": self._is_poison(record),
                "was_reviewed": True,
                "quarantined_seq": msg.quarantined_seq,
            }
            digest = _digest_pin(body)
            return InspectionReport(digest=digest, **body)

    def discard(self, message_id: str, seq: int) -> DiscardRecord:
        """Permanently discard a reviewed poison message."""
        message_id = _check_message_id(message_id)
        seq = _check_seq(seq)
        with self._lock:
            record = self._registry.get(message_id)
            if record is None or record["discarded"] is not None:
                raise UnknownMessageError(
                    f"unknown quarantined message: {message_id!r}")
            if not self._is_poison(record):
                raise PrematureDiscardError(
                    f"message {message_id!r} is still retryable: "
                    f"discard() is only for poison messages")
            if not record["reviewed"]:
                raise UnreviewedDiscardError(
                    f"message {message_id!r} must be inspect()ed before discard")
            if seq <= self._seq_high:
                raise DeadLetterError(
                    f"seq must strictly increase (high={self._seq_high}), got {seq}")
            self._seq_high = seq
            msg: QuarantinedMessage = record["message"]
            body = {
                "version": DEAD_LETTER_VERSION,
                "schema": DEAD_LETTER_SCHEMA,
                "message_id": message_id,
                "payload_digest": msg.payload_digest,
                "attempts": msg.attempts + record["retries"],
                "discarded_seq": seq,
            }
            digest = _digest_pin(body)
            discarded = DiscardRecord(digest=digest, **body)
            record["discarded"] = discarded
            return discarded


def dead_letter_audit_event(kind: str, seq: int,
                            message_id: Optional[str] = None,
                            detail: Optional[Mapping[str, Any]] = None) -> dict:
    """Shape an ``audit.ndjson/1`` record for a dead-letter event.

    Raw payloads are never emitted -- only message ids and digest pins.
    """
    if kind not in _KINDS:
        raise DeadLetterError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    if message_id is not None:
        _check_message_id(message_id)
    event = {
        "schema": AUDIT_SCHEMA,
        "kind": f"dead-letter.{kind}",
        "version": DEAD_LETTER_VERSION,
        "schema_ref": DEAD_LETTER_SCHEMA,
        "seq": seq,
    }
    if message_id is not None:
        event["message_id"] = message_id
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise DeadLetterError("detail must be a mapping")
        event["detail"] = dict(detail)
    return event


def main() -> None:
    dlq = DeadLetter(max_retries=2)
    msg = dlq.quarantine("m-1", {"op": "send", "to": "a"}, "connection timeout",
                        2, 0)
    assert msg.failure_class == TRANSIENT
    ticket = dlq.retry("m-1", 1)
    assert ticket.attempt_number == 3 and ticket.remaining_attempts == 1
    dlq.retry("m-1", 2)  # last budget
    try:
        dlq.retry("m-1", 3)
        raise AssertionError("expected RetryExhaustedError")
    except RetryExhaustedError:
        pass
    report = dlq.inspect("m-1")
    assert report.is_poison and report.was_reviewed
    discarded = dlq.discard("m-1", 4)
    assert discarded.message_id == "m-1" and dlq.size() == 0
    # permanent failure classification
    assert classify_failure("schema validation failed") == PERMANENT
    assert classify_failure("weird new error") == TRANSIENT
    print("dead-letter OK: quarantine, retry, exhaust, inspect, discard")


if __name__ == "__main__":
    main()
