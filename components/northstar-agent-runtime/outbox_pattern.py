"""Transactional outbox pattern: reliable messaging for an unreliable host.

Research note: the transactional outbox is the classic reliability pattern
(Kleppmann, *Designing Data-Intensive Applications*) for "the record was
committed but the notification never went out". An agent that writes an
audit entry, fires a webhook, or hands a result to another agent must not
lose the message if it crashes between the local commit and the send —
and must not double-apply a message the receiver already processed.

* **Store-then-send** — :meth:`Outbox.publish` appends the message to the
  outbox in the PENDING state. A separate :meth:`Outbox.dispatch` pass
  hands pending messages to a caller-supplied transport and marks them
  SENT only after the transport reports success. A crash between publish
  and dispatch leaves the message PENDING, never lost.
* **FIFO dispatch** — pending messages are dispatched in caller-seq order,
  so the receiver observes a deterministic sequence.
* **At-least-once, never at-most-once** — a transport failure (exception
  or falsy return) leaves the message PENDING for a later pass. Duplicate
  sends are possible; receivers must be idempotent. The outbox refuses to
  publish a second message with the same ``message_id`` so a retrying
  caller cannot fork the sequence.
* **Dead-letter, not infinite retry** — after ``max_attempts`` failed
  attempts a message moves to FAILED and is no longer dispatched. The
  operator inspects it; the outbox never spins forever on poison.
* **Spec entry points** — :meth:`Outbox.write` stores a message (same
  operation as :meth:`publish`); :meth:`Outbox.mark` records the send
  outcome for a message the host transported itself — only PENDING
  messages can be marked, and re-marking a terminal message is refused
  fail-closed.
* **No wall-clock** — all seqs are caller-supplied ints (the host's own
  monotonic counter), so the module is deterministic and replayable.
* **Fail-closed** — malformed messages raise at publish time; unknown
  message ids raise ``KeyError``; malformed transport results are treated
  as failures, never as success.

Honest scope: this is the *store-then-send state machine*, not a message
broker — there is no persistence beyond process memory (the host that
needs crash recovery snapshots the outbox and restores it), no transport
(codec, auth, retries-with-backoff are the caller's job), and no
exactly-once guarantee. SENT means "the transport reported success",
never "the receiver processed it exactly once". A clean dispatch report
means "nothing left pending", not "every downstream effect happened".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

#: Module version.
OUTBOX_PATTERN_VERSION = "outbox-pattern.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.outbox-pattern.v1"


class MessageState(str, Enum):
    """Lifecycle state of one outbox message."""

    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class OutboxError(Exception):
    """Malformed input to the outbox (programming error)."""


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise OutboxError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise OutboxError(f"{name} must be non-negative")
    return seq


def _check_non_empty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise OutboxError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class OutboxMessage:
    """One message staged in the outbox."""

    message_id: str
    destination: str
    payload: Mapping[str, Any]
    seq: int

    def __post_init__(self) -> None:
        _check_non_empty_str(self.message_id, "message_id")
        _check_non_empty_str(self.destination, "destination")
        if not isinstance(self.payload, Mapping):
            raise OutboxError("payload must be a mapping")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "message_id": self.message_id,
            "destination": self.destination,
            "payload": dict(self.payload),
            "seq": self.seq,
        }


@dataclass(frozen=True)
class OutboxEvent:
    """One append-only outbox event (published / sent / failed)."""

    kind: str  # "published" | "sent" | "failed"
    message_id: str
    seq: int
    attempts: int = 0
    reason: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("published", "sent", "failed"):
            raise OutboxError(f"unknown event kind: {self.kind!r}")
        _check_non_empty_str(self.message_id, "message_id")
        _check_seq(self.seq)
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise OutboxError("attempts must be an int")
        if self.attempts < 0:
            raise OutboxError("attempts must be non-negative")
        if not isinstance(self.reason, str):
            raise OutboxError("reason must be a str")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "kind": self.kind,
            "message_id": self.message_id,
            "seq": self.seq,
            "attempts": self.attempts,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DispatchReport:
    """Outcome of one :meth:`Outbox.dispatch` pass."""

    sent: tuple = ()
    failed: tuple = ()
    still_pending: tuple = ()

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "sent": list(self.sent),
            "failed": list(self.failed),
            "still_pending": list(self.still_pending),
        }


class _StoredMessage:
    """Mutable bookkeeping for one published message."""

    __slots__ = ("message", "state", "attempts")

    def __init__(self, message: OutboxMessage) -> None:
        self.message = message
        self.state = MessageState.PENDING
        self.attempts = 0


class Outbox:
    """Transactional outbox: store-then-send with dead-lettering.

    The outbox never performs I/O itself. The host supplies a
    ``transport`` callable to :meth:`dispatch`; the transport takes an
    :class:`OutboxMessage` and returns a truthy value on success, a falsy
    value on soft failure, and may raise on hard failure.
    """

    def __init__(self, max_attempts: int = 3) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise OutboxError("max_attempts must be an int")
        if max_attempts < 1:
            raise OutboxError("max_attempts must be >= 1")
        self._max_attempts = max_attempts
        self._messages: dict[str, _StoredMessage] = {}
        self._events: list[OutboxEvent] = []

    # -- publish --------------------------------------------------------

    def publish(self, message: OutboxMessage, *, seq: int) -> OutboxMessage:
        """Stage a message for dispatch. Returns the stored message."""
        if not isinstance(message, OutboxMessage):
            raise OutboxError("message must be an OutboxMessage")
        _check_seq(seq, "seq")
        if message.message_id in self._messages:
            raise OutboxError(
                f"duplicate message_id: {message.message_id!r} "
                "(retrying callers must reuse the original publish)"
            )
        self._messages[message.message_id] = _StoredMessage(message)
        self._events.append(
            OutboxEvent(kind="published", message_id=message.message_id,
                        seq=seq, attempts=0)
        )
        return message

    # -- spec entry points ----------------------------------------------

    def write(self, message: OutboxMessage, *, seq: int) -> OutboxMessage:
        """Store a message in the outbox. Alias of :meth:`publish`.

        This is the *store* half of store-then-send: the host writes the
        message in the same logical transaction as its business record,
        then :meth:`dispatch` or :meth:`mark` handles the send half.
        """
        return self.publish(message, seq=seq)

    def mark(self, message_id: str, *, seq: int,
             outcome: str = "sent", reason: str = "") -> MessageState:
        """Record the send outcome when the host transported a message itself.

        ``outcome`` is ``"sent"`` (the host's transport reported success) or
        ``"failed"`` (poison — dead-lettered immediately, no retry). Only
        PENDING messages can be marked; re-marking a terminal message is
        refused fail-closed. Returns the new :class:`MessageState`.
        """
        _check_non_empty_str(message_id, "message_id")
        _check_seq(seq, "seq")
        if outcome not in ("sent", "failed"):
            raise OutboxError(
                f"outcome must be 'sent' or 'failed', got {outcome!r}"
            )
        if not isinstance(reason, str):
            raise OutboxError("reason must be a str")
        try:
            stored = self._messages[message_id]
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None
        if stored.state is not MessageState.PENDING:
            raise OutboxError(
                f"cannot mark message {message_id!r}: already "
                f"{stored.state.value}"
            )
        if outcome == "sent":
            stored.state = MessageState.SENT
            self._events.append(
                OutboxEvent(kind="sent", message_id=message_id,
                            seq=seq, attempts=stored.attempts)
            )
        else:
            stored.state = MessageState.FAILED
            self._events.append(
                OutboxEvent(kind="failed", message_id=message_id,
                            seq=seq, attempts=stored.attempts, reason=reason)
            )
        return stored.state

    # -- views ----------------------------------------------------------

    def state(self, message_id: str) -> MessageState:
        """Lifecycle state of one message; KeyError on unknown id."""
        _check_non_empty_str(message_id, "message_id")
        try:
            return self._messages[message_id].state
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None

    def pending(self) -> tuple:
        """PENDING messages in caller-seq order (deterministic)."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.PENDING
        )

    def sent(self) -> tuple:
        """SENT messages in caller-seq order."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.SENT
        )

    def failed(self) -> tuple:
        """FAILED (dead-lettered) messages in caller-seq order."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.FAILED
        )

    def attempts(self, message_id: str) -> int:
        """Recorded dispatch attempts for one message."""
        _check_non_empty_str(message_id, "message_id")
        try:
            return self._messages[message_id].attempts
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None

    def events(self) -> tuple:
        """Append-only event log, registration order."""
        return tuple(self._events)

    # -- dispatch -------------------------------------------------------

    def dispatch(self, transport: Callable[[OutboxMessage], Any],
                 *, seq: int) -> DispatchReport:
        """Attempt every PENDING message in seq order.

        A truthy transport result marks the message SENT. A falsy result
        or an exception records one attempt and leaves the message
        PENDING; when attempts reach ``max_attempts`` the message moves
        to FAILED (dead-letter) and is no longer dispatched.
        """
        if not callable(transport):
            raise OutboxError("transport must be callable")
        _check_seq(seq, "seq")
        sent: list[str] = []
        failed: list[str] = []
        still_pending: list[str] = []
        for message in self.pending():
            stored = self._messages[message.message_id]
            try:
                ok = transport(message)
            except Exception as exc:  # noqa: BLE001 - transport failure is data
                reason = f"{type(exc).__name__}: {exc}"
                ok = False
            else:
                reason = "" if ok else "transport returned falsy"
            if ok:
                stored.state = MessageState.SENT
                sent.append(message.message_id)
                self._events.append(
                    OutboxEvent(kind="sent", message_id=message.message_id,
                                seq=seq, attempts=stored.attempts)
                )
            else:
                stored.attempts += 1
                if stored.attempts >= self._max_attempts:
                    stored.state = MessageState.FAILED
                    failed.append(message.message_id)
                    self._events.append(
                        OutboxEvent(kind="failed",
                                    message_id=message.message_id,
                                    seq=seq, attempts=stored.attempts,
                                    reason=reason)
                    )
                else:
                    still_pending.append(message.message_id)
        return DispatchReport(sent=tuple(sent), failed=tuple(failed),
                              still_pending=tuple(still_pending))


def outbox_audit_event(record: Any, *, audit_seq: int) -> dict:
    """Shape an outbox record as an ``audit.ndjson/1`` record."""
    if isinstance(record, (OutboxEvent, DispatchReport, OutboxMessage)):
        shaped = record.as_dict()
    else:
        raise TypeError(
            "record must be an OutboxEvent, DispatchReport, or OutboxMessage"
        )
    if isinstance(audit_seq, bool) or not isinstance(audit_seq, int):
        raise TypeError("audit_seq must be an int")
    if audit_seq < 0:
        raise ValueError("audit_seq must be >= 0")
    shaped["audit_seq"] = audit_seq
    return shaped


def main() -> None:
    box = Outbox(max_attempts=2)
    box.publish(OutboxMessage("m1", "webhook", {"ok": True}, seq=0), seq=0)
    box.publish(OutboxMessage("m2", "webhook", {"ok": False}, seq=1), seq=1)

    sent_log: list[str] = []

    def flaky(message: OutboxMessage) -> bool:
        if message.message_id == "m1":
            sent_log.append(message.message_id)
            return True
        raise ConnectionError("endpoint down")

    report = box.dispatch(flaky, seq=2)
    assert report.sent == ("m1",), report
    assert report.still_pending == ("m2",), report
    assert box.state("m1") is MessageState.SENT
    assert box.state("m2") is MessageState.PENDING

    # Second failure exhausts attempts -> dead-letter.
    report2 = box.dispatch(flaky, seq=3)
    assert report2.failed == ("m2",), report2
    assert box.state("m2") is MessageState.FAILED
    assert box.pending() == ()
    print("outbox-pattern OK: store-then-send, retry, dead-letter")


if __name__ == "__main__":
    main()
