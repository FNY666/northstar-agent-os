"""Transactional inbox pattern: idempotent receive for an unreliable host.

Research note: the transactional inbox is the receive-side twin of the
transactional outbox (Kleppmann, *Designing Data-Intensive Applications*).
The outbox guarantees *at-least-once* delivery; the inbox makes that safe
for the consumer by guaranteeing *at-most-once* effects:

* **Store-then-ack** — :meth:`Inbox.receive` books an incoming message in
  the RECEIVED state and returns a :class:`ReceiveReport`. A redelivery
  of a message already on the books returns ``duplicate=True`` **as
  data**, never as an exception — the transport may retry; the inbox does
  not double-apply. The host processes the message and calls
  :meth:`Inbox.ack` to mark it DONE.
* **First payload wins** — a redelivery carrying a different payload than
  the original is a forked producer, not a retry; it is refused with
  :class:`InboxError`. Retries must be byte-identical (modulo key order).
* **Poison, not infinite loop** — :meth:`Inbox.process` hands the next
  unacked message to a caller-supplied handler; a falsy return or an
  exception counts one attempt. After ``max_attempts`` attempts the
  message moves to POISONED and is parked for the operator. The inbox
  never spins forever on a message that crashes the handler.
* **Ack is idempotent** — acking an already-DONE message is a no-op
  (returns ``already=True``); the classic at-least-once consumer loop
  can retry the ack path safely. Acking an unknown id raises ``KeyError``
  fail-closed — a handler cannot invent work that was never received.
* **No wall-clock** — all seqs are caller-supplied ints (the host's own
  monotonic counter), so the module is deterministic and replayable.
* **Fail-closed** — malformed messages raise at receive time; unknown
  message ids raise ``KeyError``; a malformed handler result is treated
  as a failure, never as success.

Honest scope: this is the *store-then-ack state machine*, not a message
broker — there is no persistence beyond process memory (the host that
needs crash recovery snapshots the inbox and restores it), no transport
(codec, auth, retries-with-backoff are the caller's job), and no
exactly-once guarantee across processes. DONE means "the handler
reported success once", never "the downstream effect happened exactly
once". A clean ``process`` report means "nothing left unacked", not
"every business effect completed". Deduplication is by producer-supplied
``message_id`` — a producer that mints a fresh id per retry defeats it
(that is a producer bug, not an inbox bug).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

#: Module version.
INBOX_PATTERN_VERSION = "inbox-pattern.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.inbox-pattern.v1"


class MessageState(str, Enum):
    """Lifecycle state of one inbox message."""

    RECEIVED = "received"  # on the books, awaiting processing
    DONE = "done"  # acked; processing outcome recorded
    POISONED = "poisoned"  # exceeded max_attempts; parked for the operator


class InboxError(Exception):
    """Malformed input to the inbox (programming error)."""


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise InboxError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise InboxError(f"{name} must be non-negative")
    return seq


def _check_non_empty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise InboxError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class InboxMessage:
    """One message staged in the inbox."""

    message_id: str
    source: str
    payload: Mapping[str, Any]
    seq: int

    def __post_init__(self) -> None:
        _check_non_empty_str(self.message_id, "message_id")
        _check_non_empty_str(self.source, "source")
        if not isinstance(self.payload, Mapping):
            raise InboxError("payload must be a mapping")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "message_id": self.message_id,
            "source": self.source,
            "payload": dict(self.payload),
            "seq": self.seq,
        }


@dataclass(frozen=True)
class InboxEvent:
    """One append-only inbox event."""

    kind: str  # "received" | "duplicate" | "acked" | "poisoned"
    message_id: str
    seq: int
    attempts: int = 0
    detail: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("received", "duplicate", "acked", "poisoned"):
            raise InboxError(f"unknown event kind: {self.kind!r}")
        _check_non_empty_str(self.message_id, "message_id")
        _check_seq(self.seq)
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise InboxError("attempts must be an int")
        if self.attempts < 0:
            raise InboxError("attempts must be non-negative")
        if not isinstance(self.detail, str):
            raise InboxError("detail must be a str")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "kind": self.kind,
            "message_id": self.message_id,
            "seq": self.seq,
            "attempts": self.attempts,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ReceiveReport:
    """Outcome of one :meth:`Inbox.receive` call."""

    message: InboxMessage
    duplicate: bool  # True if this id was already on the books
    outcome: str = ""  # "stored" | "redelivered" | "redelivered-duplicate-done"

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "message": self.message.as_dict(),
            "duplicate": self.duplicate,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class AckReport:
    """Outcome of one :meth:`Inbox.ack` call."""

    message_id: str
    already: bool  # True if the message was already DONE (idempotent ack)
    outcome: str = ""

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "message_id": self.message_id,
            "already": self.already,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class ProcessReport:
    """Outcome of one :meth:`Inbox.process` call."""

    processed: tuple = ()  # ids acked this pass
    still_pending: tuple = ()  # ids awaiting processing
    poisoned: tuple = ()  # ids parked this pass

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "processed": list(self.processed),
            "still_pending": list(self.still_pending),
            "poisoned": list(self.poisoned),
        }


class _StoredMessage:
    """Mutable bookkeeping for one received message."""

    __slots__ = ("message", "state", "attempts")

    def __init__(self, message: InboxMessage) -> None:
        self.message = message
        self.state = MessageState.RECEIVED
        self.attempts = 0


class Inbox:
    """Transactional inbox: idempotent receive, store-then-ack.

    The inbox never performs I/O itself. The host delivers messages via
    :meth:`receive`, processes them, and calls :meth:`ack`; or calls
    :meth:`process` with a handler to drive the whole loop in one pass.
    """

    def __init__(self, max_attempts: int = 3) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise InboxError("max_attempts must be an int")
        if max_attempts < 1:
            raise InboxError("max_attempts must be >= 1")
        self._max_attempts = max_attempts
        self._messages: dict[str, _StoredMessage] = {}
        self._events: list[InboxEvent] = []

    # -- receive --------------------------------------------------------

    def receive(self, message: InboxMessage, *, seq: int) -> ReceiveReport:
        """Book an incoming message; redelivery is a duplicate, not an error.

        A message_id already on the books returns ``duplicate=True`` —
        the original record is kept (first payload wins). A redelivery
        carrying a different payload raises :class:`InboxError` (forked
        producer).
        """
        if not isinstance(message, InboxMessage):
            raise InboxError("message must be an InboxMessage")
        _check_seq(seq, "seq")
        stored = self._messages.get(message.message_id)
        if stored is not None:
            if dict(stored.message.payload) != dict(message.payload):
                raise InboxError(
                    f"payload mismatch on redelivery of "
                    f"{message.message_id!r} (producer forked)"
                )
            outcome = (
                "redelivered-duplicate-done"
                if stored.state is MessageState.DONE
                else "redelivered"
            )
            self._events.append(
                InboxEvent(kind="duplicate",
                           message_id=message.message_id, seq=seq,
                           attempts=stored.attempts, detail=outcome)
            )
            return ReceiveReport(message=stored.message, duplicate=True,
                                 outcome=outcome)
        self._messages[message.message_id] = _StoredMessage(message)
        self._events.append(
            InboxEvent(kind="received", message_id=message.message_id,
                       seq=seq, attempts=0, detail="stored")
        )
        return ReceiveReport(message=message, duplicate=False, outcome="stored")

    # -- dedupe ----------------------------------------------------------

    def dedupe(self, message_id: str) -> bool:
        """True if this message_id is already on the books (pure view)."""
        _check_non_empty_str(message_id, "message_id")
        return message_id in self._messages

    # -- ack -------------------------------------------------------------

    def ack(self, message_id: str, *, seq: int, outcome: str = "ok") -> AckReport:
        """Mark a received message DONE. Idempotent: already-DONE is a no-op.

        Unknown ids raise ``KeyError`` fail-closed. Acking a POISONED
        message reprocesses it deliberately — that raises
        :class:`InboxError`; the operator must reprocess poison explicitly
        (see :meth:`reprocess`).
        """
        _check_non_empty_str(message_id, "message_id")
        _check_seq(seq, "seq")
        if not isinstance(outcome, str):
            raise InboxError("outcome must be a str")
        try:
            stored = self._messages[message_id]
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None
        if stored.state is MessageState.DONE:
            return AckReport(message_id=message_id, already=True,
                             outcome="already-done")
        if stored.state is MessageState.POISONED:
            raise InboxError(
                f"message {message_id!r} is POISONED; "
                "use reprocess() to deliberately reprocess it"
            )
        stored.state = MessageState.DONE
        self._events.append(
            InboxEvent(kind="acked", message_id=message_id, seq=seq,
                       attempts=stored.attempts, detail=outcome)
        )
        return AckReport(message_id=message_id, already=False, outcome=outcome)

    # -- reprocess -------------------------------------------------------

    def reprocess(self, message_id: str, *, seq: int) -> ReceiveReport:
        """Return a POISONED message to RECEIVED for deliberate reprocessing.

        Records a fresh ``received`` event and resets the attempt counter.
        Unknown ids raise ``KeyError``; non-POISONED messages raise
        :class:`InboxError` (nothing to reprocess).
        """
        _check_non_empty_str(message_id, "message_id")
        _check_seq(seq, "seq")
        try:
            stored = self._messages[message_id]
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None
        if stored.state is not MessageState.POISONED:
            raise InboxError(
                f"message {message_id!r} is not POISONED (state: "
                f"{stored.state.value}); nothing to reprocess"
            )
        stored.state = MessageState.RECEIVED
        stored.attempts = 0
        self._events.append(
            InboxEvent(kind="received", message_id=message_id, seq=seq,
                       attempts=0, detail="reprocessed")
        )
        return ReceiveReport(message=stored.message, duplicate=True,
                             outcome="reprocessed")

    # -- views -----------------------------------------------------------

    def state(self, message_id: str) -> MessageState:
        """Lifecycle state of one message; KeyError on unknown id."""
        _check_non_empty_str(message_id, "message_id")
        try:
            return self._messages[message_id].state
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None

    def pending(self) -> tuple:
        """RECEIVED messages in caller-seq order (deterministic)."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.RECEIVED
        )

    def done(self) -> tuple:
        """DONE messages in caller-seq order."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.DONE
        )

    def poisoned(self) -> tuple:
        """POISONED messages in caller-seq order."""
        return tuple(
            stored.message
            for stored in sorted(self._messages.values(),
                                 key=lambda s: (s.message.seq, s.message.message_id))
            if stored.state is MessageState.POISONED
        )

    def attempts(self, message_id: str) -> int:
        """Recorded processing attempts for one message."""
        _check_non_empty_str(message_id, "message_id")
        try:
            return self._messages[message_id].attempts
        except KeyError:
            raise KeyError(f"unknown message_id: {message_id!r}") from None

    def events(self) -> tuple:
        """Append-only event log, registration order."""
        return tuple(self._events)

    # -- process ---------------------------------------------------------

    def process(self, handler: Callable[[InboxMessage], Any],
                *, seq: int) -> ProcessReport:
        """Process every RECEIVED message in seq order.

        The handler takes an :class:`InboxMessage`; a truthy return or
        ``None`` marks the message DONE. A falsy return or an exception
        records one attempt and leaves the message RECEIVED; when
        attempts reach ``max_attempts`` the message moves to POISONED and
        is no longer processed.
        """
        if not callable(handler):
            raise InboxError("handler must be callable")
        _check_seq(seq, "seq")
        processed: list[str] = []
        poisoned: list[str] = []
        still_pending: list[str] = []
        for message in self.pending():
            stored = self._messages[message.message_id]
            try:
                ok = handler(message)
            except Exception as exc:  # noqa: BLE001 - handler failure is data
                detail = f"{type(exc).__name__}: {exc}"
                ok = False
            else:
                detail = "" if (ok or ok is None) else "handler returned falsy"
            if ok or ok is None:
                stored.state = MessageState.DONE
                processed.append(message.message_id)
                self._events.append(
                    InboxEvent(kind="acked", message_id=message.message_id,
                               seq=seq, attempts=stored.attempts,
                               detail=detail)
                )
            else:
                stored.attempts += 1
                if stored.attempts >= self._max_attempts:
                    stored.state = MessageState.POISONED
                    poisoned.append(message.message_id)
                    self._events.append(
                        InboxEvent(kind="poisoned",
                                   message_id=message.message_id,
                                   seq=seq, attempts=stored.attempts,
                                   detail=detail)
                    )
                else:
                    still_pending.append(message.message_id)
        return ProcessReport(processed=tuple(processed),
                             still_pending=tuple(still_pending),
                             poisoned=tuple(poisoned))


def inbox_audit_event(record: Any, *, audit_seq: int) -> dict:
    """Shape an inbox record as an ``audit.ndjson/1`` record."""
    if isinstance(record, (InboxEvent, ReceiveReport, AckReport,
                           ProcessReport, InboxMessage)):
        shaped = record.as_dict()
    else:
        raise TypeError(
            "record must be an InboxEvent, ReceiveReport, AckReport, "
            "ProcessReport, or InboxMessage"
        )
    if isinstance(audit_seq, bool) or not isinstance(audit_seq, int):
        raise TypeError("audit_seq must be an int")
    if audit_seq < 0:
        raise ValueError("audit_seq must be >= 0")
    shaped["audit_seq"] = audit_seq
    return shaped


def main() -> None:
    box = Inbox(max_attempts=2)
    box.receive(InboxMessage("m1", "upstream", {"n": 1}, seq=0), seq=0)
    dup = box.receive(InboxMessage("m1", "upstream", {"n": 1}, seq=1), seq=1)
    assert dup.duplicate is True, dup
    assert dup.outcome == "redelivered", dup
    assert box.dedupe("m1") is True
    assert box.dedupe("nope") is False

    # Idempotent ack path.
    r1 = box.ack("m1", seq=2)
    assert r1.already is False, r1
    r2 = box.ack("m1", seq=3)
    assert r2.already is True, r2

    # Poison path: a handler that always crashes parks the message.
    box.receive(InboxMessage("m2", "upstream", {"n": 2}, seq=4), seq=4)

    def always_fails(message: InboxMessage) -> bool:
        raise ConnectionError("downstream down")

    report = box.process(always_fails, seq=5)
    assert report.still_pending == ("m2",), report
    report2 = box.process(always_fails, seq=6)
    assert report2.poisoned == ("m2",), report2
    assert box.state("m2") is MessageState.POISONED
    assert box.pending() == ()

    # Deliberate reprocessing brings it back for the operator.
    box.reprocess("m2", seq=7)
    assert box.state("m2") is MessageState.RECEIVED
    print("inbox-pattern OK: idempotent receive, ack, poison, reprocess")


if __name__ == "__main__":
    main()
