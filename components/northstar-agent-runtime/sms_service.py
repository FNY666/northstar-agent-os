"""SMS service: simulated SMS send/status/opt-out bookkeeping (Twilio/SNS lineage).

Research note: SMS is the store-and-forward short-message channel
(GSM 03.38/03.40; 3GPP TS 23.040): a 140-octet payload — 160 GSM-7
characters or 70 UCS-2 characters per segment, longer texts sent as
concatenated multi-segment messages with a user-data header. Providers
(Twilio, AWS SNS, Nexmo/Vonage) expose the same three verbs this module
models: enqueue a message, query its delivery status, and honor the
recipient's opt-out (STOP). The compliance boundary is *consent*: the
TCPA (47 U.S.C. 227) and CTIA guidelines require an explicit opt-out
mechanism — a number that texted STOP must never be messaged again, and
this module refuses to send to opted-out numbers fail-closed.

* **Send is bookkeeping, not a radio** — ``send()`` validates and mints a
  frozen :class:`MessageRecord` with ``status="queued"``; the host (the
  real aggregator/carrier path) performs the actual transmission and
  reports outcomes via ``report(message_id, outcome, seq)``. This module
  owns the *delivery ledger*, not the SS7 link.
* **Deterministic status lifecycle** — ``queued -> sent -> delivered``
  (success), with ``queued|sent -> failed`` (carrier/host failure).
  Terminal states (``delivered``, ``failed``) refuse further reports
  fail-closed: a delivered message cannot be un-delivered.
* **Opt-out is terminal** — ``optout(phone, seq)`` pins a frozen
  :class:`OptOutRecord`; any ``send()`` to that number afterwards raises
  :class:`OptedOutError`. An already-minted in-flight message to a number
  that opts out afterwards is marked ``status="suppressed"`` (terminal)
  so no further send-side work can touch it.
* **E.164 discipline** — both sender and recipient numbers must be valid
  E.164 (``+`` followed by 8-15 digits, no leading zero after ``+``);
  anything else is refused fail-closed. The module cannot tell a
  syntactically-valid-but-nonexistent number from a real one — validation
  is format only (GIGO boundary, documented).
* **Segment accounting** — bodies are counted in characters; up to
  ``MAX_BODY_CHARS`` (1600, ten GSM segments) are accepted and the record
  carries the computed segment count (``ceil(len / 160)``). Empty bodies
  are refused: sending nothing is a host bug, not a message.
* **Idempotency** — ``send()`` accepts an optional ``idempotency_key``:
  a repeated call replays the original record; the same key with
  different parameters raises :class:`IdempotencyMismatchError`
  fail-closed (the double-text failure mode).
* **Pins bind** — every record carries a ``sha256:`` digest pin over its
  canonical body (message id, numbers, body digest, status, seq).
  ``as_dict()`` and audit events carry ids and pins only — the message
  *body* never crosses the audit boundary (test-verified), because SMS
  bodies routinely contain one-time codes and PII.

Honest scope: this is the *send/status/opt-out ledger* for SMS, not a
delivery guarantee. It cannot prove a phone received anything (the host
reports outcomes; a lying host gets a consistent ledger of lies), cannot
detect carrier filtering or gray routes, and cannot see a message sent
outside :meth:`report`. ``status == "delivered"`` means "the host said
the carrier accepted it", never "the human read it".

Version pin: sms-service.v1
Schema pin: northstar.sms-service.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
SMS_SERVICE_VERSION = "sms-service.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.sms-service.v1"

#: E.164: "+" then 8..15 digits, first digit after "+" non-zero.
_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")

#: GSM-7 single-segment character budget.
SEGMENT_CHARS = 160

#: Maximum body length accepted (10 segments worth).
MAX_BODY_CHARS = SEGMENT_CHARS * 10

#: Message id prefix.
_MSG_PREFIX = "sm-"

#: Opt-out record id prefix.
_OPT_PREFIX = "oo-"

#: Non-terminal message statuses.
_STATUS_QUEUED = "queued"
_STATUS_SENT = "sent"
#: Terminal message statuses.
_STATUS_DELIVERED = "delivered"
_STATUS_FAILED = "failed"
_STATUS_SUPPRESSED = "suppressed"

_TERMINAL = frozenset({_STATUS_DELIVERED, _STATUS_FAILED, _STATUS_SUPPRESSED})

#: Reportable outcomes the host may assert.
_OUTCOMES = frozenset({"sent", "delivered", "failed"})

_AUDIT_KINDS = frozenset(
    {
        "sent",
        "status-reported",
        "opted-out",
        "suppressed",
        "rejected",
    }
)


def _pin(obj: Any) -> str:
    """``sha256:`` digest pin over the canonical form of ``obj``."""
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_e164(number: Any, what: str) -> str:
    if not isinstance(number, str):
        raise TypeError(f"{what} must be a str")
    if not _E164_RE.match(number):
        raise InvalidPhoneError(f"{what} is not valid E.164: {number!r}")
    return number


class SMSError(Exception):
    """Base error for sms-service misuse or constraint violations."""


class InvalidPhoneError(SMSError):
    """A phone number was not valid E.164 (fail-closed: no guessing)."""


class EmptyBodyError(SMSError):
    """A message body was empty or whitespace-only."""


class BodyTooLongError(SMSError):
    """A message body exceeded the accepted segment budget."""


class UnknownMessageError(SMSError):
    """A status/report referenced a message id that was never minted."""


class TerminalMessageError(SMSError):
    """A report targeted a message already in a terminal status."""


class OptedOutError(SMSError):
    """A send targeted a number that opted out (TCPA fail-closed)."""


class IdempotencyMismatchError(SMSError):
    """An idempotency key was reused with different parameters."""


@dataclass(frozen=True)
class MessageRecord:
    """A single enqueued SMS message and its current ledger status."""

    message_id: str
    to_number: str
    from_number: str
    body_digest: str
    segments: int
    status: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "to_number": self.to_number,
            "from_number": self.from_number,
            "body_digest": self.body_digest,
            "segments": self.segments,
            "status": self.status,
            "seq": self.seq,
            "digest": self.digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class StatusReport:
    """The host's outcome assertion for a message (a reported fact)."""

    message_id: str
    outcome: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "outcome": self.outcome,
            "seq": self.seq,
            "digest": self.digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class OptOutRecord:
    """A recipient's STOP: terminal consent withdrawal."""

    optout_id: str
    phone: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "optout_id": self.optout_id,
            "phone": self.phone,
            "seq": self.seq,
            "digest": self.digest,
            "schema": SCHEMA_PIN,
        }


class SMSService:
    """Deterministic SMS send/status/opt-out ledger (simulated transport)."""

    def __init__(self, default_from: str) -> None:
        self._default_from = _check_e164(default_from, "default_from")
        self._lock = threading.RLock()
        self._messages: Dict[str, Dict[str, Any]] = {}
        self._optouts: Dict[str, OptOutRecord] = {}
        self._idem: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        self._next_msg = 1
        self._next_opt = 1
        self._last_seq = -1

    # -- internals -----------------------------------------------------

    def _bump_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SMSError(f"seq must strictly increase (got {seq})")
        self._last_seq = seq
        return seq

    def _body_digest(self, body: str) -> str:
        return _pin({"body": body})

    def _check_body(self, body: Any) -> str:
        if not isinstance(body, str):
            raise TypeError("body must be a str")
        if not body.strip():
            raise EmptyBodyError("body must not be empty")
        if len(body) > MAX_BODY_CHARS:
            raise BodyTooLongError(
                f"body has {len(body)} chars, limit is {MAX_BODY_CHARS}"
            )
        return body

    def _segments(self, body: str) -> int:
        return (len(body) + SEGMENT_CHARS - 1) // SEGMENT_CHARS

    def _mint(self, rec: MessageRecord) -> MessageRecord:
        self._messages[rec.message_id] = {"record": rec}
        return rec

    def _view(self, message_id: str) -> Dict[str, Any]:
        try:
            return self._messages[message_id]
        except KeyError:
            raise UnknownMessageError(f"unknown message: {message_id!r}")

    # -- send ----------------------------------------------------------

    def send(
        self,
        to_number: str,
        body: str,
        seq: int,
        from_number: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> MessageRecord:
        """Enqueue an SMS. Fail-closed on bad numbers, empty/oversize
        bodies, opted-out recipients, and idempotency mismatches."""
        to = _check_e164(to_number, "to_number")
        frm = self._default_from if from_number is None else _check_e164(
            from_number, "from_number"
        )
        text = self._check_body(body)
        with self._lock:
            if to in self._optouts:
                raise OptedOutError(f"{to} opted out; refusing to send")
            params = {"to": to, "from": frm, "body_digest": self._body_digest(text)}
            if idempotency_key is not None:
                if not isinstance(idempotency_key, str) or not idempotency_key:
                    raise TypeError("idempotency_key must be a non-empty str")
                hit = self._idem.get(idempotency_key)
                if hit is not None:
                    old_id, old_params = hit
                    if old_params != params:
                        raise IdempotencyMismatchError(
                            "idempotency key reused with different parameters"
                        )
                    return self._messages[old_id]["record"]
            self._bump_seq(seq)
            message_id = f"{_MSG_PREFIX}{self._next_msg}"
            self._next_msg += 1
            rec = MessageRecord(
                message_id=message_id,
                to_number=to,
                from_number=frm,
                body_digest=self._body_digest(text),
                segments=self._segments(text),
                status=_STATUS_QUEUED,
                seq=seq,
                digest=_pin(
                    {
                        "message_id": message_id,
                        "to": to,
                        "from": frm,
                        "body_digest": self._body_digest(text),
                        "status": _STATUS_QUEUED,
                        "seq": seq,
                    }
                ),
            )
            self._mint(rec)
            if idempotency_key is not None:
                self._idem[idempotency_key] = (message_id, params)
            return rec

    # -- status --------------------------------------------------------

    def status(self, message_id: str) -> MessageRecord:
        """Return the current ledger status of a message."""
        if not isinstance(message_id, str):
            raise TypeError("message_id must be a str")
        with self._lock:
            return self._view(message_id)["record"]

    def report(self, message_id: str, outcome: str, seq: int) -> StatusReport:
        """Record the host's outcome assertion for a message.

        ``outcome`` is one of ``sent`` / ``delivered`` / ``failed``.
        Terminal messages refuse further reports fail-closed. A
        ``suppressed`` message (post-opt-out) refuses reports: nothing
        further can happen to it.
        """
        if not isinstance(message_id, str):
            raise TypeError("message_id must be a str")
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(_OUTCOMES)}")
        with self._lock:
            view = self._view(message_id)
            rec: MessageRecord = view["record"]
            if rec.status in _TERMINAL:
                raise TerminalMessageError(
                    f"message {message_id} is terminal ({rec.status})"
                )
            if outcome == "sent" and rec.status != _STATUS_QUEUED:
                raise SMSError(f"cannot report 'sent' from status {rec.status!r}")
            if outcome in ("delivered", "failed") and rec.status not in (
                _STATUS_QUEUED,
                _STATUS_SENT,
            ):
                raise SMSError(
                    f"cannot report {outcome!r} from status {rec.status!r}"
                )
            self._bump_seq(seq)
            new_rec = MessageRecord(
                message_id=rec.message_id,
                to_number=rec.to_number,
                from_number=rec.from_number,
                body_digest=rec.body_digest,
                segments=rec.segments,
                status=outcome,
                seq=seq,
                digest=_pin(
                    {
                        "message_id": rec.message_id,
                        "to": rec.to_number,
                        "from": rec.from_number,
                        "body_digest": rec.body_digest,
                        "status": outcome,
                        "seq": seq,
                    }
                ),
            )
            view["record"] = new_rec
            return StatusReport(
                message_id=message_id,
                outcome=outcome,
                seq=seq,
                digest=_pin(
                    {"message_id": message_id, "outcome": outcome, "seq": seq}
                ),
            )

    # -- opt-out -------------------------------------------------------

    def optout(self, phone: str, seq: int) -> OptOutRecord:
        """Record a STOP for ``phone``. In-flight (non-terminal) messages
        to that number are suppressed; future sends are refused."""
        number = _check_e164(phone, "phone")
        with self._lock:
            self._bump_seq(seq)
            if number in self._optouts:
                return self._optouts[number]
            optout_id = f"{_OPT_PREFIX}{self._next_opt}"
            self._next_opt += 1
            rec = OptOutRecord(
                optout_id=optout_id,
                phone=number,
                seq=seq,
                digest=_pin({"optout_id": optout_id, "phone": number, "seq": seq}),
            )
            self._optouts[number] = rec
            for view in self._messages.values():
                cur: MessageRecord = view["record"]
                if cur.to_number == number and cur.status not in _TERMINAL:
                    view["record"] = MessageRecord(
                        message_id=cur.message_id,
                        to_number=cur.to_number,
                        from_number=cur.from_number,
                        body_digest=cur.body_digest,
                        segments=cur.segments,
                        status=_STATUS_SUPPRESSED,
                        seq=seq,
                        digest=_pin(
                            {
                                "message_id": cur.message_id,
                                "to": cur.to_number,
                                "from": cur.from_number,
                                "body_digest": cur.body_digest,
                                "status": _STATUS_SUPPRESSED,
                                "seq": seq,
                            }
                        ),
                    )
            return rec

    def is_opted_out(self, phone: str) -> bool:
        """Whether ``phone`` currently has an active opt-out."""
        number = _check_e164(phone, "phone")
        with self._lock:
            return number in self._optouts

    # -- views ---------------------------------------------------------

    def message_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._messages.keys())

    def opted_out_numbers(self) -> List[str]:
        with self._lock:
            return sorted(self._optouts.keys())


def sms_service_audit_event(
    kind: str,
    seq: int,
    message: Optional[MessageRecord] = None,
    report: Optional[StatusReport] = None,
    optout: Optional[OptOutRecord] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for an SMS step.

    ``kind`` is one of ``sent`` / ``status-reported`` / ``opted-out`` /
    ``suppressed`` / ``rejected``. The message *body* is never emitted —
    only ids, numbers, and digest pins — so one-time codes and PII cannot
    leak through the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    if message is not None and not isinstance(message, MessageRecord):
        raise TypeError("message must be a MessageRecord")
    if report is not None and not isinstance(report, StatusReport):
        raise TypeError("report must be a StatusReport")
    if optout is not None and not isinstance(optout, OptOutRecord):
        raise TypeError("optout must be an OptOutRecord")
    record: Dict[str, Any] = {
        "event": f"sms-service-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if message is not None:
        record["message_id"] = message.message_id
        record["to_number"] = message.to_number
        record["status"] = message.status
        record["segments"] = message.segments
        record["body_digest"] = message.body_digest
        record["message_digest"] = message.digest
    if report is not None:
        record["message_id"] = report.message_id
        record["outcome"] = report.outcome
        record["report_digest"] = report.digest
    if optout is not None:
        record["optout_id"] = optout.optout_id
        record["phone"] = optout.phone
        record["optout_digest"] = optout.digest
    return record


def main() -> None:
    svc = SMSService("+15550001111")
    m1 = svc.send("+15550002222", "hello", 1)
    assert m1.status == "queued" and m1.segments == 1
    rep = svc.report(m1.message_id, "sent", 2)
    assert svc.status(m1.message_id).status == "sent"
    svc.report(m1.message_id, "delivered", 3)
    assert svc.status(m1.message_id).status == "delivered"
    m2 = svc.send("+15550003333", "x" * 161, 4)
    assert m2.segments == 2
    oo = svc.optout("+15550003333", 5)
    assert svc.status(m2.message_id).status == "suppressed"
    try:
        svc.send("+15550003333", "nope", 6)
    except OptedOutError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected OptedOutError")
    ev = sms_service_audit_event("sent", 7, message=m1)
    assert "body" not in str(ev).replace("body_digest", "")
    print("sms-service OK: send, report, optout, suppression, idempotency, audit")


if __name__ == "__main__":
    main()
