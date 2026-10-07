"""Email service interface: SendGrid/SES/Mailgun-shaped transactional email bookkeeping.

Research note: a *transactional email service* (SendGrid, AWS SES, Mailgun
shape) is the contract between an agent and the mail rail: the agent asks to
*send* a message to a recipient, and later the rail reports *delivery events*
(delivered / opened / clicked / bounced) back through webhooks. The
load-bearing invariants are: (1) *address validation* — malformed sender or
recipient addresses are refused at enqueue time, not silently dropped;
(2) *idempotent delivery events* — the same webhook arriving twice must not
double-count an open or a click (event dedup by idempotency key);
(3) *bounce terminality* — a hard-bounced address enters a suppression state
so future sends to it are refused instead of re-attempted; (4) *template
binding* — a send references a pinned template id so the content model stays
auditable; (5) *audit trail* — every send and every reported event is pinned
with a digest.

This module implements that shape as a deterministic, single-host ledger:

* **Send** — :meth:`EmailService.send` records a frozen :class:`MessageRecord`
  (``msg-<n>`` id, validated sender/recipient addresses, pinned template id,
  ``sha256:`` digest pin). Hard-suppressed recipients are refused fail-closed.
* **Track** — :meth:`EmailService.track` records frozen
  :class:`DeliveryEvent` records (``sent``/``delivered``/``opened``/
  ``clicked``/``unsubscribed``); event transitions are monotonic (a message
  cannot be ``opened`` before it was ``delivered``); repeats of the same
  idempotency key replay the original event instead of minting a duplicate.
* **Bounce** — :meth:`EmailService.bounce` records a frozen
  :class:`BounceRecord` (``soft``/``hard`` kind, pinned reason); a hard
  bounce suppresses the recipient address — future :meth:`send` to it raises
  :class:`SuppressedRecipientError`.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per service, no wall-clock, no RNG for ids — ids are monotonic
``msg-<n>``/``ev-<n>``/``bn-<n>`` counters), RLock-guarded, fail-closed
(malformed addresses, empty subjects, unknown message ids, bad event
transitions, re-bouncing, suppressed recipients all raise a subclass of
:class:`EmailError`), stdlib-only, type-tagged canonical digest encoding
(bool != int; NaN/inf and >2^53 integral floats refused), audit events shaped
for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a mail rail. It cannot send mail,
observe inboxes, or prove a recipient opened anything — :meth:`track` pins
what the host *reported* via webhook, and a lying host gets a consistent
ledger of lies (GIGO, same boundary as every other bookkeeping module). For
real delivery pair with an authenticated MTA webhook feed and
``remote_attestation`` for the host.

Version pin: email-service.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

VERSION = "email-service.v1"
SCHEMA = "northstar.email-service.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "EmailError",
    "UnknownMessageError",
    "InvalidAddressError",
    "EmptyFieldError",
    "InvalidEventError",
    "BadTransitionError",
    "UnknownBounceError",
    "AlreadyBouncedError",
    "SuppressedRecipientError",
    "IdempotencyMismatchError",
    "SeqOrderError",
    "MessageRecord",
    "DeliveryEvent",
    "BounceRecord",
    "EmailService",
    "email_service_audit_event",
]

_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

_EVENT_KINDS = ("sent", "delivered", "opened", "clicked", "unsubscribed")
_EVENT_ORDER = {kind: idx for idx, kind in enumerate(_EVENT_KINDS)}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class EmailError(ValueError):
    """Base class for all email-service errors."""


class UnknownMessageError(EmailError):
    pass


class InvalidAddressError(EmailError):
    pass


class EmptyFieldError(EmailError):
    pass


class InvalidEventError(EmailError):
    pass


class BadTransitionError(EmailError):
    pass


class UnknownBounceError(EmailError):
    pass


class AlreadyBouncedError(EmailError):
    pass


class SuppressedRecipientError(EmailError):
    pass


class IdempotencyMismatchError(EmailError):
    pass


class SeqOrderError(EmailError):
    pass


# ---------------------------------------------------------------------------
# Canonical digest
# ---------------------------------------------------------------------------

def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) >= 2 ** 53:
            raise EmailError(f"integer out of safe range: {value!r}")
        return f"int:{value}"
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise EmailError(f"non-finite float refused: {value!r}")
        if value.is_integer() and abs(value) < 2 ** 53:
            raise EmailError(f"integral float refused (use int): {value!r}")
        return f"float:{repr(value)}"
    if isinstance(value, str):
        return "str:" + json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "list:[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "map:{" + ",".join(_canon(k) + "=>" + _canon(v) for k, v in items) + "}"
    raise EmailError(f"non-canonicalizable value: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    body = "|".join(_canon(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MessageRecord:
    """A queued outbound message."""
    id: str
    sender: str
    recipient: str
    subject: str
    body: str
    template_id: str
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "body": self.body,
            "template_id": self.template_id,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class DeliveryEvent:
    """A host-reported delivery event against a message."""
    id: str
    message_id: str
    kind: str
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "message_id": self.message_id,
            "kind": self.kind,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class BounceRecord:
    """A host-reported bounce against a message."""
    id: str
    message_id: str
    kind: str  # "soft" | "hard"
    reason: str
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "message_id": self.message_id,
            "kind": self.kind,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class EmailService:
    """Deterministic transactional-email ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._messages: Dict[str, MessageRecord] = {}
        self._events: Dict[str, DeliveryEvent] = {}
        self._events_by_message: Dict[str, list] = {}
        self._bounces: Dict[str, BounceRecord] = {}
        self._bounces_by_message: Dict[str, list] = {}
        self._suppressed: Dict[str, str] = {}  # recipient -> bounce id
        self._idempotency: Dict[str, str] = {}  # event key -> event id
        self._msg_n = 0
        self._ev_n = 0
        self._bn_n = 0

    # -- validation helpers ------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
        if seq < 0:
            raise SeqOrderError(f"seq must be non-negative, got {seq}")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    @staticmethod
    def _check_address(value: Any, role: str) -> str:
        if not isinstance(value, str) or not _ADDRESS_RE.match(value):
            raise InvalidAddressError(f"invalid {role} address: {value!r}")
        return value

    @staticmethod
    def _check_nonempty(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise EmptyFieldError(f"{name} must be a non-empty string")
        return value

    # -- send ---------------------------------------------------------------

    def send(
        self,
        recipient: str,
        subject: str,
        body: str,
        seq: int,
        *,
        sender: str = "noreply@example.com",
        template_id: str = "plain-text.v1",
    ) -> MessageRecord:
        """Queue an outbound message; returns the frozen record."""
        with self._lock:
            self._check_seq(seq)
            sender = self._check_address(sender, "sender")
            recipient = self._check_address(recipient, "recipient")
            if recipient in self._suppressed:
                raise SuppressedRecipientError(
                    f"recipient {recipient!r} is hard-suppressed"
                )
            self._check_nonempty(subject, "subject")
            self._check_nonempty(body, "body")
            self._check_nonempty(template_id, "template_id")

            self._msg_n += 1
            msg_id = f"msg-{self._msg_n}"
            digest = _pin(
                "message", msg_id, sender, recipient, subject, body,
                template_id, seq,
            )
            record = MessageRecord(
                id=msg_id, sender=sender, recipient=recipient, subject=subject,
                body=body, template_id=template_id, seq=seq, digest=digest,
            )
            self._messages[msg_id] = record
            self._events_by_message[msg_id] = []
            self._bounces_by_message[msg_id] = []
            return record

    # -- track --------------------------------------------------------------

    def track(
        self,
        message_id: str,
        kind: str,
        seq: int,
        *,
        idempotency_key: Optional[str] = None,
    ) -> DeliveryEvent:
        """Record a host-reported delivery event; idempotent by key."""
        with self._lock:
            self._check_seq(seq)
            if message_id not in self._messages:
                raise UnknownMessageError(f"unknown message: {message_id!r}")
            if kind not in _EVENT_KINDS:
                raise InvalidEventError(f"unknown event kind: {kind!r}")

            if idempotency_key is not None:
                existing = self._idempotency.get(idempotency_key)
                if existing is not None:
                    ev = self._events[existing]
                    if ev.message_id != message_id or ev.kind != kind:
                        raise IdempotencyMismatchError(
                            "idempotency key replayed with different parameters"
                        )
                    return ev

            # monotonic lifecycle: no step before a strictly earlier one
            prior_kinds = [e.kind for e in self._events_by_message[message_id]]
            if prior_kinds and _EVENT_ORDER[kind] < max(
                _EVENT_ORDER[k] for k in prior_kinds
            ):
                raise BadTransitionError(
                    f"event {kind!r} cannot follow "
                    f"{max(prior_kinds, key=lambda k: _EVENT_ORDER[k])!r}"
                )

            self._ev_n += 1
            ev_id = f"ev-{self._ev_n}"
            digest = _pin("event", ev_id, message_id, kind, seq)
            event = DeliveryEvent(
                id=ev_id, message_id=message_id, kind=kind, seq=seq,
                digest=digest,
            )
            self._events[ev_id] = event
            self._events_by_message[message_id].append(event)
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = ev_id
            return event

    # -- bounce --------------------------------------------------------------

    def bounce(self, message_id: str, kind: str, reason: str, seq: int) -> BounceRecord:
        """Record a host-reported bounce; hard bounces suppress the recipient."""
        with self._lock:
            self._check_seq(seq)
            if message_id not in self._messages:
                raise UnknownMessageError(f"unknown message: {message_id!r}")
            if kind not in ("soft", "hard"):
                raise InvalidEventError(f"unknown bounce kind: {kind!r}")
            if self._bounces_by_message[message_id]:
                raise AlreadyBouncedError(
                    f"message {message_id!r} already has a bounce record"
                )
            self._check_nonempty(reason, "reason")

            self._bn_n += 1
            bn_id = f"bn-{self._bn_n}"
            digest = _pin("bounce", bn_id, message_id, kind, reason, seq)
            record = BounceRecord(
                id=bn_id, message_id=message_id, kind=kind, reason=reason,
                seq=seq, digest=digest,
            )
            self._bounces[bn_id] = record
            self._bounces_by_message[message_id].append(record)
            if kind == "hard":
                recipient = self._messages[message_id].recipient
                self._suppressed[recipient] = bn_id
            return record

    # -- views ----------------------------------------------------------------

    def message(self, message_id: str) -> MessageRecord:
        try:
            return self._messages[message_id]
        except KeyError:
            raise UnknownMessageError(f"unknown message: {message_id!r}")

    def events(self, message_id: str) -> Tuple[DeliveryEvent, ...]:
        if message_id not in self._messages:
            raise UnknownMessageError(f"unknown message: {message_id!r}")
        return tuple(self._events_by_message[message_id])

    def bounce_for(self, message_id: str) -> Optional[BounceRecord]:
        if message_id not in self._messages:
            raise UnknownMessageError(f"unknown message: {message_id!r}")
        records = self._bounces_by_message[message_id]
        return records[0] if records else None

    def is_suppressed(self, recipient: str) -> bool:
        return recipient in self._suppressed

    def status(self, message_id: str) -> str:
        """Lifecycle summary: sent / in-flight / bounced / unsubscribed."""
        msg = self.message(message_id)
        if self._bounces_by_message[msg.id]:
            return "bounced"
        kinds = {e.kind for e in self._events_by_message[msg.id]}
        if "unsubscribed" in kinds:
            return "unsubscribed"
        if kinds:
            return "in-flight"
        return "sent"

    def message_count(self) -> int:
        return len(self._messages)


# ---------------------------------------------------------------------------
# Audit events (audit.ndjson/1 shaped)
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("message-queued", "event-tracked", "bounced", "rejected")


def email_service_audit_event(
    kind: str, ref_id: str, digest: str, seq: int
) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise EmailError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return {
        "schema": "audit.ndjson/1",
        "module": SCHEMA,
        "kind": kind,
        "ref_id": ref_id,
        "digest": digest,
        "seq": seq,
    }


def main() -> None:
    svc = EmailService()
    m = svc.send("alice@example.com", "Hello", "body text", 1,
                 sender="noreply@agents.dev", template_id="welcome.v2")
    assert m.id == "msg-1" and m.digest.startswith("sha256:")
    svc.track(m.id, "sent", 2)
    svc.track(m.id, "delivered", 3)
    assert svc.status(m.id) == "in-flight"
    m2 = svc.send("bob@example.com", "Alert", "see this", 4)
    b = svc.bounce(m2.id, "hard", "mailbox-not-found", 5)
    assert b.kind == "hard" and svc.is_suppressed("bob@example.com")
    try:
        svc.send("bob@example.com", "Again", "nope", 6)
    except SuppressedRecipientError:
        pass
    else:
        raise AssertionError("expected SuppressedRecipientError")
    print("email-service OK: send, track, bounce, suppression")


if __name__ == "__main__":
    main()
