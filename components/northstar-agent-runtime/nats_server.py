"""NATS server interface (subject messaging + request-reply + JetStream, simulated).

Research motivation: NATS is the connective tissue of many agent
fabrics -- a single binary that does subject-based messaging,
request-reply, and (via JetStream) durable streams. Where AMQP speaks
exchanges/queues and MQTT speaks topics, NATS speaks *subjects*:
dot-delimited token hierarchies (``orders.us.created``) with its own
wildcard vocabulary -- ``*`` matches exactly one token, ``>`` matches
one or more trailing tokens (``orders.>`` catches ``orders.us.created``
and ``orders.eu`` but ``orders.*.created`` catches only the
three-token form). Three NATS-native capabilities shape this module:

- **Subject messaging** -- ``publish()`` books a message on a subject;
  every subscriber whose pattern matches (``*``/``>`` semantics)
  gets a frozen delivery record. Queue groups (``subscribe(...,
  queue_group="workers")``) load-balance: one delivery per group, to
  the group member with the fewest deliveries so far (deterministic
  tie-break by subscriber id).
- **Request-reply** -- NATS's signature primitive: ``request()``
  publishes with an ephemeral reply inbox (``_INBOX.<rand>.<rand>`` is
  host-minted; here the ledger mints ``inbox-N`` deterministically)
  and books a pending request; ``reply()`` resolves it. A pending
  request ages out via ``expire_requests(seq)`` (logical-seq timeout,
  no timers) and is refused a late reply afterwards.
- **JetStream** -- NATS's built-in persistence: ``create_stream()``
  declares a stream over subject patterns; JetStream ``publish()``
  persists messages and assigns per-stream sequence numbers;
  ``create_consumer()`` books a durable or ephemeral consumer;
  ``deliver()`` hands out the next undelivered message;
  ``ack()`` marks redelivery-complete. Replay policy and retention
  are pinned per stream.

How this differs from ``pubsub_broker``: that module is MQTT-shaped
(``+``/``#`` topic wildcards, plain fan-out, in-memory only). This
module is NATS-shaped (``*``/``>`` subject wildcards, queue groups,
request-reply inboxes, JetStream persistence with stream sequences,
consumer acks). The two share the house bookkeeping discipline but
book different protocol facts.

Fail-closed edges (fail loudly, never guess):

- Subject tokens are ``[A-Za-z0-9_-]+`` joined by ``.``; publish
  subjects may not contain wildcards; subscription patterns may use
  ``*`` for one token and ``>`` only as the final token. Anything
  else is refused.
- Payloads must survive JCS canonicalization (no NaN/inf, no
  ``|n| >= 2**53``, str keys only) -- the batch-5 JCS discipline.
- Subscriber ids, stream names, consumer names: non-empty str;
  duplicates refused (history is never silently overwritten).
- Mutation seqs are ints (not bool) and must strictly increase across
  the whole ``NATSServer`` instance; failed mutations consume their
  seq (the batch-21 ledger discipline). ``match()`` / ``inbox()`` are
  pure views: they validate the seq but do not consume it.
- ``request()`` with an unknown ``timeout_seqs <= 0`` is refused; a
  reply to an expired or unknown request is refused.
- JetStream ``ack()`` of an undelivered or already-acked delivery is
  refused; a consumer cannot be created twice on the same stream.

Honest scope:

- This module books *host-reported* messaging decisions. It cannot
  prove a subscriber processed a message, that a queue-group member
  really received its share, or that a JetStream write survived a
  disk. "Delivered" means the ledger routed it, never wire truth.
- Request-reply timeouts are logical-seq based; there is no clock
  here, so ``expire_requests(seq)`` is the explicit operator-driven
  sweep.
- In-memory only: pair with the durable audit writer if messaging
  records must survive a restart. ``main()`` self-checks the shape.

Version pin: nats-server.v1
Schema pin: northstar.nats-server.v1
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
NATS_SERVER_VERSION = "nats-server.v1"

#: Schema pin carried by records and audit events.
NATS_SERVER_SCHEMA = "northstar.nats-server.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Largest integer the JCS canonicalizer round-trips exactly.
_MAX_SAFE_INT = 2 ** 53

#: One NATS subject token: alphanumerics, dash, underscore.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]+\Z")

#: Audit event kinds.
_KINDS = (
    "published",
    "subscribed",
    "unsubscribed",
    "requested",
    "replied",
    "request-expired",
    "stream-created",
    "stream-message",
    "consumer-created",
    "jetstream-delivered",
    "acked",
    "rejected",
)

#: Detail keys banned from crossing the audit boundary (raw payloads).
_BANNED_AUDIT_KEYS = frozenset({"payload", "message", "data", "body"})


class NATSServerError(Exception):
    """Base error for the NATS server (programming errors)."""


class BadSubjectError(NATSServerError):
    """Raised when a subject or pattern is malformed."""


class BadPayloadError(NATSServerError):
    """Raised when a payload is not JCS-canonicalizable."""


class DuplicateSubscriberError(NATSServerError):
    """Raised when a subscriber id is registered twice."""


class UnknownSubscriberError(NATSServerError):
    """Raised when a subscriber id is unknown."""


class DuplicateStreamError(NATSServerError):
    """Raised when a stream name is declared twice."""


class UnknownStreamError(NATSServerError):
    """Raised when a stream name is unknown."""


class DuplicateConsumerError(NATSServerError):
    """Raised when a consumer name is created twice on a stream."""


class UnknownConsumerError(NATSServerError):
    """Raised when a consumer name is unknown on a stream."""


class UnknownRequestError(NATSServerError):
    """Raised when a request id is unknown."""


class RequestStateError(NATSServerError):
    """Raised when a request is replied twice or after expiry."""


class AckStateError(NATSServerError):
    """Raised when an ack is invalid (unknown/duplicate/undelivered)."""


class SeqOrderError(NATSServerError):
    """Raised when a mutation seq does not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise NATSServerError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise NATSServerError(f"{name} must be a non-empty str, got {value!r}")
    return value


def _check_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NATSServerError(
            f"{name} must be a mapping, got {type(value).__name__}")
    return value


def _walk_canonicalizable(value: Any, where: str) -> None:
    """Fail-closed walk: the value must survive JCS canonicalization."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise BadPayloadError(f"{where}: non-str mapping key: {key!r}")
            _walk_canonicalizable(item, where)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_canonicalizable(item, where)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadPayloadError(f"{where}: NaN/inf float refused")
    elif isinstance(value, int) and not isinstance(value, bool):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadPayloadError(
                f"{where}: int magnitude >= 2**53 refused: {value!r}")


def _check_subject(subject: Any, *, allow_wildcards: bool) -> str:
    """Validate a NATS subject (publish) or subject pattern (subscribe)."""
    if not isinstance(subject, str) or not subject:
        raise BadSubjectError(f"subject must be a non-empty str, got {subject!r}")
    tokens = subject.split(".")
    if any(t == "" for t in tokens):
        raise BadSubjectError(f"subject has empty token: {subject!r}")
    for i, token in enumerate(tokens):
        if token == "*":
            if not allow_wildcards:
                raise BadSubjectError(
                    f"wildcard '*' not allowed in publish subject: {subject!r}")
        elif token == ">":
            if not allow_wildcards:
                raise BadSubjectError(
                    f"wildcard '>' not allowed in publish subject: {subject!r}")
            if i != len(tokens) - 1:
                raise BadSubjectError(
                    f"'>' must be the final token: {subject!r}")
        elif not _TOKEN_RE.match(token):
            raise BadSubjectError(f"bad subject token {token!r} in {subject!r}")
    return subject


def _pattern_matches(pattern: str, subject: str) -> bool:
    """NATS matching: ``*`` = one token, ``>`` = one or more trailing."""
    ptoks = pattern.split(".")
    stoks = subject.split(".")
    i = 0
    for pt in ptoks:
        if pt == ">":
            return i < len(stoks)
        if i >= len(stoks):
            return False
        if pt != "*" and pt != stoks[i]:
            return False
        i += 1
    return i == len(stoks)


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex([NATS_SERVER_VERSION, *parts])


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubscriptionRecord:
    """One NATS subscription (frozen)."""

    subscriber_id: str
    pattern: str
    queue_group: Optional[str]
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "subscription", self.subscriber_id, self.pattern,
            self.queue_group or "", self.seq)


@dataclass(frozen=True)
class MessageRecord:
    """One published NATS message (frozen)."""

    message_id: str
    subject: str
    payload_digest: str
    reply_to: Optional[str]
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "message", self.message_id, self.subject,
            self.payload_digest, self.reply_to or "", self.seq)


@dataclass(frozen=True)
class DeliveryRecord:
    """One routed delivery to a subscriber (frozen)."""

    delivery_id: str
    message_id: str
    subscriber_id: str
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "delivery", self.delivery_id, self.message_id,
            self.subscriber_id, self.seq)


@dataclass(frozen=True)
class RequestRecord:
    """One pending request-reply request (frozen)."""

    request_id: str
    subject: str
    inbox: str
    timeout_seq: int
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "request", self.request_id, self.subject,
            self.inbox, self.timeout_seq, self.seq)


@dataclass(frozen=True)
class ReplyRecord:
    """One request-reply response (frozen)."""

    request_id: str
    payload_digest: str
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "reply", self.request_id, self.payload_digest, self.seq)


@dataclass(frozen=True)
class StreamRecord:
    """One JetStream stream declaration (frozen)."""

    stream: str
    subjects: Tuple[str, ...]
    retention: str
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "stream", self.stream, list(self.subjects),
            self.retention, self.seq)


@dataclass(frozen=True)
class StreamMessageRecord:
    """One JetStream-persisted message (frozen)."""

    stream: str
    stream_seq: int
    subject: str
    payload_digest: str
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "stream-message", self.stream, self.stream_seq,
            self.subject, self.payload_digest, self.seq)


@dataclass(frozen=True)
class ConsumerRecord:
    """One JetStream consumer (frozen)."""

    stream: str
    consumer: str
    durable: bool
    replay: str
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "consumer", self.stream, self.consumer,
            self.durable, self.replay, self.seq)


@dataclass(frozen=True)
class ConsumerDelivery:
    """One JetStream consumer delivery (frozen)."""

    delivery_id: str
    stream: str
    consumer: str
    stream_seq: int
    redelivered: bool
    acked: bool
    seq: int
    digest: str
    schema: str = NATS_SERVER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "consumer-delivery", self.delivery_id, self.stream,
            self.consumer, self.stream_seq, self.redelivered,
            self.acked, self.seq)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def nats_server_audit_event(kind: str, seq: int,
                            detail: Optional[Mapping[str, Any]] = None) -> dict:
    """Shape an ``audit.ndjson/1`` record for a NATS server event.

    Raw payloads are banned from the audit boundary: detail keys
    ``payload`` / ``message`` / ``data`` / ``body`` are refused
    fail-closed. Only ids, subjects, and digest pins cross.
    """
    if kind not in _KINDS:
        raise NATSServerError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    clean: Dict[str, Any] = {}
    if detail is not None:
        detail = _check_mapping(detail, "detail")
        for banned in _BANNED_AUDIT_KEYS:
            if banned in detail:
                raise NATSServerError(
                    f"audit detail key {banned!r} is banned: raw payloads "
                    f"never cross the audit boundary")
        clean = dict(detail)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": f"nats-server.{kind}",
        "version": NATS_SERVER_VERSION,
        "schema_ref": NATS_SERVER_SCHEMA,
        "seq": seq,
        "detail": clean,
    }


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


class NATSServer:
    """Deterministic NATS subject-messaging ledger (simulated).

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    #: Pinned JetStream retention policies.
    RETENTIONS = ("limits", "interest", "workqueue")

    #: Pinned consumer replay policies.
    REPLAYS = ("instant", "original")

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._subs: Dict[str, SubscriptionRecord] = {}
        self._messages: Dict[str, MessageRecord] = {}
        self._deliveries: Dict[str, DeliveryRecord] = {}
        self._group_counts: Dict[Tuple[str, str], Dict[str, int]] = {}
        self._requests: Dict[str, RequestRecord] = {}
        self._replies: Dict[str, ReplyRecord] = {}
        self._streams: Dict[str, StreamRecord] = {}
        self._stream_msgs: Dict[str, List[StreamMessageRecord]] = {}
        self._consumers: Dict[Tuple[str, str], ConsumerRecord] = {}
        self._consumer_pos: Dict[Tuple[str, str], int] = {}
        self._consumer_dlvs: Dict[str, ConsumerDelivery] = {}
        self._audit: List[dict] = []
        self._msg_n = 0
        self._dlv_n = 0
        self._inbox_n = 0
        self._req_n = 0
        self._cdlv_n = 0

    # -- internals --------------------------------------------------------

    def _bump(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase (last {self._seq})")
        self._seq = seq
        return seq

    def _burn(self, seq: int, detail: Mapping[str, Any]) -> None:
        """Book a rejected mutation: seq consumed + audited."""
        try:
            self._bump(seq)
        except SeqOrderError:
            return
        self._audit.append(
            nats_server_audit_event("rejected", seq, detail))

    def _emit(self, kind: str, seq: int,
             detail: Optional[Mapping[str, Any]] = None) -> None:
        self._audit.append(nats_server_audit_event(kind, seq, detail))

    # -- subscriptions ----------------------------------------------------

    def subscribe(self, subscriber_id: str, pattern: str, seq: int,
                  queue_group: Optional[str] = None) -> SubscriptionRecord:
        """Register a subscriber on a NATS subject pattern."""
        with self._lock:
            try:
                subscriber_id = _check_id(subscriber_id, "subscriber_id")
                pattern = _check_subject(pattern, allow_wildcards=True)
                if queue_group is not None:
                    _check_id(queue_group, "queue_group")
                if subscriber_id in self._subs:
                    raise DuplicateSubscriberError(
                        f"subscriber already registered: {subscriber_id!r}")
                seq = self._bump(seq)
            except NATSServerError as exc:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "subscribe"})
                raise
            rec = SubscriptionRecord(
                subscriber_id=subscriber_id, pattern=pattern,
                queue_group=queue_group, seq=seq,
                digest=_pin("subscription", subscriber_id, pattern,
                            queue_group or "", seq))
            self._subs[subscriber_id] = rec
            self._emit("subscribed", seq,
                       {"subscriber_id": subscriber_id, "pattern": pattern,
                        "digest": rec.digest})
            return rec

    def unsubscribe(self, subscriber_id: str, seq: int) -> None:
        """Remove a subscriber (id retired, never recycled)."""
        with self._lock:
            try:
                subscriber_id = _check_id(subscriber_id, "subscriber_id")
                if subscriber_id not in self._subs:
                    raise UnknownSubscriberError(
                        f"unknown subscriber: {subscriber_id!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "unsubscribe"})
                raise
            del self._subs[subscriber_id]
            self._emit("unsubscribed", seq,
                       {"subscriber_id": subscriber_id})

    def match(self, subject: str, seq: int) -> Tuple[str, ...]:
        """Pure view: subscriber ids whose pattern matches ``subject``."""
        with self._lock:
            _check_seq(seq)
            _check_subject(subject, allow_wildcards=False)
            return tuple(sorted(
                sid for sid, sub in self._subs.items()
                if _pattern_matches(sub.pattern, subject)))

    # -- publish ----------------------------------------------------------

    def publish(self, subject: str, payload: Mapping[str, Any], seq: int,
                reply_to: Optional[str] = None) -> Tuple[MessageRecord,
                                                        Tuple[DeliveryRecord, ...]]:
        """Publish a message; route to every matching subscriber."""
        with self._lock:
            try:
                subject = _check_subject(subject, allow_wildcards=False)
                payload = _check_mapping(payload, "payload")
                _walk_canonicalizable(payload, "payload")
                if reply_to is not None:
                    _check_subject(reply_to, allow_wildcards=False)
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "publish"})
                raise
            self._msg_n += 1
            message_id = f"msg-{self._msg_n}"
            payload_digest = "sha256:" + jcs_sha256_hex(payload)
            msg = MessageRecord(
                message_id=message_id, subject=subject,
                payload_digest=payload_digest, reply_to=reply_to, seq=seq,
                digest=_pin("message", message_id, subject,
                            payload_digest, reply_to or "", seq))
            self._messages[message_id] = msg
            # Fan out: plain subscribers get one delivery each; queue
            # groups get exactly one delivery to the least-loaded member.
            matched = [s for s in self._subs.values()
                       if _pattern_matches(s.pattern, subject)]
            plain = sorted(s.subscriber_id for s in matched
                           if s.queue_group is None)
            groups: Dict[str, List[SubscriptionRecord]] = {}
            for s in matched:
                if s.queue_group is not None:
                    groups.setdefault(s.queue_group, []).append(s)
            deliveries: List[DeliveryRecord] = []
            for sid in plain:
                deliveries.append(self._book_delivery(
                    message_id, sid, subject, seq))
            for group, members in sorted(groups.items()):
                counts = self._group_counts.setdefault((subject, group), {})
                pick = min((m.subscriber_id for m in members),
                           key=lambda sid: (counts.get(sid, 0), sid))
                counts[pick] = counts.get(pick, 0) + 1
                deliveries.append(self._book_delivery(
                    message_id, pick, subject, seq))
            self._emit("published", seq,
                       {"message_id": message_id, "subject": subject,
                        "payload_digest": payload_digest,
                        "deliveries": len(deliveries),
                        "digest": msg.digest})
            return msg, tuple(deliveries)

    def _book_delivery(self, message_id: str, subscriber_id: str,
                       subject: str, seq: int) -> DeliveryRecord:
        self._dlv_n += 1
        delivery_id = f"dlv-{self._dlv_n}"
        rec = DeliveryRecord(
            delivery_id=delivery_id, message_id=message_id,
            subscriber_id=subscriber_id, seq=seq,
            digest=_pin("delivery", delivery_id, message_id,
                        subscriber_id, seq))
        self._deliveries[delivery_id] = rec
        return rec

    # -- request-reply ----------------------------------------------------

    def request(self, subject: str, payload: Mapping[str, Any], seq: int,
                timeout_seqs: int = 100) -> RequestRecord:
        """Publish a request with a minted reply inbox (NATS request-reply)."""
        with self._lock:
            try:
                subject = _check_subject(subject, allow_wildcards=False)
                payload = _check_mapping(payload, "payload")
                _walk_canonicalizable(payload, "payload")
                if isinstance(timeout_seqs, bool) or not isinstance(
                        timeout_seqs, int) or timeout_seqs <= 0:
                    raise NATSServerError(
                        f"timeout_seqs must be a positive int, "
                        f"got {timeout_seqs!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "request"})
                raise
            self._inbox_n += 1
            self._req_n += 1
            inbox = f"_INBOX.inbox-{self._inbox_n}"
            request_id = f"req-{self._req_n}"
            rec = RequestRecord(
                request_id=request_id, subject=subject, inbox=inbox,
                timeout_seq=seq + timeout_seqs, seq=seq,
                digest=_pin("request", request_id, subject, inbox,
                            seq + timeout_seqs, seq))
            self._requests[request_id] = rec
            self._emit("requested", seq,
                       {"request_id": request_id, "subject": subject,
                        "inbox": inbox, "digest": rec.digest})
            return rec

    def reply(self, request_id: str, payload: Mapping[str, Any],
              seq: int) -> ReplyRecord:
        """Resolve a pending request with a response payload."""
        with self._lock:
            try:
                request_id = _check_id(request_id, "request_id")
                payload = _check_mapping(payload, "payload")
                _walk_canonicalizable(payload, "payload")
                req = self._requests.get(request_id)
                if req is None:
                    raise UnknownRequestError(
                        f"unknown request: {request_id!r}")
                if request_id in self._replies:
                    raise RequestStateError(
                        f"request already replied: {request_id!r}")
                seq = self._bump(seq)
                if seq > req.timeout_seq:
                    raise RequestStateError(
                        f"request {request_id!r} expired at seq "
                        f"{req.timeout_seq}")
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "reply"})
                raise
            payload_digest = "sha256:" + jcs_sha256_hex(payload)
            rec = ReplyRecord(
                request_id=request_id, payload_digest=payload_digest,
                seq=seq,
                digest=_pin("reply", request_id, payload_digest, seq))
            self._replies[request_id] = rec
            self._emit("replied", seq,
                       {"request_id": request_id,
                        "payload_digest": payload_digest,
                        "digest": rec.digest})
            return rec

    def expire_requests(self, seq: int) -> Tuple[str, ...]:
        """Sweep: mark requests whose timeout passed as expired."""
        with self._lock:
            seq = self._bump(seq)
            expired = tuple(sorted(
                rid for rid, req in self._requests.items()
                if rid not in self._replies and req.timeout_seq < seq))
            for rid in expired:
                self._emit("request-expired", seq, {"request_id": rid})
            return expired

    def inbox(self, request_id: str, seq: int) -> str:
        """Pure view: the reply inbox for a request."""
        with self._lock:
            _check_seq(seq)
            request_id = _check_id(request_id, "request_id")
            req = self._requests.get(request_id)
            if req is None:
                raise UnknownRequestError(f"unknown request: {request_id!r}")
            return req.inbox

    # -- JetStream --------------------------------------------------------

    def create_stream(self, stream: str, subjects: Tuple[str, ...],
                      seq: int, retention: str = "limits") -> StreamRecord:
        """Declare a JetStream stream over subject patterns."""
        with self._lock:
            try:
                stream = _check_id(stream, "stream")
                if not isinstance(subjects, (list, tuple)) or not subjects:
                    raise NATSServerError(
                        "subjects must be a non-empty list/tuple")
                clean = tuple(_check_subject(s, allow_wildcards=True)
                              for s in subjects)
                if retention not in self.RETENTIONS:
                    raise NATSServerError(
                        f"retention must be one of {self.RETENTIONS}, "
                        f"got {retention!r}")
                if stream in self._streams:
                    raise DuplicateStreamError(
                        f"stream already declared: {stream!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "create_stream"})
                raise
            rec = StreamRecord(
                stream=stream, subjects=clean, retention=retention,
                seq=seq,
                digest=_pin("stream", stream, list(clean), retention, seq))
            self._streams[stream] = rec
            self._stream_msgs[stream] = []
            self._emit("stream-created", seq,
                       {"stream": stream, "subjects": list(clean),
                        "retention": retention, "digest": rec.digest})
            return rec

    def jetstream_publish(self, stream: str, subject: str,
                          payload: Mapping[str, Any],
                          seq: int) -> StreamMessageRecord:
        """Persist a message to a JetStream stream (assigns stream seq)."""
        with self._lock:
            try:
                stream = _check_id(stream, "stream")
                subject = _check_subject(subject, allow_wildcards=False)
                payload = _check_mapping(payload, "payload")
                _walk_canonicalizable(payload, "payload")
                decl = self._streams.get(stream)
                if decl is None:
                    raise UnknownStreamError(
                        f"unknown stream: {stream!r}")
                if not any(_pattern_matches(p, subject)
                           for p in decl.subjects):
                    raise BadSubjectError(
                        f"subject {subject!r} not covered by stream "
                        f"{stream!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "jetstream_publish"})
                raise
            msgs = self._stream_msgs[stream]
            stream_seq = len(msgs) + 1
            payload_digest = "sha256:" + jcs_sha256_hex(payload)
            rec = StreamMessageRecord(
                stream=stream, stream_seq=stream_seq, subject=subject,
                payload_digest=payload_digest, seq=seq,
                digest=_pin("stream-message", stream, stream_seq,
                            subject, payload_digest, seq))
            msgs.append(rec)
            self._emit("stream-message", seq,
                       {"stream": stream, "stream_seq": stream_seq,
                        "subject": subject,
                        "payload_digest": payload_digest,
                        "digest": rec.digest})
            return rec

    def create_consumer(self, stream: str, consumer: str, seq: int,
                        durable: bool = True,
                        replay: str = "instant") -> ConsumerRecord:
        """Create a JetStream consumer (durable or ephemeral)."""
        with self._lock:
            try:
                stream = _check_id(stream, "stream")
                consumer = _check_id(consumer, "consumer")
                if stream not in self._streams:
                    raise UnknownStreamError(
                        f"unknown stream: {stream!r}")
                if not isinstance(durable, bool):
                    raise NATSServerError(
                        f"durable must be a bool, got {durable!r}")
                if replay not in self.REPLAYS:
                    raise NATSServerError(
                        f"replay must be one of {self.REPLAYS}, "
                        f"got {replay!r}")
                key = (stream, consumer)
                if key in self._consumers:
                    raise DuplicateConsumerError(
                        f"consumer already exists: {stream!r}/{consumer!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "create_consumer"})
                raise
            rec = ConsumerRecord(
                stream=stream, consumer=consumer, durable=durable,
                replay=replay, seq=seq,
                digest=_pin("consumer", stream, consumer,
                            durable, replay, seq))
            self._consumers[key] = rec
            # Instant replay starts at the head; original starts at the
            # tail (only new messages).
            self._consumer_pos[key] = (
                0 if replay == "instant" else len(self._stream_msgs[stream]))
            self._emit("consumer-created", seq,
                       {"stream": stream, "consumer": consumer,
                        "durable": durable, "replay": replay,
                        "digest": rec.digest})
            return rec

    def consumer_deliver(self, stream: str, consumer: str,
                         seq: int) -> ConsumerDelivery:
        """Hand the next undelivered stream message to a consumer."""
        with self._lock:
            try:
                stream = _check_id(stream, "stream")
                consumer = _check_id(consumer, "consumer")
                key = (stream, consumer)
                if key not in self._consumers:
                    raise UnknownConsumerError(
                        f"unknown consumer: {stream!r}/{consumer!r}")
                pos = self._consumer_pos[key]
                msgs = self._stream_msgs[stream]
                if pos >= len(msgs):
                    raise NATSServerError(
                        f"no undelivered messages for "
                        f"{stream!r}/{consumer!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "consumer_deliver"})
                raise
            msg = msgs[pos]
            self._consumer_pos[key] = pos + 1
            self._cdlv_n += 1
            delivery_id = f"cdlv-{self._cdlv_n}"
            rec = ConsumerDelivery(
                delivery_id=delivery_id, stream=stream, consumer=consumer,
                stream_seq=msg.stream_seq, redelivered=False, acked=False,
                seq=seq,
                digest=_pin("consumer-delivery", delivery_id, stream,
                            consumer, msg.stream_seq, False, False, seq))
            self._consumer_dlvs[delivery_id] = rec
            self._emit("jetstream-delivered", seq,
                       {"delivery_id": delivery_id, "stream": stream,
                        "consumer": consumer,
                        "stream_seq": msg.stream_seq,
                        "digest": rec.digest})
            return rec

    def ack(self, delivery_id: str, seq: int) -> ConsumerDelivery:
        """Ack a consumer delivery (redelivery-complete)."""
        with self._lock:
            try:
                delivery_id = _check_id(delivery_id, "delivery_id")
                rec = self._consumer_dlvs.get(delivery_id)
                if rec is None:
                    raise AckStateError(
                        f"unknown delivery: {delivery_id!r}")
                if rec.acked:
                    raise AckStateError(
                        f"delivery already acked: {delivery_id!r}")
                seq = self._bump(seq)
            except NATSServerError:
                self._burn(seq if isinstance(seq, int) else 0,
                           {"op": "ack"})
                raise
            acked = ConsumerDelivery(
                delivery_id=rec.delivery_id, stream=rec.stream,
                consumer=rec.consumer, stream_seq=rec.stream_seq,
                redelivered=rec.redelivered, acked=True, seq=seq,
                digest=_pin("consumer-delivery", rec.delivery_id,
                            rec.stream, rec.consumer, rec.stream_seq,
                            rec.redelivered, True, seq))
            self._consumer_dlvs[delivery_id] = acked
            self._emit("acked", seq,
                       {"delivery_id": delivery_id, "stream": rec.stream,
                        "consumer": rec.consumer,
                        "stream_seq": rec.stream_seq,
                        "digest": acked.digest})
            return acked

    # -- views ------------------------------------------------------------

    def subscribers(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._subs))

    def streams(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._streams))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "subscribers": len(self._subs),
                "messages": len(self._messages),
                "deliveries": len(self._deliveries),
                "requests": len(self._requests),
                "replies": len(self._replies),
                "streams": len(self._streams),
                "stream_messages": sum(len(v)
                                       for v in self._stream_msgs.values()),
                "consumers": len(self._consumers),
                "consumer_deliveries": len(self._consumer_dlvs),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    srv = NATSServer()
    srv.subscribe("s1", "orders.>", 1)
    srv.subscribe("s2", "orders.*.created", 2)
    msg, dlvs = srv.publish("orders.us.created", {"id": 7}, 3)
    assert msg.verify() and len(dlvs) == 2 and all(d.verify() for d in dlvs)
    srv.subscribe("w1", "jobs.run", 4, queue_group="workers")
    srv.subscribe("w2", "jobs.run", 5, queue_group="workers")
    _, qdlvs = srv.publish("jobs.run", {"n": 1}, 6)
    assert len(qdlvs) == 1  # one per queue group
    req = srv.request("svc.add", {"a": 1}, 7, timeout_seqs=10)
    assert req.verify()
    rep = srv.reply(req.request_id, {"sum": 2}, 8)
    assert rep.verify()
    st = srv.create_stream("ORDERS", ("orders.>",), 9)
    assert st.verify()
    sm = srv.jetstream_publish("ORDERS", "orders.eu.created", {"id": 9}, 10)
    assert sm.verify() and sm.stream_seq == 1
    con = srv.create_consumer("ORDERS", "audit", 11)
    assert con.verify()
    cd = srv.consumer_deliver("ORDERS", "audit", 12)
    assert cd.verify() and not cd.acked
    acked = srv.ack(cd.delivery_id, 13)
    assert acked.acked and acked.verify()
    ev = nats_server_audit_event("published", 14,
                                 {"subject": "x.y", "digest": "sha256:abc"})
    assert ev["schema"] == AUDIT_SCHEMA
    print("nats-server OK: publish, subscribe, queue-group, "
          "request-reply, jetstream, consumer, ack, audit")


if __name__ == "__main__":
    main()
