"""At-least-once pub/sub message queue.

A producer publishes JSON-canonicalizable payloads to named topics;
subscribers receive deliveries, then settle each delivery with ``ack``
(commit) or ``nack`` (requeue). Delivery is *at-least-once*: a message
stays assigned to a subscriber's pending set until it is acked, so any
message that was delivered but never acked is handed out again on the
next ``receive``. Duplicate delivery is therefore possible -- hosts that
cannot tolerate a second copy must dedupe downstream (pair with
``exactly_once`` / ``idempotency_manager``).

Semantics:

* Topics are created implicitly by the first ``publish`` or
  ``subscribe`` touching them.
* ``publish(topic, payload, seq)`` appends one frozen ``Message`` to the
  topic log and returns it. The payload is validated canonicalizable,
  deep-copied (later caller mutation cannot move the pinned digest), and
  pinned by a ``sha256:`` digest of its canonical JSON.
* ``subscribe(topic, subscriber_id, seq)`` registers a subscriber on a
  topic; returns a frozen ``Subscription``. A subscriber id may not be
  registered twice on the same topic.
* ``receive(subscriber_id, seq, limit=None)`` returns up to ``limit``
  frozen ``Delivery`` records: unacked-but-delivered ("pending")
  messages first, in topic order, then never-delivered ones. Every
  delivery increments the message's attempt count for that subscriber.
  A fresh ``receive`` after an unacked delivery therefore repeats the
  delivery -- that is the at-least-once guarantee.
* ``ack(subscriber_id, message_id, seq)`` removes the message from the
  subscriber's pending set (frozen ``AckRecord``). Acking a message that
  is not pending for that subscriber (unknown message, never delivered,
  or already acked) raises ``MessageNotPendingError`` fail-closed.
* ``nack(subscriber_id, message_id, seq)`` keeps the message in the
  pending set and bumps its attempts; the next ``receive`` redelivers it
  (frozen ``NackRecord``).

House style: frozen dataclasses, no wall-clock (caller-supplied int
seqs), fail-closed validation (``TypeError``/``ValueError``/domain
errors on malformed input), stdlib-only, RLock-guarded mutable state,
version and schema pins, ``main()`` self-check.

Honest scope: this is a *host-reported* delivery ledger, not a network
transport. It records that a message was published, that a delivery was
handed to a subscriber, and that the subscriber acked or nacked it; it
cannot prove the subscriber's real-world side effects ran, and it cannot
see messages the host never publishes. At-least-once means "no message
is silently dropped while unacked" -- it is never a promise of
exactly-once. Payloads are pinned by ``sha256:`` digests of canonical
JSON; values that are not JSON-canonicalizable (NaN/inf, non-str dict
keys, arbitrary objects) are rejected fail-closed rather than hashed
ambiguously.

Version pin: message-queue.v1
Schema pin: northstar.message-queue.v1
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Optional

MESSAGE_QUEUE_VERSION = "message-queue.v1"
SCHEMA_PIN = "northstar.message-queue.v1"

_MAX_NAME_LEN = 256

_AUDIT_KINDS = (
    "published",
    "subscribed",
    "delivered",
    "acked",
    "nacked",
    "rejected",
)


class MessageQueueError(Exception):
    """Base class for message-queue errors."""


class DuplicateSubscriberError(MessageQueueError):
    """Raised when a subscriber id is registered twice on the same topic."""


class UnknownSubscriberError(MessageQueueError):
    """Raised when a subscriber id was never registered."""


class UnknownMessageError(MessageQueueError):
    """Raised when a message id names no published message."""


class MessageNotPendingError(MessageQueueError):
    """Raised when acking/nacking a message not pending for the subscriber.

    "Not pending" covers: the message was never delivered to this
    subscriber, it was already acked, or it belongs to a different
    subscriber. Treating any of these as a silent success would let a
    confused host believe delivery was settled when it was not.
    """


class PayloadNotCanonicalError(MessageQueueError):
    """Raised when a payload is not JSON-canonicalizable for digest pinning."""


def _require_topic(topic: Any) -> str:
    if not isinstance(topic, str) or not topic:
        raise TypeError(f"topic must be a non-empty str, got {type(topic).__name__}")
    if len(topic) > _MAX_NAME_LEN:
        raise ValueError(f"topic longer than {_MAX_NAME_LEN} chars")
    return topic


def _require_subscriber_id(subscriber_id: Any) -> str:
    if not isinstance(subscriber_id, str) or not subscriber_id:
        raise TypeError(
            f"subscriber_id must be a non-empty str, got {type(subscriber_id).__name__}"
        )
    if len(subscriber_id) > _MAX_NAME_LEN:
        raise ValueError(f"subscriber_id longer than {_MAX_NAME_LEN} chars")
    return subscriber_id


def _require_message_id(message_id: Any) -> str:
    if not isinstance(message_id, str) or not message_id:
        raise TypeError(
            f"message_id must be a non-empty str, got {type(message_id).__name__}"
        )
    return message_id


def _require_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TypeError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _require_limit(limit: Any) -> Optional[int]:
    if limit is None:
        return None
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise TypeError(f"limit must be a positive int or None, got {limit!r}")
    return limit


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting; rejects non-canonicalizable input."""
    if value is None or isinstance(value, bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise PayloadNotCanonicalError("payload must not contain NaN or infinity")
    elif isinstance(value, str):
        pass
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise PayloadNotCanonicalError("dict keys must be str for canonicalization")
            _canonical(v)
    else:
        raise PayloadNotCanonicalError(
            f"value of type {type(value).__name__} is not JSON-canonicalizable"
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _require_digest(digest: Any, field: str) -> str:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError(f"{field} must be a 'sha256:' digest pin")
    return digest


@dataclass(frozen=True)
class Message:
    """One published message (frozen).

    ``payload`` is a deep copy taken at publish time; mutating the
    caller's object afterwards cannot move ``payload_digest``.
    """

    message_id: str
    topic: str
    payload: Any
    payload_digest: str
    publish_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_message_id(self.message_id)
        _require_topic(self.topic)
        _canonical(self.payload)
        _require_digest(self.payload_digest, "payload_digest")
        _require_seq(self.publish_seq)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "topic": self.topic,
            "payload_digest": self.payload_digest,
            "publish_seq": self.publish_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Subscription:
    """One subscriber registration (frozen)."""

    topic: str
    subscriber_id: str
    subscribe_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_topic(self.topic)
        _require_subscriber_id(self.subscriber_id)
        _require_seq(self.subscribe_seq)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "topic": self.topic,
            "subscriber_id": self.subscriber_id,
            "subscribe_seq": self.subscribe_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Delivery:
    """One handed-out delivery (frozen).

    ``attempts`` is the 1-based count of times this message has been
    handed to this subscriber, including this delivery. ``attempts > 1``
    means the host is seeing a redelivery under the at-least-once rule.
    """

    message_id: str
    subscriber_id: str
    topic: str
    payload: Any
    payload_digest: str
    attempts: int
    delivery_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_message_id(self.message_id)
        _require_subscriber_id(self.subscriber_id)
        _require_topic(self.topic)
        _canonical(self.payload)
        _require_digest(self.payload_digest, "payload_digest")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int) or self.attempts < 1:
            raise TypeError(f"attempts must be a positive int, got {self.attempts!r}")
        _require_seq(self.delivery_seq)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "subscriber_id": self.subscriber_id,
            "topic": self.topic,
            "payload_digest": self.payload_digest,
            "attempts": self.attempts,
            "delivery_seq": self.delivery_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AckRecord:
    """Frozen settlement record for ``ack``."""

    message_id: str
    subscriber_id: str
    ack_seq: int
    attempts: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_message_id(self.message_id)
        _require_subscriber_id(self.subscriber_id)
        _require_seq(self.ack_seq)
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int) or self.attempts < 1:
            raise TypeError(f"attempts must be a positive int, got {self.attempts!r}")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "subscriber_id": self.subscriber_id,
            "ack_seq": self.ack_seq,
            "attempts": self.attempts,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class NackRecord:
    """Frozen settlement record for ``nack``."""

    message_id: str
    subscriber_id: str
    nack_seq: int
    attempts: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_message_id(self.message_id)
        _require_subscriber_id(self.subscriber_id)
        _require_seq(self.nack_seq)
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int) or self.attempts < 1:
            raise TypeError(f"attempts must be a positive int, got {self.attempts!r}")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "subscriber_id": self.subscriber_id,
            "nack_seq": self.nack_seq,
            "attempts": self.attempts,
            "schema": self.schema,
        }


class MessageQueue:
    """At-least-once pub/sub queue (RLock-guarded).

    The topic log is append-only: message ids are minted monotonically
    (``msg-1``, ``msg-2``, ...) and never reused. Per-subscriber state
    is a pending set (delivered, not yet acked) plus an acked set; the
    pending set is the load-bearing structure -- anything in it is
    redelivered by ``receive``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_id = 1
        self._messages: dict[str, Message] = {}
        self._topics: dict[str, list[str]] = {}
        # subscriber_id -> topic
        self._subs: dict[str, str] = {}
        # subscriber_id -> message_id -> attempts
        self._pending: dict[str, dict[str, int]] = {}
        # subscriber_id -> set of acked message ids
        self._acked: dict[str, set[str]] = {}

    def publish(self, topic: str, payload: Any, seq: int) -> Message:
        """Publish ``payload`` to ``topic``; returns the pinned ``Message``."""
        _require_topic(topic)
        _require_seq(seq)
        with self._lock:
            message_id = f"msg-{self._next_id}"
            self._next_id += 1
            digest = _digest(payload)
            msg = Message(
                message_id=message_id,
                topic=topic,
                payload=copy.deepcopy(payload),
                payload_digest=digest,
                publish_seq=seq,
            )
            self._messages[message_id] = msg
            self._topics.setdefault(topic, []).append(message_id)
            return msg

    def subscribe(self, topic: str, subscriber_id: str, seq: int) -> Subscription:
        """Register ``subscriber_id`` on ``topic``; returns a ``Subscription``."""
        _require_topic(topic)
        _require_subscriber_id(subscriber_id)
        _require_seq(seq)
        with self._lock:
            self._topics.setdefault(topic, [])
            if subscriber_id in self._subs:
                raise DuplicateSubscriberError(
                    f"subscriber {subscriber_id!r} already subscribed to "
                    f"{self._subs[subscriber_id]!r}"
                )
            self._subs[subscriber_id] = topic
            self._pending[subscriber_id] = {}
            self._acked[subscriber_id] = set()
            return Subscription(topic=topic, subscriber_id=subscriber_id, subscribe_seq=seq)

    def receive(
        self, subscriber_id: str, seq: int, limit: Optional[int] = None
    ) -> tuple[Delivery, ...]:
        """Hand out deliveries: pending (unacked) first, then new messages.

        Returns a tuple of frozen ``Delivery`` records in topic order.
        Every delivery increments that message's attempt count for this
        subscriber, which is the mechanism behind at-least-once:
        anything delivered but never acked shows up here again.
        """
        _require_subscriber_id(subscriber_id)
        _require_seq(seq)
        limit = _require_limit(limit)
        with self._lock:
            if subscriber_id not in self._subs:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            topic = self._subs[subscriber_id]
            pending = self._pending[subscriber_id]
            log = self._topics[topic]
            # Position index so topic order is deterministic.
            position = {mid: i for i, mid in enumerate(log)}
            pending_sorted = sorted(pending, key=lambda mid: position[mid])
            fresh = [
                mid
                for mid in log
                if mid not in pending and mid not in self._acked[subscriber_id]
            ]
            ordered = pending_sorted + fresh
            if limit is not None:
                ordered = ordered[:limit]
            out = []
            for mid in ordered:
                attempts = pending.get(mid, 0) + 1
                pending[mid] = attempts
                msg = self._messages[mid]
                out.append(
                    Delivery(
                        message_id=mid,
                        subscriber_id=subscriber_id,
                        topic=topic,
                        payload=copy.deepcopy(msg.payload),
                        payload_digest=msg.payload_digest,
                        attempts=attempts,
                        delivery_seq=seq,
                    )
                )
            return tuple(out)

    def ack(self, subscriber_id: str, message_id: str, seq: int) -> AckRecord:
        """Acknowledge a pending delivery; returns an ``AckRecord``."""
        _require_subscriber_id(subscriber_id)
        _require_message_id(message_id)
        _require_seq(seq)
        with self._lock:
            if subscriber_id not in self._subs:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            if message_id not in self._messages:
                raise UnknownMessageError(f"unknown message {message_id!r}")
            pending = self._pending[subscriber_id]
            if message_id not in pending:
                raise MessageNotPendingError(
                    f"message {message_id!r} is not pending for subscriber "
                    f"{subscriber_id!r}"
                )
            attempts = pending.pop(message_id)
            self._acked[subscriber_id].add(message_id)
            return AckRecord(
                message_id=message_id,
                subscriber_id=subscriber_id,
                ack_seq=seq,
                attempts=attempts,
            )

    def nack(self, subscriber_id: str, message_id: str, seq: int) -> NackRecord:
        """Requeue a pending delivery; the next ``receive`` redelivers it."""
        _require_subscriber_id(subscriber_id)
        _require_message_id(message_id)
        _require_seq(seq)
        with self._lock:
            if subscriber_id not in self._subs:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            if message_id not in self._messages:
                raise UnknownMessageError(f"unknown message {message_id!r}")
            pending = self._pending[subscriber_id]
            if message_id not in pending:
                raise MessageNotPendingError(
                    f"message {message_id!r} is not pending for subscriber "
                    f"{subscriber_id!r}"
                )
            attempts = pending[message_id]
            return NackRecord(
                message_id=message_id,
                subscriber_id=subscriber_id,
                nack_seq=seq,
                attempts=attempts,
            )

    # -- views ---------------------------------------------------------

    def pending_count(self, subscriber_id: str) -> int:
        """Number of delivered-but-unacked messages for a subscriber."""
        _require_subscriber_id(subscriber_id)
        with self._lock:
            if subscriber_id not in self._subs:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            return len(self._pending[subscriber_id])

    def published_count(self, topic: Optional[str] = None) -> int:
        """Messages published; optionally restricted to one topic."""
        with self._lock:
            if topic is None:
                return len(self._messages)
            _require_topic(topic)
            return len(self._topics.get(topic, []))

    def subscribers(self, topic: str) -> tuple[str, ...]:
        """Subscriber ids registered on a topic."""
        _require_topic(topic)
        with self._lock:
            return tuple(sorted(s for s, t in self._subs.items() if t == topic))


def message_queue_audit_event(
    kind: str,
    seq: int,
    subscriber_id: Optional[str] = None,
    message: Optional[Message] = None,
    delivery: Optional[Delivery] = None,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a queue step.

    ``kind`` is one of ``published`` / ``subscribed`` / ``delivered`` /
    ``acked`` / ``nacked`` / ``rejected``. Payloads are never emitted --
    only the ``sha256:`` payload digest -- so payload content does not
    leak through the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _require_seq(seq)
    if subscriber_id is not None:
        _require_subscriber_id(subscriber_id)
    if message is not None and not isinstance(message, Message):
        raise TypeError("message must be a Message")
    if delivery is not None and not isinstance(delivery, Delivery):
        raise TypeError("delivery must be a Delivery")
    record = {
        "event": f"message-queue-{kind}",
        "audit_seq": seq,
        "subscriber_id": subscriber_id,
        "schema": SCHEMA_PIN,
    }
    if message is not None:
        record["message_id"] = message.message_id
        record["topic"] = message.topic
        record["payload_digest"] = message.payload_digest
    if delivery is not None:
        record["message_id"] = delivery.message_id
        record["topic"] = delivery.topic
        record["payload_digest"] = delivery.payload_digest
        record["attempts"] = delivery.attempts
    return record


def main() -> None:
    q = MessageQueue()
    m1 = q.publish("orders", {"secret_token_xyz": 1}, seq=0)
    assert m1.message_id == "msg-1"
    assert m1.payload_digest.startswith("sha256:")
    sub = q.subscribe("orders", "worker-1", seq=1)
    assert sub.topic == "orders"
    (d1,) = q.receive("worker-1", seq=2)
    assert d1.attempts == 1 and d1.payload == {"secret_token_xyz": 1}
    # At-least-once: unacked message is redelivered on the next receive.
    (d2,) = q.receive("worker-1", seq=3)
    assert d2.message_id == d1.message_id and d2.attempts == 2
    rec = q.nack("worker-1", "msg-1", seq=4)
    assert rec.attempts == 2
    acked = q.ack("worker-1", "msg-1", seq=5)
    assert acked.attempts == 2
    assert q.receive("worker-1", seq=6) == ()
    assert q.pending_count("worker-1") == 0

    try:
        q.ack("worker-1", "msg-1", seq=7)
    except MessageNotPendingError:
        pass
    else:
        raise AssertionError("double ack should raise")
    try:
        q.subscribe("orders", "worker-1", seq=8)
    except DuplicateSubscriberError:
        pass
    else:
        raise AssertionError("duplicate subscribe should raise")
    try:
        q.receive("ghost", seq=9)
    except UnknownSubscriberError:
        pass
    else:
        raise AssertionError("unknown subscriber should raise")
    try:
        q.publish("orders", {"bad": float("nan")}, seq=10)
    except PayloadNotCanonicalError:
        pass
    else:
        raise AssertionError("NaN payload should raise")

    ev = message_queue_audit_event("delivered", seq=11, subscriber_id="worker-1", delivery=d1)
    assert ev["event"] == "message-queue-delivered" and ev["attempts"] == 1
    assert "secret_token_xyz" not in str(ev)
    print("message-queue OK: publish, subscribe, redeliver, nack, ack")


if __name__ == "__main__":
    main()
