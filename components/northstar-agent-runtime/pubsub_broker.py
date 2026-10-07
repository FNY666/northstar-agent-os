"""PubSubBroker: topic-routed publish/subscribe messaging for agent pipelines.

Research note: *publish/subscribe* decouples producers from consumers through
named *topics* — a pattern at the core of message brokers (MQTT, AMQP,
Apache Kafka topics, Redis pub/sub, NATS subjects). Two capabilities matter
here:

* **Topic routing** — a ``publish(topic, ...)`` call is delivered to every
  subscriber whose subscription pattern matches the topic. MQTT-style
  wildcards apply: ``+`` matches exactly one topic level (``a/+/c`` matches
  ``a/b/c`` but not ``a/b/d`` or ``a/b/c/d``) and ``#`` matches zero or more
  trailing levels (``a/#`` matches ``a``, ``a/b``, ``a/b/c``).
* **Delivery ledger** — every delivery is a frozen record with a ``sha256:``
  digest pin binding (topic, subscriber id, message digest, seq), so an
  audit trail can later prove "this subscriber received this message on this
  topic" without retaining the payload.

Fail-closed rules: subscribing to a malformed topic pattern, publishing to a
malformed topic, publishing a non-canonicalizable payload, unsubscribing an
unknown subscription, or delivering to a subscriber id that was removed all
raise instead of silently dropping. Duplicate subscriber ids are refused;
the same subscriber may hold several distinct subscription patterns.

Honest scope: this is a *single-host, in-memory* routing ledger, not a
networked broker — there is no transport, no persistence, no cross-process
fan-out, and no delivery guarantee beyond the calling thread. ``publish()``
records deliveries to the currently-subscribed set; it cannot prove a
subscriber *processed* the message, only that it was routed. Delivery
ordering is deterministic (subscriber id, then pattern registration order)
but a dropped process loses everything.

Version pin: pubsub-broker.v1
Schema pin: northstar.pubsub-broker.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Tuple

#: Module version.
PUBSUB_BROKER_VERSION = "pubsub-broker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.pubsub-broker.v1"


class PubSubError(Exception):
    """Malformed use of the pub/sub contract (programming error)."""


class TopicError(PubSubError):
    """A topic or pattern is malformed (empty level, bad wildcard)."""


class DuplicateSubscriberError(PubSubError):
    """A subscriber id is already registered on this broker."""


class UnknownSubscriberError(PubSubError):
    """Operation names a subscriber id the broker does not know."""


class PayloadError(PubSubError):
    """A payload is not canonicalizable (cannot be pinned)."""


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise PubSubError(f"{what} must be a non-empty str")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PubSubError("seq must be a non-negative int")
    return seq


def _validate_topic(topic: str) -> Tuple[str, ...]:
    """Validate an exact topic: non-empty levels, no wildcards."""
    _check_str(topic, "topic")
    levels = topic.split("/")
    for level in levels:
        if not level:
            raise TopicError("topic levels must be non-empty")
        if level in ("+", "#"):
            raise TopicError("exact topics must not contain wildcards")
        if any(ch in level for ch in ("+", "#")):
            raise TopicError("wildcards must occupy a whole level")
    return tuple(levels)


def _validate_pattern(pattern: str) -> Tuple[str, ...]:
    """Validate a subscription pattern: MQTT-style + and # wildcards."""
    _check_str(pattern, "pattern")
    levels = pattern.split("/")
    for i, level in enumerate(levels):
        if not level:
            raise TopicError("pattern levels must be non-empty")
        if level == "#":
            if i != len(levels) - 1:
                raise TopicError("'#' must be the final level")
        elif any(ch in level for ch in ("+", "#")):
            if level != "+":
                raise TopicError("wildcards must occupy a whole level")
    return tuple(levels)


def _pattern_matches(pattern_levels: Tuple[str, ...], topic_levels: Tuple[str, ...]) -> bool:
    i = 0
    for i, plevel in enumerate(pattern_levels):
        if plevel == "#":
            return True
        if i >= len(topic_levels):
            return False
        if plevel == "+":
            continue
        if plevel != topic_levels[i]:
            return False
    return i + 1 == len(topic_levels)


def _canonical(value: Any) -> bytes:
    """Type-tagged canonical encoding for payload pinning.

    Bool is distinct from int, NaN/inf and integral floats > 2**53 are
    refused (same JCS float-loss caveat as the rest of the batch line).
    """
    if isinstance(value, bool):
        return b"b:" + (b"1" if value else b"0")
    if isinstance(value, int):
        return b"i:" + str(value).encode("ascii")
    if isinstance(value, float):
        import math

        if math.isnan(value) or math.isinf(value):
            raise PayloadError("NaN/inf payloads cannot be pinned")
        if value == int(value) and abs(value) >= 2**53:
            raise PayloadError("integral float beyond 2**53 cannot be pinned safely")
        return b"f:" + repr(value).encode("ascii")
    if isinstance(value, str):
        return b"s:" + value.encode("utf-8")
    if value is None:
        return b"n:"
    if isinstance(value, bytes):
        return b"y:" + value.hex().encode("ascii")
    if isinstance(value, (list, tuple)):
        return b"l:" + b",".join(_canonical(v) for v in value)
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise PayloadError("mapping keys must be str")
        return b"m:" + b",".join(
            _canonical(k) + b"=" + _canonical(value[k]) for k in sorted(value)
        )
    raise PayloadError(f"payload of type {type(value).__name__} cannot be pinned")


def _pin(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class Subscription:
    """One registered subscription: subscriber id + pattern."""

    subscriber_id: str
    pattern: str
    pattern_levels: Tuple[str, ...] = field(compare=False)
    seq: int
    version: str = PUBSUB_BROKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "subscriber_id": self.subscriber_id,
            "pattern": self.pattern,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Delivery:
    """One routed message delivery: topic + subscriber + payload pins."""

    topic: str
    subscriber_id: str
    pattern: str
    payload_digest: str
    seq: int
    digest: str
    version: str = PUBSUB_BROKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "topic": self.topic,
            "subscriber_id": self.subscriber_id,
            "pattern": self.pattern,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PublishReport:
    """Outcome of one publish call: deliveries made + digest pin."""

    topic: str
    seq: int
    deliveries: Tuple[Delivery, ...]
    digest: str
    version: str = PUBSUB_BROKER_VERSION
    schema: str = SCHEMA_PIN

    @property
    def delivered_count(self) -> int:
        return len(self.deliveries)

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "topic": self.topic,
            "seq": self.seq,
            "deliveries": [d.as_dict() for d in self.deliveries],
            "delivered_count": self.delivered_count,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class PubSubBroker:
    """In-memory topic-routed pub/sub broker.

    Subscriber ids are unique; each subscriber may hold several patterns.
    ``publish()`` routes to every matching subscription in deterministic
    order (subscriber id, then registration seq). No wall-clock: all seqs
    are caller-supplied.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # subscriber_id -> list[Subscription] in registration order
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._published: int = 0

    def subscribe(self, subscriber_id: str, pattern: str, seq: int) -> Subscription:
        """Register ``subscriber_id`` for ``pattern`` (MQTT wildcards)."""
        _check_str(subscriber_id, "subscriber_id")
        levels = _validate_pattern(pattern)
        seq = _check_seq(seq)
        with self._lock:
            subs = self._subscriptions.setdefault(subscriber_id, [])
            for existing in subs:
                if existing.pattern == pattern:
                    raise DuplicateSubscriberError(
                        f"subscriber {subscriber_id!r} already subscribed to {pattern!r}"
                    )
            record = Subscription(
                subscriber_id=subscriber_id,
                pattern=pattern,
                pattern_levels=levels,
                seq=seq,
            )
            subs.append(record)
            return record

    def unsubscribe(self, subscriber_id: str, pattern: str | None, seq: int) -> int:
        """Remove subscriptions.

        ``pattern=None`` removes *all* subscriptions of the subscriber;
        otherwise removes only that pattern. Returns the count removed.
        Unknown subscriber or unknown pattern raises.
        """
        _check_str(subscriber_id, "subscriber_id")
        seq = _check_seq(seq)
        with self._lock:
            if subscriber_id not in self._subscriptions:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            subs = self._subscriptions[subscriber_id]
            if pattern is None:
                removed = len(subs)
                del self._subscriptions[subscriber_id]
                return removed
            for i, existing in enumerate(subs):
                if existing.pattern == pattern:
                    del subs[i]
                    if not subs:
                        del self._subscriptions[subscriber_id]
                    return 1
            raise PubSubError(
                f"subscriber {subscriber_id!r} has no subscription for {pattern!r}"
            )

    def publish(self, topic: str, payload: Any, seq: int) -> PublishReport:
        """Route ``payload`` to every subscription whose pattern matches.

        Returns a frozen :class:`PublishReport`. Publishing to a topic with
        no subscribers is a valid no-op (zero deliveries).
        """
        topic_levels = _validate_topic(topic)
        seq = _check_seq(seq)
        payload_bytes = _canonical(payload)
        payload_digest = _pin(b"payload", payload_bytes)
        with self._lock:
            deliveries: list[Delivery] = []
            for subscriber_id in sorted(self._subscriptions):
                for sub in self._subscriptions[subscriber_id]:
                    if _pattern_matches(sub.pattern_levels, topic_levels):
                        delivery = Delivery(
                            topic=topic,
                            subscriber_id=subscriber_id,
                            pattern=sub.pattern,
                            payload_digest=payload_digest,
                            seq=seq,
                            digest=_pin(
                                b"delivery",
                                topic.encode("utf-8"),
                                subscriber_id.encode("utf-8"),
                                sub.pattern.encode("utf-8"),
                                payload_digest.encode("ascii"),
                                seq.to_bytes(8, "big"),
                            ),
                        )
                        deliveries.append(delivery)
            self._published += 1
            report = PublishReport(
                topic=topic,
                seq=seq,
                deliveries=tuple(deliveries),
                digest=_pin(
                    b"publish",
                    topic.encode("utf-8"),
                    b"".join(d.digest.encode("ascii") for d in deliveries),
                    seq.to_bytes(8, "big"),
                ),
            )
            return report

    def subscribers(self) -> Tuple[str, ...]:
        """Subscriber ids currently registered, sorted."""
        with self._lock:
            return tuple(sorted(self._subscriptions))

    def subscriptions(self, subscriber_id: str) -> Tuple[Subscription, ...]:
        """Patterns held by ``subscriber_id`` in registration order."""
        _check_str(subscriber_id, "subscriber_id")
        with self._lock:
            if subscriber_id not in self._subscriptions:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r}")
            return tuple(self._subscriptions[subscriber_id])

    def published_count(self) -> int:
        """Total publish calls made."""
        with self._lock:
            return self._published


_PUBSUB_AUDIT_KINDS = ("subscribed", "unsubscribed", "published", "rejected")


def pubsub_broker_audit_event(kind: str, seq: int, **fields: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a broker event.

    Carries pins and ids only — never raw payloads.
    """
    if kind not in _PUBSUB_AUDIT_KINDS:
        raise PubSubError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    return {
        "kind": f"pubsub-broker.{kind}",
        "seq": seq,
        "version": PUBSUB_BROKER_VERSION,
        "schema": SCHEMA_PIN,
        **{k: v for k, v in fields.items()},
    }


def main() -> None:
    broker = PubSubBroker()
    broker.subscribe("audit-sink", "events/#", 1)
    broker.subscribe("metrics", "events/+/cpu", 2)
    report = broker.publish("events/host1/cpu", {"load": 0.5}, 3)
    assert report.delivered_count == 2, report.delivered_count
    report2 = broker.publish("events/host1/mem", {"used": 1}, 4)
    assert report2.delivered_count == 1, report2.delivered_count
    broker.unsubscribe("metrics", "events/+/cpu", 5)
    report3 = broker.publish("events/host1/cpu", {"load": 0.9}, 6)
    assert report3.delivered_count == 1, report3.delivered_count
    print("pubsub-broker OK: subscribe, wildcard routing, publish, unsubscribe")


if __name__ == "__main__":
    main()
