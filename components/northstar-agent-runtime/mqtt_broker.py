"""MQTT publish/subscribe broker bookkeeping (Mosquitto/HiveMQ-shaped).

An ``MQTTBroker`` books MQTT control-plane *decisions* as a deterministic
single-host state machine:

- ``subscribe(client_id, topic_filter, seq, qos=0)`` pins a subscription.
  Filters support MQTT wildcards: ``+`` (one level) and ``#`` (rest of
  tree, must be the final level). New subscriptions immediately receive
  matching retained messages as frozen ``DeliveryRecord`` catch-up rows.
- ``unsubscribe(client_id, topic_filter, seq)`` retires a subscription.
- ``publish(topic, payload_digest, seq, qos=0)`` books a message by digest
  only and fans it out to matching subscriptions. Delivery QoS is
  ``min(publish qos, subscription qos)`` per MQTT semantics.
- ``retain(topic, seq, payload_digest=None)`` sets (digest given) or
  clears (``None``) the retained message for a topic.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``mqtt-broker.v1``,
schema pin ``northstar.mqtt-broker.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* publish/subscribe
decisions. Payload bytes never enter a record or the audit boundary —
only ``sha256:`` digest pins. It performs no networking, runs no TCP
listener, enforces no authentication, and cannot prove a subscriber
actually received anything: a ``DeliveryRecord`` means "the broker
ledger routed this message", never wire truth. Topic ACLs are the
host's job.
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
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
MQTT_BROKER_VERSION = "mqtt-broker.v1"

#: Schema pin carried by records and audit events.
MQTT_BROKER_SCHEMA = "northstar.mqtt-broker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned QoS vocabulary (MQTT-3.1.1 §4.3).
QOS_LEVELS = (0, 1, 2)

#: Max topic/filter length we book (keeps pins bounded).
_MAX_TOPIC_LEN = 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class MQTTBrokerError(ValueError):
    """Base for all MQTT broker structural problems and refused transitions."""


class BadTopicError(MQTTBrokerError):
    """A publish/retain topic is malformed (wildcards, empty levels, ...)."""


class BadFilterError(MQTTBrokerError):
    """A subscription topic filter is malformed."""


class BadQoSError(MQTTBrokerError):
    """QoS is not one of the pinned levels 0/1/2."""


class BadDigestError(MQTTBrokerError):
    """A payload digest is not a ``sha256:`` + 64 hex pin."""


class DuplicateSubscriptionError(MQTTBrokerError):
    """The (client, filter) pair is already subscribed."""


class UnknownSubscriptionError(MQTTBrokerError):
    """No such (client, filter) subscription exists."""


class UnknownRetainedError(MQTTBrokerError):
    """No retained message is pinned for the topic."""


class SeqOrderError(MQTTBrokerError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MQTTBrokerError(f"{name} must be a non-empty string")
    return value.strip()


def _check_qos(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadQoSError(f"qos must be one of {QOS_LEVELS}")
    if value not in QOS_LEVELS:
        raise BadQoSError(f"qos must be one of {QOS_LEVELS}")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise BadDigestError(f"{name} must be 'sha256:' + 64 hex chars")
    return value


def _split_levels(value: str) -> List[str]:
    return value.split("/")


def _check_topic(topic: Any) -> str:
    """Validate a publish/retain topic: no wildcards, no empty levels."""
    topic = _check_nonempty_str(topic, "topic")
    if len(topic) > _MAX_TOPIC_LEN:
        raise BadTopicError(f"topic exceeds {_MAX_TOPIC_LEN} chars")
    if any(ch in topic for ch in ("+", "#")):
        raise BadTopicError("publish topic must not contain wildcards")
    levels = _split_levels(topic)
    if any(level == "" for level in levels):
        raise BadTopicError("topic has empty levels")
    if any(ch.isspace() for ch in topic):
        raise BadTopicError("topic must not contain whitespace")
    return topic


def _check_filter(topic_filter: Any) -> str:
    """Validate a subscription filter: ``+``/``#`` allowed per MQTT rules."""
    topic_filter = _check_nonempty_str(topic_filter, "topic_filter")
    if len(topic_filter) > _MAX_TOPIC_LEN:
        raise BadFilterError(f"topic_filter exceeds {_MAX_TOPIC_LEN} chars")
    if any(ch.isspace() for ch in topic_filter):
        raise BadFilterError("topic_filter must not contain whitespace")
    levels = _split_levels(topic_filter)
    if any(level == "" for level in levels):
        raise BadFilterError("topic_filter has empty levels")
    for i, level in enumerate(levels):
        if "#" in level:
            if level != "#" or i != len(levels) - 1:
                raise BadFilterError(
                    "'#' must occupy an entire final level"
                )
        if "+" in level and level != "+":
            raise BadFilterError("'+' must occupy an entire level")
    return topic_filter


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([MQTT_BROKER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _filter_matches(topic_filter: str, topic: str) -> bool:
    """MQTT topic-filter matching (``+`` one level, ``#`` rest of tree)."""
    f_levels = _split_levels(topic_filter)
    t_levels = _split_levels(topic)
    i = 0
    while i < len(f_levels):
        f = f_levels[i]
        if f == "#":
            return True
        if i >= len(t_levels):
            return False
        if f != "+" and f != t_levels[i]:
            return False
        i += 1
    return i == len(t_levels)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubscriptionRecord:
    """One pinned (client, filter) subscription."""

    client_id: str
    topic_filter: str
    qos: int
    seq: int
    digest: str
    schema: str = MQTT_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "subscribe", self.client_id, self.topic_filter, self.qos, self.seq
        )


@dataclass(frozen=True)
class UnsubscribeRecord:
    """One subscription retirement."""

    client_id: str
    topic_filter: str
    seq: int
    digest: str
    schema: str = MQTT_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "unsubscribe", self.client_id, self.topic_filter, self.seq
        )


@dataclass(frozen=True)
class PublishRecord:
    """One booked publish. Payload is a digest pin; bytes never enter."""

    publish_id: str
    topic: str
    payload_digest: str
    qos: int
    seq: int
    digest: str
    schema: str = MQTT_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "publish", self.publish_id, self.topic, self.payload_digest,
            self.qos, self.seq,
        )


@dataclass(frozen=True)
class DeliveryRecord:
    """One ledger-routed delivery to a subscriber (decision, not wire truth)."""

    delivery_id: str
    publish_id: str
    client_id: str
    topic: str
    qos: int
    retained: bool
    seq: int
    digest: str
    schema: str = MQTT_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deliver", self.delivery_id, self.publish_id, self.client_id,
            self.topic, self.qos, self.retained, self.seq,
        )


@dataclass(frozen=True)
class RetainRecord:
    """One retained-message set/clear. ``cleared=True`` carries no digest."""

    topic: str
    payload_digest: str
    cleared: bool
    seq: int
    digest: str
    schema: str = MQTT_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "retain", self.topic, self.payload_digest, self.cleared, self.seq
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SUBSCRIBED = "mqtt.subscribed"
KIND_UNSUBSCRIBED = "mqtt.unsubscribed"
KIND_PUBLISHED = "mqtt.published"
KIND_RETAINED_SET = "mqtt.retained-set"
KIND_RETAINED_CLEARED = "mqtt.retained-cleared"
KIND_REJECTED = "mqtt.rejected"
_KINDS = (
    KIND_SUBSCRIBED, KIND_UNSUBSCRIBED, KIND_PUBLISHED,
    KIND_RETAINED_SET, KIND_RETAINED_CLEARED, KIND_REJECTED,
)


def mqtt_broker_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the MQTT broker module."""
    if kind not in _KINDS:
        raise MQTTBrokerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise MQTTBrokerError("detail must be a mapping")
    # Payload bytes never cross the audit boundary; pins only.
    banned = {"payload", "payload_bytes", "message"}
    if any(k in detail for k in banned):
        raise MQTTBrokerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": MQTT_BROKER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class MQTTBroker:
    """Deterministic MQTT publish/subscribe bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._subscriptions: Dict[Tuple[str, str], SubscriptionRecord] = {}
        self._retained: Dict[str, Tuple[str, int]] = {}  # topic -> (digest, seq)
        self._publishes: Dict[str, PublishRecord] = {}
        self._deliveries: Dict[str, DeliveryRecord] = {}
        self._publish_seq = 0
        self._delivery_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(mqtt_broker_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    def _deliver_locked(
        self,
        publish_id: str,
        client_id: str,
        topic: str,
        qos: int,
        retained: bool,
    ) -> DeliveryRecord:
        self._delivery_seq += 1
        delivery_id = f"dlv-{self._delivery_seq}"
        record = DeliveryRecord(
            delivery_id=delivery_id, publish_id=publish_id,
            client_id=client_id, topic=topic, qos=qos, retained=retained,
            seq=self._last_seq,
            digest=_pin(
                "deliver", delivery_id, publish_id, client_id, topic, qos,
                retained, self._last_seq,
            ),
        )
        self._deliveries[delivery_id] = record
        return record

    # -- subscriptions --------------------------------------------------

    def subscribe(
        self, client_id: str, topic_filter: str, seq: int, qos: int = 0
    ) -> SubscriptionRecord:
        """Pin a subscription; immediately catch up matching retained rows."""
        with self._lock:
            client_id = _check_nonempty_str(client_id, "client_id")
            topic_filter = _check_filter(topic_filter)
            qos = _check_qos(qos)
            self._claim_seq(seq)
            key = (client_id, topic_filter)
            if key in self._subscriptions:
                self._reject_locked("duplicate-subscription")
                raise DuplicateSubscriptionError(
                    f"{client_id!r} already subscribed to {topic_filter!r}"
                )
            record = SubscriptionRecord(
                client_id=client_id, topic_filter=topic_filter, qos=qos,
                seq=seq,
                digest=_pin("subscribe", client_id, topic_filter, qos, seq),
            )
            self._subscriptions[key] = record
            # Retained catch-up: frozen delivery rows, flagged retained.
            for topic in sorted(self._retained):
                if _filter_matches(topic_filter, topic):
                    digest, _ = self._retained[topic]
                    self._deliver_locked(
                        f"retained:{topic}", client_id, topic,
                        min(qos, 1), True,
                    )
            self._audit_locked(
                KIND_SUBSCRIBED,
                {
                    "client_id": client_id,
                    "topic_filter": topic_filter,
                    "qos": qos,
                    "digest": record.digest,
                },
            )
            return record

    def unsubscribe(
        self, client_id: str, topic_filter: str, seq: int
    ) -> UnsubscribeRecord:
        """Retire a subscription (id never recycled)."""
        with self._lock:
            client_id = _check_nonempty_str(client_id, "client_id")
            topic_filter = _check_filter(topic_filter)
            self._claim_seq(seq)
            key = (client_id, topic_filter)
            if key not in self._subscriptions:
                self._reject_locked("unknown-subscription")
                raise UnknownSubscriptionError(
                    f"{client_id!r} is not subscribed to {topic_filter!r}"
                )
            del self._subscriptions[key]
            record = UnsubscribeRecord(
                client_id=client_id, topic_filter=topic_filter, seq=seq,
                digest=_pin("unsubscribe", client_id, topic_filter, seq),
            )
            self._audit_locked(
                KIND_UNSUBSCRIBED,
                {"client_id": client_id, "topic_filter": topic_filter},
            )
            return record

    # -- publishing -----------------------------------------------------

    def publish(
        self, topic: str, payload_digest: str, seq: int, qos: int = 0
    ) -> PublishRecord:
        """Book a publish by digest and fan out to matching subscriptions."""
        with self._lock:
            topic = _check_topic(topic)
            payload_digest = _check_digest(payload_digest, "payload_digest")
            qos = _check_qos(qos)
            self._claim_seq(seq)
            self._publish_seq += 1
            publish_id = f"pub-{self._publish_seq}"
            record = PublishRecord(
                publish_id=publish_id, topic=topic,
                payload_digest=payload_digest, qos=qos, seq=seq,
                digest=_pin(
                    "publish", publish_id, topic, payload_digest, qos, seq
                ),
            )
            self._publishes[publish_id] = record
            matched = 0
            for (client_id, topic_filter), sub in sorted(
                self._subscriptions.items()
            ):
                if _filter_matches(topic_filter, topic):
                    self._deliver_locked(
                        publish_id, client_id, topic,
                        min(qos, sub.qos), False,
                    )
                    matched += 1
            self._audit_locked(
                KIND_PUBLISHED,
                {
                    "publish_id": publish_id,
                    "topic": topic,
                    "payload_digest": payload_digest,
                    "qos": qos,
                    "matched": matched,
                },
            )
            return record

    # -- retained -------------------------------------------------------

    def retain(
        self, topic: str, seq: int, payload_digest: Optional[str] = None
    ) -> RetainRecord:
        """Set (digest given) or clear (``None``) the retained message."""
        with self._lock:
            topic = _check_topic(topic)
            if payload_digest is not None:
                payload_digest = _check_digest(payload_digest, "payload_digest")
            self._claim_seq(seq)
            if payload_digest is None:
                if topic not in self._retained:
                    self._reject_locked("unknown-retained")
                    raise UnknownRetainedError(
                        f"no retained message for {topic!r}"
                    )
                del self._retained[topic]
                record = RetainRecord(
                    topic=topic, payload_digest="", cleared=True, seq=seq,
                    digest=_pin("retain", topic, "", True, seq),
                )
                self._audit_locked(KIND_RETAINED_CLEARED, {"topic": topic})
            else:
                self._retained[topic] = (payload_digest, seq)
                record = RetainRecord(
                    topic=topic, payload_digest=payload_digest,
                    cleared=False, seq=seq,
                    digest=_pin("retain", topic, payload_digest, False, seq),
                )
                self._audit_locked(
                    KIND_RETAINED_SET,
                    {"topic": topic, "payload_digest": payload_digest},
                )
            return record

    # -- views ----------------------------------------------------------

    def subscription(
        self, client_id: str, topic_filter: str
    ) -> SubscriptionRecord:
        with self._lock:
            record = self._subscriptions.get(
                (
                    _check_nonempty_str(client_id, "client_id"),
                    _check_filter(topic_filter),
                )
            )
            if record is None:
                raise UnknownSubscriptionError(
                    f"{client_id!r} is not subscribed to {topic_filter!r}"
                )
            return record

    def subscription_ids(self) -> Tuple[Tuple[str, str], ...]:
        with self._lock:
            return tuple(sorted(self._subscriptions))

    def client_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted({c for c, _ in self._subscriptions}))

    def retained(self, topic: str) -> RetainRecord:
        """Read the retained pin for a topic (pure view, no seq consumed)."""
        with self._lock:
            topic = _check_topic(topic)
            entry = self._retained.get(topic)
            if entry is None:
                raise UnknownRetainedError(
                    f"no retained message for {topic!r}"
                )
            digest, set_seq = entry
            return RetainRecord(
                topic=topic, payload_digest=digest, cleared=False,
                seq=set_seq,
                digest=_pin("retain", topic, digest, False, set_seq),
            )

    def deliveries_for(self, client_id: str) -> Tuple[DeliveryRecord, ...]:
        with self._lock:
            _check_nonempty_str(client_id, "client_id")
            return tuple(
                d for d in self._deliveries.values()
                if d.client_id == client_id
            )

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read view: counts only (seq validated, not consumed)."""
        _check_seq(seq, "seq")
        with self._lock:
            return {
                "subscriptions": len(self._subscriptions),
                "clients": len({c for c, _ in self._subscriptions}),
                "retained_topics": len(self._retained),
                "publishes": len(self._publishes),
                "deliveries": len(self._deliveries),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    broker = MQTTBroker()
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    # retained before anyone subscribes
    r = broker.retain("home/livingroom/temp", 1, digest_a)
    assert r.verify() and not r.cleared
    sub = broker.subscribe("sensor-1", "home/+/temp", 2, qos=1)
    assert sub.verify()
    # retained catch-up arrived flagged retained
    catchup = broker.deliveries_for("sensor-1")
    assert len(catchup) == 1 and catchup[0].retained
    assert catchup[0].verify()
    # plain publish fans out; qos = min(pub, sub)
    pub = broker.publish("home/livingroom/temp", digest_b, 3, qos=2)
    assert pub.verify()
    live = [d for d in broker.deliveries_for("sensor-1") if not d.retained]
    assert len(live) == 1 and live[0].qos == 1 and live[0].verify()
    # multi-level wildcard
    broker.subscribe("logger", "home/#", 4)
    pub2 = broker.publish("home/kitchen/humidity", digest_a, 5)
    assert pub2.verify()
    assert any(
        d.client_id == "logger" and d.topic == "home/kitchen/humidity"
        for d in broker.deliveries_for("logger")
    )
    # unsubscribe retires; further publishes skip the client
    unsub = broker.unsubscribe("sensor-1", "home/+/temp", 6)
    assert unsub.verify()
    broker.publish("home/livingroom/temp", digest_b, 7)
    assert len([d for d in broker.deliveries_for("sensor-1")
                if not d.retained]) == 1
    # clear retained
    cleared = broker.retain("home/livingroom/temp", 8)
    assert cleared.verify() and cleared.cleared
    print("mqtt-broker OK: subscribe, retain catch-up, publish fan-out, "
          "wildcards, unsubscribe, retain clear")
    return None


if __name__ == "__main__":
    main()
