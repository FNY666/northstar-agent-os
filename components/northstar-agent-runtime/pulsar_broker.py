"""Apache-Pulsar-shaped broker bookkeeping: topics, subscriptions, cursors.

A ``PulsarBroker`` ledger books Pulsar control-plane decisions as a
deterministic single-host state machine:

- ``topic(topic_id, name, seq, partitions=1, persistence="persistent")``
  pins a topic definition. Pulsar-style names are normalized:
  ``persistent://tenant/namespace/name`` (also accepts
  ``tenant/namespace/name`` or a bare ``name``, defaulting to
  ``tenant="public"``, ``namespace="default"``).
- ``publish(topic_id, seq, payload_digest)`` appends a message record
  (payload bytes never enter a record — only a ``sha256:`` digest
  reference). Messages are assigned to partitions deterministically
  by ``msg_index % partitions``.
- ``subscription(topic_id, subscription_id, sub_type, seq)`` pins a
  Pulsar subscription of a pinned type (``exclusive`` / ``shared`` /
  ``failover`` / ``key_shared``) with an initial position
  (``earliest`` / ``latest``).
- ``acknowledge(subscription_id, seq, msg_id)`` is a cumulative ack:
  it advances the cursor past the acknowledged message on that
  message's partition (Pulsar cumulative-ack semantics as data).
- ``cursor(subscription_id, seq)`` is a pure read view (validates the
  seq shape, consumes nothing): per-partition published/cursor/backlog.
- ``seek(subscription_id, seq, msg_id)`` rewinds a cursor to a pinned
  message position; ``unsubscribe`` is terminal; ``delete_topic`` is
  terminal and refuses while subscriptions remain.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only plus the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events, version pin
``pulsar-broker.v1``, schema pin ``northstar.pulsar-broker.v1``,
``main()`` self-check.

Honest scope: this module books *declared* topology and *host-reported*
positions — it runs no broker, stores no payload bytes, cannot prove a
message was delivered, and cannot observe unreported consumption. A
zero-backlog cursor means "no unacked messages are booked", never "the
consumer has seen everything".
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
PULSAR_BROKER_VERSION = "pulsar-broker.v1"

#: Schema pin carried by records and audit events.
PULSAR_BROKER_SCHEMA = "northstar.pulsar-broker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pinned persistence vocabulary.
PERSISTENT = "persistent"
NON_PERSISTENT = "non-persistent"
_PERSISTENCE = (PERSISTENT, NON_PERSISTENT)

#: Pinned subscription-type vocabulary (Pulsar subscription types).
SUB_EXCLUSIVE = "exclusive"
SUB_SHARED = "shared"
SUB_FAILOVER = "failover"
SUB_KEY_SHARED = "key_shared"
_SUB_TYPES = (SUB_EXCLUSIVE, SUB_SHARED, SUB_FAILOVER, SUB_KEY_SHARED)

#: Pinned initial-position vocabulary.
POS_EARLIEST = "earliest"
POS_LATEST = "latest"
_POSITIONS = (POS_EARLIEST, POS_LATEST)

#: Partition bounds.
_MIN_PARTITIONS = 1
_MAX_PARTITIONS = 1000

_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,254}[A-Za-z0-9])?$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class PulsarBrokerError(ValueError):
    """Base for all pulsar-broker structural problems and refused transitions."""


class BadTopicError(PulsarBrokerError):
    """Topic definition is malformed (bad id, name, partitions, persistence)."""


class DuplicateTopicError(PulsarBrokerError):
    """A topic id is already registered."""


class UnknownTopicError(PulsarBrokerError):
    """No topic is pinned for the requested topic id."""


class DeletedTopicError(PulsarBrokerError):
    """The topic is deleted; further mutations are refused."""


class BadMessageError(PulsarBrokerError):
    """A publish request is malformed (bad digest)."""


class BadSubscriptionError(PulsarBrokerError):
    """A subscription definition is malformed (bad id, type, position)."""


class DuplicateSubscriptionError(PulsarBrokerError):
    """A subscription id is already registered."""


class UnknownSubscriptionError(PulsarBrokerError):
    """No subscription is pinned for the requested subscription id."""


class RemovedSubscriptionError(PulsarBrokerError):
    """The subscription is removed; further mutations are refused."""


class UnknownMessageError(PulsarBrokerError):
    """No message is booked for the referenced message id."""


class BadPositionError(PulsarBrokerError):
    """The ack/seek position does not exist for the subscription."""


class ActiveSubscriptionsError(PulsarBrokerError):
    """The topic cannot be deleted while subscriptions remain."""


class SeqOrderError(PulsarBrokerError):
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
        raise PulsarBrokerError(f"{name} must be a non-empty string")
    return value.strip()


def _check_id(value: Any, name: str) -> str:
    value = _check_nonempty_str(value, name)
    if not _NAME_RE.match(value):
        raise PulsarBrokerError(f"{name} must match [A-Za-z0-9._-], got {value!r}")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise BadMessageError(f"{name} must be 'sha256:' + 64 hex chars")
    return value


def _parse_name(name: Any) -> Tuple[str, str, str, str]:
    """Normalize a Pulsar topic name -> (persistence, tenant, namespace, name)."""
    if not isinstance(name, str) or not name.strip():
        raise BadTopicError("topic name must be a non-empty string")
    text = name.strip()
    persistence = PERSISTENT
    if "://" in text:
        persistence, _, text = text.partition("://")
        if persistence not in _PERSISTENCE:
            raise BadTopicError(
                f"persistence must be one of {_PERSISTENCE}, got {persistence!r}"
            )
    parts = text.split("/")
    if len(parts) == 3:
        tenant, namespace, topic = parts
    elif len(parts) == 1:
        tenant, namespace, topic = "public", "default", parts[0]
    else:
        raise BadTopicError(
            f"name must be persistent://tenant/namespace/topic, "
            f"tenant/namespace/topic, or a bare name; got {name!r}"
        )
    for label, piece in (("tenant", tenant), ("namespace", namespace), ("topic", topic)):
        if not _NAME_RE.match(piece):
            raise BadTopicError(f"{label} must match [A-Za-z0-9._-], got {piece!r}")
    return persistence, tenant, namespace, topic


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([PULSAR_BROKER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TopicRecord:
    """One pinned topic definition (frozen)."""

    topic_id: str
    persistence: str
    tenant: str
    namespace: str
    name: str
    partitions: int
    seq: int
    deleted: bool
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "topic", self.topic_id, self.persistence, self.tenant,
            self.namespace, self.name, self.partitions, self.seq,
        )


@dataclass(frozen=True)
class MessageRecord:
    """One booked publish (frozen). Payloads are digest references only."""

    msg_id: str
    topic_id: str
    partition: int
    msg_index: int
    payload_digest: str
    seq: int
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "message", self.msg_id, self.topic_id, self.partition,
            self.msg_index, self.payload_digest, self.seq,
        )


@dataclass(frozen=True)
class SubscriptionRecord:
    """One pinned subscription (frozen)."""

    subscription_id: str
    topic_id: str
    sub_type: str
    initial_position: str
    seq: int
    removed: bool
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "subscription", self.subscription_id, self.topic_id,
            self.sub_type, self.initial_position, self.seq,
        )


@dataclass(frozen=True)
class AckRecord:
    """One cumulative ack (frozen)."""

    ack_id: str
    subscription_id: str
    msg_id: str
    partition: int
    msg_index: int
    seq: int
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "ack", self.ack_id, self.subscription_id, self.msg_id,
            self.partition, self.msg_index, self.seq,
        )


@dataclass(frozen=True)
class SeekRecord:
    """One cursor rewind (frozen)."""

    seek_id: str
    subscription_id: str
    msg_id: str
    partition: int
    msg_index: int
    seq: int
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "seek", self.seek_id, self.subscription_id, self.msg_id,
            self.partition, self.msg_index, self.seq,
        )


@dataclass(frozen=True)
class PartitionCursor:
    """One per-partition cursor position (frozen)."""

    partition: int
    published: int
    cursor: int
    backlog: int


@dataclass(frozen=True)
class CursorReport:
    """A read view over one subscription's cursors (frozen)."""

    subscription_id: str
    topic_id: str
    partitions: Tuple[PartitionCursor, ...]
    seq: int
    digest: str
    schema: str = PULSAR_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "cursor", self.subscription_id, self.topic_id,
            [(p.partition, p.published, p.cursor, p.backlog)
             for p in self.partitions],
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_TOPIC_DEFINED = "pulsar.topic-defined"
KIND_MESSAGE_PUBLISHED = "pulsar.message-published"
KIND_SUBSCRIBED = "pulsar.subscribed"
KIND_ACKED = "pulsar.acked"
KIND_SEEKED = "pulsar.seeked"
KIND_UNSUBSCRIBED = "pulsar.unsubscribed"
KIND_TOPIC_DELETED = "pulsar.topic-deleted"
KIND_REJECTED = "pulsar.rejected"
_KINDS = (
    KIND_TOPIC_DEFINED, KIND_MESSAGE_PUBLISHED, KIND_SUBSCRIBED,
    KIND_ACKED, KIND_SEEKED, KIND_UNSUBSCRIBED, KIND_TOPIC_DELETED,
    KIND_REJECTED,
)

# Raw payload material is banned from the audit boundary; digests only.
_BANNED_AUDIT_KEYS = {"payload", "payload_bytes", "message_body"}


def pulsar_broker_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the pulsar-broker module."""
    if kind not in _KINDS:
        raise PulsarBrokerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise PulsarBrokerError("detail must be a mapping")
    if any(k in detail for k in _BANNED_AUDIT_KEYS):
        raise PulsarBrokerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": PULSAR_BROKER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class PulsarBroker:
    """Deterministic Pulsar-shaped topic/subscription/cursor ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._topics: Dict[str, TopicRecord] = {}
        self._messages: Dict[str, MessageRecord] = {}
        self._subscriptions: Dict[str, SubscriptionRecord] = {}
        # subscription_id -> {partition: cursor} where cursor is the
        # next unread msg_index on that partition.
        self._cursors: Dict[str, Dict[int, int]] = {}
        # topic_id -> [msg_id ...] in publish order
        self._topic_messages: Dict[str, List[str]] = {}
        self._ack_counter = 0
        self._seek_counter = 0
        self._msg_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers ---------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(pulsar_broker_audit_event(kind, detail, seq))

    def _reject_locked(self, seq: int, reason: str) -> None:
        try:
            self._emit(KIND_REJECTED, seq, reason=reason)
        except PulsarBrokerError:
            pass

    def _get_topic_locked(self, topic_id: str) -> TopicRecord:
        topic = self._topics.get(topic_id)
        if topic is None:
            raise UnknownTopicError(f"unknown topic: {topic_id!r}")
        if topic.deleted:
            raise DeletedTopicError(f"topic is deleted: {topic_id!r}")
        return topic

    def _cursor_map_locked(self, subscription_id: str) -> Tuple[SubscriptionRecord, Dict[int, int]]:
        sub = self._subscriptions.get(subscription_id)
        if sub is None:
            raise UnknownSubscriptionError(f"unknown subscription: {subscription_id!r}")
        if sub.removed:
            raise RemovedSubscriptionError(
                f"subscription is removed: {subscription_id!r}"
            )
        return sub, self._cursors[subscription_id]

    def _init_cursors_locked(
        self, subscription_id: str, topic: TopicRecord, position: str, msg_ids: List[str]
    ) -> Dict[int, int]:
        cursors: Dict[int, int] = {}
        for partition in range(topic.partitions):
            if position == POS_LATEST:
                cursor = len(self._messages_on_locked(topic.topic_id, partition))
            else:
                cursor = 0
            cursors[partition] = cursor
        return cursors

    def _messages_on_locked(self, topic_id: str, partition: int) -> List[str]:
        return [
            mid
            for mid in self._topic_messages[topic_id]
            if self._messages[mid].partition == partition
        ]

    # -- public API ---------------------------------------------------------

    def topic(
        self,
        topic_id: str,
        name: str,
        seq: int,
        partitions: int = 1,
        persistence: str = PERSISTENT,
    ) -> TopicRecord:
        """Pin a topic definition. Duplicate ids are refused fail-closed."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                tid = _check_id(topic_id, "topic_id")
                parsed_persistence, tenant, namespace, topic_name = _parse_name(name)
                if isinstance(persistence, str) and persistence in _PERSISTENCE:
                    persistence = persistence
                else:
                    if persistence not in _PERSISTENCE:
                        raise BadTopicError(
                            f"persistence must be one of {_PERSISTENCE}, "
                            f"got {persistence!r}"
                        )
                if isinstance(partitions, bool) or not isinstance(partitions, int):
                    raise BadTopicError("partitions must be an int")
                if not _MIN_PARTITIONS <= partitions <= _MAX_PARTITIONS:
                    raise BadTopicError(
                        f"partitions must be in [{_MIN_PARTITIONS}, {_MAX_PARTITIONS}]"
                    )
                if tid in self._topics:
                    raise DuplicateTopicError(f"duplicate topic id: {tid!r}")
                record = TopicRecord(
                    topic_id=tid,
                    persistence=persistence,
                    tenant=tenant,
                    namespace=namespace,
                    name=topic_name,
                    partitions=partitions,
                    seq=seq,
                    deleted=False,
                    digest=_pin(
                        "topic", tid, persistence, tenant, namespace,
                        topic_name, partitions, seq,
                    ),
                )
                self._topics[tid] = record
                self._topic_messages[tid] = []
                self._last_seq = seq
                self._emit(
                    KIND_TOPIC_DEFINED, seq,
                    topic_id=tid, tenant=tenant, namespace=namespace,
                    name=topic_name, partitions=partitions,
                    persistence=persistence,
                )
                return record
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def publish(self, topic_id: str, seq: int, payload_digest: str) -> MessageRecord:
        """Book one message (payloads are digest references only)."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                topic = self._get_topic_locked(topic_id)
                digest_ref = _check_digest(payload_digest, "payload_digest")
                self._msg_counter += 1
                msg_id = f"msg-{self._msg_counter}"
                msg_index = len(self._topic_messages[topic.topic_id])
                partition = msg_index % topic.partitions
                record = MessageRecord(
                    msg_id=msg_id,
                    topic_id=topic.topic_id,
                    partition=partition,
                    msg_index=msg_index,
                    payload_digest=digest_ref,
                    seq=seq,
                    digest=_pin(
                        "message", msg_id, topic.topic_id, partition,
                        msg_index, digest_ref, seq,
                    ),
                )
                self._messages[msg_id] = record
                self._topic_messages[topic.topic_id].append(msg_id)
                self._last_seq = seq
                self._emit(
                    KIND_MESSAGE_PUBLISHED, seq,
                    msg_id=msg_id, topic_id=topic.topic_id,
                    partition=partition, msg_index=msg_index,
                    payload_digest=digest_ref,
                )
                return record
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def subscription(
        self,
        topic_id: str,
        subscription_id: str,
        sub_type: str,
        seq: int,
        initial_position: str = POS_EARLIEST,
    ) -> SubscriptionRecord:
        """Pin a subscription on a topic. Duplicate ids are refused."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                topic = self._get_topic_locked(topic_id)
                sid = _check_id(subscription_id, "subscription_id")
                if sub_type not in _SUB_TYPES:
                    raise BadSubscriptionError(
                        f"sub_type must be one of {_SUB_TYPES}, got {sub_type!r}"
                    )
                if initial_position not in _POSITIONS:
                    raise BadSubscriptionError(
                        f"initial_position must be one of {_POSITIONS}, "
                        f"got {initial_position!r}"
                    )
                if sid in self._subscriptions:
                    raise DuplicateSubscriptionError(
                        f"duplicate subscription id: {sid!r}"
                    )
                record = SubscriptionRecord(
                    subscription_id=sid,
                    topic_id=topic.topic_id,
                    sub_type=sub_type,
                    initial_position=initial_position,
                    seq=seq,
                    removed=False,
                    digest=_pin(
                        "subscription", sid, topic.topic_id, sub_type,
                        initial_position, seq,
                    ),
                )
                self._subscriptions[sid] = record
                self._cursors[sid] = self._init_cursors_locked(
                    sid, topic, initial_position, self._topic_messages[topic.topic_id]
                )
                self._last_seq = seq
                self._emit(
                    KIND_SUBSCRIBED, seq,
                    subscription_id=sid, topic_id=topic.topic_id,
                    sub_type=sub_type, initial_position=initial_position,
                )
                return record
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def acknowledge(self, subscription_id: str, seq: int, msg_id: str) -> AckRecord:
        """Cumulative ack: advance the cursor past the referenced message.

        Refuses acking a message the subscription cannot see (unknown
        message, or a message on another topic) and acking an already
        passed position.
        """
        with self._lock:
            try:
                seq = self._next_seq(seq)
                sub, cursors = self._cursor_map_locked(subscription_id)
                msg = self._messages.get(msg_id)
                if msg is None:
                    raise UnknownMessageError(f"unknown message: {msg_id!r}")
                if msg.topic_id != sub.topic_id:
                    raise BadPositionError(
                        f"message {msg_id!r} is not on subscription topic "
                        f"{sub.topic_id!r}"
                    )
                current = cursors[msg.partition]
                if msg.msg_index < current:
                    raise BadPositionError(
                        f"message {msg_id!r} is already acked "
                        f"(cursor={current}, index={msg.msg_index})"
                    )
                self._ack_counter += 1
                ack_id = f"ack-{self._ack_counter}"
                new_cursor = msg.msg_index + 1
                cursors[msg.partition] = new_cursor
                record = AckRecord(
                    ack_id=ack_id,
                    subscription_id=sub.subscription_id,
                    msg_id=msg_id,
                    partition=msg.partition,
                    msg_index=msg.msg_index,
                    seq=seq,
                    digest=_pin(
                        "ack", ack_id, sub.subscription_id, msg_id,
                        msg.partition, msg.msg_index, seq,
                    ),
                )
                self._last_seq = seq
                self._emit(
                    KIND_ACKED, seq,
                    ack_id=ack_id, subscription_id=sub.subscription_id,
                    msg_id=msg_id, partition=msg.partition,
                    msg_index=msg.msg_index,
                )
                return record
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def seek(self, subscription_id: str, seq: int, msg_id: str) -> SeekRecord:
        """Rewind the cursor to the referenced message's position."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                sub, cursors = self._cursor_map_locked(subscription_id)
                msg = self._messages.get(msg_id)
                if msg is None:
                    raise UnknownMessageError(f"unknown message: {msg_id!r}")
                if msg.topic_id != sub.topic_id:
                    raise BadPositionError(
                        f"message {msg_id!r} is not on subscription topic "
                        f"{sub.topic_id!r}"
                    )
                self._seek_counter += 1
                seek_id = f"seek-{self._seek_counter}"
                cursors[msg.partition] = msg.msg_index
                record = SeekRecord(
                    seek_id=seek_id,
                    subscription_id=sub.subscription_id,
                    msg_id=msg_id,
                    partition=msg.partition,
                    msg_index=msg.msg_index,
                    seq=seq,
                    digest=_pin(
                        "seek", seek_id, sub.subscription_id, msg_id,
                        msg.partition, msg.msg_index, seq,
                    ),
                )
                self._last_seq = seq
                self._emit(
                    KIND_SEEKED, seq,
                    seek_id=seek_id, subscription_id=sub.subscription_id,
                    msg_id=msg_id, partition=msg.partition,
                    msg_index=msg.msg_index,
                )
                return record
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def cursor(self, subscription_id: str, seq: int) -> CursorReport:
        """Pure read view of one subscription's per-partition cursors.

        Validates the seq shape but consumes nothing and writes no audit
        row.
        """
        with self._lock:
            _check_seq(seq, "seq")
            sub, cursors = self._cursor_map_locked(subscription_id)
            topic = self._topics[sub.topic_id]
            partitions: List[PartitionCursor] = []
            for partition in range(topic.partitions):
                published = len(self._messages_on_locked(sub.topic_id, partition))
                cur = cursors[partition]
                backlog = max(0, published - cur)
                partitions.append(
                    PartitionCursor(
                        partition=partition,
                        published=published,
                        cursor=cur,
                        backlog=backlog,
                    )
                )
            report = CursorReport(
                subscription_id=sub.subscription_id,
                topic_id=sub.topic_id,
                partitions=tuple(partitions),
                seq=seq,
                digest="",
            )
            return CursorReport(
                subscription_id=report.subscription_id,
                topic_id=report.topic_id,
                partitions=report.partitions,
                seq=report.seq,
                digest=_pin(
                    "cursor", report.subscription_id, report.topic_id,
                    [(p.partition, p.published, p.cursor, p.backlog)
                     for p in report.partitions],
                    report.seq,
                ),
            )

    def unsubscribe(self, subscription_id: str, seq: int, reason: str = "") -> None:
        """Terminally remove a subscription. Its cursor state is dropped."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                sub, _ = self._cursor_map_locked(subscription_id)
                if reason is not None and not isinstance(reason, str):
                    raise PulsarBrokerError("reason must be a string")
                self._subscriptions[sub.subscription_id] = SubscriptionRecord(
                    subscription_id=sub.subscription_id,
                    topic_id=sub.topic_id,
                    sub_type=sub.sub_type,
                    initial_position=sub.initial_position,
                    seq=sub.seq,
                    removed=True,
                    digest=sub.digest,
                )
                del self._cursors[sub.subscription_id]
                self._last_seq = seq
                self._emit(
                    KIND_UNSUBSCRIBED, seq,
                    subscription_id=sub.subscription_id, reason=reason or "",
                )
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    def delete_topic(self, topic_id: str, seq: int, reason: str = "") -> None:
        """Terminally delete a topic. Refused while subscriptions remain."""
        with self._lock:
            try:
                seq = self._next_seq(seq)
                topic = self._get_topic_locked(topic_id)
                if reason is not None and not isinstance(reason, str):
                    raise PulsarBrokerError("reason must be a string")
                active = [
                    sid
                    for sid, sub in self._subscriptions.items()
                    if sub.topic_id == topic_id and not sub.removed
                ]
                if active:
                    raise ActiveSubscriptionsError(
                        f"topic {topic_id!r} has active subscriptions: {active}"
                    )
                self._topics[topic_id] = TopicRecord(
                    topic_id=topic.topic_id,
                    persistence=topic.persistence,
                    tenant=topic.tenant,
                    namespace=topic.namespace,
                    name=topic.name,
                    partitions=topic.partitions,
                    seq=topic.seq,
                    deleted=True,
                    digest=topic.digest,
                )
                self._last_seq = seq
                self._emit(
                    KIND_TOPIC_DELETED, seq,
                    topic_id=topic_id, reason=reason or "",
                )
            except PulsarBrokerError as exc:
                self._last_seq = max(self._last_seq, seq)
                self._reject_locked(seq, str(exc))
                raise

    # -- views ---------------------------------------------------------------

    def topic_record(self, topic_id: str) -> TopicRecord:
        """Lookup one topic definition (raises on unknown/deleted)."""
        with self._lock:
            return self._get_topic_locked(topic_id)

    def subscription_record(self, subscription_id: str) -> SubscriptionRecord:
        """Lookup one subscription (raises on unknown/removed)."""
        with self._lock:
            sub, _ = self._cursor_map_locked(subscription_id)
            return sub

    def message_record(self, msg_id: str) -> MessageRecord:
        """Lookup one booked message."""
        with self._lock:
            msg = self._messages.get(msg_id)
            if msg is None:
                raise UnknownMessageError(f"unknown message: {msg_id!r}")
            return msg

    def topic_ids(self) -> Tuple[str, ...]:
        """Sorted ids of non-deleted topics."""
        with self._lock:
            return tuple(
                sorted(tid for tid, t in self._topics.items() if not t.deleted)
            )

    def subscription_ids(self, topic_id: Optional[str] = None) -> Tuple[str, ...]:
        """Sorted ids of active subscriptions, optionally filtered by topic."""
        with self._lock:
            ids = [
                sid
                for sid, sub in self._subscriptions.items()
                if not sub.removed
                and (topic_id is None or sub.topic_id == topic_id)
            ]
            return tuple(sorted(ids))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All booked audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> Dict[str, Any]:
        """Counts plus a digest pin (pure view)."""
        with self._lock:
            counts = {
                "topics": sum(1 for t in self._topics.values() if not t.deleted),
                "messages": len(self._messages),
                "subscriptions": sum(
                    1 for s in self._subscriptions.values() if not s.removed
                ),
                "audit_events": len(self._audit),
            }
            return {
                **counts,
                "schema": PULSAR_BROKER_SCHEMA,
                "digest": _pin("stats", counts),
            }


def main() -> None:
    """Self-check: topic, publish, subscribe, ack, cursor."""
    broker = PulsarBroker()
    digest = "sha256:" + "ab" * 32
    topic = broker.topic("t1", "persistent://public/default/orders", 1, partitions=2)
    assert topic.verify()
    m1 = broker.publish("t1", 2, digest)
    m2 = broker.publish("t1", 3, digest)
    assert m1.partition == 0 and m2.partition == 1
    assert m1.verify() and m2.verify()
    sub = broker.subscription("t1", "s1", SUB_SHARED, 4)
    assert sub.verify()
    view = broker.cursor("s1", 5)
    assert view.verify()
    assert sum(p.backlog for p in view.partitions) == 2
    ack = broker.acknowledge("s1", 6, m1.msg_id)
    assert ack.verify()
    view2 = broker.cursor("s1", 7)
    assert sum(p.backlog for p in view2.partitions) == 1
    broker.unsubscribe("s1", 8)
    assert broker.subscription_ids() == ()
    print("pulsar-broker OK: topic, publish, subscription, cursor, ack")


if __name__ == "__main__":
    main()
