"""Kafka/RabbitMQ-shaped message broker bookkeeping.

A ``MessageBroker`` books host-declared topic/partition topology and
message flow as a deterministic single-host state machine:

- ``declare_topic(topic_id, partitions, seq)`` pins a topic with a fixed
  partition count.
- ``publish(topic_id, key, payload_digest, seq, partition=None)`` books
  one message: payload *bytes* never cross this module's boundary — the
  message is booked by its ``sha256:`` digest only. Partition is chosen
  deterministically (``sha256(key)`` over the pinned count) unless the
  caller pins one; the per-partition offset is the next free offset.
- ``create_group(group_id, seq)`` pins a consumer group.
- ``consume(group_id, topic_id, seq, max_messages=10)`` returns a frozen
  ``DeliveryPage`` of the group's next unacked records per partition;
  delivery is booked so ``ack`` can commit it.
- ``ack(group_id, topic_id, seq, partition=None, offset=None)`` commits
  offsets: with no explicit target it commits every delivered-but-unacked
  offset; with ``partition``/``offset`` it commits that one point.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``message-broker.v1``,
schema pin ``northstar.message-broker.v1``, ``main()`` self-check.

Honest scope: this module books *declared* flow — it stores no payload
bytes, performs no network I/O, and cannot prove a consumer actually
received anything. A quiet ledger means "no known flow", never "no
delivery". ``consume`` delivers by committed offset, not by wire truth;
``ack`` records the host's claim that processing happened.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
MESSAGE_BROKER_VERSION = "message-broker.v1"

#: Schema pin carried by records and audit events.
MESSAGE_BROKER_SCHEMA = "northstar.message-broker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pinned partition-count bounds.
MIN_PARTITIONS = 1
MAX_PARTITIONS = 64

#: Default delivery-page size.
DEFAULT_MAX_MESSAGES = 10
MAX_DELIVERY_BATCH = 1000


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class MessageBrokerError(ValueError):
    """Base for all message-broker structural problems and refused transitions."""


class BadTopicError(MessageBrokerError):
    """Topic declaration is malformed (bad id, partition count)."""


class DuplicateTopicError(MessageBrokerError):
    """A topic id is already declared."""


class UnknownTopicError(MessageBrokerError):
    """No topic is declared for the requested id."""


class BadMessageError(MessageBrokerError):
    """A publish request is malformed (bad key, digest, partition)."""


class BadGroupError(MessageBrokerError):
    """A consumer-group id is malformed."""


class DuplicateGroupError(MessageBrokerError):
    """A consumer-group id is already registered."""


class UnknownGroupError(MessageBrokerError):
    """No consumer group is registered for the requested id."""


class BadAckError(MessageBrokerError):
    """An ack request is malformed (bad partition, offset, nothing to commit)."""


class SeqOrderError(MessageBrokerError):
    """Caller seq did not strictly increase."""


class AuditKindError(MessageBrokerError):
    """Unknown audit-event kind."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MessageBrokerError(f"{name} must be a non-empty string")
    return value.strip()


def _check_partitions(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTopicError("partitions must be an int")
    if not MIN_PARTITIONS <= value <= MAX_PARTITIONS:
        raise BadTopicError(
            f"partitions must be in [{MIN_PARTITIONS}, {MAX_PARTITIONS}]"
        )
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadMessageError(f"{name} must be a sha256: digest")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadMessageError(f"{name} must be sha256: + 64 hex chars")
    return value


def _check_offset(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadAckError(f"{name} must be a non-negative int")
    return value


def _check_max(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MessageBrokerError("max_messages must be an int")
    if value < 1 or value > MAX_DELIVERY_BATCH:
        raise MessageBrokerError(
            f"max_messages must be in [1, {MAX_DELIVERY_BATCH}]"
        )
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([MESSAGE_BROKER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _default_partition(key: str, partitions: int) -> int:
    """Deterministic key -> partition mapping."""
    return (
        int(hashlib.sha256(jcs_canonical_json(["partition", key])).hexdigest(), 16)
        % partitions
    )


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TopicRecord:
    """One declared topic (frozen)."""

    topic_id: str
    partitions: int
    seq: int
    digest: str
    schema: str = MESSAGE_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("topic", self.topic_id, self.partitions, self.seq)


@dataclass(frozen=True)
class ConsumerGroupRecord:
    """One registered consumer group (frozen)."""

    group_id: str
    seq: int
    digest: str
    schema: str = MESSAGE_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("group", self.group_id, self.seq)


@dataclass(frozen=True)
class MessageRecord:
    """One published message (frozen). Payload bytes never enter the record."""

    message_id: str
    topic_id: str
    partition: int
    offset: int
    payload_digest: str
    seq: int
    digest: str
    schema: str = MESSAGE_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "message", self.message_id, self.topic_id, self.partition,
            self.offset, self.payload_digest, self.seq,
        )


@dataclass(frozen=True)
class DeliveryRecord:
    """One delivered record inside a delivery page (frozen)."""

    message_id: str
    topic_id: str
    partition: int
    offset: int
    payload_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "delivery", self.message_id, self.topic_id, self.partition,
            self.offset, self.payload_digest,
        )


@dataclass(frozen=True)
class DeliveryPage:
    """One consume result (frozen): the group's next unacked records."""

    group_id: str
    topic_id: str
    deliveries: Tuple[DeliveryRecord, ...]
    seq: int
    digest: str
    schema: str = MESSAGE_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deliveries", self.group_id, self.topic_id,
            [d.digest for d in self.deliveries], self.seq,
        )


@dataclass(frozen=True)
class CommitRecord:
    """One committed-offset ack (frozen)."""

    group_id: str
    topic_id: str
    committed: Tuple[Tuple[int, int], ...]  # (partition, offset) pairs, sorted
    seq: int
    digest: str
    schema: str = MESSAGE_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "commit", self.group_id, self.topic_id,
            [list(pair) for pair in self.committed], self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_TOPIC_DECLARED = "message-broker.topic-declared"
KIND_GROUP_CREATED = "message-broker.group-created"
KIND_PUBLISHED = "message-broker.published"
KIND_CONSUMED = "message-broker.consumed"
KIND_ACKED = "message-broker.acked"
KIND_REJECTED = "message-broker.rejected"
_KINDS = (
    KIND_TOPIC_DECLARED, KIND_GROUP_CREATED, KIND_PUBLISHED,
    KIND_CONSUMED, KIND_ACKED, KIND_REJECTED,
)

#: Keys banned from crossing the audit boundary (ids + digest pins only).
_BANNED_AUDIT_KEYS = {"key", "payload", "payload_bytes", "body", "value"}


def message_broker_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the message-broker module."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise MessageBrokerError("detail must be a mapping")
    if any(k in detail for k in _BANNED_AUDIT_KEYS):
        raise MessageBrokerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": MESSAGE_BROKER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class MessageBroker:
    """Deterministic publish/consume/ack bookkeeping (single-host ledger).

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._topics: Dict[str, TopicRecord] = {}
        self._groups: Dict[str, ConsumerGroupRecord] = {}
        self._messages: Dict[str, MessageRecord] = {}
        self._by_partition: Dict[Tuple[str, int], List[str]] = {}
        self._next_offset: Dict[Tuple[str, int], int] = {}
        self._committed: Dict[Tuple[str, str, int], int] = {}
        self._delivered: Dict[Tuple[str, str, int], int] = {}
        self._msg_counter: int = 0
        self._audit: List[Dict[str, Any]] = []
        self._prev_digest: str = _GENESIS

    # -- internal ------------------------------------------------------

    def _touch_seq(self, seq: int) -> None:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq

    def _emit(self, kind: str, detail: Dict[str, Any], seq: int) -> None:
        record = message_broker_audit_event(kind, detail, seq)
        record["prev_digest"] = self._prev_digest
        self._prev_digest = _pin("audit", kind, sorted(detail.items()), seq)
        self._audit.append(record)

    def _reject_locked(self, reason: str, seq: int) -> None:
        self._emit(KIND_REJECTED, {"reason": reason}, seq)

    # -- topics --------------------------------------------------------

    def declare_topic(self, topic_id: str, partitions: int, seq: int) -> TopicRecord:
        """Pin a topic with a fixed partition count."""
        with self._lock:
            self._touch_seq(seq)
            try:
                tid = _check_nonempty_str(topic_id, "topic_id")
                nparts = _check_partitions(partitions)
                if tid in self._topics:
                    raise DuplicateTopicError(f"topic already declared: {tid!r}")
                record = TopicRecord(
                    topic_id=tid, partitions=nparts, seq=seq,
                    digest=_pin("topic", tid, nparts, seq),
                )
            except (MessageBrokerError, SeqOrderError) as exc:
                self._reject_locked(str(exc), seq)
                raise
            self._topics[tid] = record
            for p in range(nparts):
                self._next_offset[(tid, p)] = 0
            self._emit(
                KIND_TOPIC_DECLARED,
                {"topic_id": tid, "partitions": nparts},
                seq,
            )
            return record

    def topic(self, topic_id: str) -> TopicRecord:
        with self._lock:
            tid = _check_nonempty_str(topic_id, "topic_id")
            try:
                return self._topics[tid]
            except KeyError:
                raise UnknownTopicError(f"unknown topic: {tid!r}")

    def topic_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._topics))

    # -- groups --------------------------------------------------------

    def create_group(self, group_id: str, seq: int) -> ConsumerGroupRecord:
        """Register a consumer group."""
        with self._lock:
            self._touch_seq(seq)
            try:
                gid = _check_nonempty_str(group_id, "group_id")
            except MessageBrokerError as exc:
                raise BadGroupError(str(exc))
            try:
                if gid in self._groups:
                    raise DuplicateGroupError(f"group already exists: {gid!r}")
                record = ConsumerGroupRecord(
                    group_id=gid, seq=seq, digest=_pin("group", gid, seq)
                )
            except MessageBrokerError as exc:
                self._reject_locked(str(exc), seq)
                raise
            self._groups[gid] = record
            self._emit(KIND_GROUP_CREATED, {"group_id": gid}, seq)
            return record

    def group(self, group_id: str) -> ConsumerGroupRecord:
        with self._lock:
            gid = _check_nonempty_str(group_id, "group_id")
            try:
                return self._groups[gid]
            except KeyError:
                raise UnknownGroupError(f"unknown group: {gid!r}")

    def group_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._groups))

    # -- publish -------------------------------------------------------

    def publish(
        self,
        topic_id: str,
        key: str,
        payload_digest: str,
        seq: int,
        partition: Optional[int] = None,
    ) -> MessageRecord:
        """Book one message; payload bytes never enter the record."""
        with self._lock:
            self._touch_seq(seq)
            try:
                trec = self.topic(topic_id)
                k = _check_nonempty_str(key, "key")
                pd = _check_digest(payload_digest, "payload_digest")
                if partition is None:
                    part = _default_partition(k, trec.partitions)
                else:
                    if (
                        isinstance(partition, bool)
                        or not isinstance(partition, int)
                        or not 0 <= partition < trec.partitions
                    ):
                        raise BadMessageError(
                            "partition out of range for topic"
                        )
                    part = partition
                self._msg_counter += 1
                mid = f"msg-{self._msg_counter}"
                offset = self._next_offset[(trec.topic_id, part)]
                record = MessageRecord(
                    message_id=mid,
                    topic_id=trec.topic_id,
                    partition=part,
                    offset=offset,
                    payload_digest=pd,
                    seq=seq,
                    digest=_pin(
                        "message", mid, trec.topic_id, part, offset, pd, seq
                    ),
                )
            except (MessageBrokerError, SeqOrderError) as exc:
                self._reject_locked(str(exc), seq)
                raise
            self._messages[mid] = record
            self._by_partition.setdefault((trec.topic_id, part), []).append(mid)
            self._next_offset[(trec.topic_id, part)] = offset + 1
            self._emit(
                KIND_PUBLISHED,
                {
                    "message_id": mid,
                    "topic_id": trec.topic_id,
                    "partition": part,
                    "offset": offset,
                    "payload_digest": pd,
                },
                seq,
            )
            return record

    def message(self, message_id: str) -> MessageRecord:
        with self._lock:
            mid = _check_nonempty_str(message_id, "message_id")
            try:
                return self._messages[mid]
            except KeyError:
                raise BadMessageError(f"unknown message: {mid!r}")

    # -- consume --------------------------------------------------------

    def _partition_messages(self, topic_id: str, part: int) -> List[str]:
        return self._by_partition.get((topic_id, part), [])

    def consume(
        self,
        group_id: str,
        topic_id: str,
        seq: int,
        max_messages: int = DEFAULT_MAX_MESSAGES,
    ) -> DeliveryPage:
        """Deliver the group's next unacked records (books the delivery)."""
        with self._lock:
            self._touch_seq(seq)
            try:
                grec = self.group(group_id)
                trec = self.topic(topic_id)
                n = _check_max(max_messages)
                deliveries: List[DeliveryRecord] = []
                for part in range(trec.partitions):
                    if len(deliveries) >= n:
                        break
                    mids = self._partition_messages(trec.topic_id, part)
                    start = self._committed.get(
                        (grec.group_id, trec.topic_id, part), 0
                    )
                    for mid in mids[start : start + (n - len(deliveries))]:
                        mrec = self._messages[mid]
                        drec = DeliveryRecord(
                            message_id=mrec.message_id,
                            topic_id=mrec.topic_id,
                            partition=mrec.partition,
                            offset=mrec.offset,
                            payload_digest=mrec.payload_digest,
                            digest=_pin(
                                "delivery", mrec.message_id, mrec.topic_id,
                                mrec.partition, mrec.offset, mrec.payload_digest,
                            ),
                        )
                        deliveries.append(drec)
                        key = (grec.group_id, trec.topic_id, part)
                        self._delivered[key] = max(
                            self._delivered.get(key, -1), mrec.offset
                        )
            except (MessageBrokerError, SeqOrderError) as exc:
                self._reject_locked(str(exc), seq)
                raise
            page = DeliveryPage(
                group_id=grec.group_id,
                topic_id=trec.topic_id,
                deliveries=tuple(deliveries),
                seq=seq,
                digest=_pin(
                    "deliveries", grec.group_id, trec.topic_id,
                    [d.digest for d in deliveries], seq,
                ),
            )
            self._emit(
                KIND_CONSUMED,
                {
                    "group_id": grec.group_id,
                    "topic_id": trec.topic_id,
                    "delivered": len(deliveries),
                },
                seq,
            )
            return page

    # -- ack --------------------------------------------------------------

    def ack(
        self,
        group_id: str,
        topic_id: str,
        seq: int,
        partition: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> CommitRecord:
        """Commit offsets for a group/topic (explicit point or all delivered)."""
        with self._lock:
            self._touch_seq(seq)
            try:
                grec = self.group(group_id)
                trec = self.topic(topic_id)
                committed: List[Tuple[int, int]] = []
                if partition is None and offset is None:
                    for part in range(trec.partitions):
                        key = (grec.group_id, trec.topic_id, part)
                        if key in self._delivered:
                            new_off = self._delivered[key] + 1
                            self._committed[key] = new_off
                            committed.append((part, new_off))
                elif partition is not None and offset is not None:
                    if (
                        isinstance(partition, bool)
                        or not isinstance(partition, int)
                        or not 0 <= partition < trec.partitions
                    ):
                        raise BadAckError("partition out of range for topic")
                    off = _check_offset(offset, "offset")
                    key = (grec.group_id, trec.topic_id, partition)
                    available = self._next_offset.get(
                        (trec.topic_id, partition), 0
                    )
                    if off > available:
                        raise BadAckError("offset beyond published records")
                    current = self._committed.get(key, 0)
                    if off < current:
                        raise BadAckError("offset already committed (rewind)")
                    self._committed[key] = off
                    if self._delivered.get(key, -1) >= off:
                        del self._delivered[key]
                    committed.append((partition, off))
                else:
                    raise BadAckError(
                        "partition and offset must be given together"
                    )
                if not committed:
                    raise BadAckError("nothing to ack")
                committed_t = tuple(sorted(committed))
                record = CommitRecord(
                    group_id=grec.group_id,
                    topic_id=trec.topic_id,
                    committed=committed_t,
                    seq=seq,
                    digest=_pin(
                        "commit", grec.group_id, trec.topic_id,
                        [list(pair) for pair in committed_t], seq,
                    ),
                )
            except (MessageBrokerError, SeqOrderError) as exc:
                self._reject_locked(str(exc), seq)
                raise
            self._emit(
                KIND_ACKED,
                {
                    "group_id": grec.group_id,
                    "topic_id": trec.topic_id,
                    "committed": [list(pair) for pair in committed_t],
                },
                seq,
            )
            return record

    # -- views ------------------------------------------------------------

    def committed_offset(self, group_id: str, topic_id: str, partition: int) -> int:
        """Pure view of a group's committed offset (no seq consumed)."""
        with self._lock:
            grec = self.group(group_id)
            trec = self.topic(topic_id)
            if not 0 <= partition < trec.partitions:
                raise BadAckError("partition out of range for topic")
            return self._committed.get(
                (grec.group_id, trec.topic_id, partition), 0
            )

    def pending(self, group_id: str, topic_id: str) -> int:
        """Pure view: unacked records for a group/topic (no seq consumed)."""
        with self._lock:
            grec = self.group(group_id)
            trec = self.topic(topic_id)
            total = 0
            for part in range(trec.partitions):
                published = len(self._partition_messages(trec.topic_id, part))
                committed = self._committed.get(
                    (grec.group_id, trec.topic_id, part), 0
                )
                total += max(0, published - committed)
            return total

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "topics": len(self._topics),
                "groups": len(self._groups),
                "messages": len(self._messages),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": MESSAGE_BROKER_VERSION,
                "schema": MESSAGE_BROKER_SCHEMA,
                "topics": [t.topic_id for t in self._topics.values()],
                "groups": [g.group_id for g in self._groups.values()],
                "stats": self.stats(),
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: declare, publish, consume, ack."""
    broker = MessageBroker()
    seq = 0

    def nxt() -> int:
        nonlocal seq
        seq += 1
        return seq

    trec = broker.declare_topic("orders", 3, nxt())
    assert trec.verify()
    grec = broker.create_group("billing", nxt())
    assert grec.verify()

    pd = "sha256:" + "a" * 64
    m1 = broker.publish("orders", "order-1", pd, nxt())
    m2 = broker.publish("orders", "order-2", pd, nxt())
    assert m1.verify() and m2.verify()

    page = broker.consume("billing", "orders", nxt())
    assert page.verify()
    assert len(page.deliveries) == 2
    assert [d.message_id for d in page.deliveries] == [m1.message_id, m2.message_id]

    commit = broker.ack("billing", "orders", nxt())
    assert commit.verify()
    assert broker.pending("billing", "orders") == 0

    page2 = broker.consume("billing", "orders", nxt())
    assert len(page2.deliveries) == 0

    # Duplicate topic refused; unknown group refused.
    for bad in (
        lambda: broker.declare_topic("orders", 1, nxt()),
        lambda: broker.consume("nope", "orders", nxt()),
    ):
        try:
            bad()
        except MessageBrokerError:
            pass
        else:
            raise AssertionError("expected refusal")

    print("message-broker OK: declare, publish, consume, ack, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
