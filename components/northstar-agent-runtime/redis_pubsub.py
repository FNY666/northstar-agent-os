"""Redis Pub/Sub interface (channel publish/subscribe bookkeeping, simulated).

Research motivation: Redis Pub/Sub is the canonical fire-and-forget
message bus -- producers ``PUBLISH`` to named channels without knowing
who listens; consumers ``SUBSCRIBE`` to channels or ``PSUBSCRIBE`` to
glob patterns and receive every message published while they are
attached. No persistence, no acknowledgements, no replay: a message
published to a channel with zero subscribers is dropped on the floor.
That at-most-once, zero-retention shape is exactly what an agent
runtime wants for ephemeral fan-out (presence heartbeats, cache
invalidations, task-progress broadcasts) where a durable queue would
be the wrong tool.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's pub/sub plumbing speaks one dialect:

- ``RedisPubSub`` -- owns the channel/pattern registry. ``subscribe()``
  attaches a client to a channel; ``psubscribe()`` attaches a client to
  a glob pattern; ``publish()`` books a message and fans it out to
  every matching subscriber *as data* (see delivery semantics below);
  ``unsubscribe()`` / ``punsubscribe()`` detach.
- ``redis_pubsub_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``subscribed`` / ``unsubscribed`` / ``pattern-subscribed`` /
  ``pattern-unsubscribed`` / ``published`` / ``delivered`` /
  ``rejected``); caller-supplied seqs only. Raw payloads never cross
  the audit boundary -- pins only.

Channel and pattern language (pinned subset of Redis):

- Channel names are non-empty strings, lowercased, no whitespace or
  control characters, at most 256 chars, and must not contain ``*``,
  ``?``, ``[``, ``]`` or ``\\`` (those are pattern metacharacters).
- Patterns are non-empty strings over literals plus two wildcards:
  ``*`` matches any run of characters (including empty), ``?`` matches
  exactly one character. ``[seq]`` character classes and backslash
  escapes are *refused* fail-closed -- the module pins a two-wildcard
  subset rather than guessing at the rest of the glob grammar.
- A pattern consisting only of ``*`` matches every channel.

Delivery semantics (Redis-faithful):

- ``publish()`` performs exactly one fan-out pass. Receivers are the
  direct subscribers of the channel *plus* every client whose pattern
  subscription matches the channel.
- A client holding both a direct subscription *and* a matching pattern
  subscription receives the message *twice* -- once as a channel
  delivery and once as a pattern delivery. This mirrors real Redis
  (``message`` vs ``pmessage`` replies); each delivery is booked as a
  separate frozen ``DeliveryRecord``.
- A publish to a channel with no subscribers is booked as a message
  with zero deliveries (Redis drops it; the ledger books the attempt).
- Deliveries are *data*: the ledger records that a delivery was
  booked, never that bytes reached a socket. The host declares wire
  truth; the honest-scope boundary below applies.

Fail-closed edges (fail loudly, never guess):

- ``client_id`` / ``channel`` / ``pattern`` must be non-empty ``str``;
  duplicate subscriptions are refused (history is never silently
  overwritten). ``unsubscribe()`` / ``punsubscribe()`` on a
  non-existent subscription raise ``UnknownSubscriptionError`` /
  ``UnknownPatternError``.
- Payloads must be ``str``, ``bytes``, or a JSON-canonicalizable
  mapping/list; NaN/inf floats, non-str mapping keys, and integers
  with ``abs(n) >= 2**53`` are refused (the batch-5 JCS discipline).
  Payload bytes enter in-memory records (this is a message bus, not an
  audit sink) but *never* cross the audit boundary -- audit rows carry
  ids and ``sha256:`` digest pins only.
- Mutation seqs are ints (not bool) and must strictly increase across
  the whole ``RedisPubSub`` instance; failed mutations consume their
  seq (the batch-21 ledger discipline). Views validate the seq shape
  but do not consume it and write no audit rows.
- Message ids (``msg-N``) and delivery ids (``del-N``) are monotonic
  and never recycled.

Honest scope:

- This module books *host-reported* pub/sub decisions. It cannot prove
  a published message reflects a real event, that a subscriber really
  received bytes, or that a pattern match corresponds to a genuine
  interest -- the ledger records what the host *declared*.
- In-memory only: pair with the durable audit writer if pub/sub
  records must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
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
REDIS_PUBSUB_VERSION = "redis-pubsub.v1"

#: Schema pin carried by records and audit events.
REDIS_PUBSUB_SCHEMA = "northstar.redis-pubsub.v1"

#: Schema pin for audit.ndjson/1 rows emitted by this module.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Max channel / pattern length, in characters.
MAX_NAME_LEN = 256

#: Metacharacters that may only appear in patterns, never channels.
_PATTERN_CHARS = frozenset("*?[]\\")


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class RedisPubSubError(Exception):
    """Base class for all redis-pubsub errors."""


class BadChannelError(RedisPubSubError):
    """Channel name failed validation."""


class BadPatternError(RedisPubSubError):
    """Pattern failed validation."""


class BadPayloadError(RedisPubSubError):
    """Payload failed validation."""


class DuplicateSubscriptionError(RedisPubSubError):
    """Client already subscribed to this channel."""


class UnknownSubscriptionError(RedisPubSubError):
    """No such (client, channel) subscription."""


class DuplicatePatternError(RedisPubSubError):
    """Client already pattern-subscribed to this pattern."""


class UnknownPatternError(RedisPubSubError):
    """No such (client, pattern) pattern subscription."""


class SeqOrderError(RedisPubSubError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be an int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RedisPubSubError(f"{name} must be a non-empty string")
    return value.strip()


def _check_channel(value: Any) -> str:
    name = _check_nonempty_str(value, "channel").lower()
    if len(name) > MAX_NAME_LEN:
        raise BadChannelError(f"channel too long (>{MAX_NAME_LEN})")
    if any(c.isspace() or ord(c) < 0x20 for c in name):
        raise BadChannelError("channel must not contain whitespace/control chars")
    if any(c in _PATTERN_CHARS for c in name):
        raise BadChannelError("channel must not contain pattern metacharacters")
    return name


def _check_pattern(value: Any) -> str:
    pat = _check_nonempty_str(value, "pattern").lower()
    if len(pat) > MAX_NAME_LEN:
        raise BadPatternError(f"pattern too long (>{MAX_NAME_LEN})")
    if any(c.isspace() or ord(c) < 0x20 for c in pat):
        raise BadPatternError("pattern must not contain whitespace/control chars")
    for c in pat:
        if c in "[]\\":
            raise BadPatternError(
                "only '*' and '?' wildcards are supported; "
                f"character classes/escapes refused (saw {c!r})"
            )
    return pat


def _canonical_payload(payload: Any) -> bytes:
    """Return canonical bytes for a payload, fail-closed on bad input."""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, Mapping):
        for k in payload.keys():
            if not isinstance(k, str):
                raise BadPayloadError("mapping payload keys must be strings")
        _reject_unsafe(payload)
        return jcs_canonical_json(payload)
    if isinstance(payload, (list, tuple)):
        _reject_unsafe(payload)
        return jcs_canonical_json(list(payload))
    raise BadPayloadError(
        "payload must be str, bytes, or a JSON-canonicalizable mapping/list"
    )


def _reject_unsafe(obj: Any) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if abs(obj) >= 2**53:
            raise BadPayloadError("integer payload out of safe range (|n| >= 2**53)")
        return
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise BadPayloadError("NaN/inf payload refused")
        return
    if isinstance(obj, Mapping):
        for v in obj.values():
            _reject_unsafe(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_unsafe(v)


def _pin(*parts: Any) -> str:
    digest = jcs_sha256_hex([REDIS_PUBSUB_VERSION, *parts])
    return f"sha256:{digest}"


def _glob_match(pattern: str, channel: str) -> bool:
    """Two-wildcard glob match: ``*`` any run, ``?`` exactly one char."""
    # Dynamic programming over (pattern idx, channel idx).
    plen, clen = len(pattern), len(channel)
    prev = [False] * (clen + 1)
    prev[0] = True
    for p in pattern:
        cur = [False] * (clen + 1)
        if p == "*":
            # '*' extends any reachable prefix to the right.
            acc = prev[0]
            cur[0] = acc
            for j in range(1, clen + 1):
                acc = acc or prev[j]
                cur[j] = acc
        elif p == "?":
            for j in range(1, clen + 1):
                cur[j] = prev[j - 1]
        else:
            for j in range(1, clen + 1):
                cur[j] = prev[j - 1] and channel[j - 1] == p
        prev = cur
    return prev[clen]


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubscriptionRecord:
    """One (client, channel) subscription (frozen)."""

    client_id: str
    channel: str
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "subscribe", self.client_id, self.channel, self.seq
        )


@dataclass(frozen=True)
class PatternSubscriptionRecord:
    """One (client, pattern) pattern subscription (frozen)."""

    client_id: str
    pattern: str
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "psubscribe", self.client_id, self.pattern, self.seq
        )


@dataclass(frozen=True)
class UnsubscribeRecord:
    """One terminal unsubscribe (frozen). The id is retired."""

    client_id: str
    channel: str
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "unsubscribe", self.client_id, self.channel, self.seq
        )


@dataclass(frozen=True)
class PunsubscribeRecord:
    """One terminal pattern-unsubscribe (frozen). The id is retired."""

    client_id: str
    pattern: str
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "punsubscribe", self.client_id, self.pattern, self.seq
        )


@dataclass(frozen=True)
class MessageRecord:
    """One published message (frozen). Payload digest-pinned."""

    message_id: str
    channel: str
    payload_digest: str
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "publish", self.message_id, self.channel,
            self.payload_digest, self.seq,
        )


@dataclass(frozen=True)
class DeliveryRecord:
    """One booked delivery to a subscriber (frozen). Delivery is data."""

    delivery_id: str
    message_id: str
    client_id: str
    channel: str
    kind: str  # "channel" | "pattern"
    pattern: str  # "" for direct channel deliveries
    seq: int
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deliver", self.delivery_id, self.message_id, self.client_id,
            self.channel, self.kind, self.pattern, self.seq,
        )


@dataclass(frozen=True)
class PublishReport:
    """Result of a publish fan-out (data, not a mutation)."""

    message_id: str
    channel: str
    channel_deliveries: int
    pattern_deliveries: int
    receivers: Tuple[str, ...]
    digest: str
    schema: str = REDIS_PUBSUB_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "publish-report", self.message_id, self.channel,
            self.channel_deliveries, self.pattern_deliveries,
            list(self.receivers),
        )

    @property
    def total_deliveries(self) -> int:
        return self.channel_deliveries + self.pattern_deliveries


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SUBSCRIBED = "redis-pubsub.subscribed"
KIND_UNSUBSCRIBED = "redis-pubsub.unsubscribed"
KIND_PATTERN_SUBSCRIBED = "redis-pubsub.pattern-subscribed"
KIND_PATTERN_UNSUBSCRIBED = "redis-pubsub.pattern-unsubscribed"
KIND_PUBLISHED = "redis-pubsub.published"
KIND_DELIVERED = "redis-pubsub.delivered"
KIND_REJECTED = "redis-pubsub.rejected"
_KINDS = (
    KIND_SUBSCRIBED, KIND_UNSUBSCRIBED, KIND_PATTERN_SUBSCRIBED,
    KIND_PATTERN_UNSUBSCRIBED, KIND_PUBLISHED, KIND_DELIVERED,
    KIND_REJECTED,
)


def redis_pubsub_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the redis-pubsub module."""
    if kind not in _KINDS:
        raise RedisPubSubError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise RedisPubSubError("detail must be a mapping")
    # Payloads never cross the audit boundary; pins only.
    banned = {"payload", "message", "body", "data"}
    if any(k in detail for k in banned):
        raise RedisPubSubError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": REDIS_PUBSUB_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class RedisPubSub:
    """Deterministic Redis-style pub/sub bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._msg_counter = 0
        self._del_counter = 0
        # (client_id, channel) -> SubscriptionRecord
        self._subs: Dict[Tuple[str, str], SubscriptionRecord] = {}
        # (client_id, pattern) -> PatternSubscriptionRecord
        self._psubs: Dict[Tuple[str, str], PatternSubscriptionRecord] = {}
        # message_id -> (MessageRecord, canonical payload bytes)
        self._messages: Dict[str, Tuple[MessageRecord, bytes]] = {}
        # delivery_id -> DeliveryRecord
        self._deliveries: Dict[str, DeliveryRecord] = {}
        # client_id -> [delivery_id, ...] in booking order
        self._inbox: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        self._seq = seq
        return seq

    def _reject_locked(self, seq: int, reason: str) -> None:
        try:
            self._seq_check_only(seq)
        except SeqOrderError:
            pass
        else:
            if seq > self._seq:
                self._seq = seq
        self._audit.append(
            redis_pubsub_audit_event(
                KIND_REJECTED, {"reason": reason}, self._seq
            )
        )

    def _seq_check_only(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(redis_pubsub_audit_event(kind, detail, seq))

    # -- subscriptions --------------------------------------------------

    def subscribe(self, client_id: str, channel: str, seq: int) -> SubscriptionRecord:
        """Attach ``client_id`` to ``channel`` (fail-closed on duplicates)."""
        with self._lock:
            try:
                cid = _check_nonempty_str(client_id, "client_id")
                ch = _check_channel(channel)
                self._next_seq(seq)
            except RedisPubSubError as exc:
                self._reject_locked(seq, type(exc).__name__)
                raise
            key = (cid, ch)
            if key in self._subs:
                self._reject_locked(seq, "DuplicateSubscriptionError")
                raise DuplicateSubscriptionError(
                    f"client {cid!r} already subscribed to {ch!r}"
                )
            rec = SubscriptionRecord(
                client_id=cid, channel=ch, seq=seq,
                digest=_pin("subscribe", cid, ch, seq),
            )
            self._subs[key] = rec
            self._emit(
                KIND_SUBSCRIBED,
                {"client_id": cid, "channel": ch,
                 "digest": rec.digest},
                seq,
            )
            return rec

    def unsubscribe(self, client_id: str, channel: str, seq: int) -> UnsubscribeRecord:
        """Detach ``client_id`` from ``channel`` (terminal for the id)."""
        with self._lock:
            try:
                cid = _check_nonempty_str(client_id, "client_id")
                ch = _check_channel(channel)
                self._next_seq(seq)
            except RedisPubSubError as exc:
                self._reject_locked(seq, type(exc).__name__)
                raise
            key = (cid, ch)
            if key not in self._subs:
                self._reject_locked(seq, "UnknownSubscriptionError")
                raise UnknownSubscriptionError(
                    f"no subscription for client {cid!r} on {ch!r}"
                )
            del self._subs[key]
            rec = UnsubscribeRecord(
                client_id=cid, channel=ch, seq=seq,
                digest=_pin("unsubscribe", cid, ch, seq),
            )
            self._emit(
                KIND_UNSUBSCRIBED,
                {"client_id": cid, "channel": ch,
                 "digest": rec.digest},
                seq,
            )
            return rec

    def psubscribe(self, client_id: str, pattern: str, seq: int) -> PatternSubscriptionRecord:
        """Attach ``client_id`` to a glob ``pattern`` (``*`` / ``?`` only)."""
        with self._lock:
            try:
                cid = _check_nonempty_str(client_id, "client_id")
                pat = _check_pattern(pattern)
                self._next_seq(seq)
            except RedisPubSubError as exc:
                self._reject_locked(seq, type(exc).__name__)
                raise
            key = (cid, pat)
            if key in self._psubs:
                self._reject_locked(seq, "DuplicatePatternError")
                raise DuplicatePatternError(
                    f"client {cid!r} already pattern-subscribed to {pat!r}"
                )
            rec = PatternSubscriptionRecord(
                client_id=cid, pattern=pat, seq=seq,
                digest=_pin("psubscribe", cid, pat, seq),
            )
            self._psubs[key] = rec
            self._emit(
                KIND_PATTERN_SUBSCRIBED,
                {"client_id": cid, "pattern": pat,
                 "digest": rec.digest},
                seq,
            )
            return rec

    def punsubscribe(self, client_id: str, pattern: str, seq: int) -> PunsubscribeRecord:
        """Detach ``client_id`` from a glob ``pattern`` (terminal)."""
        with self._lock:
            try:
                cid = _check_nonempty_str(client_id, "client_id")
                pat = _check_pattern(pattern)
                self._next_seq(seq)
            except RedisPubSubError as exc:
                self._reject_locked(seq, type(exc).__name__)
                raise
            key = (cid, pat)
            if key not in self._psubs:
                self._reject_locked(seq, "UnknownPatternError")
                raise UnknownPatternError(
                    f"no pattern subscription for client {cid!r} on {pat!r}"
                )
            del self._psubs[key]
            rec = PunsubscribeRecord(
                client_id=cid, pattern=pat, seq=seq,
                digest=_pin("punsubscribe", cid, pat, seq),
            )
            self._emit(
                KIND_PATTERN_UNSUBSCRIBED,
                {"client_id": cid, "pattern": pat,
                 "digest": rec.digest},
                seq,
            )
            return rec

    # -- publish ----------------------------------------------------------

    def publish(self, channel: str, payload: Any, seq: int) -> PublishReport:
        """Book a message on ``channel`` and fan out to subscribers.

        Returns a frozen :class:`PublishReport` (data): direct
        subscribers receive one channel delivery each; clients whose
        pattern subscriptions match receive one pattern delivery per
        matching pattern -- a client holding both gets the message
        twice, Redis-faithfully.
        """
        with self._lock:
            try:
                ch = _check_channel(channel)
                canon = _canonical_payload(payload)
                self._next_seq(seq)
            except RedisPubSubError as exc:
                self._reject_locked(seq, type(exc).__name__)
                raise
            self._msg_counter += 1
            msg_id = f"msg-{self._msg_counter}"
            payload_digest = _pin("payload", canon.decode("utf-8", "replace"))
            msg = MessageRecord(
                message_id=msg_id, channel=ch,
                payload_digest=payload_digest, seq=seq,
                digest=_pin("publish", msg_id, ch, payload_digest, seq),
            )
            self._messages[msg_id] = (msg, canon)
            self._emit(
                KIND_PUBLISHED,
                {"message_id": msg_id, "channel": ch,
                 "payload_digest": payload_digest, "digest": msg.digest},
                seq,
            )
            channel_hits = 0
            pattern_hits = 0
            receivers: List[str] = []
            # Direct channel subscribers (sorted for determinism).
            for (cid, c), _sub in sorted(self._subs.items()):
                if c != ch:
                    continue
                self._del_counter += 1
                del_id = f"del-{self._del_counter}"
                rec = DeliveryRecord(
                    delivery_id=del_id, message_id=msg_id,
                    client_id=cid, channel=ch, kind="channel",
                    pattern="", seq=seq,
                    digest=_pin("deliver", del_id, msg_id, cid, ch,
                                "channel", "", seq),
                )
                self._deliveries[del_id] = rec
                self._inbox.setdefault(cid, []).append(del_id)
                receivers.append(cid)
                channel_hits += 1
                self._emit(
                    KIND_DELIVERED,
                    {"delivery_id": del_id, "message_id": msg_id,
                     "client_id": cid, "kind": "channel",
                     "digest": rec.digest},
                    seq,
                )
            # Pattern subscribers (sorted for determinism).
            for (cid, pat), _psub in sorted(self._psubs.items()):
                if not _glob_match(pat, ch):
                    continue
                self._del_counter += 1
                del_id = f"del-{self._del_counter}"
                rec = DeliveryRecord(
                    delivery_id=del_id, message_id=msg_id,
                    client_id=cid, channel=ch, kind="pattern",
                    pattern=pat, seq=seq,
                    digest=_pin("deliver", del_id, msg_id, cid, ch,
                                "pattern", pat, seq),
                )
                self._deliveries[del_id] = rec
                self._inbox.setdefault(cid, []).append(del_id)
                receivers.append(cid)
                pattern_hits += 1
                self._emit(
                    KIND_DELIVERED,
                    {"delivery_id": del_id, "message_id": msg_id,
                     "client_id": cid, "kind": "pattern",
                     "pattern": pat, "digest": rec.digest},
                    seq,
                )
            report = PublishReport(
                message_id=msg_id, channel=ch,
                channel_deliveries=channel_hits,
                pattern_deliveries=pattern_hits,
                receivers=tuple(receivers),
                digest=_pin("publish-report", msg_id, ch, channel_hits,
                            pattern_hits, receivers),
            )
            assert report.verify()
            return report

    # -- views (pure reads: validate seq, consume nothing) -----------------

    def subscription(self, client_id: str, channel: str, seq: int) -> SubscriptionRecord:
        with self._lock:
            _check_seq(seq)
            cid = _check_nonempty_str(client_id, "client_id")
            ch = _check_channel(channel)
            key = (cid, ch)
            if key not in self._subs:
                raise UnknownSubscriptionError(
                    f"no subscription for client {cid!r} on {ch!r}"
                )
            return self._subs[key]

    def subscriptions_for(self, client_id: str, seq: int) -> Tuple[str, ...]:
        """Sorted channels ``client_id`` is directly subscribed to."""
        with self._lock:
            _check_seq(seq)
            cid = _check_nonempty_str(client_id, "client_id")
            return tuple(sorted(c for (c_id, c) in self._subs if c_id == cid))

    def patterns_for(self, client_id: str, seq: int) -> Tuple[str, ...]:
        """Sorted patterns ``client_id`` is pattern-subscribed to."""
        with self._lock:
            _check_seq(seq)
            cid = _check_nonempty_str(client_id, "client_id")
            return tuple(sorted(p for (c_id, p) in self._psubs if c_id == cid))

    def channel_subscribers(self, channel: str, seq: int) -> Tuple[str, ...]:
        """Sorted client ids directly subscribed to ``channel``."""
        with self._lock:
            _check_seq(seq)
            ch = _check_channel(channel)
            return tuple(sorted(c for (c, cch) in self._subs if cch == ch))

    def message(self, message_id: str, seq: int) -> MessageRecord:
        with self._lock:
            _check_seq(seq)
            mid = _check_nonempty_str(message_id, "message_id")
            if mid not in self._messages:
                raise RedisPubSubError(f"unknown message: {mid!r}")
            return self._messages[mid][0]

    def payload_for(self, message_id: str, seq: int) -> bytes:
        """Host-side payload bytes (never audited)."""
        with self._lock:
            _check_seq(seq)
            mid = _check_nonempty_str(message_id, "message_id")
            if mid not in self._messages:
                raise RedisPubSubError(f"unknown message: {mid!r}")
            return self._messages[mid][1]

    def deliveries_for(self, client_id: str, seq: int) -> Tuple[DeliveryRecord, ...]:
        """Booked deliveries for ``client_id``, in booking order."""
        with self._lock:
            _check_seq(seq)
            cid = _check_nonempty_str(client_id, "client_id")
            return tuple(
                self._deliveries[d] for d in self._inbox.get(cid, [])
            )

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            _check_seq(seq)
            return {
                "subscriptions": len(self._subs),
                "pattern_subscriptions": len(self._psubs),
                "messages": len(self._messages),
                "deliveries": len(self._deliveries),
                "clients": len({c for (c, _c) in self._subs}
                               | {c for (c, _p) in self._psubs}),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    bus = RedisPubSub()
    bus.subscribe("a", "news", 1)
    bus.psubscribe("b", "n*", 2)
    rep = bus.publish("news", {"headline": "hi"}, 3)
    assert rep.total_deliveries == 2, rep
    assert bus.stats(4)["deliveries"] == 2
    print("redis-pubsub OK: subscribe, psubscribe, publish, fanout, pins, audit")


if __name__ == "__main__":
    main()
