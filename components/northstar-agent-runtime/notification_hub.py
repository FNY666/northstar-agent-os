"""Notification hub interface (multi-channel fanout + preferences, simulated).

Research motivation: every production agent eventually needs to reach a
human -- incident pages, approval requests, digest summaries, deploy
notices. The industry shape is the same everywhere (SendGrid/Twilio/
OneSignal/Firebase Cloud Messaging, Slack webhooks): a *hub* that owns

- *channels*: named delivery pipes (``email`` / ``sms`` / ``push`` /
  ``webhook`` / ``slack``) registered once;
- *subscriptions*: which subjects listen on which channels, and for
  which *categories* (``"approvals"``, ``"incidents"``, ``"all"``);
- *preferences*: per-subject delivery mode -- ``immediate``, ``digest``
  (buffered, collected by ``digest()``), or ``muted`` (temporary or
  indefinite suppression) -- plus whether ``urgent`` notifications
  bypass suppression;
- *fanout*: one ``notify()`` call produces a per-channel
  ``DeliveryReport``; ``digest()`` collects buffered items into a
  digest the host renders.

This module is the *bookkeeping* half of that shape:

- ``NotificationHub`` -- ``register_channel()`` pins a channel kind,
  ``subscribe()`` / ``unsubscribe()`` manage (subject, channel)
  subscriptions, ``set_preferences()`` records a subject's delivery
  preferences, ``preferences()`` reads them back, ``notify()`` fans
  one notification out to every matching subscription and returns a
  frozen ``DeliveryReport``, ``digest()`` collects buffered items
  into a frozen ``DigestReport`` and clears the buffer.
- ``notification_hub_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``channel-registered`` / ``subscribed`` / ``unsubscribed``
  / ``preferences-set`` / ``notified`` / ``digested`` /
  ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``channel_id`` / ``subject_id`` / ``category`` / ``title`` /
  ``body`` are non-empty ``str``; ``priority`` is ``normal`` or
  ``urgent``; ``kind`` is one of the five pinned channel kinds;
  caller seqs are ints (not bool) >= 0.
- Duplicate channel ids and duplicate (subject, channel) subscriptions
  are refused. ``unsubscribe()`` on a non-existent subscription
  raises ``UnknownSubscriptionError``.
- ``notify()`` to a subject with *no* subscription matching the
  category raises ``NoRouteError`` -- a notification is never
  silently dropped. ``notify()`` / ``digest()`` /
  ``set_preferences()`` on a subject that never subscribed raises
  ``UnknownSubjectError``.
- A mute is explicit: ``mode="muted"`` mutes everything until the
  mode changes; ``muted_until_seq`` must be >= the current seq
  (a mute window already in the past is refused as a probable host
  bug). Only ``urgent`` notifications with ``urgent_bypass=True``
  escape a mute; everything else is reported ``dropped-muted`` --
  suppression is *visible* in the delivery report, never invisible.
- ``digest()`` on an empty buffer is a valid no-op (returns an empty
  ``DigestReport``); losing buffered items would be worse than
  admitting there are none.

Honest scope:

- This module books *fanout decisions*. A ``queued`` attempt means
  "the host should deliver this on this channel now"; it cannot prove
  the email was sent, the SMS arrived, or the webhook was read.
  Pair with a host-side delivery receipt log for proof.
- Caller-supplied seqs are the clock -- the host owns "now", so mute
  windows are seq ranges, not wall-clock.
- Buffered digest content is digest-pinned only; the host holds the
  original text. A ``DigestReport`` proves *which* notifications were
  collected, never what they said.
- In-memory only: pair with the durable audit writer if delivery
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

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
NOTIFICATION_HUB_VERSION = "notification-hub.v1"

#: Schema pin carried by records and audit events.
NOTIFICATION_HUB_SCHEMA = "northstar.notification-hub.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned channel kinds.
CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"
CHANNEL_PUSH = "push"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_SLACK = "slack"
_CHANNEL_KINDS = (CHANNEL_EMAIL, CHANNEL_SMS, CHANNEL_PUSH, CHANNEL_WEBHOOK, CHANNEL_SLACK)

#: Delivery modes.
MODE_IMMEDIATE = "immediate"
MODE_DIGEST = "digest"
MODE_MUTED = "muted"
_MODES = (MODE_IMMEDIATE, MODE_DIGEST, MODE_MUTED)

#: Notification priorities.
PRIORITY_NORMAL = "normal"
PRIORITY_URGENT = "urgent"
_PRIORITIES = (PRIORITY_NORMAL, PRIORITY_URGENT)

#: Subscription category wildcard.
CATEGORY_ALL = "all"

#: Delivery attempt statuses.
STATUS_QUEUED = "queued"
STATUS_BUFFERED = "buffered"
STATUS_DROPPED_MUTED = "dropped-muted"

#: Audit event kinds.
KIND_CHANNEL_REGISTERED = "channel-registered"
KIND_SUBSCRIBED = "subscribed"
KIND_UNSUBSCRIBED = "unsubscribed"
KIND_PREFERENCES_SET = "preferences-set"
KIND_NOTIFIED = "notified"
KIND_DIGESTED = "digested"
KIND_REJECTED = "rejected"
_KINDS = (
    KIND_CHANNEL_REGISTERED,
    KIND_SUBSCRIBED,
    KIND_UNSUBSCRIBED,
    KIND_PREFERENCES_SET,
    KIND_NOTIFIED,
    KIND_DIGESTED,
    KIND_REJECTED,
)


class NotificationHubError(Exception):
    """Base error for the notification hub."""


class DuplicateChannelError(NotificationHubError):
    """A channel with this id is already registered."""


class UnknownChannelError(NotificationHubError):
    """Channel id is not known to the registry."""


class UnknownSubjectError(NotificationHubError):
    """Subject has never subscribed to anything."""


class DuplicateSubscriptionError(NotificationHubError):
    """This (subject, channel) subscription already exists."""


class UnknownSubscriptionError(NotificationHubError):
    """No such (subject, channel) subscription exists."""


class NoRouteError(NotificationHubError):
    """Subject has no subscription matching this category; refused, not dropped."""


class BadPreferenceError(NotificationHubError):
    """Preference values are inconsistent or out of range."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise NotificationHubError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise NotificationHubError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class ChannelRecord:
    """One registered delivery channel, digest-pinned."""

    channel_id: str
    kind: str
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class SubscriptionRecord:
    """One (subject, channel) subscription with its categories."""

    subject_id: str
    channel_id: str
    categories: Tuple[str, ...]
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class UnsubscribeRecord:
    """Record of a subscription being removed."""

    subject_id: str
    channel_id: str
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class PreferenceRecord:
    """One subject's delivery preferences, digest-pinned."""

    subject_id: str
    mode: str
    muted_until_seq: Optional[int]
    urgent_bypass: bool
    digest_every_seqs: int
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class DeliveryAttempt:
    """Fanout outcome for one channel."""

    notification_id: str
    channel_id: str
    channel_kind: str
    status: str
    reason: str
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class DeliveryReport:
    """Frozen report of one notify() fanout."""

    notification_id: str
    subject_id: str
    category: str
    priority: str
    attempts: Tuple[DeliveryAttempt, ...]
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class DigestItem:
    """One buffered notification collected into a digest."""

    notification_id: str
    category: str
    priority: str
    seq: int
    content_digest: str
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


@dataclass(frozen=True)
class DigestReport:
    """Frozen report of one digest() collection."""

    subject_id: str
    items: Tuple[DigestItem, ...]
    seq: int
    digest: str
    version: str = NOTIFICATION_HUB_VERSION
    schema: str = NOTIFICATION_HUB_SCHEMA


def notification_hub_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the notification hub."""
    if kind not in _KINDS:
        raise NotificationHubError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "notification_hub",
        "module_version": NOTIFICATION_HUB_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


class NotificationHub:
    """Multi-channel notification fanout with per-subject preferences."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._channels: dict = {}  # channel_id -> ChannelRecord
        self._subscriptions: dict = {}  # (subject_id, channel_id) -> SubscriptionRecord
        self._subjects: set = set()  # subject ids that ever subscribed
        self._preferences: dict = {}  # subject_id -> PreferenceRecord
        self._buffer: dict = {}  # subject_id -> list[_Buffered] (digest mode)
        self._next_notification = 0

    # -- helpers ----------------------------------------------------

    def _default_preferences(self, subject_id: str) -> PreferenceRecord:
        return PreferenceRecord(
            subject_id=subject_id,
            mode=MODE_IMMEDIATE,
            muted_until_seq=None,
            urgent_bypass=True,
            digest_every_seqs=100,
            seq=0,
            digest=_pin(["prefs", subject_id, MODE_IMMEDIATE, None, True, 100]),
        )

    def _prefs_for(self, subject_id: str) -> PreferenceRecord:
        return self._preferences.get(subject_id, self._default_preferences(subject_id))

    @staticmethod
    def _is_muted(prefs: PreferenceRecord, seq: int) -> bool:
        if prefs.mode == MODE_MUTED:
            return True
        return prefs.muted_until_seq is not None and seq <= prefs.muted_until_seq

    # -- channels ---------------------------------------------------

    def register_channel(self, channel_id: str, kind: str, seq: int) -> ChannelRecord:
        """Register a delivery channel."""
        _check_str(channel_id, "channel_id")
        if kind not in _CHANNEL_KINDS:
            raise NotificationHubError(f"kind must be one of {_CHANNEL_KINDS}")
        _check_seq(seq)
        with self._lock:
            if channel_id in self._channels:
                raise DuplicateChannelError(f"channel already registered: {channel_id!r}")
            rec = ChannelRecord(
                channel_id=channel_id,
                kind=kind,
                seq=seq,
                digest=_pin(["channel", channel_id, kind, seq]),
            )
            self._channels[channel_id] = rec
            return rec

    def channels(self) -> Tuple[ChannelRecord, ...]:
        """All registered channels, sorted by id."""
        with self._lock:
            return tuple(sorted(self._channels.values(), key=lambda r: r.channel_id))

    # -- subscriptions ----------------------------------------------

    def subscribe(
        self,
        subject_id: str,
        channel_id: str,
        seq: int,
        categories: Optional[Tuple[str, ...]] = None,
    ) -> SubscriptionRecord:
        """Subscribe a subject to a channel for categories (None = all)."""
        _check_str(subject_id, "subject_id")
        _check_str(channel_id, "channel_id")
        _check_seq(seq)
        if categories is None:
            cats: Tuple[str, ...] = (CATEGORY_ALL,)
        else:
            if not isinstance(categories, (tuple, list)) or not categories:
                raise NotificationHubError("categories must be a non-empty tuple/list")
            cats = tuple(sorted({_check_str(c, "category") for c in categories}))
        with self._lock:
            if channel_id not in self._channels:
                raise UnknownChannelError(f"unknown channel: {channel_id!r}")
            key = (subject_id, channel_id)
            if key in self._subscriptions:
                raise DuplicateSubscriptionError(
                    f"already subscribed: {subject_id!r} on {channel_id!r}"
                )
            rec = SubscriptionRecord(
                subject_id=subject_id,
                channel_id=channel_id,
                categories=cats,
                seq=seq,
                digest=_pin(["subscribe", subject_id, channel_id, list(cats), seq]),
            )
            self._subscriptions[key] = rec
            self._subjects.add(subject_id)
            self._buffer.setdefault(subject_id, [])
            return rec

    def unsubscribe(self, subject_id: str, channel_id: str, seq: int) -> UnsubscribeRecord:
        """Remove a (subject, channel) subscription."""
        _check_str(subject_id, "subject_id")
        _check_str(channel_id, "channel_id")
        _check_seq(seq)
        with self._lock:
            key = (subject_id, channel_id)
            if key not in self._subscriptions:
                raise UnknownSubscriptionError(
                    f"no subscription: {subject_id!r} on {channel_id!r}"
                )
            del self._subscriptions[key]
            return UnsubscribeRecord(
                subject_id=subject_id,
                channel_id=channel_id,
                seq=seq,
                digest=_pin(["unsubscribe", subject_id, channel_id, seq]),
            )

    def subscriptions(self, subject_id: str) -> Tuple[SubscriptionRecord, ...]:
        """All subscriptions for a subject, sorted by channel id."""
        _check_str(subject_id, "subject_id")
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            return tuple(
                sorted(
                    (r for (s, _), r in self._subscriptions.items() if s == subject_id),
                    key=lambda r: r.channel_id,
                )
            )

    # -- preferences -------------------------------------------------

    def set_preferences(
        self,
        subject_id: str,
        seq: int,
        mode: str = MODE_IMMEDIATE,
        muted_until_seq: Optional[int] = None,
        urgent_bypass: bool = True,
        digest_every_seqs: int = 100,
    ) -> PreferenceRecord:
        """Record a subject's delivery preferences."""
        _check_str(subject_id, "subject_id")
        _check_seq(seq)
        if mode not in _MODES:
            raise BadPreferenceError(f"mode must be one of {_MODES}")
        if muted_until_seq is not None:
            _check_seq(muted_until_seq, "muted_until_seq")
            if muted_until_seq < seq:
                raise BadPreferenceError(
                    "muted_until_seq is already in the past; mute windows must be future"
                )
        if not isinstance(urgent_bypass, bool):
            raise BadPreferenceError("urgent_bypass must be a bool")
        if isinstance(digest_every_seqs, bool) or not isinstance(digest_every_seqs, int):
            raise BadPreferenceError("digest_every_seqs must be an int")
        if digest_every_seqs < 1:
            raise BadPreferenceError("digest_every_seqs must be >= 1")
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            rec = PreferenceRecord(
                subject_id=subject_id,
                mode=mode,
                muted_until_seq=muted_until_seq,
                urgent_bypass=urgent_bypass,
                digest_every_seqs=digest_every_seqs,
                seq=seq,
                digest=_pin(
                    ["prefs", subject_id, mode, muted_until_seq, urgent_bypass,
                     digest_every_seqs, seq]
                ),
            )
            self._preferences[subject_id] = rec
            return rec

    def preferences(self, subject_id: str) -> PreferenceRecord:
        """Read a subject's delivery preferences (defaults if never set)."""
        _check_str(subject_id, "subject_id")
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            return self._prefs_for(subject_id)

    # -- fanout ------------------------------------------------------

    def notify(
        self,
        subject_id: str,
        category: str,
        title: str,
        body: str,
        seq: int,
        priority: str = PRIORITY_NORMAL,
    ) -> DeliveryReport:
        """Fan one notification out to every matching subscription."""
        _check_str(subject_id, "subject_id")
        _check_str(category, "category")
        _check_str(title, "title")
        _check_str(body, "body")
        if priority not in _PRIORITIES:
            raise NotificationHubError(f"priority must be one of {_PRIORITIES}")
        _check_seq(seq)
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            matching = [
                r
                for (s, _), r in self._subscriptions.items()
                if s == subject_id
                and (CATEGORY_ALL in r.categories or category in r.categories)
            ]
            if not matching:
                raise NoRouteError(
                    f"no subscription matches category {category!r} "
                    f"for subject {subject_id!r}; refused, not dropped"
                )
            self._next_notification += 1
            notification_id = f"ntf-{self._next_notification}"
            content_digest = _pin(["content", subject_id, category, title, body, priority])
            prefs = self._prefs_for(subject_id)
            muted = self._is_muted(prefs, seq)
            urgent = priority == PRIORITY_URGENT
            bypass = urgent and prefs.urgent_bypass
            attempts = []
            for sub in sorted(matching, key=lambda r: r.channel_id):
                channel = self._channels[sub.channel_id]
                if muted and not bypass:
                    status, reason = STATUS_DROPPED_MUTED, "subject muted"
                elif prefs.mode == MODE_DIGEST and not bypass:
                    status, reason = STATUS_BUFFERED, "digest mode"
                    self._buffer[subject_id].append(
                        (
                            notification_id,
                            category,
                            priority,
                            seq,
                            content_digest,
                        )
                    )
                else:
                    status, reason = STATUS_QUEUED, "queued for host delivery"
                attempts.append(
                    DeliveryAttempt(
                        notification_id=notification_id,
                        channel_id=sub.channel_id,
                        channel_kind=channel.kind,
                        status=status,
                        reason=reason,
                        seq=seq,
                        digest=_pin(["attempt", notification_id, sub.channel_id, status, seq]),
                    )
                )
            return DeliveryReport(
                notification_id=notification_id,
                subject_id=subject_id,
                category=category,
                priority=priority,
                attempts=tuple(attempts),
                seq=seq,
                digest=_pin(["report", notification_id, subject_id, category, priority,
                             [a.digest for a in attempts], seq]),
            )

    # -- digest ------------------------------------------------------

    def pending_digest_count(self, subject_id: str) -> int:
        """How many items are buffered for a subject's digest."""
        _check_str(subject_id, "subject_id")
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            return len(self._buffer.get(subject_id, []))

    def digest(self, subject_id: str, seq: int) -> DigestReport:
        """Collect buffered items into a digest and clear the buffer."""
        _check_str(subject_id, "subject_id")
        _check_seq(seq)
        with self._lock:
            if subject_id not in self._subjects:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            buffered = self._buffer.get(subject_id, [])
            items = tuple(
                DigestItem(
                    notification_id=nid,
                    category=cat,
                    priority=prio,
                    seq=nseq,
                    content_digest=cdigest,
                    digest=_pin(["digest-item", nid, cat, prio, nseq, cdigest]),
                )
                for (nid, cat, prio, nseq, cdigest) in buffered
            )
            self._buffer[subject_id] = []
            return DigestReport(
                subject_id=subject_id,
                items=items,
                seq=seq,
                digest=_pin(["digest", subject_id, [i.digest for i in items], seq]),
            )


def main() -> None:
    hub = NotificationHub()
    hub.register_channel("ops-email", CHANNEL_EMAIL, 1)
    hub.register_channel("ops-sms", CHANNEL_SMS, 2)
    hub.subscribe("oncall", "ops-email", 3)
    hub.subscribe("oncall", "ops-sms", 4, categories=("incidents",))
    report = hub.notify("oncall", "incidents", "DB down", "primary is unreachable", 5)
    assert len(report.attempts) == 2
    assert all(a.status == STATUS_QUEUED for a in report.attempts)
    hub.set_preferences("oncall", 6, mode=MODE_DIGEST)
    report2 = hub.notify("oncall", "incidents", "Slow queries", "p99 rising", 7)
    assert all(a.status == STATUS_BUFFERED for a in report2.attempts)
    assert hub.pending_digest_count("oncall") == 2
    digest = hub.digest("oncall", 8)
    assert len(digest.items) == 2
    assert hub.pending_digest_count("oncall") == 0
    hub.set_preferences("oncall", 9, mode=MODE_MUTED)
    report3 = hub.notify("oncall", "incidents", "Noise", "ignored", 10)
    assert all(a.status == STATUS_DROPPED_MUTED for a in report3.attempts)
    report4 = hub.notify("oncall", "incidents", "SEV-1", "page now", 11, priority="urgent")
    assert all(a.status == STATUS_QUEUED for a in report4.attempts)
    hub.set_preferences("oncall", 12, mode=MODE_MUTED, urgent_bypass=False)
    report5 = hub.notify("oncall", "incidents", "SEV-1", "page now", 13, priority="urgent")
    assert all(a.status == STATUS_DROPPED_MUTED for a in report5.attempts)
    empty = hub.digest("oncall", 14)
    assert empty.items == ()
    for kind in _KINDS:
        ev = notification_hub_audit_event(kind, 15, note="self-check")
        assert ev["schema"] == AUDIT_SCHEMA
        assert ev["module"] == "notification_hub"
    print("notification-hub OK: register, subscribe, notify, digest, mute, urgent-bypass")


if __name__ == "__main__":
    main()
