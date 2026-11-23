"""Event analytics tracker (twenty-ninth batch).

Segment/Mixpanel/Amplitude-shaped event bookkeeping as a deterministic
single-host ledger:

* :meth:`AnalyticsTracker.track` appends an immutable, digest-pinned
  event to the ledger (``evt-N`` ids, hash-chained).
* :meth:`AnalyticsTracker.funnel` runs an ordered conversion query over
  the ledger: for each user, the first occurrence of ``steps[0]`` is the
  funnel entry; later steps count only when they occur *after* the
  previous step and within ``conversion_window`` of the entry.
* :meth:`AnalyticsTracker.cohort` runs a retention-cohort query: users
  are bucketed by ``anchor_seq // bucket_size`` (first anchor event per
  user); retention for period ``p`` is the fraction of the bucket with
  at least one ``activity_event`` in
  ``[anchor + p*bucket_size, anchor + (p+1)*bucket_size)``.

The semantics follow the standard product-analytics definitions
(Amplitude "Funnels", Mixpanel "Cohorts"); the implementation is plain
deterministic bookkeeping — no sampling, no significance testing, no
statistical inference anywhere.

House rules: no wall-clock (callers inject integer seqs), frozen
dataclasses, fail-closed validation (structural problems raise;
*queries* over empty data return zeros, never exceptions), stdlib-only,
records sealed with ``sha256:`` digest pins over the canonical payload
and chained per ledger via ``prev_digest`` (``"genesis"`` for the
first). Every mutation consumes its seq — failed mutations advance the
ledger position too, so the audit trail stays totally ordered.
State transitions emit ``audit.ndjson/1`` events.

Event names are validated structurally (non-empty, length-capped, no
control characters) but intentionally *not* pinned to a vocabulary:
analytics event taxonomies are domain-defined, and pinning them would
force a registry edit for every new product event. Property values are
limited to ``str``/``int``/``bool``/``None`` (floats refused — no
``>2**53`` precision hazard; ints outside the safe range refused).

Honest boundary: this module books *host-reported* events consistently
(digests recompute, the chain is append-only, funnel/cohort math is
exact over the ledger). It cannot prove an event happened on a real
client, resolve identities across ``user_id`` values, or detect
under-reporting — the GIGO boundary sits at :meth:`track`. Audit
events carry ids, digests, and aggregate counts only: ``user_id``
values and property values never cross the audit boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping

#: Version pin for this module's record shape.
ANALYTICS_TRACKER_VERSION = "analytics-tracker.v1"

#: Schema pin carried by records and audit events.
ANALYTICS_TRACKER_SCHEMA = "northstar.analytics-tracker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis marker for the first record in a hash chain.
_GENESIS = "genesis"

#: Audit event kinds.
KIND_EVENT_TRACKED = "analytics.event-tracked"
KIND_FUNNEL = "analytics.funnel-analyzed"
KIND_COHORT = "analytics.cohort-analyzed"
KIND_REJECTED = "analytics.rejected"
_KINDS = (KIND_EVENT_TRACKED, KIND_FUNNEL, KIND_COHORT, KIND_REJECTED)

#: Validation caps.
MAX_EVENT_NAME_LEN = 128
MAX_USER_ID_LEN = 256
MAX_TRACKER_NAME_LEN = 128
MAX_PROPERTIES = 32
MAX_PROP_KEY_LEN = 64
MAX_PROP_VALUE_LEN = 1024
MAX_STEPS = 16
MAX_PERIODS = 64

#: Safe integer range for property values (JCS >2^53 discipline).
_SAFE_INT = 2 ** 53


class AnalyticsError(ValueError):
    """A malformed request or a refused state transition."""


class SeqOrderError(AnalyticsError):
    """A mutation seq that is not strictly greater than the last one."""


class UnknownEventError(AnalyticsError):
    """Lookup of an event id the ledger does not hold."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnalyticsError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str, cap: int) -> str:
    if not isinstance(value, str) or not value:
        raise AnalyticsError(f"{field_name} must be a non-empty string")
    if len(value) > cap:
        raise AnalyticsError(f"{field_name} must be at most {cap} chars")
    return value


def _check_event_name(value: Any) -> str:
    name = _check_nonempty_str(value, "event_name", MAX_EVENT_NAME_LEN)
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise AnalyticsError("event_name must not contain control characters")
    return name


def _check_user_id(value: Any) -> str:
    return _check_nonempty_str(value, "user_id", MAX_USER_ID_LEN)


def _check_properties(value: Any) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise AnalyticsError("properties must be a mapping or None")
    if len(value) > MAX_PROPERTIES:
        raise AnalyticsError(f"at most {MAX_PROPERTIES} properties per event")
    items = []
    for key, val in value.items():
        _check_nonempty_str(key, "property key", MAX_PROP_KEY_LEN)
        if isinstance(val, bool):
            items.append((key, val))
        elif isinstance(val, int):
            if abs(val) >= _SAFE_INT:
                raise AnalyticsError("int property values must be within ±2^53")
            items.append((key, val))
        elif isinstance(val, str):
            if len(val) > MAX_PROP_VALUE_LEN:
                raise AnalyticsError("str property values must be at most "
                                     f"{MAX_PROP_VALUE_LEN} chars")
            items.append((key, val))
        elif val is None:
            items.append((key, None))
        else:
            raise AnalyticsError(
                "property values must be str/int/bool/None "
                f"(key {key!r} held {type(val).__name__})"
            )
    # Keys are unique, so sorting by key alone is a total order.
    return tuple(sorted(items, key=lambda kv: kv[0]))


def _check_steps(value: Any) -> tuple:
    if not isinstance(value, (list, tuple)) or not 2 <= len(value) <= MAX_STEPS:
        raise AnalyticsError(
            f"steps must be a list/tuple of 2..{MAX_STEPS} event names"
        )
    return tuple(_check_event_name(step) for step in value)


def _check_window(value: Any) -> int:
    _check_seq(value, "conversion_window")
    if value <= 0:
        raise AnalyticsError("conversion_window must be a positive int")
    return value


def _check_bucket_size(value: Any) -> int:
    _check_seq(value, "bucket_size")
    if value <= 0:
        raise AnalyticsError("bucket_size must be a positive int")
    return value


def _check_periods(value: Any) -> int:
    _check_seq(value, "periods")
    if not 1 <= value <= MAX_PERIODS:
        raise AnalyticsError(f"periods must be within 1..{MAX_PERIODS}")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads hold only str/int/bool/None and lists/tuples thereof —
    # no floats, so no >2^53 precision hazard; ints serialize exactly.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrackedEvent:
    """One immutable event on the ledger.

    ``properties`` is a tuple of ``(key, value)`` pairs sorted by key.
    ``prev_digest`` chains to the previous event's ``record_digest``
    (``"genesis"`` for the first event).
    """

    event_id: str
    user_id: str
    event_name: str
    seq: int
    properties: tuple = ()
    prev_digest: str = _GENESIS
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.event_id, "event_id", 64)
        _check_user_id(self.user_id)
        _check_event_name(self.event_name)
        _check_seq(self.seq)
        _check_properties(dict(self.properties))
        if self.prev_digest != _GENESIS and (
            not isinstance(self.prev_digest, str)
            or not self.prev_digest.startswith("sha256:")
        ):
            raise AnalyticsError("prev_digest must be 'genesis' or a sha256: pin")


def _event_payload(event: TrackedEvent) -> dict[str, Any]:
    return {
        "schema": ANALYTICS_TRACKER_SCHEMA,
        "kind": "tracked-event",
        "event_id": event.event_id,
        "user_id": event.user_id,
        "event_name": event.event_name,
        "seq": event.seq,
        "properties": [[k, v] for k, v in event.properties],
        "prev_digest": event.prev_digest,
    }


def compute_event_digest(event: TrackedEvent) -> str:
    """Recompute an event's seal over all fields except itself."""
    return _pin(_event_payload(event))


def _seal_event(event: TrackedEvent) -> TrackedEvent:
    return replace(event, record_digest=compute_event_digest(event))


@dataclass(frozen=True)
class FunnelReport:
    """Result of a funnel query.

    ``step_counts[i]`` is the number of users who reached ``steps[i]``
    in order within the window; ``conversion_rates[i]`` is
    ``step_counts[i] / step_counts[0]`` rounded to 6 decimals
    (``0.0`` when no user entered the funnel).
    """

    name: str
    steps: tuple
    conversion_window: int
    seq: int
    step_counts: tuple
    conversion_rates: tuple
    analyzed_events: int
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.name, "name", MAX_TRACKER_NAME_LEN)
        _check_steps(list(self.steps))
        _check_window(self.conversion_window)
        _check_seq(self.seq)
        if len(self.step_counts) != len(self.steps):
            raise AnalyticsError("step_counts must align with steps")
        if len(self.conversion_rates) != len(self.steps):
            raise AnalyticsError("conversion_rates must align with steps")


def _funnel_payload(report: FunnelReport) -> dict[str, Any]:
    return {
        "schema": ANALYTICS_TRACKER_SCHEMA,
        "kind": "funnel-report",
        "name": report.name,
        "steps": list(report.steps),
        "conversion_window": report.conversion_window,
        "seq": report.seq,
        "step_counts": list(report.step_counts),
        "conversion_rates": list(report.conversion_rates),
        "analyzed_events": report.analyzed_events,
    }


def compute_funnel_digest(report: FunnelReport) -> str:
    """Recompute a funnel report's seal over all fields except itself."""
    return _pin(_funnel_payload(report))


@dataclass(frozen=True)
class CohortBucket:
    """One retention bucket of a cohort report."""

    bucket: int
    size: int
    retention: tuple

    def __post_init__(self) -> None:
        _check_seq(self.bucket, "bucket")
        _check_seq(self.size, "size")


@dataclass(frozen=True)
class CohortReport:
    """Result of a cohort query.

    ``buckets`` is sorted by bucket index; each bucket's ``retention``
    tuple has one entry per requested period (period 0 covers
    ``[anchor, anchor + bucket_size)``).
    """

    name: str
    anchor_event: str
    activity_event: str
    bucket_size: int
    periods: int
    seq: int
    buckets: tuple
    analyzed_events: int
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.name, "name", MAX_TRACKER_NAME_LEN)
        _check_event_name(self.anchor_event)
        _check_event_name(self.activity_event)
        _check_bucket_size(self.bucket_size)
        _check_periods(self.periods)
        _check_seq(self.seq)


def _cohort_payload(report: CohortReport) -> dict[str, Any]:
    return {
        "schema": ANALYTICS_TRACKER_SCHEMA,
        "kind": "cohort-report",
        "name": report.name,
        "anchor_event": report.anchor_event,
        "activity_event": report.activity_event,
        "bucket_size": report.bucket_size,
        "periods": report.periods,
        "seq": report.seq,
        "buckets": [
            {"bucket": b.bucket, "size": b.size, "retention": list(b.retention)}
            for b in report.buckets
        ],
        "analyzed_events": report.analyzed_events,
    }


def compute_cohort_digest(report: CohortReport) -> str:
    """Recompute a cohort report's seal over all fields except itself."""
    return _pin(_cohort_payload(report))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def analytics_tracker_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the analytics tracker.

    Carries ids, digests, and aggregate counts only — never ``user_id``
    values or property values.
    """
    if kind not in _KINDS:
        raise AnalyticsError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "analytics_tracker",
        "module_version": ANALYTICS_TRACKER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# AnalyticsTracker
# ---------------------------------------------------------------------------


class AnalyticsTracker:
    """Append-only event ledger with funnel and cohort queries.

    All mutations require a strictly increasing caller-supplied ``seq``
    (logical time — no wall-clock reads anywhere). Failed mutations
    still consume their seq, keeping the audit trail totally ordered.
    RLock-guarded for concurrent callers.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: list[TrackedEvent] = []
        self._by_user: dict[str, list[TrackedEvent]] = {}
        self._by_id: dict[str, TrackedEvent] = {}
        self._last_seq = -1
        self._next_n = 1
        self._audit: list[Mapping[str, Any]] = []

    # -- internals --------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last={self._last_seq}, saw={seq})"
            )
        # Consumed up front: failed mutations advance the position too.
        self._last_seq = seq
        return seq

    def _audit_event(self, kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
        event = analytics_tracker_audit_event(kind, seq, **detail)
        self._audit.append(event)
        return event

    def _rejected(self, seq: int, op: str, reason: str) -> None:
        self._audit_event(KIND_REJECTED, seq, op=op, reason=reason)

    # -- mutations ----------------------------------------------------------

    def track(
        self,
        user_id: str,
        event_name: str,
        seq: int,
        properties: Mapping[str, Any] | None = None,
    ) -> TrackedEvent:
        """Append one event to the ledger. Returns the sealed record."""
        with self._lock:
            self._claim_seq(seq)
            try:
                uid = _check_user_id(user_id)
                name = _check_event_name(event_name)
                props = _check_properties(properties)
            except AnalyticsError as exc:
                self._rejected(seq, "track", str(exc))
                raise
            event_id = f"evt-{self._next_n}"
            self._next_n += 1
            prev = self._events[-1].record_digest if self._events else _GENESIS
            event = _seal_event(TrackedEvent(
                event_id=event_id, user_id=uid, event_name=name,
                seq=seq, properties=props, prev_digest=prev,
            ))
            self._events.append(event)
            self._by_user.setdefault(uid, []).append(event)
            self._by_id[event_id] = event
            # Audit carries ids/digests only — no user_id, no property values.
            self._audit_event(
                KIND_EVENT_TRACKED, seq,
                event_id=event_id, event_name=name,
                record_digest=event.record_digest,
            )
            return event

    # -- queries ------------------------------------------------------------

    def funnel(
        self,
        name: str,
        steps: list[str] | tuple[str, ...],
        seq: int,
        conversion_window: int,
    ) -> FunnelReport:
        """Run an ordered conversion query over the ledger.

        For each user, the first occurrence of ``steps[0]`` is the
        funnel entry; step ``i`` counts only when it occurs strictly
        after the previous counted step and no later than
        ``entry_seq + conversion_window``.
        """
        with self._lock:
            self._claim_seq(seq)
            try:
                funnel_name = _check_nonempty_str(name, "name", MAX_TRACKER_NAME_LEN)
                step_names = _check_steps(steps)
                window = _check_window(conversion_window)
            except AnalyticsError as exc:
                self._rejected(seq, "funnel", str(exc))
                raise
            counts = self._funnel_counts(step_names, window)
            rates = tuple(
                round(c / counts[0], 6) if counts[0] else 0.0 for c in counts
            )
            report = FunnelReport(
                name=funnel_name, steps=step_names, conversion_window=window,
                seq=seq, step_counts=tuple(counts), conversion_rates=rates,
                analyzed_events=len(self._events),
            )
            report = replace(report, record_digest=compute_funnel_digest(report))
            self._audit_event(
                KIND_FUNNEL, seq, name=funnel_name,
                step_counts=list(counts), analyzed_events=len(self._events),
            )
            return report

    def _funnel_counts(self, steps: tuple, window: int) -> list[int]:
        counts = [0] * len(steps)
        for events in self._by_user.values():
            entry_seq: int | None = None
            prev_seq = -1
            reached = 0
            for event in events:  # already in seq order
                if reached == 0:
                    if event.event_name == steps[0]:
                        entry_seq = event.seq
                        prev_seq = event.seq
                        reached = 1
                else:
                    assert entry_seq is not None
                    if event.seq > entry_seq + window:
                        break
                    if event.event_name == steps[reached] and event.seq > prev_seq:
                        prev_seq = event.seq
                        reached += 1
                        if reached == len(steps):
                            break
            for i in range(reached):
                counts[i] += 1
        return counts

    def cohort(
        self,
        name: str,
        anchor_event: str,
        activity_event: str,
        seq: int,
        bucket_size: int,
        periods: int,
    ) -> CohortReport:
        """Run a retention-cohort query over the ledger.

        Users are bucketed by ``first_anchor_seq // bucket_size``;
        retention for period ``p`` is the fraction of the bucket with at
        least one ``activity_event`` in
        ``[anchor + p*bucket_size, anchor + (p+1)*bucket_size)``.
        """
        with self._lock:
            self._claim_seq(seq)
            try:
                cohort_name = _check_nonempty_str(name, "name", MAX_TRACKER_NAME_LEN)
                anchor = _check_event_name(anchor_event)
                activity = _check_event_name(activity_event)
                size = _check_bucket_size(bucket_size)
                n_periods = _check_periods(periods)
            except AnalyticsError as exc:
                self._rejected(seq, "cohort", str(exc))
                raise
            buckets = self._cohort_buckets(anchor, activity, size, n_periods)
            report = CohortReport(
                name=cohort_name, anchor_event=anchor, activity_event=activity,
                bucket_size=size, periods=n_periods, seq=seq,
                buckets=buckets, analyzed_events=len(self._events),
            )
            report = replace(report, record_digest=compute_cohort_digest(report))
            self._audit_event(
                KIND_COHORT, seq, name=cohort_name,
                bucket_count=len(buckets), analyzed_events=len(self._events),
            )
            return report

    def _cohort_buckets(
        self, anchor_event: str, activity_event: str,
        bucket_size: int, periods: int,
    ) -> tuple:
        anchor_first: dict[str, int] = {}
        activity_seqs: dict[str, list[int]] = {}
        for event in self._events:  # seq order
            if event.event_name == anchor_event and event.user_id not in anchor_first:
                anchor_first[event.user_id] = event.seq
            if event.event_name == activity_event:
                activity_seqs.setdefault(event.user_id, []).append(event.seq)
        by_bucket: dict[int, list[tuple[str, int]]] = {}
        for user_id, anchor_seq in anchor_first.items():
            by_bucket.setdefault(anchor_seq // bucket_size, []).append(
                (user_id, anchor_seq)
            )
        result = []
        for bucket in sorted(by_bucket):
            members = by_bucket[bucket]
            size = len(members)
            retention = []
            for p in range(periods):
                active = 0
                for user_id, anchor_seq in members:
                    lo = anchor_seq + p * bucket_size
                    hi = anchor_seq + (p + 1) * bucket_size
                    if any(lo <= s < hi for s in activity_seqs.get(user_id, [])):
                        active += 1
                retention.append(round(active / size, 6))
            result.append(CohortBucket(
                bucket=bucket, size=size, retention=tuple(retention)))
        return tuple(result)

    # -- views ---------------------------------------------------------------

    def event(self, event_id: str) -> TrackedEvent:
        """Fetch one event by id; unknown ids raise (a lookup is a query)."""
        with self._lock:
            try:
                return self._by_id[event_id]
            except KeyError:
                raise UnknownEventError(f"unknown event id: {event_id!r}") from None

    def event_ids(self) -> tuple:
        """All event ids in ledger order."""
        with self._lock:
            return tuple(event.event_id for event in self._events)

    def events_for(self, user_id: str) -> tuple:
        """All events for a user in seq order; unknown users yield ``()``."""
        with self._lock:
            return tuple(self._by_user.get(user_id, ()))

    def stats(self) -> Mapping[str, Any]:
        """Ledger counters (no user data)."""
        with self._lock:
            return {
                "events": len(self._events),
                "users": len(self._by_user),
                "last_seq": self._last_seq,
                "module_version": ANALYTICS_TRACKER_VERSION,
            }

    def audit_log(self) -> tuple:
        """Append-only audit events in seq order."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    tracker = AnalyticsTracker()
    tracker.track("u1", "signup", 1)
    tracker.track("u1", "purchase", 2, {"amount": 99})
    tracker.track("u2", "signup", 3)
    funnel = tracker.funnel("buy", ("signup", "purchase"), 4, conversion_window=100)
    assert funnel.step_counts == (2, 1), funnel.step_counts
    assert funnel.conversion_rates == (1.0, 0.5), funnel.conversion_rates
    assert compute_funnel_digest(funnel) == funnel.record_digest
    cohort = tracker.cohort("retention", "signup", "purchase", 5,
                            bucket_size=10, periods=2)
    assert len(cohort.buckets) == 1 and cohort.buckets[0].size == 2
    assert cohort.buckets[0].retention == (0.5, 0.0), cohort.buckets[0].retention
    assert compute_cohort_digest(cohort) == cohort.record_digest
    assert tracker.stats()["events"] == 3
    print("analytics-tracker OK: track, funnel, cohort, pins, audit")


if __name__ == "__main__":
    main()


__all__ = [
    "ANALYTICS_TRACKER_VERSION",
    "ANALYTICS_TRACKER_SCHEMA",
    "AUDIT_SCHEMA",
    "KIND_EVENT_TRACKED",
    "KIND_FUNNEL",
    "KIND_COHORT",
    "KIND_REJECTED",
    "AnalyticsError",
    "SeqOrderError",
    "UnknownEventError",
    "TrackedEvent",
    "FunnelReport",
    "CohortBucket",
    "CohortReport",
    "AnalyticsTracker",
    "compute_event_digest",
    "compute_funnel_digest",
    "compute_cohort_digest",
    "analytics_tracker_audit_event",
    "main",
]
