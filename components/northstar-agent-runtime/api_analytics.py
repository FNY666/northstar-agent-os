"""API analytics (thirty-fourth batch).

Moesif-shaped API-usage bookkeeping as a deterministic single-host
ledger:

* :meth:`APIAnalytics.track` appends an immutable, digest-pinned API
  call record to the ledger (``call-N`` ids, hash-chained).
* :meth:`APIAnalytics.funnel` runs an ordered conversion query over
  the ledger: for each user, the first call matching ``steps[0]`` is
  the funnel entry; later steps count only when they occur *after* the
  previous step and within ``conversion_window`` of the entry.
* :meth:`APIAnalytics.cohort` runs a retention-cohort query: users are
  bucketed by ``anchor_seq // bucket_size`` (first anchor-step call
  per user); retention for period ``p`` is the fraction of the bucket
  with at least one ``activity`` call in
  ``[anchor + p*bucket_size, anchor + (p+1)*bucket_size)``.

Funnel/cohort steps are ``(method, endpoint)`` pairs: an API funnel
distinguishes ``GET /checkout`` from ``POST /checkout``, and Moesif
analyses treat API routes as method+path, not path alone. The math is
exact over the ledger — no sampling, no significance testing, no
statistical inference anywhere.

House rules: no wall-clock (callers inject integer seqs), frozen
dataclasses, fail-closed validation (structural problems raise;
*queries* over empty data return zeros, never exceptions), stdlib-only,
records sealed with ``sha256:`` digest pins over the canonical payload
and chained per ledger via ``prev_digest`` (``"genesis"`` for the
first). Every mutation consumes its seq — failed mutations advance the
ledger position too, so the audit trail stays totally ordered.
State transitions emit ``audit.ndjson/1`` events.

Endpoints are validated structurally (non-empty, start with ``/``,
length-capped, no whitespace) but intentionally *not* pinned to a
registry: route taxonomies are product-defined, and pinning them would
force a registry edit for every new route. HTTP methods are pinned to
the standard vocabulary. Status codes and latencies are validated but
never re-derived: a call record books what the host *reported*.

Honest boundary: this module books *host-reported* API calls
consistently (digests recompute, the chain is append-only, funnel /
cohort math is exact over the ledger). It cannot prove a request
crossed a real wire, resolve identities across ``user_id`` values, or
detect under-reporting — the GIGO boundary sits at :meth:`track`.
Audit events carry ids, digests, and aggregate counts only:
``user_id`` values never cross the audit boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping

#: Version pin for this module's record shape.
API_ANALYTICS_VERSION = "api-analytics.v1"

#: Schema pin carried by records and audit events.
API_ANALYTICS_SCHEMA = "northstar.api-analytics.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis marker for the first record in a hash chain.
_GENESIS = "genesis"

#: Audit event kinds.
KIND_CALL_TRACKED = "api-analytics.call-tracked"
KIND_FUNNEL = "api-analytics.funnel-analyzed"
KIND_COHORT = "api-analytics.cohort-analyzed"
KIND_REJECTED = "api-analytics.rejected"
_KINDS = (KIND_CALL_TRACKED, KIND_FUNNEL, KIND_COHORT, KIND_REJECTED)

#: Pinned HTTP method vocabulary (RFC 9110).
METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")

#: Validation caps.
MAX_ENDPOINT_LEN = 256
MAX_USER_ID_LEN = 256
MAX_FUNNEL_NAME_LEN = 128
MAX_STEPS = 16
MAX_PERIODS = 64
MAX_LATENCY_MS = 86_400_000  # 24h in ms; anything larger is a reporting bug.

#: Safe integer range for latency values (JCS >2^53 discipline).
_SAFE_INT = 2 ** 53


class APIAnalyticsError(ValueError):
    """A malformed request or a refused state transition."""


class SeqOrderError(APIAnalyticsError):
    """A mutation seq that is not strictly greater than the last one."""


class UnknownCallError(APIAnalyticsError):
    """Lookup of a call id the ledger does not hold."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise APIAnalyticsError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str, cap: int) -> str:
    if not isinstance(value, str) or not value:
        raise APIAnalyticsError(f"{field_name} must be a non-empty string")
    if len(value) > cap:
        raise APIAnalyticsError(f"{field_name} must be at most {cap} chars")
    return value


def _check_user_id(value: Any) -> str:
    return _check_nonempty_str(value, "user_id", MAX_USER_ID_LEN)


def _check_endpoint(value: Any) -> str:
    endpoint = _check_nonempty_str(value, "endpoint", MAX_ENDPOINT_LEN)
    if not endpoint.startswith("/"):
        raise APIAnalyticsError("endpoint must start with '/'")
    if any(c.isspace() for c in endpoint):
        raise APIAnalyticsError("endpoint must not contain whitespace")
    return endpoint


def _check_method(value: Any) -> str:
    if not isinstance(value, str) or value not in METHODS:
        raise APIAnalyticsError(
            f"method must be one of {', '.join(METHODS)}"
        )
    return value


def _check_status_code(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise APIAnalyticsError("status_code must be an int")
    if not 100 <= value <= 599:
        raise APIAnalyticsError("status_code must be within 100..599")
    return value


def _check_latency(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise APIAnalyticsError("latency_ms must be an int")
    if not 0 <= value <= MAX_LATENCY_MS:
        raise APIAnalyticsError(
            f"latency_ms must be within 0..{MAX_LATENCY_MS}"
        )
    return value


def _check_step(value: Any) -> tuple:
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
    ):
        raise APIAnalyticsError("a funnel/cohort step must be (method, endpoint)")
    method, endpoint = value
    return (_check_method(method), _check_endpoint(endpoint))


def _check_steps(value: Any) -> tuple:
    if not isinstance(value, (list, tuple)) or not 2 <= len(value) <= MAX_STEPS:
        raise APIAnalyticsError(
            f"steps must be a list/tuple of 2..{MAX_STEPS} (method, endpoint) pairs"
        )
    return tuple(_check_step(step) for step in value)


def _check_window(value: Any) -> int:
    _check_seq(value, "conversion_window")
    if value <= 0:
        raise APIAnalyticsError("conversion_window must be a positive int")
    return value


def _check_bucket_size(value: Any) -> int:
    _check_seq(value, "bucket_size")
    if value <= 0:
        raise APIAnalyticsError("bucket_size must be a positive int")
    return value


def _check_periods(value: Any) -> int:
    _check_seq(value, "periods")
    if not 1 <= value <= MAX_PERIODS:
        raise APIAnalyticsError(f"periods must be within 1..{MAX_PERIODS}")
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
class APITrackedCall:
    """One immutable API call on the ledger.

    ``prev_digest`` chains to the previous call's ``record_digest``
    (``"genesis"`` for the first call).
    """

    call_id: str
    user_id: str
    method: str
    endpoint: str
    status_code: int
    latency_ms: int
    seq: int
    prev_digest: str = _GENESIS
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.call_id, "call_id", 64)
        _check_user_id(self.user_id)
        _check_method(self.method)
        _check_endpoint(self.endpoint)
        _check_status_code(self.status_code)
        _check_latency(self.latency_ms)
        _check_seq(self.seq)
        if self.prev_digest != _GENESIS and (
            not isinstance(self.prev_digest, str)
            or not self.prev_digest.startswith("sha256:")
        ):
            raise APIAnalyticsError(
                "prev_digest must be 'genesis' or a sha256: pin"
            )


def _call_payload(call: APITrackedCall) -> dict[str, Any]:
    return {
        "schema": API_ANALYTICS_SCHEMA,
        "kind": "api-call",
        "call_id": call.call_id,
        "user_id": call.user_id,
        "method": call.method,
        "endpoint": call.endpoint,
        "status_code": call.status_code,
        "latency_ms": call.latency_ms,
        "seq": call.seq,
        "prev_digest": call.prev_digest,
    }


def compute_call_digest(call: APITrackedCall) -> str:
    """Seal an API call record with its digest pin."""
    return _pin(_call_payload(call))


def _seal_call(call: APITrackedCall) -> APITrackedCall:
    digest = compute_call_digest(call)
    if call.record_digest and call.record_digest != digest:
        raise APIAnalyticsError("call digest mismatch")
    return replace(call, record_digest=digest)


@dataclass(frozen=True)
class FunnelReport:
    """One funnel analysis over the ledger.

    ``step_counts[i]`` is the number of users whose calls reach step
    ``i`` (entry step first). ``conversion_rates[i]`` is
    ``step_counts[i] / step_counts[0]`` rounded to 6dp (0 when the entry
    step has no users).
    """

    name: str
    steps: tuple
    conversion_window: int
    seq: int
    step_counts: tuple
    conversion_rates: tuple
    analyzed_calls: int
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.name, "name", MAX_FUNNEL_NAME_LEN)
        _check_steps(list(self.steps))
        _check_window(self.conversion_window)
        _check_seq(self.seq)
        if len(self.step_counts) != len(self.steps):
            raise APIAnalyticsError(
                "step_counts must have one entry per step"
            )
        if len(self.conversion_rates) != len(self.steps):
            raise APIAnalyticsError(
                "conversion_rates must have one entry per step"
            )


def _funnel_payload(report: FunnelReport) -> dict[str, Any]:
    return {
        "schema": API_ANALYTICS_SCHEMA,
        "kind": "funnel-report",
        "name": report.name,
        "steps": [[m, e] for m, e in report.steps],
        "conversion_window": report.conversion_window,
        "seq": report.seq,
        "step_counts": list(report.step_counts),
        "conversion_rates": list(report.conversion_rates),
        "analyzed_calls": report.analyzed_calls,
    }


def compute_funnel_digest(report: FunnelReport) -> str:
    """Seal a funnel report with its digest pin."""
    return _pin(_funnel_payload(report))


@dataclass(frozen=True)
class CohortReport:
    """One retention-cohort analysis over the ledger.

    ``buckets`` is a tuple of ``(bucket_index, cohort_size,
    retained)`` where ``retained`` is a tuple of ``periods`` counts:
    users of the bucket whose anchor step was the first call, with at
    least one activity-step call in each period window.
    """

    anchor_step: tuple
    activity_step: tuple
    bucket_size: int
    periods: int
    seq: int
    buckets: tuple
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_step(list(self.anchor_step))
        _check_step(list(self.activity_step))
        _check_bucket_size(self.bucket_size)
        _check_periods(self.periods)
        _check_seq(self.seq)
        for bucket in self.buckets:
            if (
                not isinstance(bucket, (list, tuple)) or len(bucket) != 3
            ):
                raise APIAnalyticsError("each bucket must be (index, size, retained)")
            _index, size, retained = bucket
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise APIAnalyticsError("bucket size must be a non-negative int")
            if not isinstance(retained, (list, tuple)) or len(retained) != self.periods:
                raise APIAnalyticsError(
                    "bucket retained must have one entry per period"
                )


def _cohort_payload(report: CohortReport) -> dict[str, Any]:
    return {
        "schema": API_ANALYTICS_SCHEMA,
        "kind": "cohort-report",
        "anchor_step": [report.anchor_step[0], report.anchor_step[1]],
        "activity_step": [report.activity_step[0], report.activity_step[1]],
        "bucket_size": report.bucket_size,
        "periods": report.periods,
        "seq": report.seq,
        "buckets": [
            [index, size, list(retained)] for index, size, retained in report.buckets
        ],
    }


def compute_cohort_digest(report: CohortReport) -> str:
    """Seal a cohort report with its digest pin."""
    return _pin(_cohort_payload(report))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def api_analytics_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for API analytics.

    Carries ids, digests, and aggregate counts only — never ``user_id``
    values.
    """
    if kind not in _KINDS:
        raise APIAnalyticsError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "api_analytics",
        "module_version": API_ANALYTICS_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# APIAnalytics
# ---------------------------------------------------------------------------


class APIAnalytics:
    """Deterministic API-call analytics ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._calls: list[APITrackedCall] = []
        self._by_user: dict[str, list[APITrackedCall]] = {}
        self._by_id: dict[str, APITrackedCall] = {}
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
        event = api_analytics_audit_event(kind, seq, **detail)
        self._audit.append(event)
        return event

    def _rejected(self, seq: int, op: str, reason: str) -> None:
        self._audit_event(KIND_REJECTED, seq, op=op, reason=reason)

    @staticmethod
    def _matches(call: APITrackedCall, step: tuple) -> bool:
        return call.method == step[0] and call.endpoint == step[1]

    # -- mutations ----------------------------------------------------------

    def track(
        self,
        user_id: str,
        method: str,
        endpoint: str,
        seq: int,
        status_code: int = 200,
        latency_ms: int = 0,
    ) -> APITrackedCall:
        """Append one API call to the ledger. Returns the sealed record."""
        with self._lock:
            self._claim_seq(seq)
            try:
                uid = _check_user_id(user_id)
                m = _check_method(method)
                ep = _check_endpoint(endpoint)
                sc = _check_status_code(status_code)
                lat = _check_latency(latency_ms)
            except APIAnalyticsError as exc:
                self._rejected(seq, "track", str(exc))
                raise
            call_id = f"call-{self._next_n}"
            self._next_n += 1
            prev = self._calls[-1].record_digest if self._calls else _GENESIS
            call = _seal_call(APITrackedCall(
                call_id=call_id, user_id=uid, method=m, endpoint=ep,
                status_code=sc, latency_ms=lat, seq=seq, prev_digest=prev,
            ))
            self._calls.append(call)
            self._by_user.setdefault(uid, []).append(call)
            self._by_id[call_id] = call
            # Audit carries ids/digests only — no user_id.
            self._audit_event(
                KIND_CALL_TRACKED, seq,
                call_id=call_id, method=m, endpoint=ep,
                record_digest=call.record_digest,
            )
            return call

    # -- queries ------------------------------------------------------------

    def funnel(
        self,
        name: str,
        steps: list[tuple] | tuple,
        seq: int,
        conversion_window: int,
    ) -> FunnelReport:
        """Run an ordered conversion query over the ledger.

        For each user, the first call matching ``steps[0]`` is the
        funnel entry; step ``i`` counts only when it occurs strictly
        after the previous counted step and no later than
        ``entry_seq + conversion_window``.
        """
        with self._lock:
            self._claim_seq(seq)
            try:
                funnel_name = _check_nonempty_str(name, "name", MAX_FUNNEL_NAME_LEN)
                step_pairs = _check_steps(steps)
                window = _check_window(conversion_window)
            except APIAnalyticsError as exc:
                self._rejected(seq, "funnel", str(exc))
                raise
            counts = self._funnel_counts(step_pairs, window)
            rates = tuple(
                round(c / counts[0], 6) if counts[0] else 0.0 for c in counts
            )
            report = FunnelReport(
                name=funnel_name, steps=step_pairs, conversion_window=window,
                seq=seq, step_counts=tuple(counts), conversion_rates=rates,
                analyzed_calls=len(self._calls),
            )
            report = replace(report, record_digest=compute_funnel_digest(report))
            self._audit_event(
                KIND_FUNNEL, seq, name=funnel_name,
                step_counts=list(counts), analyzed_calls=len(self._calls),
            )
            return report

    def _funnel_counts(self, steps: tuple, window: int) -> list[int]:
        counts = [0] * len(steps)
        for calls in self._by_user.values():
            entry_seq: int | None = None
            prev_seq = -1
            reached = 0
            for call in calls:  # already in seq order
                if reached == 0:
                    if self._matches(call, steps[0]):
                        entry_seq = call.seq
                        prev_seq = call.seq
                        reached = 1
                else:
                    if (
                        call.seq > prev_seq
                        and call.seq <= entry_seq + window
                        and self._matches(call, steps[reached])
                    ):
                        prev_seq = call.seq
                        reached += 1
                        if reached == len(steps):
                            break
            for i in range(reached):
                counts[i] += 1
        return counts

    def cohort(
        self,
        anchor_step: tuple,
        activity_step: tuple,
        seq: int,
        bucket_size: int,
        periods: int,
    ) -> CohortReport:
        """Run a retention-cohort query over the ledger.

        Users are bucketed by ``anchor_seq // bucket_size`` using the
        first call matching ``anchor_step`` per user. Retention for
        period ``p`` is the fraction of the bucket with at least one
        call matching ``activity_step`` in
        ``[anchor + p*bucket_size, anchor + (p+1)*bucket_size)``.
        """
        with self._lock:
            self._claim_seq(seq)
            try:
                anchor = _check_step(list(anchor_step))
                activity = _check_step(list(activity_step))
                size = _check_bucket_size(bucket_size)
                n_periods = _check_periods(periods)
            except APIAnalyticsError as exc:
                self._rejected(seq, "cohort", str(exc))
                raise
            buckets = self._cohort_buckets(anchor, activity, size, n_periods)
            report = CohortReport(
                anchor_step=anchor, activity_step=activity,
                bucket_size=size, periods=n_periods, seq=seq,
                buckets=tuple(buckets),
            )
            report = replace(report, record_digest=compute_cohort_digest(report))
            self._audit_event(
                KIND_COHORT, seq,
                anchor_step=[anchor[0], anchor[1]],
                activity_step=[activity[0], activity[1]],
                bucket_count=len(buckets),
                analyzed_calls=len(self._calls),
            )
            return report

    def _cohort_buckets(
        self, anchor: tuple, activity: tuple, size: int, periods: int
    ) -> list:
        # First anchor-step call per user (calls are in seq order).
        anchors: dict[str, int] = {}
        for call in self._calls:
            if call.user_id not in anchors and self._matches(call, anchor):
                anchors[call.user_id] = call.seq
        activity_seqs: dict[str, list[int]] = {}
        for call in self._calls:
            if self._matches(call, activity):
                activity_seqs.setdefault(call.user_id, []).append(call.seq)
        buckets: dict[int, dict[str, Any]] = {}
        for user_id, anchor_seq in anchors.items():
            index = anchor_seq // size
            bucket = buckets.setdefault(index, {"members": 0, "retained": [0] * periods})
            bucket["members"] += 1
            for p in range(periods):
                lo = anchor_seq + p * size
                hi = anchor_seq + (p + 1) * size
                if any(lo <= s < hi for s in activity_seqs.get(user_id, ())):
                    bucket["retained"][p] += 1
        return [
            (index, bucket["members"], tuple(bucket["retained"]))
            for index, bucket in sorted(buckets.items())
        ]

    # -- views ----------------------------------------------------------------

    def call(self, call_id: str) -> APITrackedCall:
        """Return the sealed call record for ``call_id``."""
        try:
            return self._by_id[call_id]
        except KeyError:
            raise UnknownCallError(f"unknown call id: {call_id!r}") from None

    def call_ids(self) -> tuple:
        """All call ids in ledger order."""
        return tuple(call.call_id for call in self._calls)

    def calls_for(self, user_id: str) -> tuple:
        """All sealed call records for one user, in ledger order."""
        uid = _check_user_id(user_id)
        return tuple(self._by_user.get(uid, ()))

    def stats(self) -> Mapping[str, Any]:
        """Ledger totals (aggregate counts only)."""
        return {
            "calls": len(self._calls),
            "users": len(self._by_user),
            "last_seq": self._last_seq,
        }

    def audit_log(self) -> tuple:
        """All audit events emitted so far, in order."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: track, funnel, cohort, digest pins, audit."""
    aa = APIAnalytics()
    c1 = aa.track("u1", "GET", "/signup", 1)
    aa.track("u1", "POST", "/checkout", 2)
    aa.track("u2", "GET", "/signup", 3)
    funnel = aa.funnel(
        "onboarding",
        [("GET", "/signup"), ("POST", "/checkout")],
        4,
        conversion_window=10,
    )
    cohort = aa.cohort(
        ("GET", "/signup"), ("POST", "/checkout"),
        5, bucket_size=10, periods=2,
    )
    assert funnel.step_counts == (2, 1), funnel.step_counts
    assert cohort.buckets[0][1] == 2, cohort.buckets
    assert compute_call_digest(c1) == c1.record_digest
    assert compute_funnel_digest(funnel) == funnel.record_digest
    assert compute_cohort_digest(cohort) == cohort.record_digest
    kinds = {e["kind"] for e in aa.audit_log()}
    assert KIND_CALL_TRACKED in kinds and KIND_FUNNEL in kinds and KIND_COHORT in kinds
    print("api-analytics OK: track, funnel, cohort, pins, audit")


if __name__ == "__main__":
    main()
