"""Synthetic monitoring — simulated uptime-check bookkeeping (thirty-second batch).

Research note (synthetic monitoring literature): Datadog, Pingdom,
and Prometheus' blackbox_exporter model synthetic checks as
*caller-scheduled probes* against a target; each probe records a
verdict (up/down/degraded), a latency figure, and the results of a
pinned set of assertions (HTTP status, keyword presence, TLS
certificate validity). Alerting reduces to *firing conditions* over
the results ledger (N consecutive failures, latency above a
threshold, availability below an SLO); SLOs are pinned targets
(e.g. 99.9%) evaluated over a rolling window. This module takes the
intersection for a single-host deterministic ledger:

* **Definitions, not probes**: ``define`` books a check definition
  (kind, target, assertion vocabulary, interval in logical-seq
  units). No timers fire — ``due`` is a pure caller-driven view of
  which checks are overdue at a given seq.
* **Host-reported observations**: ``check`` books a measurement the
  host reports (status, latency, which assertions passed). The
  verdict is computed deterministically from the *declared*
  assertions; observations are GIGO.
* **Alerts as data**: ``alert`` books a firing policy; ``evaluate``
  is a pure view returning ``firing`` as data, never raising an
  action. ``sla`` books an availability report over the last N
  results with an SLO met/unmet verdict as data.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), sha256 digest pins over type-tagged canonical payloads,
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* check results
deterministically. It performs no network probing, cannot observe
wire truth, and cannot prove a target is reachable — the host
declares every observation. An ``up`` record means "the host
reported success", never "the target answered". A firing alert is a
record, not a page; production still needs a real prober, a
notification path, and an on-call rotation.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
SYNTHETIC_MONITOR_VERSION = "synthetic-monitor.v1"

#: Schema pin carried by records and audit events.
SYNTHETIC_MONITOR_SCHEMA = "northstar.synthetic-monitor.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned check kinds (probe vocabulary; drift detectable).
KIND_HTTP = "http"
KIND_TCP = "tcp"
KIND_DNS = "dns"
KIND_SSL = "ssl"
KIND_ICMP = "icmp"
KIND_KEYWORD = "keyword"
CHECK_KINDS = (KIND_HTTP, KIND_TCP, KIND_DNS, KIND_SSL, KIND_ICMP, KIND_KEYWORD)

#: Pinned assertion vocabulary (each definition declares a subset).
ASSERT_STATUS_2XX = "status-2xx"
ASSERT_LATENCY_LE = "latency-ms-le"
ASSERT_KEYWORD_PRESENT = "keyword-present"
ASSERT_CERT_VALID = "cert-valid"
ASSERTIONS = (
    ASSERT_STATUS_2XX,
    ASSERT_LATENCY_LE,
    ASSERT_KEYWORD_PRESENT,
    ASSERT_CERT_VALID,
)

#: Assertion parameters: ``(kind, operand)``. Operands are validated per
#: kind at definition time.
_PARAMLESS_ASSERTIONS = (ASSERT_STATUS_2XX, ASSERT_KEYWORD_PRESENT, ASSERT_CERT_VALID)

#: Result verdicts (computed data).
STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_DEGRADED = "degraded"
RESULT_STATUSES = (STATUS_UP, STATUS_DOWN, STATUS_DEGRADED)

#: Observation statuses the host may report.
OBS_UP = "up"
OBS_DOWN = "down"
OBS_STATUSES = (OBS_UP, OBS_DOWN)

#: Alert firing conditions.
COND_CONSECUTIVE_FAILURES = "consecutive-failures"
COND_LATENCY_GT = "latency-ms-gt"
COND_AVAILABILITY_BELOW = "availability-below"
ALERT_CONDITIONS = (
    COND_CONSECUTIVE_FAILURES,
    COND_LATENCY_GT,
    COND_AVAILABILITY_BELOW,
)

#: Pinned SLO targets (percent).
SLO_TARGETS = (99.0, 99.9, 99.95, 99.99)

#: Audit event kinds.
KIND_CHECK_DEFINED = "synthetic.check-defined"
KIND_CHECKED = "synthetic.checked"
KIND_ALERT_DEFINED = "synthetic.alert-defined"
KIND_ALERT_EVALUATED = "synthetic.alert-evaluated"
KIND_SLA_REPORTED = "synthetic.sla-reported"
KIND_REJECTED = "synthetic.rejected"
_KINDS = (
    KIND_CHECK_DEFINED,
    KIND_CHECKED,
    KIND_ALERT_DEFINED,
    KIND_ALERT_EVALUATED,
    KIND_SLA_REPORTED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SyntheticMonitorError(ValueError):
    """Base error for the synthetic monitor."""


class BadCheckError(SyntheticMonitorError):
    """Malformed check definition (bad kind, target, interval, assertions)."""


class DuplicateCheckError(SyntheticMonitorError):
    """A check with this id is already defined."""


class UnknownCheckError(SyntheticMonitorError):
    """No check with this id is defined."""


class BadObservationError(SyntheticMonitorError):
    """Malformed host-reported observation."""


class BadAlertError(SyntheticMonitorError):
    """Malformed alert policy (bad condition, threshold, window)."""


class DuplicateAlertError(SyntheticMonitorError):
    """An alert policy with this id is already defined."""


class UnknownAlertError(SyntheticMonitorError):
    """No alert policy with this id is defined."""


class BadSlaError(SyntheticMonitorError):
    """Malformed SLO report request (bad target, window)."""


class SeqOrderError(SyntheticMonitorError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SyntheticMonitorError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SyntheticMonitorError(f"{field_name} must be a non-empty string")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise SyntheticMonitorError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise SyntheticMonitorError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise SyntheticMonitorError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckDefinition:
    """A pinned synthetic check definition."""

    check_id: str
    name: str
    kind: str
    target: str
    interval_seq: int
    assertions: tuple
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "check-definition",
                    self.check_id,
                    self.name,
                    self.kind,
                    self.target,
                    self.interval_seq,
                    [list(a) for a in self.assertions],
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class CheckResult:
    """A sealed, host-reported check outcome."""

    result_id: str
    check_id: str
    status: str
    latency_ms: int
    assertions_passed: tuple
    assertions_failed: tuple
    prev_digest: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "check-result",
                    self.result_id,
                    self.check_id,
                    self.status,
                    self.latency_ms,
                    sorted(self.assertions_passed),
                    sorted(self.assertions_failed),
                    self.prev_digest,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class AlertPolicy:
    """A pinned firing policy over the results ledger."""

    alert_id: str
    check_id: str
    condition: str
    threshold: float
    window: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "alert-policy",
                    self.alert_id,
                    self.check_id,
                    self.condition,
                    repr(self.threshold),
                    self.window,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class AlertEvaluation:
    """A pure-view firing verdict (data, never an action)."""

    alert_id: str
    firing: bool
    detail: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["alert-evaluation", self.alert_id, self.firing, self.detail],
                seed,
            ),
        )


@dataclass(frozen=True)
class SLAReport:
    """An availability report over the last N results."""

    check_id: str
    slo: float
    window: int
    total: int
    ups: int
    downs: int
    availability: float
    met: bool
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "sla-report",
                    self.check_id,
                    repr(self.slo),
                    self.window,
                    self.total,
                    self.ups,
                    self.downs,
                ],
                seed,
            ),
        )


def synthetic_monitor_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the synthetic monitor."""
    if kind not in _KINDS:
        raise SyntheticMonitorError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "synthetic_monitor",
        "module_version": SYNTHETIC_MONITOR_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SyntheticMonitor
# ---------------------------------------------------------------------------


class SyntheticMonitor:
    """Deterministic synthetic-monitoring bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads (``evaluate``, ``sla``, ``due``) validate the seq shape but do
    not consume it; ``evaluate`` and ``sla`` append read audit events
    (the audited-read house pattern), ``due`` writes nothing.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._checks: dict[str, CheckDefinition] = {}
        self._results: dict[str, CheckResult] = {}
        self._result_ids: list[str] = []
        self._alerts: dict[str, AlertPolicy] = {}
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(synthetic_monitor_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _validate_assertions(self, assertions: Any) -> tuple:
        if (
            not isinstance(assertions, (list, tuple))
            or not assertions
            or not all(isinstance(a, (list, tuple)) and len(a) == 2 for a in assertions)
        ):
            raise BadCheckError("assertions must be a non-empty list of (kind, operand)")
        cleaned: list[tuple] = []
        for kind, operand in assertions:
            if kind not in ASSERTIONS:
                raise BadCheckError(f"unknown assertion: {kind!r}")
            if kind in _PARAMLESS_ASSERTIONS:
                if operand is not None:
                    raise BadCheckError(f"assertion {kind!r} takes no operand")
            else:  # latency-ms-le: operand must be a positive int of milliseconds
                if (
                    isinstance(operand, bool)
                    or not isinstance(operand, int)
                    or operand <= 0
                ):
                    raise BadCheckError(
                        f"assertion {kind!r} needs a positive int operand"
                    )
            cleaned.append((kind, operand))
        kinds = [k for k, _ in cleaned]
        if len(set(kinds)) != len(kinds):
            raise BadCheckError("duplicate assertion kinds")
        return tuple(cleaned)

    # -- check definitions ----------------------------------------------

    def define(
        self,
        check_id: str,
        name: str,
        kind: str,
        target: str,
        interval_seq: int,
        assertions: Any,
        seq: int,
    ) -> CheckDefinition:
        """Book a synthetic check definition (no timers; ``due`` is the view)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                check_id = _check_nonempty_str(check_id, "check_id")
                name = _check_nonempty_str(name, "name")
                if kind not in CHECK_KINDS:
                    raise BadCheckError(f"unknown check kind: {kind!r}")
                target = _check_nonempty_str(target, "target")
                if (
                    isinstance(interval_seq, bool)
                    or not isinstance(interval_seq, int)
                    or interval_seq <= 0
                ):
                    raise BadCheckError("interval_seq must be a positive int")
                cleaned = self._validate_assertions(assertions)
                if check_id in self._checks:
                    raise DuplicateCheckError(f"check already defined: {check_id!r}")
            except SyntheticMonitorError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                [
                    "check-definition",
                    check_id,
                    name,
                    kind,
                    target,
                    interval_seq,
                    [list(a) for a in cleaned],
                ],
                self._seed,
            )
            record = CheckDefinition(
                check_id=check_id,
                name=name,
                kind=kind,
                target=target,
                interval_seq=interval_seq,
                assertions=cleaned,
                digest=digest,
            )
            self._checks[check_id] = record
            self._emit(
                KIND_CHECK_DEFINED,
                seq,
                check_id=check_id,
                check_kind=kind,
                digest=digest,
            )
            return record

    # -- check runs --------------------------------------------------------

    def check(
        self, check_id: str, observation: Mapping[str, Any], seq: int
    ) -> CheckResult:
        """Book a host-reported observation; verdict is computed deterministically."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                if check_id not in self._checks:
                    raise UnknownCheckError(f"unknown check: {check_id!r}")
                if not isinstance(observation, Mapping):
                    raise BadObservationError("observation must be a mapping")
                status = observation.get("status")
                if status not in OBS_STATUSES:
                    raise BadObservationError("observation status must be up/down")
                latency = observation.get("latency_ms")
                if (
                    isinstance(latency, bool)
                    or not isinstance(latency, int)
                    or latency < 0
                    or latency >= 2**53
                ):
                    raise BadObservationError("latency_ms must be a non-negative int")
                reported = observation.get("assertions_passed", ())
                if not isinstance(reported, (list, tuple)) or not all(
                    isinstance(a, str) for a in reported
                ):
                    raise BadObservationError("assertions_passed must be a list of str")
                reported_set = set(reported)
                declared = self._checks[check_id].assertions
                declared_kinds = {k for k, _ in declared}
                if not reported_set <= declared_kinds:
                    raise BadObservationError(
                        "reported assertion not declared on the check"
                    )
                for kind, operand in declared:
                    if kind == ASSERT_LATENCY_LE and status == OBS_UP:
                        if latency > operand:
                            raise BadObservationError(
                                "latency exceeds declared latency-ms-le but status is up"
                            )
            except SyntheticMonitorError as exc:
                self._reject(seq, str(exc))
                raise
            definition = self._checks[check_id]
            declared_kinds = {k for k, _ in definition.assertions}
            if status == OBS_DOWN:
                verdict = STATUS_DOWN
            elif reported_set == declared_kinds:
                verdict = STATUS_UP
            else:
                verdict = STATUS_DEGRADED
            failed = tuple(sorted(declared_kinds - reported_set))
            prev = (
                self._results[self._result_ids[-1]].digest if self._result_ids else _GENESIS
            )
            result_id = f"res-{len(self._result_ids) + 1}"
            digest = _pin(
                [
                    "check-result",
                    result_id,
                    check_id,
                    verdict,
                    latency,
                    sorted(reported_set),
                    sorted(failed),
                    prev,
                ],
                self._seed,
            )
            record = CheckResult(
                result_id=result_id,
                check_id=check_id,
                status=verdict,
                latency_ms=latency,
                assertions_passed=tuple(sorted(reported_set)),
                assertions_failed=failed,
                prev_digest=prev,
                digest=digest,
            )
            self._results[result_id] = record
            self._result_ids.append(result_id)
            self._emit(
                KIND_CHECKED,
                seq,
                check_id=check_id,
                result_id=result_id,
                verdict=verdict,
                digest=digest,
            )
            return record

    # -- alert policies ----------------------------------------------------

    def alert(
        self,
        alert_id: str,
        check_id: str,
        condition: str,
        threshold: Any,
        seq: int,
        window: int = 10,
    ) -> AlertPolicy:
        """Book a firing policy over the results ledger (verdicts are data)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                alert_id = _check_nonempty_str(alert_id, "alert_id")
                if check_id not in self._checks:
                    raise UnknownCheckError(f"unknown check: {check_id!r}")
                if condition not in ALERT_CONDITIONS:
                    raise BadAlertError(f"unknown alert condition: {condition!r}")
                if (
                    isinstance(threshold, bool)
                    or not isinstance(threshold, (int, float))
                    or threshold != threshold
                    or threshold in (float("inf"), float("-inf"))
                ):
                    raise BadAlertError("threshold must be a finite number")
                threshold = float(threshold)
                if condition == COND_CONSECUTIVE_FAILURES and (
                    not threshold.is_integer() or threshold <= 0
                ):
                    raise BadAlertError("consecutive-failures needs a positive int")
                if condition == COND_AVAILABILITY_BELOW and not (
                    0 < threshold < 100
                ):
                    raise BadAlertError("availability-below needs 0 < threshold < 100")
                if condition == COND_LATENCY_GT and threshold <= 0:
                    raise BadAlertError("latency-ms-gt needs a positive threshold")
                if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
                    raise BadAlertError("window must be a positive int")
                if alert_id in self._alerts:
                    raise DuplicateAlertError(f"alert already defined: {alert_id!r}")
            except SyntheticMonitorError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                [
                    "alert-policy",
                    alert_id,
                    check_id,
                    condition,
                    repr(threshold),
                    window,
                ],
                self._seed,
            )
            policy = AlertPolicy(
                alert_id=alert_id,
                check_id=check_id,
                condition=condition,
                threshold=threshold,
                window=window,
                digest=digest,
            )
            self._alerts[alert_id] = policy
            self._emit(
                KIND_ALERT_DEFINED,
                seq,
                alert_id=alert_id,
                check_id=check_id,
                condition=condition,
                digest=digest,
            )
            return policy

    def evaluate(self, alert_id: str, seq: int) -> AlertEvaluation:
        """Firing verdict over the results ledger.

        Pure view on the ledger: the seq is validated but not consumed.
        Appends an audited-read event; the returned verdict is data,
        never an action.
        """
        _check_seq(seq, "seq")
        with self._lock:
            if alert_id not in self._alerts:
                raise UnknownAlertError(f"unknown alert: {alert_id!r}")
            policy = self._alerts[alert_id]
            history = [
                self._results[r] for r in self._result_ids if r and self._results[r].check_id == policy.check_id
            ]
            if policy.condition == COND_CONSECUTIVE_FAILURES:
                need = int(policy.threshold)
                tail = [r.status != STATUS_UP for r in history[-need:]]
                firing = len(tail) == need and all(tail)
                detail = f"trailing-not-up={len([t for t in tail if t])}/{need}"
            elif policy.condition == COND_LATENCY_GT:
                last = history[-1] if history else None
                firing = last is not None and last.latency_ms > policy.threshold
                detail = (
                    f"last-latency-ms={last.latency_ms if last else 'none'}"
                )
            else:  # availability-below
                windowed = history[-policy.window :]
                total = len(windowed)
                ups = sum(1 for r in windowed if r.status == STATUS_UP)
                avail = (100.0 * ups / total) if total else 100.0
                firing = avail < policy.threshold
                detail = f"availability={avail:.4f}%<{policy.threshold}%"
            digest = _pin(
                ["alert-evaluation", alert_id, firing, detail], self._seed
            )
            evaluation = AlertEvaluation(
                alert_id=alert_id, firing=firing, detail=detail, digest=digest
            )
            self._emit(KIND_ALERT_EVALUATED, seq, alert_id=alert_id, firing=firing)
            return evaluation

    # -- SLO reports ---------------------------------------------------------

    def sla(
        self, check_id: str, slo: float, seq: int, window: int = 100
    ) -> SLAReport:
        """Availability over the last N results vs a pinned SLO target.

        Pure view on the ledger: the seq is validated but not consumed.
        Appends an audited-read event; the met/unmet verdict is data.
        """
        _check_seq(seq, "seq")
        with self._lock:
            if check_id not in self._checks:
                raise UnknownCheckError(f"unknown check: {check_id!r}")
            if slo not in SLO_TARGETS:
                raise BadSlaError(f"slo must be one of {SLO_TARGETS}")
            if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
                raise BadSlaError("window must be a positive int")
            history = [
                self._results[r]
                for r in self._result_ids
                if self._results[r].check_id == check_id
            ][-window:]
            total = len(history)
            ups = sum(1 for r in history if r.status == STATUS_UP)
            downs = total - ups
            availability = round(100.0 * ups / total, 6) if total else 100.0
            met = availability >= slo
            digest = _pin(
                [
                    "sla-report",
                    check_id,
                    repr(float(slo)),
                    window,
                    total,
                    ups,
                    downs,
                ],
                self._seed,
            )
            report = SLAReport(
                check_id=check_id,
                slo=float(slo),
                window=window,
                total=total,
                ups=ups,
                downs=downs,
                availability=availability,
                met=met,
                digest=digest,
            )
            self._emit(
                KIND_SLA_REPORTED,
                seq,
                check_id=check_id,
                availability=availability,
                met=met,
                digest=digest,
            )
            return report

    def due(self, seq: int) -> tuple:
        """Pure view: check ids overdue for a run at ``seq`` (never run or past interval)."""
        _check_seq(seq, "seq")
        with self._lock:
            last_run: dict[str, int] = {}
            # logical run clock: the host ticks seq; a check's last run seq is
            # derived from its results' insertion order counter.
            run_seq = 0
            for rid in self._result_ids:
                run_seq += 1
                last_run[self._results[rid].check_id] = run_seq
            overdue = []
            for check_id, definition in self._checks.items():
                prior = last_run.get(check_id)
                if prior is None or prior + definition.interval_seq <= run_seq:
                    overdue.append(check_id)
            return tuple(sorted(overdue))

    # -- views ----------------------------------------------------------------

    def definition(self, check_id: str) -> CheckDefinition:
        with self._lock:
            if check_id not in self._checks:
                raise UnknownCheckError(f"unknown check: {check_id!r}")
            return self._checks[check_id]

    def result(self, result_id: str) -> CheckResult:
        with self._lock:
            if result_id not in self._results:
                raise SyntheticMonitorError(f"unknown result: {result_id!r}")
            return self._results[result_id]

    def results_for(self, check_id: str) -> tuple:
        with self._lock:
            if check_id not in self._checks:
                raise UnknownCheckError(f"unknown check: {check_id!r}")
            return tuple(
                r
                for r in (self._results[rid] for rid in self._result_ids)
                if r.check_id == check_id
            )

    def alert_policy(self, alert_id: str) -> AlertPolicy:
        with self._lock:
            if alert_id not in self._alerts:
                raise UnknownAlertError(f"unknown alert: {alert_id!r}")
            return self._alerts[alert_id]

    def check_ids(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._checks))

    def alert_ids(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._alerts))

    def stats(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "checks": len(self._checks),
                "results": len(self._results),
                "alerts": len(self._alerts),
                "audit_events": len(self._audit_log),
            }

    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "module": "synthetic_monitor",
                "version": SYNTHETIC_MONITOR_VERSION,
                "schema": SYNTHETIC_MONITOR_SCHEMA,
                "checks": [c.check_id for c in self._checks.values()],
                "results": len(self._results),
                "alerts": [a.alert_id for a in self._alerts.values()],
                "last_seq": self._last_seq,
            }


def main() -> None:
    mon = SyntheticMonitor(seed="selfcheck")
    mon.define(
        "web",
        "homepage probe",
        "http",
        "https://example.com",
        5,
        [(ASSERT_STATUS_2XX, None), (ASSERT_LATENCY_LE, 500)],
        0,
    )
    r = mon.check(
        "web",
        {"status": "up", "latency_ms": 120, "assertions_passed": [ASSERT_STATUS_2XX, ASSERT_LATENCY_LE]},
        1,
    )
    assert r.status == "up" and r.verify(seed="selfcheck")
    mon.alert("web-fail", "web", COND_CONSECUTIVE_FAILURES, 3, 2)
    ev = mon.evaluate("web-fail", 2)
    assert ev.firing is False and ev.verify(seed="selfcheck")
    report = mon.sla("web", 99.9, 2)
    assert report.met is True and report.verify(seed="selfcheck")
    assert mon.due(3) == ()
    print("synthetic-monitor OK: define, check, alert, evaluate, sla, due, pins, audit")


if __name__ == "__main__":
    main()
