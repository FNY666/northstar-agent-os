"""Capacity planning: utilization ledger, forecasts, rightsizing recommendations.

AWS Compute Optimizer-shaped capacity bookkeeping as a deterministic
single-host state machine:

- ``register_workload(workload_id, resource_type, seq, current_size="")``
  pins a workload of a pinned resource-type vocabulary
  (``ec2``/``rds``/``lambda``/``ecs``/``ebs``).
- ``record_utilization(workload_id, cpu_pct, memory_pct, seq)`` books a
  host-reported utilization sample (``utl-N`` ids, hash-chained via
  ``prev_digest``).
- ``forecast(workload_id, horizon_seq, seq)`` is a pure read view:
  average + linear-trend projection clamped to [0, 100] over
  ``horizon_seq`` logical-seq units into the future.
- ``rightsize(workload_id, seq)`` is a pure read view returning the
  recommendation as *data* (``downsize``/``upsize``/``optimal``/
  ``insufficient-data``) — a suggestion, not an action.
- ``report(seq)`` is a pure read view aggregating the fleet by
  recommendation category.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``capacity-planning.v1``, schema pin ``northstar.capacity-planning.v1``,
``main()`` self-check.

Honest scope: this module books *host-reported* utilization and does
deterministic arithmetic on those numbers. It cannot verify the samples
are representative, cannot measure anything, cannot observe real load,
and a ``downsize`` recommendation is not a safe action — pair with real
telemetry before touching production capacity. A quiet ledger means
"nothing reported", never "nothing needed".
"""

from __future__ import annotations

import hashlib
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
CAPACITY_PLANNING_VERSION = "capacity-planning.v1"

#: Schema pin carried by records and audit events.
CAPACITY_PLANNING_SCHEMA = "northstar.capacity-planning.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pinned resource-type vocabulary (AWS Compute Optimizer supports these).
_RESOURCE_TYPES = ("ec2", "rds", "lambda", "ecs", "ebs")

#: Recommendation categories.
RECOMMENDATION_DOWNSIZE = "downsize"
RECOMMENDATION_UPSIZE = "upsize"
RECOMMENDATION_OPTIMAL = "optimal"
RECOMMENDATION_INSUFFICIENT = "insufficient-data"
_RECOMMENDATIONS = (
    RECOMMENDATION_DOWNSIZE,
    RECOMMENDATION_UPSIZE,
    RECOMMENDATION_OPTIMAL,
    RECOMMENDATION_INSUFFICIENT,
)

#: Rightsize thresholds (pinned): downsize when both avg_cpu < 20 and
#: avg_mem < 40; upsize when avg_cpu > 85 or avg_mem > 90.
_DOWNSIZE_CPU = 20.0
_DOWNSIZE_MEM = 40.0
_UPSIZE_CPU = 85.0
_UPSIZE_MEM = 90.0

#: Utilization values are clamped to this range.
_PCT_MIN = 0.0
_PCT_MAX = 100.0


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class CapacityPlanningError(ValueError):
    """Base for all capacity-planning structural problems and refusals."""


class BadWorkloadError(CapacityPlanningError):
    """Workload definition is malformed (bad id, resource type, size)."""


class DuplicateWorkloadError(CapacityPlanningError):
    """A workload id is already registered."""


class UnknownWorkloadError(CapacityPlanningError):
    """No workload is pinned for the requested id."""


class BadUtilizationError(CapacityPlanningError):
    """A utilization sample is malformed (bad values or workload)."""


class BadForecastError(CapacityPlanningError):
    """A forecast request is malformed (bad horizon or workload)."""


class SeqOrderError(CapacityPlanningError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_seq_shape(value: Any, name: str) -> int:
    """Validate a seq shape for pure read views (does not consume)."""
    return _check_seq(value, name)


def _check_nonempty_str(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapacityPlanningError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > max_len:
        raise CapacityPlanningError(f"{name} must be at most {max_len} chars")
    return value


def _check_pct(value: Any, name: str, exc: type = BadUtilizationError) -> float:
    if isinstance(value, bool):
        raise exc(f"{name} must be a number, not bool")
    if not isinstance(value, (int, float)):
        raise exc(f"{name} must be a number")
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise exc(f"{name} must be finite")
    if not (_PCT_MIN <= value <= _PCT_MAX):
        raise exc(f"{name} must be in [{_PCT_MIN}, {_PCT_MAX}]")
    return round(value, 6)


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([CAPACITY_PLANNING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkloadRecord:
    """One pinned workload (frozen)."""

    workload_id: str
    resource_type: str
    current_size: str
    seq: int
    digest: str
    schema: str = CAPACITY_PLANNING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "workload", self.workload_id, self.resource_type,
            self.current_size, self.seq,
        )


@dataclass(frozen=True)
class UtilizationSample:
    """One host-reported utilization sample (frozen, hash-chained)."""

    sample_id: str
    workload_id: str
    cpu_pct: float
    memory_pct: float
    seq: int
    prev_digest: str
    digest: str
    schema: str = CAPACITY_PLANNING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "sample", self.sample_id, self.workload_id, self.cpu_pct,
            self.memory_pct, self.seq, self.prev_digest,
        )


@dataclass(frozen=True)
class ForecastReport:
    """One deterministic utilization projection (frozen, pure view)."""

    workload_id: str
    horizon_seq: int
    avg_cpu: float
    avg_memory: float
    trend_cpu: float
    trend_memory: float
    projected_cpu: float
    projected_memory: float
    sample_count: int
    seq: int
    digest: str
    schema: str = CAPACITY_PLANNING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "forecast", self.workload_id, self.horizon_seq, self.avg_cpu,
            self.avg_memory, self.trend_cpu, self.trend_memory,
            self.projected_cpu, self.projected_memory, self.sample_count,
            self.seq,
        )


@dataclass(frozen=True)
class RightsizeRecommendation:
    """One rightsizing recommendation (frozen, data — not an action)."""

    workload_id: str
    recommendation: str
    reason: str
    avg_cpu: float
    avg_memory: float
    sample_count: int
    seq: int
    digest: str
    schema: str = CAPACITY_PLANNING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "rightsize", self.workload_id, self.recommendation, self.reason,
            self.avg_cpu, self.avg_memory, self.sample_count, self.seq,
        )


@dataclass(frozen=True)
class FleetReport:
    """One fleet-wide aggregation (frozen, pure view)."""

    total_workloads: int
    with_samples: int
    downsize: int
    upsize: int
    optimal: int
    insufficient_data: int
    seq: int
    digest: str
    schema: str = CAPACITY_PLANNING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "fleet", self.total_workloads, self.with_samples, self.downsize,
            self.upsize, self.optimal, self.insufficient_data, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_WORKLOAD_REGISTERED = "capacity.workload-registered"
KIND_UTILIZATION_RECORDED = "capacity.utilization-recorded"
KIND_REJECTED = "capacity.rejected"
_KINDS = (KIND_WORKLOAD_REGISTERED, KIND_UTILIZATION_RECORDED, KIND_REJECTED)


def capacity_planning_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the capacity-planning module."""
    if kind not in _KINDS:
        raise CapacityPlanningError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise CapacityPlanningError("detail must be a mapping")
    # Raw utilization values never cross the audit boundary; pins only.
    banned = {"cpu_pct", "memory_pct", "samples", "values"}
    if any(k in detail for k in banned):
        raise CapacityPlanningError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CAPACITY_PLANNING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class CapacityPlanning:
    """Deterministic capacity-planning utilization/forecast ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). Pure read views
    (``forecast``, ``rightsize``, ``report``) validate the seq shape
    but consume nothing and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._workloads: Dict[str, WorkloadRecord] = {}
        self._samples: Dict[str, List[UtilizationSample]] = {}
        self._sample_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        self._seq = seq
        return seq

    def _reject(self, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(
            capacity_planning_audit_event(KIND_REJECTED, detail, seq)
        )

    def _reject_locked(self, exc: CapacityPlanningError,
                       detail: Mapping[str, Any], seq: int) -> None:
        self._reject(detail, seq)
        raise exc

    def _averages(self, workload_id: str) -> Tuple[float, float, int]:
        samples = self._samples.get(workload_id, [])
        n = len(samples)
        if n == 0:
            return 0.0, 0.0, 0
        avg_cpu = round(sum(s.cpu_pct for s in samples) / n, 6)
        avg_mem = round(sum(s.memory_pct for s in samples) / n, 6)
        return avg_cpu, avg_mem, n

    def _trends(self, workload_id: str) -> Tuple[float, float]:
        samples = self._samples.get(workload_id, [])
        n = len(samples)
        if n < 2:
            return 0.0, 0.0
        trend_cpu = round(
            (samples[-1].cpu_pct - samples[0].cpu_pct) / (n - 1), 6
        )
        trend_mem = round(
            (samples[-1].memory_pct - samples[0].memory_pct) / (n - 1), 6
        )
        return trend_cpu, trend_mem

    def _recommend(self, workload_id: str) -> Tuple[str, str, float, float, int]:
        avg_cpu, avg_mem, n = self._averages(workload_id)
        if n == 0:
            return (
                RECOMMENDATION_INSUFFICIENT, "no utilization samples booked",
                avg_cpu, avg_mem, n,
            )
        if avg_cpu < _DOWNSIZE_CPU and avg_mem < _DOWNSIZE_MEM:
            return (
                RECOMMENDATION_DOWNSIZE,
                f"avg_cpu={avg_cpu} < {_DOWNSIZE_CPU} and "
                f"avg_mem={avg_mem} < {_DOWNSIZE_MEM}",
                avg_cpu, avg_mem, n,
            )
        if avg_cpu > _UPSIZE_CPU or avg_mem > _UPSIZE_MEM:
            return (
                RECOMMENDATION_UPSIZE,
                f"avg_cpu={avg_cpu} or avg_mem={avg_mem} above "
                f"upsize thresholds ({_UPSIZE_CPU}/{_UPSIZE_MEM})",
                avg_cpu, avg_mem, n,
            )
        return (
            RECOMMENDATION_OPTIMAL,
            f"avg_cpu={avg_cpu} within "
            f"[{_DOWNSIZE_CPU}, {_UPSIZE_CPU}] and avg_mem={avg_mem} "
            f"within [{_DOWNSIZE_MEM}, {_UPSIZE_MEM}]",
            avg_cpu, avg_mem, n,
        )

    # -- mutations -----------------------------------------------------

    def register_workload(
        self,
        workload_id: str,
        resource_type: str,
        seq: int,
        current_size: str = "",
    ) -> WorkloadRecord:
        """Pin a workload; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                workload_id = _check_nonempty_str(workload_id, "workload_id")
                if (
                    not isinstance(resource_type, str)
                    or resource_type not in _RESOURCE_TYPES
                ):
                    raise BadWorkloadError(
                        f"resource_type must be one of {_RESOURCE_TYPES}"
                    )
                if not isinstance(current_size, str):
                    raise BadWorkloadError("current_size must be a string")
                current_size = current_size.strip()[:64]
                if workload_id in self._workloads:
                    raise DuplicateWorkloadError(
                        f"workload already registered: {workload_id!r}"
                    )
            except CapacityPlanningError as exc:
                self._reject_locked(
                    exc, {"workload_id": str(workload_id)}, seq
                )
            record = WorkloadRecord(
                workload_id=workload_id,
                resource_type=resource_type,
                current_size=current_size,
                seq=seq,
                digest=_pin(
                    "workload", workload_id, resource_type, current_size, seq
                ),
            )
            self._workloads[workload_id] = record
            self._samples[workload_id] = []
            self._audit.append(
                capacity_planning_audit_event(
                    KIND_WORKLOAD_REGISTERED,
                    {"workload_id": workload_id,
                     "resource_type": resource_type},
                    seq,
                )
            )
            return record

    def record_utilization(
        self,
        workload_id: str,
        cpu_pct: float,
        memory_pct: float,
        seq: int,
    ) -> UtilizationSample:
        """Book a host-reported utilization sample (hash-chained)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if (
                    not isinstance(workload_id, str)
                    or workload_id not in self._workloads
                ):
                    raise UnknownWorkloadError(
                        f"unknown workload: {workload_id!r}"
                    )
                cpu = _check_pct(cpu_pct, "cpu_pct")
                mem = _check_pct(memory_pct, "memory_pct")
            except CapacityPlanningError as exc:
                self._reject_locked(
                    exc, {"workload_id": str(workload_id)}, seq
                )
            self._sample_counter += 1
            sample_id = f"utl-{self._sample_counter}"
            prior = self._samples[workload_id]
            prev_digest = prior[-1].digest if prior else _GENESIS
            sample = UtilizationSample(
                sample_id=sample_id,
                workload_id=workload_id,
                cpu_pct=cpu,
                memory_pct=mem,
                seq=seq,
                prev_digest=prev_digest,
                digest=_pin(
                    "sample", sample_id, workload_id, cpu, mem, seq,
                    prev_digest,
                ),
            )
            prior.append(sample)
            self._audit.append(
                capacity_planning_audit_event(
                    KIND_UTILIZATION_RECORDED,
                    {"workload_id": workload_id, "sample_id": sample_id},
                    seq,
                )
            )
            return sample

    # -- pure read views ------------------------------------------------

    def forecast(
        self, workload_id: str, horizon_seq: int, seq: int
    ) -> ForecastReport:
        """Project avg + linear trend ``horizon_seq`` units out (pure view)."""
        with self._lock:
            seq = _check_seq_shape(seq, "seq")
            if (
                not isinstance(horizon_seq, bool)
                and isinstance(horizon_seq, int)
                and horizon_seq >= 0
            ):
                pass
            else:
                raise BadForecastError("horizon_seq must be a non-negative int")
            if (
                not isinstance(workload_id, str)
                or workload_id not in self._workloads
            ):
                raise UnknownWorkloadError(
                    f"unknown workload: {workload_id!r}"
                )
            avg_cpu, avg_mem, n = self._averages(workload_id)
            trend_cpu, trend_mem = self._trends(workload_id)
            projected_cpu = round(
                min(max(avg_cpu + trend_cpu * horizon_seq, 0.0), 100.0), 6
            )
            projected_mem = round(
                min(max(avg_mem + trend_mem * horizon_seq, 0.0), 100.0), 6
            )
            return ForecastReport(
                workload_id=workload_id,
                horizon_seq=horizon_seq,
                avg_cpu=avg_cpu,
                avg_memory=avg_mem,
                trend_cpu=trend_cpu,
                trend_memory=trend_mem,
                projected_cpu=projected_cpu,
                projected_memory=projected_mem,
                sample_count=n,
                seq=seq,
                digest=_pin(
                    "forecast", workload_id, horizon_seq, avg_cpu, avg_mem,
                    trend_cpu, trend_mem, projected_cpu, projected_mem, n,
                    seq,
                ),
            )

    def rightsize(self, workload_id: str, seq: int) -> RightsizeRecommendation:
        """Return the rightsizing recommendation as data (pure view)."""
        with self._lock:
            seq = _check_seq_shape(seq, "seq")
            if (
                not isinstance(workload_id, str)
                or workload_id not in self._workloads
            ):
                raise UnknownWorkloadError(
                    f"unknown workload: {workload_id!r}"
                )
            recommendation, reason, avg_cpu, avg_mem, n = self._recommend(
                workload_id
            )
            return RightsizeRecommendation(
                workload_id=workload_id,
                recommendation=recommendation,
                reason=reason,
                avg_cpu=avg_cpu,
                avg_memory=avg_mem,
                sample_count=n,
                seq=seq,
                digest=_pin(
                    "rightsize", workload_id, recommendation, reason,
                    avg_cpu, avg_mem, n, seq,
                ),
            )

    def report(self, seq: int) -> FleetReport:
        """Aggregate the fleet by recommendation category (pure view)."""
        with self._lock:
            seq = _check_seq_shape(seq, "seq")
            counts = {r: 0 for r in _RECOMMENDATIONS}
            with_samples = 0
            for workload_id in self._workloads:
                rec, _, _, _, n = self._recommend(workload_id)
                counts[rec] += 1
                if n > 0:
                    with_samples += 1
            total = len(self._workloads)
            return FleetReport(
                total_workloads=total,
                with_samples=with_samples,
                downsize=counts[RECOMMENDATION_DOWNSIZE],
                upsize=counts[RECOMMENDATION_UPSIZE],
                optimal=counts[RECOMMENDATION_OPTIMAL],
                insufficient_data=counts[RECOMMENDATION_INSUFFICIENT],
                seq=seq,
                digest=_pin(
                    "fleet", total, with_samples,
                    counts[RECOMMENDATION_DOWNSIZE],
                    counts[RECOMMENDATION_UPSIZE],
                    counts[RECOMMENDATION_OPTIMAL],
                    counts[RECOMMENDATION_INSUFFICIENT], seq,
                ),
            )

    # -- views ----------------------------------------------------------

    def workload(self, workload_id: str) -> WorkloadRecord:
        with self._lock:
            try:
                return self._workloads[workload_id]
            except KeyError:
                raise UnknownWorkloadError(
                    f"unknown workload: {workload_id!r}"
                )

    def workload_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._workloads))

    def samples_for(self, workload_id: str) -> Tuple[UtilizationSample, ...]:
        with self._lock:
            if workload_id not in self._workloads:
                raise UnknownWorkloadError(
                    f"unknown workload: {workload_id!r}"
                )
            return tuple(self._samples[workload_id])

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "workloads": len(self._workloads),
                "samples": sum(len(v) for v in self._samples.values()),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    cp = CapacityPlanning()
    cp.register_workload("w1", "ec2", 1, current_size="m5.large")
    cp.record_utilization("w1", 8.0, 12.0, 2)
    cp.record_utilization("w1", 6.0, 10.0, 3)
    fc = cp.forecast("w1", 10, 4)
    assert fc.verify() and fc.sample_count == 2
    rec = cp.rightsize("w1", 5)
    assert rec.verify() and rec.recommendation == "downsize"
    rep = cp.report(6)
    assert rep.verify() and rep.downsize == 1 and rep.total_workloads == 1
    print(
        "capacity-planning OK: register, sample, forecast, rightsize, report"
    )


if __name__ == "__main__":
    main()
