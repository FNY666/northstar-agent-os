"""Experiment tracking interface (MLflow / Weights & Biases shape, simulated).

Research motivation: serious ML work lives or dies on experiment
tracking. Tools like MLflow (Zaharia et al., 2018), Weights & Biases,
and TensorBoard turn a pile of training runs into a *comparable*
record: hyperparameters pinned per run, metrics logged per run, runs
ranked by outcome. Without that record, "which config won" is tribal
knowledge and reproductions are guesswork.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's experiment plumbing speaks one dialect:

- ``ExperimentTracker`` -- owns the run registry. ``log_run(params,
  metrics, seq, run_id=None)`` records one run and returns a frozen
  ``RunRecord``; missing ``run_id`` is minted deterministically as
  ``run-<n>`` (no wall-clock, no randomness, audit replay is exact).
- ``compare(run_ids, seq)`` -- side-by-side ``ComparisonReport`` over
  the union of metrics, with the per-metric winner named.
- ``best(metric, mode="max"|"min", seq=...)`` -- the run with the best
  reported value for one metric; ties break by earliest ``seq``
  (documented, deterministic).
- ``experiment_tracker_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``run-logged`` / ``compared`` / ``best-selected``);
  caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``params`` must be a mapping with non-empty ``str`` keys; values must
  be JSON-canonicalizable and contain no NaN/inf floats (a NaN
  hyperparameter would poison every downstream comparison).
- ``metrics`` must be a mapping of non-empty ``str`` keys to *finite*
  real numbers. ``bool`` is rejected anywhere a number is expected
  (``True`` must not alias ``1``); NaN/inf are refused because
  comparisons over them are not total.
- Duplicate ``run_id`` is refused (history is never silently
  overwritten); ``compare`` with an unknown, empty, or duplicated id
  list is refused.
- ``best`` over a metric no run logged raises ``UnknownMetricError``;
  ``best``/``compare`` on an empty tracker raises ``EmptyTrackerError``.
- Caller-supplied seqs are ints (not bool), >= 0.

Honest scope:

- This module books *host-reported* numbers. It cannot verify that a
  reported ``val_loss`` is the loss the host actually measured; a host
  that lies about metrics gets a lying leaderboard. ``best()`` ranks
  reported values, never ground truth.
- Ties are broken by earliest ``seq``, a bookkeeping convention, not a
  claim that earlier is better.
- Runs that did not log a metric are skipped by ``best`` and shown as
  missing by ``compare``; absence is reported, never imputed.
- No persistence: the registry is in-memory. Pair with the durable
  audit writer if runs must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
EXPERIMENT_TRACKER_VERSION = "experiment-tracker.v1"

#: Schema pin carried by records and audit events.
EXPERIMENT_TRACKER_SCHEMA = "northstar.experiment-tracker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Selection modes for best().
MODE_MAX = "max"
MODE_MIN = "min"
_MODES = (MODE_MAX, MODE_MIN)


class ExperimentTrackerError(Exception):
    """Base error for the experiment tracker (programming errors)."""


class DuplicateRunError(ExperimentTrackerError):
    """Raised when a run_id is logged twice."""


class UnknownRunError(ExperimentTrackerError):
    """Raised when a run_id names no logged run."""


class UnknownMetricError(ExperimentTrackerError):
    """Raised when no logged run carries the requested metric."""


class EmptyTrackerError(ExperimentTrackerError):
    """Raised when an operation needs runs and the tracker has none."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_run_id(value: object) -> str:
    """Validate a run identifier: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"run_id must be str, got {type(value).__name__}")
    if not value:
        raise ValueError("run_id must be non-empty")
    return value


def _reject_non_finite(value: Any, where: str) -> None:
    """Recursively refuse NaN/inf floats inside a params tree."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{where} must not contain NaN/inf")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item, where)
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_non_finite(item, where)


def _check_params(params: object) -> Tuple[Tuple[str, Any], ...]:
    """Validate run params: mapping, str keys, canonicalizable values."""
    if not isinstance(params, Mapping):
        raise TypeError(f"params must be a mapping, got {type(params).__name__}")
    pairs = []
    for key, value in params.items():
        if not isinstance(key, str):
            raise TypeError(f"params keys must be str, got {type(key).__name__}")
        if not key:
            raise ValueError("params keys must be non-empty")
        _reject_non_finite(value, "params")
        try:
            jcs_canonical_json(value)
        except Exception as exc:
            raise TypeError(f"params value for {key!r} is not canonicalizable: {exc}") from exc
        pairs.append((key, value))
    return tuple(sorted(pairs, key=lambda kv: kv[0]))


def _check_metric_value(name: str, value: object) -> float:
    """Validate one metric value: finite real number, never bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"metric {name!r} must be a number, got {type(value).__name__}")
    if not math.isfinite(value):
        raise ValueError(f"metric {name!r} must be finite")
    return float(value)


def _check_metrics(metrics: object) -> Tuple[Tuple[str, float], ...]:
    """Validate run metrics: mapping of str keys to finite numbers."""
    if not isinstance(metrics, Mapping):
        raise TypeError(f"metrics must be a mapping, got {type(metrics).__name__}")
    pairs = []
    for key, value in metrics.items():
        if not isinstance(key, str):
            raise TypeError(f"metrics keys must be str, got {type(key).__name__}")
        if not key:
            raise ValueError("metrics keys must be non-empty")
        pairs.append((key, _check_metric_value(key, value)))
    return tuple(sorted(pairs, key=lambda kv: kv[0]))


def _pin_run(run_id: str, params: Mapping[str, Any],
             metrics: Mapping[str, float], seq: int) -> str:
    """Digest-pin the canonical run body."""
    return "sha256:" + jcs_sha256_hex({
        "run_id": run_id,
        "params": dict(params),
        "metrics": dict(metrics),
        "seq": seq,
    })


@dataclass(frozen=True)
class RunRecord:
    """One logged experiment run (frozen)."""
    run_id: str
    params: Tuple[Tuple[str, Any], ...]
    metrics: Tuple[Tuple[str, float], ...]
    seq: int
    digest: str
    version: str = EXPERIMENT_TRACKER_VERSION
    schema: str = EXPERIMENT_TRACKER_SCHEMA

    def params_dict(self) -> dict:
        return dict(self.params)

    def metrics_dict(self) -> dict:
        return dict(self.metrics)

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "params": dict(self.params),
            "metrics": dict(self.metrics),
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class MetricComparison:
    """One metric's side-by-side values across compared runs (frozen).

    ``values`` aligns with the report's ``run_ids``; a run that did not
    log the metric contributes ``None`` (absence is reported, never
    imputed). ``best_run_id`` is ``None`` when no compared run logged
    the metric.
    """
    metric: str
    values: Tuple[Optional[float], ...]
    best_run_id: Optional[str]

    def as_dict(self) -> dict:
        return {
            "metric": self.metric,
            "values": list(self.values),
            "best_run_id": self.best_run_id,
        }


@dataclass(frozen=True)
class ComparisonReport:
    """Side-by-side comparison of several runs (frozen)."""
    run_ids: Tuple[str, ...]
    comparisons: Tuple[MetricComparison, ...]
    seq: int
    digest: str
    version: str = EXPERIMENT_TRACKER_VERSION
    schema: str = EXPERIMENT_TRACKER_SCHEMA

    def metrics(self) -> Tuple[str, ...]:
        return tuple(c.metric for c in self.comparisons)

    def as_dict(self) -> dict:
        return {
            "run_ids": list(self.run_ids),
            "comparisons": [c.as_dict() for c in self.comparisons],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class BestResult:
    """The winning run for one metric (frozen)."""
    metric: str
    mode: str
    run_id: str
    value: float
    candidates: int
    seq: int
    version: str = EXPERIMENT_TRACKER_VERSION
    schema: str = EXPERIMENT_TRACKER_SCHEMA

    def as_dict(self) -> dict:
        return {
            "metric": self.metric,
            "mode": self.mode,
            "run_id": self.run_id,
            "value": self.value,
            "candidates": self.candidates,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


class ExperimentTracker:
    """In-memory registry of experiment runs (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._runs: dict[str, RunRecord] = {}
        self._counter = 0

    def log_run(self, params: Mapping[str, Any], metrics: Mapping[str, float],
                seq: object, run_id: object = None) -> RunRecord:
        """Log one run; returns the frozen record.

        ``run_id`` is optional; when omitted a deterministic
        ``run-<n>`` id is minted from the per-tracker counter.
        """
        seq = _check_seq(seq)
        checked_params = _check_params(params)
        checked_metrics = _check_metrics(metrics)
        if run_id is None:
            with self._lock:
                self._counter += 1
                run_id = f"run-{self._counter}"
        else:
            run_id = _check_run_id(run_id)
        with self._lock:
            if run_id in self._runs:
                raise DuplicateRunError(f"run_id {run_id!r} already logged")
            record = RunRecord(
                run_id=run_id,
                params=checked_params,
                metrics=checked_metrics,
                seq=seq,
                digest=_pin_run(run_id, dict(checked_params),
                                dict(checked_metrics), seq),
            )
            self._runs[run_id] = record
            return record

    def get(self, run_id: object) -> RunRecord:
        """Fetch one run record by id."""
        run_id = _check_run_id(run_id)
        with self._lock:
            try:
                return self._runs[run_id]
            except KeyError:
                raise UnknownRunError(f"unknown run_id {run_id!r}") from None

    def run_ids(self) -> Tuple[str, ...]:
        """All logged run ids, in insertion order."""
        with self._lock:
            return tuple(self._runs.keys())

    def run_count(self) -> int:
        """Number of logged runs."""
        with self._lock:
            return len(self._runs)

    def compare(self, run_ids: object, seq: object) -> ComparisonReport:
        """Side-by-side comparison of the named runs."""
        seq = _check_seq(seq)
        if not isinstance(run_ids, (list, tuple)):
            raise TypeError(f"run_ids must be a list/tuple, got {type(run_ids).__name__}")
        if not run_ids:
            raise ExperimentTrackerError("compare needs at least one run_id")
        ids = tuple(_check_run_id(r) for r in run_ids)
        if len(set(ids)) != len(ids):
            raise ExperimentTrackerError("compare run_ids must be unique")
        with self._lock:
            if not self._runs:
                raise EmptyTrackerError("tracker has no runs")
            records = []
            for rid in ids:
                try:
                    records.append(self._runs[rid])
                except KeyError:
                    raise UnknownRunError(f"unknown run_id {rid!r}") from None
            metric_names = sorted({k for rec in records for k, _ in rec.metrics})
            comparisons = []
            for name in metric_names:
                values = tuple(dict(rec.metrics).get(name) for rec in records)
                present = [(rid, v) for rid, v in zip(ids, values) if v is not None]
                best_run_id = max(present, key=lambda p: p[1])[0] if present else None
                comparisons.append(MetricComparison(
                    metric=name, values=values, best_run_id=best_run_id))
            report = ComparisonReport(
                run_ids=ids,
                comparisons=tuple(comparisons),
                seq=seq,
                digest="sha256:" + jcs_sha256_hex({
                    "run_ids": list(ids),
                    "comparisons": [c.as_dict() for c in comparisons],
                    "seq": seq,
                }),
            )
            return report

    def best(self, metric: object, mode: object = MODE_MAX,
             seq: object = 0) -> BestResult:
        """The run with the best reported value for ``metric``.

        Runs that did not log the metric are skipped. Ties break by
        earliest run ``seq`` (deterministic, documented).
        """
        if not isinstance(metric, str) or not metric:
            raise TypeError("metric must be a non-empty str")
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
        seq = _check_seq(seq)
        with self._lock:
            if not self._runs:
                raise EmptyTrackerError("tracker has no runs")
            candidates = []
            for rec in self._runs.values():
                value = dict(rec.metrics).get(metric)
                if value is not None:
                    candidates.append((rec.seq, rec.run_id, value))
            if not candidates:
                raise UnknownMetricError(f"no run logged metric {metric!r}")
            if mode == MODE_MAX:
                winner = max(candidates, key=lambda c: (c[2], -c[0]))
            else:
                winner = min(candidates, key=lambda c: (c[2], c[0]))
            return BestResult(
                metric=metric,
                mode=mode,
                run_id=winner[1],
                value=winner[2],
                candidates=len(candidates),
                seq=seq,
            )


def experiment_tracker_audit_event(kind: str, seq: object,
                                   run_id: Optional[str] = None,
                                   metric: Optional[str] = None) -> dict:
    """Audit-shaped record for an experiment-tracker observation."""
    if kind not in ("run-logged", "compared", "best-selected"):
        raise ValueError("unknown kind")
    _check_seq(seq)
    if run_id is not None:
        _check_run_id(run_id)
    if metric is not None and (not isinstance(metric, str) or not metric):
        raise TypeError("metric must be a non-empty str")
    body: dict[str, Any] = {
        "event": "experiment-tracker",
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
    }
    if run_id is not None:
        body["run_id"] = run_id
    if metric is not None:
        body["metric"] = metric
    return body


def main() -> None:
    tracker = ExperimentTracker()
    tracker.log_run({"lr": 0.01, "depth": 4}, {"acc": 0.91, "loss": 0.22}, seq=1)
    tracker.log_run({"lr": 0.02, "depth": 6}, {"acc": 0.94, "loss": 0.17}, seq=2)
    report = tracker.compare(("run-1", "run-2"), seq=3)
    winner = tracker.best("acc", mode="max", seq=4)
    assert winner.run_id == "run-2", winner
    assert report.comparisons[0].metric == "acc"
    print("experiment-tracker OK: log, compare, best")


if __name__ == "__main__":
    main()
