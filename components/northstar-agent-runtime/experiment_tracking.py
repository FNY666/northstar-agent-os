"""Experiment tracking — simulated W&B-style run bookkeeping (thirty-third batch).

Research note (experiment-tracking literature): Weights & Biases, MLflow,
and TensorBoard model experiment tracking as a *run ledger*: each run
books a pinned hyperparameter config, a stream of logged metric values
(keyed by step), and bound artifact references (models, datasets,
checkpoints). Comparison reduces to ranking runs by an aggregate of a
chosen metric (last value, min, max, mean). This module takes the
intersection for a single-host deterministic ledger:

* **Runs, not jobs**: ``create_experiment`` books a run's config
  (hyperparameter mapping, pinned at creation). Nothing executes — the
  module never trains, never touches GPUs, never reads data.
* **Host-reported metrics**: ``log`` books a metric mapping the host
  reports at a step. Values are validated (finite numbers) and sealed
  with a digest pin; the module cannot verify the numbers came from a
  real training loop (GIGO boundary).
* **Artifacts by reference**: ``artifact`` binds an artifact id to a run
  by digest reference only — bytes never cross the module boundary, so
  the ledger cannot prove what a digest names.
* **Comparison as data**: ``compare`` ranks runs by a pinned
  aggregation of one metric and returns the ranking as data, never as
  an action (no auto-promotion, no deployment).

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), sha256 digest pins over type-tagged canonical payloads,
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* experiment metadata
deterministically. It runs no training, observes no hardware, stores no
artifacts, and cannot prove a logged metric was measured — a metric
record means "the host reported this number", never "the model achieved
this". Pair with a real tracking backend (W&B, MLflow) and a real
artifact store for production.
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
EXPERIMENT_TRACKING_VERSION = "experiment-tracking.v1"

#: Schema pin carried by records and audit events.
EXPERIMENT_TRACKING_SCHEMA = "northstar.experiment-tracking.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned artifact kinds (artifact vocabulary; drift detectable).
ARTIFACT_MODEL = "model"
ARTIFACT_DATASET = "dataset"
ARTIFACT_CONFIG = "config"
ARTIFACT_LOG = "log"
ARTIFACT_OTHER = "other"
ARTIFACT_KINDS = (
    ARTIFACT_MODEL,
    ARTIFACT_DATASET,
    ARTIFACT_CONFIG,
    ARTIFACT_LOG,
    ARTIFACT_OTHER,
)

#: Pinned comparison aggregation modes.
AGG_LAST = "last"
AGG_MIN = "min"
AGG_MAX = "max"
AGG_MEAN = "mean"
AGGREGATIONS = (AGG_LAST, AGG_MIN, AGG_MAX, AGG_MEAN)

#: Pinned comparison direction.
DIR_MAX = "max"
DIR_MIN = "min"
DIRECTIONS = (DIR_MAX, DIR_MIN)

#: Audit event kinds.
KIND_EXPERIMENT_CREATED = "experiment.created"
KIND_METRIC_LOGGED = "experiment.metric-logged"
KIND_ARTIFACT_BOUND = "experiment.artifact-bound"
KIND_COMPARED = "experiment.compared"
KIND_REJECTED = "experiment.rejected"
_KINDS = (
    KIND_EXPERIMENT_CREATED,
    KIND_METRIC_LOGGED,
    KIND_ARTIFACT_BOUND,
    KIND_COMPARED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"
_DIGEST_HEX_LEN = 64


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ExperimentTrackingError(ValueError):
    """Base error for experiment tracking."""


class BadExperimentError(ExperimentTrackingError):
    """Malformed experiment definition (bad id, name, config)."""


class DuplicateExperimentError(ExperimentTrackingError):
    """An experiment with this id already exists."""


class UnknownExperimentError(ExperimentTrackingError):
    """No experiment with this id exists."""


class BadMetricError(ExperimentTrackingError):
    """Malformed metric log (bad names, values, step)."""


class BadArtifactError(ExperimentTrackingError):
    """Malformed artifact binding (bad id, kind, digest reference)."""


class DuplicateArtifactError(ExperimentTrackingError):
    """This experiment already bound this artifact id."""


class BadCompareError(ExperimentTrackingError):
    """Malformed comparison request (bad experiments, metric, mode)."""


class SeqOrderError(ExperimentTrackingError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExperimentTrackingError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperimentTrackingError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_id(value: Any, field_name: str) -> str:
    cleaned = _check_nonempty_str(value, field_name)
    if len(cleaned) > 128:
        raise ExperimentTrackingError(f"{field_name} must be <= 128 chars")
    return cleaned


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise ExperimentTrackingError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ExperimentTrackingError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ExperimentTrackingError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _check_metric_value(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise BadMetricError(f"metric {name!r} must be a number, not bool")
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadMetricError(f"metric {name!r} outside safe integer range")
        return float(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadMetricError(f"metric {name!r} must be finite")
        return value
    raise BadMetricError(f"metric {name!r} must be a number")


def _check_digest_ref(value: Any, field_name: str = "digest_ref") -> str:
    if not isinstance(value, str):
        raise BadArtifactError(f"{field_name} must be a string")
    if not value.startswith(_DIGEST_PREFIX):
        raise BadArtifactError(f"{field_name} must start with 'sha256:'")
    hexpart = value[len(_DIGEST_PREFIX):]
    if len(hexpart) != _DIGEST_HEX_LEN or any(
        c not in "0123456789abcdef" for c in hexpart
    ):
        raise BadArtifactError(f"{field_name} must be sha256:<64 hex chars>")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExperimentRecord:
    """A pinned experiment definition (config sealed at creation)."""

    experiment_id: str
    name: str
    config: tuple  # tuple of (key, value) pairs, sorted by key
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "experiment",
                    self.experiment_id,
                    self.name,
                    [[k, v] for k, v in self.config],
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class MetricLog:
    """One sealed metric-log entry at a step."""

    log_id: str
    experiment_id: str
    step: int
    metrics: tuple  # tuple of (name, float value) pairs, sorted by name
    seq: int
    prev_digest: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "metric-log",
                    self.log_id,
                    self.experiment_id,
                    self.step,
                    [[k, v] for k, v in self.metrics],
                    self.seq,
                    self.prev_digest,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class ArtifactRecord:
    """One artifact binding: digest reference only, no bytes."""

    experiment_id: str
    artifact_id: str
    kind: str
    digest_ref: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "artifact",
                    self.experiment_id,
                    self.artifact_id,
                    self.kind,
                    self.digest_ref,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class ComparisonRow:
    """One ranked row of a comparison report (data)."""

    experiment_id: str
    value: float
    steps: int


@dataclass(frozen=True)
class ComparisonReport:
    """A sealed ranking of experiments by one metric (data, not an action)."""

    report_id: str
    metric: str
    aggregation: str
    direction: str
    rows: tuple  # tuple of ComparisonRow, best first
    excluded: tuple  # experiment ids with no samples of the metric
    best_id: str | None
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "comparison",
                    self.report_id,
                    self.metric,
                    self.aggregation,
                    self.direction,
                    [[r.experiment_id, r.value, r.steps] for r in self.rows],
                    list(self.excluded),
                    self.best_id,
                    self.seq,
                ],
                seed,
            ),
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def experiment_tracking_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for experiment tracking."""
    if kind not in _KINDS:
        raise ExperimentTrackingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "experiment_tracking",
        "module_version": EXPERIMENT_TRACKING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# ExperimentTracking
# ---------------------------------------------------------------------------


class ExperimentTracking:
    """Deterministic experiment-tracking ledger.

    Mutations (``create_experiment``, ``log``, ``artifact``) consume
    strictly-increasing caller seqs; failed mutations consume their seq
    and book a ``experiment.rejected`` audit row (ledger position stays
    total). ``compare`` is an audited read: it validates the seq shape
    but does not consume it, and appends a ``experiment.compared`` row
    (the audited-read house pattern).

    Metric values and configs are host-reported; the ledger pins them
    but cannot verify they were measured.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._experiments: dict[str, ExperimentRecord] = {}
        self._logs: dict[str, MetricLog] = {}
        self._log_ids: list[str] = []
        self._artifacts: dict[tuple[str, str], ArtifactRecord] = {}
        self._next_log_n = 0
        self._next_report_n = 0
        self._step_counters: dict[str, int] = {}
        self._last_digest = _GENESIS
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
        self._audit_log.append(experiment_tracking_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _validate_config(self, config: Any) -> tuple:
        if not isinstance(config, Mapping):
            raise BadExperimentError("config must be a mapping")
        cleaned: list[tuple] = []
        for key, value in config.items():
            if not isinstance(key, str) or not key.strip():
                raise BadExperimentError("config keys must be non-empty strings")
            if isinstance(value, bool) or value is None or isinstance(
                value, (str, int, float)
            ):
                pass
            else:
                raise BadExperimentError(
                    f"config value for {key!r} must be str/int/float/bool/None"
                )
            if isinstance(value, float) and (
                value != value or value in (float("inf"), float("-inf"))
            ):
                raise BadExperimentError(f"config value for {key!r} must be finite")
            if isinstance(value, int) and abs(value) >= 2**53:
                raise BadExperimentError(
                    f"config value for {key!r} outside safe integer range"
                )
            cleaned.append((key, value))
        # _canonical raises on anything unencodable; probe it here so the
        # refusal happens before any state mutates.
        _canonical({k: v for k, v in cleaned})
        return tuple(sorted(cleaned, key=lambda kv: kv[0]))

    def _validate_metrics(self, metrics: Any) -> tuple:
        if not isinstance(metrics, Mapping) or not metrics:
            raise BadMetricError("metrics must be a non-empty mapping")
        cleaned: list[tuple] = []
        for name, value in metrics.items():
            if not isinstance(name, str) or not name.strip():
                raise BadMetricError("metric names must be non-empty strings")
            cleaned.append((name, _check_metric_value(value, name)))
        names = [n for n, _ in cleaned]
        if len(set(names)) != len(names):
            raise BadMetricError("duplicate metric names")
        return tuple(sorted(cleaned, key=lambda kv: kv[0]))

    # -- experiments ---------------------------------------------------

    def create_experiment(
        self, experiment_id: str, name: str, config: Mapping[str, Any], seq: int
    ) -> ExperimentRecord:
        """Book a new experiment with a pinned config."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                eid = _check_id(experiment_id, "experiment_id")
                nm = _check_nonempty_str(name, "name")
                cfg = self._validate_config(config)
                if eid in self._experiments:
                    raise DuplicateExperimentError(
                        f"experiment {eid!r} already exists"
                    )
            except ExperimentTrackingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                ["experiment", eid, nm, [[k, v] for k, v in cfg], seq],
                self._seed,
            )
            record = ExperimentRecord(
                experiment_id=eid, name=nm, config=cfg, seq=seq, digest=digest
            )
            self._experiments[eid] = record
            self._step_counters[eid] = 0
            self._emit(
                KIND_EXPERIMENT_CREATED,
                seq,
                experiment_id=eid,
                name=nm,
                config_keys=[k for k, _ in cfg],
            )
            return record

    # -- metric logging ------------------------------------------------

    def log(
        self,
        experiment_id: str,
        metrics: Mapping[str, Any],
        seq: int,
        step: int | None = None,
    ) -> MetricLog:
        """Book host-reported metric values at a step (sealed, hash-chained)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                eid = _check_id(experiment_id, "experiment_id")
                if eid not in self._experiments:
                    raise UnknownExperimentError(f"unknown experiment {eid!r}")
                vals = self._validate_metrics(metrics)
                if step is None:
                    step = self._step_counters[eid]
                elif isinstance(step, bool) or not isinstance(step, int) or step < 0:
                    raise BadMetricError("step must be a non-negative int or None")
            except ExperimentTrackingError as exc:
                self._reject(seq, str(exc))
                raise
            self._step_counters[eid] = max(self._step_counters[eid], step + 1)
            log_id = f"log-{self._next_log_n}"
            self._next_log_n += 1
            prev = self._last_digest
            digest = _pin(
                [
                    "metric-log",
                    log_id,
                    eid,
                    step,
                    [[k, v] for k, v in vals],
                    seq,
                    prev,
                ],
                self._seed,
            )
            record = MetricLog(
                log_id=log_id,
                experiment_id=eid,
                step=step,
                metrics=vals,
                seq=seq,
                prev_digest=prev,
                digest=digest,
            )
            self._logs[log_id] = record
            self._log_ids.append(log_id)
            self._last_digest = digest
            self._emit(
                KIND_METRIC_LOGGED,
                seq,
                experiment_id=eid,
                log_id=log_id,
                step=step,
                metric_names=[k for k, _ in vals],
            )
            return record

    # -- artifacts -----------------------------------------------------

    def artifact(
        self,
        experiment_id: str,
        artifact_id: str,
        kind: str,
        digest_ref: str,
        seq: int,
    ) -> ArtifactRecord:
        """Bind an artifact reference (digest only) to an experiment."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                eid = _check_id(experiment_id, "experiment_id")
                if eid not in self._experiments:
                    raise UnknownExperimentError(f"unknown experiment {eid!r}")
                aid = _check_id(artifact_id, "artifact_id")
                if kind not in ARTIFACT_KINDS:
                    raise BadArtifactError(f"unknown artifact kind: {kind!r}")
                ref = _check_digest_ref(digest_ref)
                if (eid, aid) in self._artifacts:
                    raise DuplicateArtifactError(
                        f"artifact {aid!r} already bound to experiment {eid!r}"
                    )
            except ExperimentTrackingError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                ["artifact", eid, aid, kind, ref, seq], self._seed
            )
            record = ArtifactRecord(
                experiment_id=eid,
                artifact_id=aid,
                kind=kind,
                digest_ref=ref,
                seq=seq,
                digest=digest,
            )
            self._artifacts[(eid, aid)] = record
            self._emit(
                KIND_ARTIFACT_BOUND,
                seq,
                experiment_id=eid,
                artifact_id=aid,
                artifact_kind=kind,
            )
            return record

    # -- comparison (audited read) -------------------------------------

    def compare(
        self,
        experiment_ids: Any,
        metric: str,
        seq: int,
        aggregation: str = AGG_LAST,
        direction: str = DIR_MAX,
    ) -> ComparisonReport:
        """Rank experiments by an aggregation of one metric (data, not action).

        Returns a sealed :class:`ComparisonReport` with rows best-first.
        Experiments with no samples of the metric are listed in
        ``excluded`` rather than raising. Validates the seq shape but does
        not consume it; appends an audited-read event.
        """
        with self._lock:
            seq = _check_seq(seq, "seq")
            metric = _check_nonempty_str(metric, "metric")
            if not isinstance(experiment_ids, (list, tuple)) or not experiment_ids:
                raise BadCompareError("experiment_ids must be a non-empty list")
            ids = [_check_id(e, "experiment_id") for e in experiment_ids]
            if len(set(ids)) != len(ids):
                raise BadCompareError("duplicate experiment ids")
            for eid in ids:
                if eid not in self._experiments:
                    raise UnknownExperimentError(f"unknown experiment {eid!r}")
            if aggregation not in AGGREGATIONS:
                raise BadCompareError(f"unknown aggregation: {aggregation!r}")
            if direction not in DIRECTIONS:
                raise BadCompareError(f"unknown direction: {direction!r}")

            rows: list[ComparisonRow] = []
            excluded: list[str] = []
            for eid in ids:
                samples = [
                    (dict(rec.metrics)[metric], rec.step)
                    for rec in (self._logs[lid] for lid in self._log_ids)
                    if rec.experiment_id == eid and metric in dict(rec.metrics)
                ]
                if not samples:
                    excluded.append(eid)
                    continue
                values = [v for v, _ in samples]
                if aggregation == AGG_LAST:
                    agg_value = values[-1]
                elif aggregation == AGG_MIN:
                    agg_value = min(values)
                elif aggregation == AGG_MAX:
                    agg_value = max(values)
                else:  # AGG_MEAN
                    agg_value = sum(values) / len(values)
                rows.append(
                    ComparisonRow(
                        experiment_id=eid, value=agg_value, steps=len(samples)
                    )
                )
            reverse = direction == DIR_MAX
            rows.sort(key=lambda r: (r.value, r.experiment_id), reverse=reverse)
            best_id = rows[0].experiment_id if rows else None
            report_id = f"cmp-{self._next_report_n}"
            self._next_report_n += 1
            digest = _pin(
                [
                    "comparison",
                    report_id,
                    metric,
                    aggregation,
                    direction,
                    [[r.experiment_id, r.value, r.steps] for r in rows],
                    excluded,
                    best_id,
                    seq,
                ],
                self._seed,
            )
            report = ComparisonReport(
                report_id=report_id,
                metric=metric,
                aggregation=aggregation,
                direction=direction,
                rows=tuple(rows),
                excluded=tuple(excluded),
                best_id=best_id,
                seq=seq,
                digest=digest,
            )
            self._emit(
                KIND_COMPARED,
                seq,
                report_id=report_id,
                metric=metric,
                aggregation=aggregation,
                direction=direction,
                best_id=best_id,
                ranked=[r.experiment_id for r in rows],
                excluded=list(excluded),
            )
            return report

    # -- views ---------------------------------------------------------

    def experiment(self, experiment_id: str) -> ExperimentRecord:
        """Return the pinned record for one experiment."""
        with self._lock:
            eid = _check_id(experiment_id, "experiment_id")
            try:
                return self._experiments[eid]
            except KeyError:
                raise UnknownExperimentError(f"unknown experiment {eid!r}")

    def experiment_ids(self) -> tuple:
        """Sorted experiment ids."""
        with self._lock:
            return tuple(sorted(self._experiments))

    def metric_log(self, log_id: str) -> MetricLog:
        """Return one sealed metric-log entry."""
        with self._lock:
            lid = _check_id(log_id, "log_id")
            try:
                return self._logs[lid]
            except KeyError:
                raise ExperimentTrackingError(f"unknown log {lid!r}")

    def metrics_for(self, experiment_id: str) -> tuple:
        """All metric-log entries for one experiment, in log order."""
        with self._lock:
            eid = _check_id(experiment_id, "experiment_id")
            if eid not in self._experiments:
                raise UnknownExperimentError(f"unknown experiment {eid!r}")
            return tuple(
                self._logs[lid]
                for lid in self._log_ids
                if self._logs[lid].experiment_id == eid
            )

    def artifacts_for(self, experiment_id: str) -> tuple:
        """All artifact bindings for one experiment, sorted by artifact id."""
        with self._lock:
            eid = _check_id(experiment_id, "experiment_id")
            if eid not in self._experiments:
                raise UnknownExperimentError(f"unknown experiment {eid!r}")
            return tuple(
                self._artifacts[key]
                for key in sorted(self._artifacts)
                if key[0] == eid
            )

    def stats(self) -> Mapping[str, Any]:
        """Ledger counts."""
        with self._lock:
            return {
                "experiments": len(self._experiments),
                "metric_logs": len(self._logs),
                "artifacts": len(self._artifacts),
                "comparisons": self._next_report_n,
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> tuple:
        """The booked audit events, in order."""
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> Mapping[str, Any]:
        """JSON-encodable snapshot of the ledger."""
        with self._lock:
            return {
                "version": EXPERIMENT_TRACKING_VERSION,
                "schema": EXPERIMENT_TRACKING_SCHEMA,
                "experiments": {
                    eid: {
                        "name": rec.name,
                        "config": {k: v for k, v in rec.config},
                        "seq": rec.seq,
                        "digest": rec.digest,
                    }
                    for eid, rec in sorted(self._experiments.items())
                },
                "stats": dict(self.stats()),
            }


def main() -> None:
    mon = ExperimentTracking(seed="selfcheck")
    rec = mon.create_experiment(
        "exp-1", "baseline", {"lr": 0.01, "model": "mlp"}, 0
    )
    assert rec.verify(seed="selfcheck")
    entry = mon.log("exp-1", {"loss": 0.5, "acc": 0.8}, 1)
    assert entry.verify(seed="selfcheck") and entry.step == 0
    entry2 = mon.log("exp-1", {"loss": 0.4}, 2, step=7)
    assert entry2.step == 7
    art = mon.artifact(
        "exp-1",
        "ckpt-1",
        ARTIFACT_MODEL,
        "sha256:" + "ab" * 32,
        3,
    )
    assert art.verify(seed="selfcheck")
    mon.create_experiment("exp-2", "tuned", {"lr": 0.001}, 4)
    mon.log("exp-2", {"loss": 0.3}, 5)
    report = mon.compare(["exp-1", "exp-2"], "loss", 5, direction=DIR_MIN)
    assert report.best_id == "exp-2" and report.verify(seed="selfcheck")
    assert mon.stats()["experiments"] == 2
    print("experiment-tracking OK: create, log, artifact, compare, pins, audit")


if __name__ == "__main__":
    main()
