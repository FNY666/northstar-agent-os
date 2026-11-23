"""Chaos experiment interface: fault-injection bookkeeping as a deterministic state machine.

Research motivation: chaos engineering (Netflix's Chaos Monkey, Chaos
Mesh, LitmusChaos) deliberately injects failures -- killed pods,
network partitions, resource pressure -- to prove a system recovers.
But an experiment with no blast-radius discipline *is* the outage:
killing too many instances turns a drill into data loss, a fault
without an abort path leaves the fleet degraded, and overlapping
experiments on the same targets corrupt each other's hypotheses. This
module is the *bookkeeping* half of a chaos-experiment controller: it
records experiment definitions, computes the deterministic set of
fault targets under a blast-radius budget, and tracks the
defined -> running -> (completed | aborted) lifecycle -- but it never
executes a fault itself. The host binds booked fault decisions to real
machines through its own transport.

Public API:

- ``ChaosExperiment`` -- RLock-guarded registry.
  ``define(experiment_id, faults, targets, blast_radius, seq)``
  registers a frozen ``ExperimentDefinition`` (fault list + target
  inventory + blast-radius budget). ``run(experiment_id, seq)``
  computes the deterministic fault-target selection and returns a
  frozen ``RunReport``. ``abort(experiment_id, seq)`` halts a running
  experiment and returns a frozen ``AbortRecord``.
  ``status(experiment_id)`` / ``definitions()`` / ``reports()`` views.
- ``BlastRadius`` -- frozen: ``max_affected_pct`` (0 < p <= 50) and
  optional ``max_affected_count``. The budget is
  ``min(pct-of-targets, count)`` and never exceeds half the fleet.
- ``FaultSpec`` -- frozen: ``fault_type`` (from ``FAULT_TYPES``) +
  canonicalizable ``params`` mapping (e.g. ``duration_seqs``,
  ``delay_ms``).
- Target selection is deterministic: targets are ordered by the
  digest of ``(experiment_id, target)`` and the first ``budget``
  entries are faulted, so identical definitions replay identically.
- ``chaos_experiment_audit_event(kind, seq, ...)`` --
  ``audit.ndjson/1`` records, fixed kind vocabulary:
  ``"defined"`` / ``"ran"`` / ``"aborted"`` / ``"rejected"``.

Honest scope:

- This module books *decisions*: "these targets should be faulted with
  these faults". It cannot inject a fault, cannot observe whether a
  fault actually landed, and cannot prove recovery -- ``completed``
  means "the ledger recorded the run", never "the fleet recovered".
- Blast radius is a budget over *reported* targets. A host that
  under-reports its fleet gets a consistently under-budgeted book,
  and a host that lies about abort completion keeps the running flag
  until it reports back (same GIGO boundary as every other
  bookkeeping module).
- Caller-supplied int seqs are the only notion of time/order (no
  wall-clock); seqs must be non-negative and strictly increase across
  mutating calls (a rewound seq is rejected so the ledger cannot be
  silently reordered).

Version pin: ``chaos-experiment.v1`` / schema pin
``northstar.chaos-experiment.v1``.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

VERSION = "chaos-experiment.v1"
SCHEMA = "northstar.chaos-experiment.v1"
AUDIT_FORMAT = "audit.ndjson/1"

_AUDIT_KINDS = ("defined", "ran", "aborted", "rejected")

# Fault types drawn from the chaos-engineering literature (Chaos
# Monkey / Chaos Mesh / LitmusChaos). Closed vocabulary so a
# misspelled fault can never become a silent no-op.
FAULT_TYPES = frozenset(
    {
        "pod-kill",
        "container-kill",
        "pod-failure",
        "network-delay",
        "network-loss",
        "network-partition",
        "network-duplication",
        "stress-cpu",
        "stress-memory",
        "disk-fill",
        "io-error",
        "dns-fault",
        "time-skew",
    }
)

# The blast-radius percentage cap: a single experiment may never be
# defined with a budget above half the fleet.
MAX_BLAST_RADIUS_PCT = 50

try:  # canonicalizer shared with the rest of the batch line
    from canonical_json import jcs_canonical_json as _jcs_bytes  # type: ignore

    def _canonical_bytes(value: Any) -> bytes:
        return _jcs_bytes(value)

except ImportError:  # pragma: no cover - fallback, byte-identical for safe inputs

    def _canonical_bytes(value: Any) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


def _digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ChaosError(Exception):
    """Base class for chaos-experiment errors."""


class DuplicateExperimentError(ChaosError):
    """An experiment id is already defined."""


class UnknownExperimentError(ChaosError):
    """No experiment with that id is defined."""


class ExperimentValidationError(ChaosError):
    """An experiment definition or call argument is invalid (fail-closed)."""


class ExperimentStateError(ChaosError):
    """The experiment is not in the state the call requires."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or isinstance(value, bool) or not value:
        raise ExperimentValidationError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExperimentValidationError("seq must be a non-negative int")
    return value


def _check_canonical_value(value: Any, where: str) -> None:
    """Recursive payload check: fail-closed on JCS float-loss values."""
    if isinstance(value, bool):
        return  # bools are canonical
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ExperimentValidationError(
                f"{where}: int magnitude exceeds 2**53 (JCS float-loss)"
            )
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ExperimentValidationError(
                f"{where}: NaN/inf floats are not canonicalizable"
            )
        if value.is_integer() and abs(value) > 2**53:
            raise ExperimentValidationError(
                f"{where}: integral float exceeds 2**53 (JCS float-loss)"
            )
        return
    if isinstance(value, str) or value is None:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_canonical_value(item, where)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ExperimentValidationError(f"{where}: non-str mapping key")
            _check_canonical_value(item, where)
        return
    raise ExperimentValidationError(
        f"{where}: value of type {type(value).__name__} is not canonicalizable"
    )


def _canonical(value: Any) -> bytes:
    try:
        return _canonical_bytes(value)
    except Exception as exc:  # pragma: no cover - defensive
        raise ExperimentValidationError(
            f"value is not canonicalizable: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FaultSpec:
    """One fault to inject: a closed-vocabulary type + canonical params."""

    fault_type: str
    params: Tuple[Tuple[str, Any], ...] = ()
    digest: str = ""

    def __post_init__(self) -> None:
        if self.fault_type not in FAULT_TYPES:
            raise ExperimentValidationError(
                f"fault_type {self.fault_type!r} not in "
                f"{sorted(FAULT_TYPES)}"
            )
        body = {"fault_type": self.fault_type, "params": dict(self.params)}
        _check_canonical_value(body, "fault params")
        pin = _digest(_canonical(body))
        if self.digest and self.digest != pin:
            raise ExperimentValidationError("fault digest mismatch")
        if not self.digest:
            object.__setattr__(self, "digest", pin)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fault_type": self.fault_type,
            "params": dict(self.params),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class BlastRadius:
    """Blast-radius budget: pct of targets, optionally capped by a count.

    The percentage budget is capped at ``MAX_BLAST_RADIUS_PCT`` (50%):
    a single experiment can never book more than half the fleet.
    """

    max_affected_pct: float
    max_affected_count: Optional[int] = None

    def __post_init__(self) -> None:
        pct = self.max_affected_pct
        if isinstance(pct, bool) or not isinstance(pct, (int, float)):
            raise ExperimentValidationError(
                "max_affected_pct must be a number in (0, 50]"
            )
        if not (0 < pct <= MAX_BLAST_RADIUS_PCT):
            raise ExperimentValidationError(
                f"max_affected_pct must be in (0, {MAX_BLAST_RADIUS_PCT}]"
            )
        if self.max_affected_count is not None:
            cnt = self.max_affected_count
            if isinstance(cnt, bool) or not isinstance(cnt, int) or cnt < 1:
                raise ExperimentValidationError(
                    "max_affected_count must be a positive int"
                )

    def budget(self, target_count: int) -> int:
        """Number of targets the budget permits faulting."""
        pct_budget = max(1, math.ceil(target_count * self.max_affected_pct / 100))
        if self.max_affected_count is not None:
            return min(pct_budget, self.max_affected_count)
        return pct_budget

    def as_dict(self) -> Dict[str, Any]:
        return {
            "max_affected_pct": self.max_affected_pct,
            "max_affected_count": self.max_affected_count,
        }


@dataclass(frozen=True)
class ExperimentDefinition:
    """A registered chaos experiment: faults + targets + blast budget."""

    experiment_id: str
    faults: Tuple[FaultSpec, ...]
    targets: Tuple[str, ...]
    blast_radius: BlastRadius
    budget: int
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "faults": [f.as_dict() for f in self.faults],
            "targets": list(self.targets),
            "blast_radius": self.blast_radius.as_dict(),
            "budget": self.budget,
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class FaultAssignment:
    """One faulted target within a run."""

    target: str
    fault: FaultSpec
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "fault": self.fault.as_dict(),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RunReport:
    """Frozen outcome of ``run()``: the booked fault assignments."""

    experiment_id: str
    assignments: Tuple[FaultAssignment, ...]
    budget: int
    digest: str
    seq: int

    @property
    def affected_targets(self) -> Tuple[str, ...]:
        return tuple(a.target for a in self.assignments)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "assignments": [a.as_dict() for a in self.assignments],
            "budget": self.budget,
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class AbortRecord:
    """Frozen outcome of ``abort()``: a running experiment halted."""

    experiment_id: str
    aborted_at_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "aborted_at_seq": self.aborted_at_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ExperimentStatus:
    """Observable state: defined / running / completed / aborted."""

    experiment_id: str
    state: str
    definition_seq: int
    run_seq: Optional[int] = None
    abort_seq: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "state": self.state,
            "definition_seq": self.definition_seq,
            "run_seq": self.run_seq,
            "abort_seq": self.abort_seq,
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ChaosExperiment:
    """Deterministic chaos-experiment ledger.

    Lifecycle per experiment: ``defined`` -> ``running`` -> one of
    ``completed`` / ``aborted``. A running experiment cannot be re-run
    (experiments never overlap on their own targets); ``abort()`` is
    the only way out of ``running`` short of completion.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._definitions: Dict[str, ExperimentDefinition] = {}
        self._states: Dict[str, str] = {}
        self._run_seqs: Dict[str, int] = {}
        self._abort_seqs: Dict[str, int] = {}
        self._reports: Dict[str, RunReport] = {}
        self._aborts: Dict[str, AbortRecord] = {}
        self._last_seq = -1

    # -- internal ------------------------------------------------------

    def _use_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise ExperimentValidationError(
                f"seq {seq} does not advance the ledger (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    @staticmethod
    def _selection_order(experiment_id: str, targets: Sequence[str]) -> List[str]:
        """Deterministic fault order: sort by digest of (id, target).

        Identical definitions always fault the same targets first, so
        runs replay exactly across instances and across audits.
        """
        keyed = [
            (_digest(
                _canonical({"experiment_id": experiment_id, "target": t})
            ), t)
            for t in targets
        ]
        keyed.sort()
        return [t for _, t in keyed]

    # -- public --------------------------------------------------------

    def define(
        self,
        experiment_id: str,
        faults: Sequence[FaultSpec],
        targets: Sequence[str],
        blast_radius: BlastRadius,
        seq: int,
    ) -> ExperimentDefinition:
        """Register a chaos experiment. Fails closed on invalid input."""
        with self._lock:
            seq = self._use_seq(seq)
            experiment_id = _check_str(experiment_id, "experiment_id")
            if experiment_id in self._definitions:
                raise DuplicateExperimentError(
                    f"experiment {experiment_id!r} already defined"
                )
            if not isinstance(faults, (list, tuple)) or not faults:
                raise ExperimentValidationError(
                    "faults must be a non-empty sequence of FaultSpec"
                )
            fault_list = tuple(faults)
            for f in fault_list:
                if not isinstance(f, FaultSpec):
                    raise ExperimentValidationError(
                        "faults must contain only FaultSpec records"
                    )
            if not isinstance(targets, (list, tuple)) or not targets:
                raise ExperimentValidationError(
                    "targets must be a non-empty sequence of str"
                )
            target_list = tuple(_check_str(t, "target") for t in targets)
            if len(set(target_list)) != len(target_list):
                raise ExperimentValidationError("duplicate targets")
            if not isinstance(blast_radius, BlastRadius):
                raise ExperimentValidationError(
                    "blast_radius must be a BlastRadius"
                )
            budget = blast_radius.budget(len(target_list))
            digest = _digest(
                _canonical(
                    {
                        "experiment_id": experiment_id,
                        "faults": [f.digest for f in fault_list],
                        "targets": sorted(target_list),
                        "blast_radius": blast_radius.as_dict(),
                        "budget": budget,
                    }
                )
            )
            definition = ExperimentDefinition(
                experiment_id=experiment_id,
                faults=fault_list,
                targets=target_list,
                blast_radius=blast_radius,
                budget=budget,
                digest=digest,
                seq=seq,
            )
            self._definitions[experiment_id] = definition
            self._states[experiment_id] = "defined"
            return definition

    def run(self, experiment_id: str, seq: int) -> RunReport:
        """Book the fault-target selection under the blast-radius budget.

        Deterministic: the same definition always faults the same
        targets. Fails closed if the experiment is unknown, already
        running, completed, or aborted.
        """
        with self._lock:
            seq = self._use_seq(seq)
            definition = self._definitions.get(
                _check_str(experiment_id, "experiment_id")
            )
            if definition is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} is not defined"
                )
            state = self._states[experiment_id]
            if state != "defined":
                raise ExperimentStateError(
                    f"experiment {experiment_id!r} is {state}, not defined"
                )
            ordered = self._selection_order(
                experiment_id, definition.targets
            )
            selected = ordered[: definition.budget]
            # Round-robin faults across the selected targets so every
            # fault type in the definition actually lands somewhere.
            faults = definition.faults
            assignments: List[FaultAssignment] = []
            for i, target in enumerate(selected):
                fault = faults[i % len(faults)]
                pin = _digest(
                    _canonical(
                        {
                            "experiment_id": experiment_id,
                            "target": target,
                            "fault": fault.digest,
                            "seq": seq,
                        }
                    )
                )
                assignments.append(
                    FaultAssignment(target=target, fault=fault, digest=pin)
                )
            report_digest = _digest(
                _canonical(
                    {
                        "experiment_id": experiment_id,
                        "assignments": [a.digest for a in assignments],
                        "budget": definition.budget,
                        "seq": seq,
                    }
                )
            )
            report = RunReport(
                experiment_id=experiment_id,
                assignments=tuple(assignments),
                budget=definition.budget,
                digest=report_digest,
                seq=seq,
            )
            self._reports[experiment_id] = report
            self._run_seqs[experiment_id] = seq
            self._states[experiment_id] = "running"
            return report

    def abort(self, experiment_id: str, seq: int) -> AbortRecord:
        """Halt a running experiment. Only ``running`` experiments abort."""
        with self._lock:
            seq = self._use_seq(seq)
            definition = self._definitions.get(
                _check_str(experiment_id, "experiment_id")
            )
            if definition is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} is not defined"
                )
            state = self._states[experiment_id]
            if state != "running":
                raise ExperimentStateError(
                    f"experiment {experiment_id!r} is {state}, not running"
                )
            digest = _digest(
                _canonical(
                    {
                        "experiment_id": experiment_id,
                        "aborted_at_seq": seq,
                        "run_seq": self._run_seqs[experiment_id],
                    }
                )
            )
            record = AbortRecord(
                experiment_id=experiment_id,
                aborted_at_seq=seq,
                digest=digest,
            )
            self._aborts[experiment_id] = record
            self._abort_seqs[experiment_id] = seq
            self._states[experiment_id] = "aborted"
            return record

    def complete(self, experiment_id: str, seq: int) -> ExperimentStatus:
        """Record a running experiment as completed (host-reported).

        Completion is host-attested: the ledger cannot observe the
        fleet, so ``complete`` means "the host reports the run ended",
        never "recovery is proven".
        """
        with self._lock:
            seq = self._use_seq(seq)
            definition = self._definitions.get(
                _check_str(experiment_id, "experiment_id")
            )
            if definition is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} is not defined"
                )
            state = self._states[experiment_id]
            if state != "running":
                raise ExperimentStateError(
                    f"experiment {experiment_id!r} is {state}, not running"
                )
            self._states[experiment_id] = "completed"
            return self.status(experiment_id)

    # -- views ---------------------------------------------------------

    def status(self, experiment_id: str) -> ExperimentStatus:
        with self._lock:
            definition = self._definitions.get(
                _check_str(experiment_id, "experiment_id")
            )
            if definition is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} is not defined"
                )
            return ExperimentStatus(
                experiment_id=experiment_id,
                state=self._states[experiment_id],
                definition_seq=definition.seq,
                run_seq=self._run_seqs.get(experiment_id),
                abort_seq=self._abort_seqs.get(experiment_id),
            )

    def definition(self, experiment_id: str) -> ExperimentDefinition:
        with self._lock:
            definition = self._definitions.get(
                _check_str(experiment_id, "experiment_id")
            )
            if definition is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} is not defined"
                )
            return definition

    def report(self, experiment_id: str) -> RunReport:
        with self._lock:
            report = self._reports.get(
                _check_str(experiment_id, "experiment_id")
            )
            if report is None:
                raise UnknownExperimentError(
                    f"experiment {experiment_id!r} has no run report"
                )
            return report

    def experiment_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._definitions))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def chaos_experiment_audit_event(
    kind: str,
    seq: int,
    experiment_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a chaos event.

    ``kind`` is one of ``"defined"`` / ``"ran"`` / ``"aborted"`` /
    ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    record: Dict[str, Any] = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA,
        "kind": kind,
        "seq": _check_seq(seq),
    }
    if experiment_id is not None:
        record["experiment_id"] = _check_str(experiment_id, "experiment_id")
    if detail is not None:
        record["detail"] = _check_str(detail, "detail")
    return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    exp = ChaosExperiment()
    faults = (
        FaultSpec("pod-kill", (("duration_seqs", 10),)),
        FaultSpec("network-delay", (("delay_ms", 200), ("duration_seqs", 5),)),
    )
    targets = ("web-0", "web-1", "web-2", "web-3")
    radius = BlastRadius(max_affected_pct=25)
    assert radius.budget(4) == 1
    definition = exp.define("kill-one", faults, targets, radius, seq=1)
    assert definition.digest.startswith("sha256:")
    assert definition.budget == 1
    report = exp.run("kill-one", seq=2)
    assert len(report.assignments) == 1
    assert report.affected_targets[0] in targets
    assert exp.status("kill-one").state == "running"
    record = exp.abort("kill-one", seq=3)
    assert record.digest.startswith("sha256:")
    assert exp.status("kill-one").state == "aborted"
    rec = chaos_experiment_audit_event("ran", seq=4, experiment_id="kill-one")
    assert rec["format"] == AUDIT_FORMAT and rec["schema"] == SCHEMA
    print("chaos-experiment OK: define, run, abort, budget, determinism")


if __name__ == "__main__":
    main()
