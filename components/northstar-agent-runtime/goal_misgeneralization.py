"""GoalMisgeneralization: goal-misgeneralization detection / correction bookkeeping for agents.

Research note: Shah et al. (2022, "Goal Misgeneralization in Deep
Reinforcement Learning") show that an agent's *capabilities* can
generalize to a new situation while its *goal* does not -- training
reward proxies (e.g. "move right to reach the coin") correlate with the
true goal in-distribution, then decorrelate out-of-distribution and the
agent pursues the wrong objective. This module is the *ledger* layer
for that practice:

* **declare_goal()** books the intended goal, pinned by digest only
  (raw intent text never enters a record).
* **observe()** books one host-reported behavioral sample
  (``obs-N`` ids) against a declared goal.
* **detect()** compares the booked behavior digests against the
  intended goal digest and reports divergence as data: an exact
  ``divergent/total`` fraction and a ``misgeneralized`` boolean
  (``divergence >= threshold``) -- never raised, never a claim about a
  real system.
* **correct()** books one declared correction decision against a
  pinned strategy vocabulary (``retrain`` / ``reward-reshape`` /
  ``constraint-add`` / ``monitor`` / ``rollback`` / ``human-review``);
  it is fail-closed without a booked detection report.
* **test()** books one declared out-of-distribution probe of a booked
  goal, with the scenario pinned by digest and the verdict
  (``holds`` / ``breaks`` / ``inconclusive``) booked as data.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* goals, *host-reported*
behavioral samples, and *declared* corrections; it cannot observe a
real agent, prove a goal really misgeneralized, or prove a correction
worked. Raw intent/behavior text never enters records and never
crosses the audit boundary (digest pins only). Simulated per spec.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
GOAL_MISGENERALIZATION_VERSION = "goal-misgeneralization.v1"

#: Schema pin carried by records and audit events.
GOAL_MISGENERALIZATION_SCHEMA = "northstar.goal-misgeneralization.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_GOAL_DECLARED = "goal-misgeneralization.goal-declared"
KIND_OBSERVED = "goal-misgeneralization.observed"
KIND_DETECTED = "goal-misgeneralization.detected"
KIND_CORRECTED = "goal-misgeneralization.corrected"
KIND_TESTED = "goal-misgeneralization.tested"
KIND_REJECTED = "goal-misgeneralization.rejected"
_KINDS = frozenset(
    {
        KIND_GOAL_DECLARED,
        KIND_OBSERVED,
        KIND_DETECTED,
        KIND_CORRECTED,
        KIND_TESTED,
        KIND_REJECTED,
    }
)

#: Pinned correction-strategy vocabulary.
STRATEGY_RETRAIN = "retrain"
STRATEGY_REWARD_RESHAPE = "reward-reshape"
STRATEGY_CONSTRAINT_ADD = "constraint-add"
STRATEGY_MONITOR = "monitor"
STRATEGY_ROLLBACK = "rollback"
STRATEGY_HUMAN_REVIEW = "human-review"
_STRATEGIES = frozenset(
    {
        STRATEGY_RETRAIN,
        STRATEGY_REWARD_RESHAPE,
        STRATEGY_CONSTRAINT_ADD,
        STRATEGY_MONITOR,
        STRATEGY_ROLLBACK,
        STRATEGY_HUMAN_REVIEW,
    }
)

#: Pinned OOD-test verdict vocabulary.
VERDICT_HOLDS = "holds"
VERDICT_BREAKS = "breaks"
VERDICT_INCONCLUSIVE = "inconclusive"
_VERDICTS = frozenset({VERDICT_HOLDS, VERDICT_BREAKS, VERDICT_INCONCLUSIVE})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class GoalMisgeneralizationError(Exception):
    """Base class for all goal-misgeneralization errors."""


class BadGoalError(GoalMisgeneralizationError):
    """goal_id is not a usable non-empty str."""


class DuplicateGoalError(GoalMisgeneralizationError):
    """goal_id was already declared."""


class UnknownGoalError(GoalMisgeneralizationError):
    """goal_id names no declared goal."""


class BadDigestError(GoalMisgeneralizationError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadStrategyError(GoalMisgeneralizationError):
    """correction strategy is not in the pinned vocabulary."""


class BadVerdictError(GoalMisgeneralizationError):
    """test verdict is not in the pinned vocabulary."""


class BadThresholdError(GoalMisgeneralizationError):
    """threshold is not a finite float in (0, 1]."""


class NoObservationsError(GoalMisgeneralizationError):
    """No behavioral observations booked for a goal that needs them."""


class NoDetectionError(GoalMisgeneralizationError):
    """No detection report booked for a goal that needs one."""


class SeqOrderError(GoalMisgeneralizationError):
    """seq is not a strictly-increasing int."""


class AuditKindError(GoalMisgeneralizationError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadGoalError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadGoalError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadGoalError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_digest(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_strategy(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadStrategyError(f"strategy must be a str, got {type(value).__name__}")
    if value not in _STRATEGIES:
        raise BadStrategyError(f"strategy {value!r} not in pinned vocabulary")
    return value


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in _VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned vocabulary")
    return value


def _check_threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadThresholdError(f"threshold must be a number, got {type(value).__name__}")
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise BadThresholdError("threshold must be finite")
    if not 0.0 < value <= 1.0:
        raise BadThresholdError("threshold must be in (0, 1]")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        result = _cj.jcs_dumps(payload)  # type: ignore
        if isinstance(result, str):
            return result.encode("utf-8")
        return bytes(result)

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise GoalMisgeneralizationError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise GoalMisgeneralizationError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise GoalMisgeneralizationError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoalRecord:
    """One declared intended goal; the intent text is digest-pinned only."""

    goal_id: str
    intended_digest: str
    digest: str
    seq: int
    schema: str = GOAL_MISGENERALIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.goal_id, self.intended_digest), "goal"
        )


@dataclass(frozen=True)
class ObservationRecord:
    """One host-reported behavioral sample against a declared goal."""

    observation_id: str
    goal_id: str
    behavior_digest: str
    outcome_digest: str
    context_digest: str
    digest: str
    seq: int
    schema: str = GOAL_MISGENERALIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.observation_id,
                self.goal_id,
                self.behavior_digest,
                self.outcome_digest,
                self.context_digest,
            ),
            "observation",
        )


@dataclass(frozen=True)
class DetectionReport:
    """Divergence report for a goal: exact fraction + misgeneralized as data."""

    report_id: str
    goal_id: str
    intended_digest: str
    divergent: int
    total: int
    divergence_text: str
    misgeneralized: bool
    threshold: float
    digest: str
    seq: int
    schema: str = GOAL_MISGENERALIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.report_id,
                self.goal_id,
                self.intended_digest,
                self.divergent,
                self.total,
                self.divergence_text,
                self.misgeneralized,
                repr(self.threshold),
            ),
            "detection",
        )


@dataclass(frozen=True)
class CorrectionRecord:
    """One declared correction decision against a booked detection report."""

    correction_id: str
    report_id: str
    goal_id: str
    strategy: str
    digest: str
    seq: int
    schema: str = GOAL_MISGENERALIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.correction_id, self.report_id, self.goal_id, self.strategy),
            "correction",
        )


@dataclass(frozen=True)
class TestReport:
    """One declared out-of-distribution probe of a booked goal; verdict as data."""

    test_id: str
    goal_id: str
    scenario_digest: str
    verdict: str
    digest: str
    seq: int
    schema: str = GOAL_MISGENERALIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.test_id, self.goal_id, self.scenario_digest, self.verdict),
            "test",
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def goal_misgeneralization_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw intent/behavior text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "intent",
        "behavior",
        "outcome",
        "scenario",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "goal-misgeneralization",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# GoalMisgeneralization ledger
# ---------------------------------------------------------------------------


class GoalMisgeneralization:
    """Goal-misgeneralization detection/correction bookkeeping ledger.

    declare_goal -> observe -> detect -> correct / test. All verdicts are
    data; nothing here proves anything about a real agent.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # goal_id -> GoalRecord (ordered)
        self._goals: Dict[str, GoalRecord] = {}
        # observation_id -> ObservationRecord (ordered)
        self._observations: Dict[str, ObservationRecord] = {}
        # goal_id -> [observation_id] in booking order
        self._observations_for: Dict[str, List[str]] = {}
        # report_id -> DetectionReport (ordered)
        self._reports: Dict[str, DetectionReport] = {}
        # goal_id -> count of detection reports
        self._report_counts: Dict[str, int] = {}
        # correction_id -> CorrectionRecord (ordered)
        self._corrections: Dict[str, CorrectionRecord] = {}
        # test_id -> TestReport (ordered)
        self._tests: Dict[str, TestReport] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            goal_misgeneralization_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: GoalMisgeneralizationError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def declare_goal(self, goal_id: str, intended_digest: str, seq: int) -> GoalRecord:
        """Declare the intended goal; the intent text travels as a digest pin only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_id(goal_id, "goal_id")
                intended_digest = _check_digest(intended_digest, "intended_digest")
            except GoalMisgeneralizationError as exc:
                self._fail(seq, exc, goal_id=str(goal_id))
            if goal_id in self._goals:
                self._fail(
                    seq,
                    DuplicateGoalError(f"goal already declared: {goal_id!r}"),
                    goal_id=goal_id,
                )
            record = GoalRecord(
                goal_id=goal_id,
                intended_digest=intended_digest,
                digest=_digest_pin((goal_id, intended_digest), "goal"),
                seq=seq,
            )
            self._goals[goal_id] = record
            self._observations_for[goal_id] = []
            self._report_counts[goal_id] = 0
            self._emit(
                KIND_GOAL_DECLARED,
                seq,
                goal_id=goal_id,
                intended_digest=intended_digest,
                record_digest=record.digest,
            )
            return record

    def observe(
        self,
        goal_id: str,
        behavior_digest: str,
        outcome_digest: str,
        seq: int,
        context_digest: str = "",
    ) -> ObservationRecord:
        """Book one host-reported behavioral sample against a declared goal."""
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_id(goal_id, "goal_id")
                behavior_digest = _check_digest(behavior_digest, "behavior_digest")
                outcome_digest = _check_digest(outcome_digest, "outcome_digest")
                if context_digest != "":
                    context_digest = _check_digest(context_digest, "context_digest")
            except GoalMisgeneralizationError as exc:
                self._fail(seq, exc, goal_id=str(goal_id))
            if goal_id not in self._goals:
                self._fail(
                    seq,
                    UnknownGoalError(f"unknown goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            observation_id = f"obs-{len(self._observations) + 1}"
            record = ObservationRecord(
                observation_id=observation_id,
                goal_id=goal_id,
                behavior_digest=behavior_digest,
                outcome_digest=outcome_digest,
                context_digest=context_digest,
                digest=_digest_pin(
                    (
                        observation_id,
                        goal_id,
                        behavior_digest,
                        outcome_digest,
                        context_digest,
                    ),
                    "observation",
                ),
                seq=seq,
            )
            self._observations[observation_id] = record
            self._observations_for[goal_id].append(observation_id)
            self._emit(
                KIND_OBSERVED,
                seq,
                observation_id=observation_id,
                goal_id=goal_id,
                behavior_digest=behavior_digest,
                outcome_digest=outcome_digest,
                record_digest=record.digest,
            )
            return record

    def detect(self, goal_id: str, seq: int, threshold: float = 0.5) -> DetectionReport:
        """Compare booked behavior digests against the intended goal digest.

        An observation is divergent when its behavior digest differs from
        the intended digest. ``misgeneralized`` is ``divergence >=
        threshold`` -- booked as data, never raised.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_id(goal_id, "goal_id")
                threshold = _check_threshold(threshold)
            except GoalMisgeneralizationError as exc:
                self._fail(seq, exc, goal_id=str(goal_id))
            if goal_id not in self._goals:
                self._fail(
                    seq,
                    UnknownGoalError(f"unknown goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            obs_ids = self._observations_for[goal_id]
            if not obs_ids:
                self._fail(
                    seq,
                    NoObservationsError(f"no observations for goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            intended = self._goals[goal_id].intended_digest
            divergent = sum(
                1
                for oid in obs_ids
                if self._observations[oid].behavior_digest != intended
            )
            total = len(obs_ids)
            divergence = Fraction(divergent, total)
            divergence_text = f"{divergence.numerator}/{divergence.denominator}"
            misgeneralized = divergence >= Fraction(str(threshold))
            report_id = f"rep-{len(self._reports) + 1}"
            report = DetectionReport(
                report_id=report_id,
                goal_id=goal_id,
                intended_digest=intended,
                divergent=divergent,
                total=total,
                divergence_text=divergence_text,
                misgeneralized=misgeneralized,
                threshold=threshold,
                digest=_digest_pin(
                    (
                        report_id,
                        goal_id,
                        intended,
                        divergent,
                        total,
                        divergence_text,
                        misgeneralized,
                        repr(threshold),
                    ),
                    "detection",
                ),
                seq=seq,
            )
            self._reports[report_id] = report
            self._report_counts[goal_id] += 1
            self._emit(
                KIND_DETECTED,
                seq,
                report_id=report_id,
                goal_id=goal_id,
                divergent=divergent,
                total=total,
                divergence_text=divergence_text,
                misgeneralized=misgeneralized,
                record_digest=report.digest,
            )
            return report

    def correct(self, goal_id: str, seq: int, strategy: str) -> CorrectionRecord:
        """Book a declared correction decision against a booked detection report.

        Fail-closed when the goal has no detection report on record.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_id(goal_id, "goal_id")
                strategy = _check_strategy(strategy)
            except GoalMisgeneralizationError as exc:
                self._fail(seq, exc, goal_id=str(goal_id))
            if goal_id not in self._goals:
                self._fail(
                    seq,
                    UnknownGoalError(f"unknown goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            if self._report_counts[goal_id] == 0:
                self._fail(
                    seq,
                    NoDetectionError(f"no detection report for goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            report_id = f"rep-{len(self._reports)}"
            correction_id = f"cor-{len(self._corrections) + 1}"
            record = CorrectionRecord(
                correction_id=correction_id,
                report_id=report_id,
                goal_id=goal_id,
                strategy=strategy,
                digest=_digest_pin(
                    (correction_id, report_id, goal_id, strategy), "correction"
                ),
                seq=seq,
            )
            self._corrections[correction_id] = record
            self._emit(
                KIND_CORRECTED,
                seq,
                correction_id=correction_id,
                report_id=report_id,
                goal_id=goal_id,
                strategy=strategy,
                record_digest=record.digest,
            )
            return record

    def test(self, goal_id: str, seq: int, scenario_digest: str = "", verdict: str = VERDICT_INCONCLUSIVE) -> TestReport:
        """Book a declared out-of-distribution probe; the verdict is data."""
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_id(goal_id, "goal_id")
                if scenario_digest != "":
                    scenario_digest = _check_digest(scenario_digest, "scenario_digest")
                verdict = _check_verdict(verdict)
            except GoalMisgeneralizationError as exc:
                self._fail(seq, exc, goal_id=str(goal_id))
            if goal_id not in self._goals:
                self._fail(
                    seq,
                    UnknownGoalError(f"unknown goal: {goal_id!r}"),
                    goal_id=goal_id,
                )
            test_id = f"tst-{len(self._tests) + 1}"
            record = TestReport(
                test_id=test_id,
                goal_id=goal_id,
                scenario_digest=scenario_digest,
                verdict=verdict,
                digest=_digest_pin(
                    (test_id, goal_id, scenario_digest, verdict), "test"
                ),
                seq=seq,
            )
            self._tests[test_id] = record
            self._emit(
                KIND_TESTED,
                seq,
                test_id=test_id,
                goal_id=goal_id,
                scenario_digest=scenario_digest,
                verdict=verdict,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def goal_record(self, goal_id: str, seq: int) -> Optional[GoalRecord]:
        """Pure read: the booked goal record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._goals.get(goal_id)

    def goal_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of declared goals, in declaration order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._goals)

    def observations_for(self, goal_id: str, seq: int) -> Tuple[ObservationRecord, ...]:
        """Pure read: behavioral samples booked for a goal, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._observations[oid] for oid in self._observations_for.get(goal_id, ()))

    def detection_report(self, report_id: str, seq: int) -> Optional[DetectionReport]:
        """Pure read: the booked detection report, or None."""
        _check_seq(seq)
        with self._lock:
            return self._reports.get(report_id)

    def reports_for(self, goal_id: str, seq: int) -> Tuple[DetectionReport, ...]:
        """Pure read: detection reports booked for a goal, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(r for r in self._reports.values() if r.goal_id == goal_id)

    def corrections_for(self, goal_id: str, seq: int) -> Tuple[CorrectionRecord, ...]:
        """Pure read: correction decisions booked for a goal, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(c for c in self._corrections.values() if c.goal_id == goal_id)

    def tests_for(self, goal_id: str, seq: int) -> Tuple[TestReport, ...]:
        """Pure read: OOD probes booked for a goal, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(t for t in self._tests.values() if t.goal_id == goal_id)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "goals": len(self._goals),
                "observations": len(self._observations),
                "reports": len(self._reports),
                "corrections": len(self._corrections),
                "tests": len(self._tests),
                "misgeneralized_goals": sum(1 for r in self._reports.values() if r.misgeneralized),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: declare, observe, detect, correct, test."""
    ledger = GoalMisgeneralization()
    intended = "sha256:" + "a" * 64
    off_goal = "sha256:" + "b" * 64
    goal = ledger.declare_goal("coinrun", intended, 1)
    assert goal.verify()
    for seq in (2, 3, 4):
        obs = ledger.observe("coinrun", intended, intended, seq)
        assert obs.verify()
    # one divergent sample
    obs4 = ledger.observe("coinrun", off_goal, off_goal, 5)
    assert obs4.verify() and obs4.observation_id == "obs-4"
    report = ledger.detect("coinrun", 6)
    assert report.verify()
    assert report.divergent == 1 and report.total == 4
    assert report.divergence_text == "1/4"
    assert report.misgeneralized is False  # 0.25 < default 0.5
    report2 = ledger.detect("coinrun", 7, threshold=0.25)
    assert report2.misgeneralized is True
    cor = ledger.correct("coinrun", 8, "reward-reshape")
    assert cor.verify() and cor.correction_id == "cor-1"
    assert cor.report_id == "rep-2"  # latest report
    tst = ledger.test("coinrun", 9, scenario_digest=off_goal, verdict="breaks")
    assert tst.verify() and tst.test_id == "tst-1"
    stats = ledger.stats(10)
    assert stats["goals"] == 1 and stats["reports"] == 2
    assert stats["misgeneralized_goals"] == 1
    print("goal-misgeneralization OK: declare, observe, detect, correct, test, pins")


if __name__ == "__main__":
    main()
