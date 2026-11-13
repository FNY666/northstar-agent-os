"""Deterministic gate-and-score ledger with a three-state case outcome.

Motivation (sources, read 2026-11-13/14 -- see ``docs/design/
deterministic-gate-score.md`` for the verbatim excerpts):

- Agents' Last Exam (arXiv 2606.05405) scores 93.2% of its tasks with
  deterministic code, not LLM-as-judge, and decomposes a task into named
  deterministic gates that all have to pass.
- Inspect AI's "Scoring Policy" gives a scorer three outcomes: a score,
  ``Score.unscored()`` (no verdict, NaN, excluded from metrics, does *not*
  trigger a retry) and a raised error (recorded on the sample, produces no
  score, retryable via ``retry_on_error``).

Northstar's own ``evaluation_harness.py`` has neither concept: it books
exactly one pass boolean and one metric per case, so an infrastructure
failure during scoring can only be recorded as a model failure (score 0) or
not recorded at all (the run is lost).  This module adds the missing
half: a case is decomposed into *named deterministic gates*, and the
outcome of scoring a case is one of three states.

Three states (Northstar extension; the source shape is Inspect AI's):

- ``scored``  -- a verdict and a metric in [0, 1].  The case passed iff
  *every* gate passed.
- ``unscored`` -- the scorer could not reach a verdict.  The metric is NaN,
  the case is excluded from every aggregate, and it does not trigger a
  retry (Inspect: unscored "does not trigger a retry").
- ``errored`` -- an infrastructure or solver error.  No score is produced,
  the error text is recorded, and the case *is* eligible for a retry.

The aggregate pass rate divides by the number of ``scored`` cases only:
``errored`` is not a model failure and ``unscored`` is not a verdict, so
neither may land in the denominator.  A report always states the three
counts separately -- a bare pass rate is not a report.

``score_on_error`` mirrors Inspect AI: when the solver errored, the state
that *was* reached may still be scored.  If that partial state fails a
gate the case counts as a scored failure (it is in the denominator), and
the error is still recorded.

Honest scope:

- Gates are *declared* deterministic checks.  This module runs them and
  books their verdicts; it cannot prove that a gate is fair, complete, or
  free of side effects.  Gate callables are expected to be pure.
- A booked score is a ledger entry, not a verified measurement.
- The ledger is in-memory.  Pair with the durable audit writer if eval
  state must survive a restart.

Fail-closed edges (raise, never guess):

- ``suite_id`` / ``case_id`` / gate names are non-empty str, <= 256 chars,
  with no whitespace.
- Digest pins must look like ``sha256:<64 hex>``.
- A case must declare at least one gate (an empty gate set is refused: it
  could trivially "pass all gates") and gate names must be unique.
- Gate callables must return a ``bool``; anything else is an error, never
  a silent truthiness conversion.
- A metric override must be a finite float in [0, 1] (bool refused).
- Seqs are ints (not bool), >= 0, strictly increasing per book.

Determinism: no wall clock anywhere.  The caller supplies the ``seq``.
"""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

#: Module version pin.
VERSION = "deterministic-gate-score.v1"

#: Schema pin for records produced by this module.
SCHEMA = "northstar.deterministic-gate-score.v1"

_ID_RE = re.compile(r"^[^\s]{1,256}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: The three scoring outcomes of one case.
OUTCOME_SCORED = "scored"
OUTCOME_UNSCORED = "unscored"
OUTCOME_ERRORED = "errored"

#: All three outcome names, in a stable order.
OUTCOMES = (OUTCOME_SCORED, OUTCOME_UNSCORED, OUTCOME_ERRORED)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class DeterministicGateScoreError(Exception):
    """Base error: every integrity failure raises, never returns bad data."""


class BadGateSetError(DeterministicGateScoreError):
    """The gate set is malformed (empty, bad name, non-callable check)."""


class EmptyGateSetError(BadGateSetError):
    """A case declared zero gates: it could trivially "pass everything"."""


class DuplicateGateError(BadGateSetError):
    """Two gates share a name."""


class BadCaseError(DeterministicGateScoreError):
    """The case spec is malformed."""


class DuplicateCaseError(DeterministicGateScoreError):
    """The same case was booked twice."""


class BadMetricError(DeterministicGateScoreError):
    """The metric is not a finite float in [0, 1]."""


class GateExecutionError(DeterministicGateScoreError):
    """A gate callable raised or returned a non-bool: no verdict."""


class SeqOrderError(DeterministicGateScoreError):
    """Seq discipline violation."""


# ---------------------------------------------------------------------------
# gates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Gate:
    """One named deterministic gate.

    ``check`` is a callable that receives the case artifact and returns a
    ``bool``: ``True`` means the gate passed.  It is expected to be pure
    -- the module calls it exactly once per scoring attempt and books the
    boolean, nothing else.

    ``evidence`` is a *pointer* to what the gate judged (a path, a digest
    pin, a section name).  It records where the verdict came from; the
    artifact itself is never copied into the ledger.
    """

    name: str
    check: Callable[[Any], bool]
    evidence: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _ID_RE.match(self.name):
            raise BadGateSetError(f"bad gate name: {self.name!r}")
        if not callable(self.check):
            raise BadGateSetError(f"gate {self.name!r} check is not callable")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise BadGateSetError(f"gate {self.name!r} needs an evidence pointer")

    def run(self, artifact: Any) -> bool:
        """Run the gate once.  Any failure to reach a bool is an error."""
        try:
            outcome = self.check(artifact)
        except Exception as error:  # noqa: BLE001 - deliberate: infra, not a verdict
            raise GateExecutionError(
                f"gate {self.name!r} raised {type(error).__name__}: {error}") from error
        if not isinstance(outcome, bool):
            raise GateExecutionError(
                f"gate {self.name!r} returned {type(outcome).__name__}, not bool")
        return outcome

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# case spec
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CaseSpec:
    """The pinned identity of one case.

    Only the artifact *digest* is kept -- raw case material never enters
    the ledger (same discipline as ``evaluation_harness.py``).
    """

    case_id: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not _ID_RE.match(self.case_id):
            raise BadCaseError(f"bad case_id: {self.case_id!r}")
        if not isinstance(self.artifact_digest, str) or not _DIGEST_RE.match(
                self.artifact_digest):
            raise BadCaseError(
                f"bad artifact digest pin: {self.artifact_digest!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "artifact_digest": self.artifact_digest,
            "schema": SCHEMA,
        }


def _check_metric(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadMetricError(f"metric must be a number, got {value!r}")
    f = float(value)
    if not math.isfinite(f) or not (0.0 <= f <= 1.0):
        raise BadMetricError(f"metric must be a finite float in [0, 1], got {value!r}")
    return f


def _check_gates(gates: Any) -> Tuple[Gate, ...]:
    """Validate a gate set fail-closed: non-empty, unique names."""
    if not isinstance(gates, (list, tuple)):
        raise BadGateSetError(f"gates must be a list or tuple, got {type(gates).__name__}")
    if not gates:
        raise EmptyGateSetError("empty gate set: a case must declare at least one gate")
    seen = set()
    out: list = []
    for gate in gates:
        if not isinstance(gate, Gate):
            raise BadGateSetError(f"gate must be a Gate, got {type(gate).__name__}")
        if gate.name in seen:
            raise DuplicateGateError(f"duplicate gate name: {gate.name!r}")
        seen.add(gate.name)
        out.append(gate)
    return tuple(out)


# ---------------------------------------------------------------------------
# gate verdicts and case outcome
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GateVerdict:
    """The verdict of one gate: passed or failed, with its evidence pointer."""

    name: str
    passed: bool
    evidence: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class GateReport:
    """The result of running one case's whole gate set.

    ``passed`` is True iff *every* gate passed -- the pass rule of the
    source (a case passes only if all of its gates pass).  The failing
    gate names are kept so a failure says *which* gate failed.
    """

    passed: bool
    verdicts: Tuple[GateVerdict, ...]

    @property
    def failed_gates(self) -> Tuple[str, ...]:
        return tuple(v.name for v in self.verdicts if not v.passed)

    @property
    def passed_gates(self) -> Tuple[str, ...]:
        return tuple(v.name for v in self.verdicts if v.passed)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "failed_gates": list(self.failed_gates),
            "verdicts": [v.as_dict() for v in self.verdicts],
        }


def run_gates(gates: Sequence[Gate], artifact: Any) -> GateReport:
    """Run a whole gate set over one artifact and return the gate report.

    Every gate is run, even after one fails, so the report names *all*
    failing gates rather than only the first.  A gate that raises or
    returns a non-bool raises ``GateExecutionError`` -- that is an
    execution failure, not a verdict.
    """
    gates = _check_gates(gates)
    verdicts = tuple(
        GateVerdict(name=g.name, passed=g.run(artifact), evidence=g.evidence)
        for g in gates)
    return GateReport(passed=all(v.passed for v in verdicts), verdicts=verdicts)


@dataclass(frozen=True)
class CaseOutcome:
    """The booked outcome of scoring one case.

    Exactly one of the three states:

    - ``scored``  -- ``metric`` is a finite float in [0, 1]; ``passed`` is
      a bool; ``failed_gates`` names the gates that failed (empty iff the
      case passed).  A scored case is in the pass-rate denominator.
    - ``unscored`` -- the scorer could not reach a verdict.  ``metric`` is
      NaN, ``passed`` is None, and the case is excluded from every
      aggregate.  It does not trigger a retry.
    - ``errored`` -- an infrastructure or solver error.  ``metric`` is
      NaN, ``passed`` is None, ``error`` carries the error text, and the
      case *is* eligible for a retry.  It is not a model failure and is
      not in the denominator.

    With ``score_on_error`` the solver errored but the state it had
    already reached was scored anyway: the outcome is then ``scored``
    (in the denominator, possibly failed) and the error is still
    recorded in ``error``.
    """

    case_id: str
    outcome: str
    passed: Optional[bool] = None
    metric: float = float("nan")
    failed_gates: Tuple[str, ...] = ()
    passed_gates: Tuple[str, ...] = ()
    error: str = ""
    attempt: int = 1

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise DeterministicGateScoreError(
                f"bad outcome: {self.outcome!r}")
        if self.outcome == OUTCOME_SCORED:
            if not isinstance(self.passed, bool):
                raise DeterministicGateScoreError(
                    "a scored outcome needs a bool passed")
            _check_metric(self.metric)
            if self.passed and self.failed_gates:
                raise DeterministicGateScoreError(
                    "a passed case cannot name failed gates")
            if not self.passed and not self.failed_gates:
                raise DeterministicGateScoreError(
                    "a failed case must name the gates that failed")
        else:
            if self.passed is not None:
                raise DeterministicGateScoreError(
                    f"a {self.outcome} outcome has no pass/fail verdict")
            if not math.isnan(self.metric):
                raise DeterministicGateScoreError(
                    f"a {self.outcome} outcome has no metric")

    @property
    def scored(self) -> bool:
        return self.outcome == OUTCOME_SCORED

    @property
    def unscored(self) -> bool:
        return self.outcome == OUTCOME_UNSCORED

    @property
    def errored(self) -> bool:
        return self.outcome == OUTCOME_ERRORED

    @property
    def retryable(self) -> bool:
        """Only an errored case may be scored again.

        An unscored case is final: the source's unscored state does not
        trigger a retry.  A scored case is final too.
        """
        return self.errored

    @property
    def counts_in_denominator(self) -> bool:
        """Only a scored case lands in the pass-rate denominator."""
        return self.scored

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "outcome": self.outcome,
            "passed": self.passed,
            "metric": None if math.isnan(self.metric) else self.metric,
            "failed_gates": list(self.failed_gates),
            "passed_gates": list(self.passed_gates),
            "error": self.error,
            "attempt": self.attempt,
            "retryable": self.retryable,
            "schema": SCHEMA,
        }


def is_retryable(outcome: str) -> bool:
    """Retry eligibility of a booking state, as a free function."""
    if outcome not in OUTCOMES:
        raise DeterministicGateScoreError(f"bad outcome: {outcome!r}")
    return outcome == OUTCOME_ERRORED


# ---------------------------------------------------------------------------
# aggregates
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Aggregates:
    """The aggregate view of one run.

    The pass rate divides by the number of *scored* cases only.  Errored
    cases are not model failures and unscored cases are not verdicts;
    neither lands in the denominator.  All three counts are always
    reported: a bare pass rate is not a report.
    """

    scored_count: int
    passed_count: int
    unscored_count: int
    errored_count: int
    pass_rate_text: str
    mean_metric_text: str
    failure_gates: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scored_count": self.scored_count,
            "passed_count": self.passed_count,
            "unscored_count": self.unscored_count,
            "errored_count": self.errored_count,
            "pass_rate_text": self.pass_rate_text,
            "mean_metric_text": self.mean_metric_text,
            "failure_gates": list(self.failure_gates),
            "schema": SCHEMA,
        }


def _rate_text(numerator: int, denominator: int) -> str:
    """Exact "n/m" text -- no floats, no rounding."""
    if denominator == 0:
        return "n/a"
    return f"{numerator}/{denominator}"


def _mean_text(values: Sequence[float]) -> str:
    """Exact mean metric as a fraction -- no floats, no rounding."""
    if not values:
        return "n/a"
    total = Fraction(0)
    for value in values:
        total += Fraction(value).limit_denominator(10 ** 9)
    mean = total / len(values)
    return f"{mean.numerator}/{mean.denominator}"


def aggregate(outcomes: Sequence[CaseOutcome]) -> Aggregates:
    """Aggregate a sequence of case outcomes.

    ``score_on_error`` outcomes are ``scored`` outcomes that also carry an
    error text, so they are in the denominator like any other scored
    case; the error is still recorded on the outcome itself.
    """
    scored = [o for o in outcomes if o.scored]
    unscored = [o for o in outcomes if o.unscored]
    errored = [o for o in outcomes if o.errored]
    passed = [o for o in scored if o.passed]
    failure_gates: list = []
    for outcome in outcomes:
        for name in outcome.failed_gates:
            if name not in failure_gates:
                failure_gates.append(name)
    return Aggregates(
        scored_count=len(scored),
        passed_count=len(passed),
        unscored_count=len(unscored),
        errored_count=len(errored),
        pass_rate_text=_rate_text(len(passed), len(scored)),
        mean_metric_text=_mean_text([o.metric for o in scored]),
        failure_gates=tuple(failure_gates),
    )


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CaseBooking:
    """One booked case: its identity, its outcome and its attempt count."""

    case_id: str
    artifact_digest: str
    outcome: CaseOutcome
    attempts: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "artifact_digest": self.artifact_digest,
            "outcome": self.outcome.as_dict(),
            "attempts": self.attempts,
            "schema": SCHEMA,
        }


class GateScoreLedger:
    """A deterministic gate-and-score ledger with three-state outcomes.

    Booking rules:

    - A case is booked exactly once per attempt.  Re-booking a case that
      already has a final state (``scored`` or ``unscored``) is refused.
    - An ``errored`` case may be booked again: that is the retry.  The
      attempt counter rises.
    - ``errored`` and ``unscored`` cases stay out of the pass-rate
      denominator; only ``scored`` cases are in it.

    The ledger keeps no wall clock: the caller supplies the ``seq``, which
    must be a strictly increasing int per instance.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._bookings: Dict[str, CaseBooking] = {}

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError(f"bad seq: {seq!r}")
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq {seq} not strictly increasing (last={self._last_seq})")
            self._last_seq = seq
            return seq

    # -- read views --------------------------------------------------------

    def booking(self, case_id: str) -> CaseBooking:
        """The booking of one case.  Raises if the case is unknown."""
        with self._lock:
            if case_id not in self._bookings:
                raise BadCaseError(f"unknown case: {case_id!r}")
            return self._bookings[case_id]

    def outcomes(self) -> Tuple[CaseOutcome, ...]:
        """Every booked outcome, in booking order (case id order for ties)."""
        with self._lock:
            return tuple(self._bookings[k].outcome for k in sorted(self._bookings))

    def report(self) -> Aggregates:
        """The aggregate view of the ledger."""
        return aggregate(self.outcomes())

    # -- booking -----------------------------------------------------------

    def _book(self, case_id: str, artifact_digest: str, outcome: CaseOutcome,
              attempt: int, seq: int) -> CaseOutcome:
        with self._lock:
            existing = self._bookings.get(case_id)
            if existing is not None and not existing.outcome.retryable:
                raise DuplicateCaseError(
                    f"case {case_id!r} already has a final outcome "
                    f"({existing.outcome.outcome})")
            self._bookings[case_id] = CaseBooking(
                case_id=case_id,
                artifact_digest=artifact_digest,
                outcome=outcome,
                attempts=attempt,
            )
        return outcome

    def score(self, case_id: str, artifact_digest: str, gates: Sequence[Gate],
              artifact: Any, seq: int, *, error: str = "",
              score_on_error: bool = False) -> CaseOutcome:
        """Score one case by running its deterministic gates.

        A case passes iff every gate passes; a failing gate names itself.

        ``error`` marks a solver or infrastructure error that happened
        while the case was being solved.  Without ``score_on_error`` the
        case is booked ``errored``: no score, error text recorded, retry
        eligible.  With ``score_on_error`` the state the solver had
        already reached is scored anyway: the outcome is ``scored`` (in
        the denominator, possibly failed) and the error text is still
        recorded on the outcome.
        """
        self._claim(seq)
        gates = _check_gates(gates)
        if not isinstance(artifact_digest, str) or not _DIGEST_RE.match(
                artifact_digest):
            raise BadCaseError(f"bad artifact digest pin: {artifact_digest!r}")
        with self._lock:
            existing = self._bookings.get(case_id)
        attempt = (existing.attempts + 1) if existing is not None else 1

        if error and not score_on_error:
            outcome = CaseOutcome(
                case_id=case_id,
                outcome=OUTCOME_ERRORED,
                error=error,
                attempt=attempt,
            )
            return self._book(case_id, artifact_digest, outcome, attempt, seq)

        report = run_gates(gates, artifact)
        outcome = CaseOutcome(
            case_id=case_id,
            outcome=OUTCOME_SCORED,
            passed=report.passed,
            metric=1.0 if report.passed else 0.0,
            failed_gates=report.failed_gates,
            passed_gates=report.passed_gates,
            error=error,
            attempt=attempt,
        )
        return self._book(case_id, artifact_digest, outcome, attempt, seq)

    def mark_unscored(self, case_id: str, artifact_digest: str, reason: str,
                      seq: int) -> CaseOutcome:
        """Book a case as ``unscored``: the scorer reached no verdict.

        The case is excluded from every aggregate and does not trigger a
        retry.  It is final.
        """
        self._claim(seq)
        if not isinstance(artifact_digest, str) or not _DIGEST_RE.match(
                artifact_digest):
            raise BadCaseError(f"bad artifact digest pin: {artifact_digest!r}")
        if not isinstance(reason, str) or not reason.strip():
            raise BadCaseError("an unscored booking needs a reason")
        with self._lock:
            existing = self._bookings.get(case_id)
        attempt = (existing.attempts + 1) if existing is not None else 1
        outcome = CaseOutcome(
            case_id=case_id,
            outcome=OUTCOME_UNSCORED,
            error=reason,
            attempt=attempt,
        )
        return self._book(case_id, artifact_digest, outcome, attempt, seq)

    def mark_errored(self, case_id: str, artifact_digest: str, error: str,
                     seq: int) -> CaseOutcome:
        """Book a case as ``errored``: an infrastructure or solver error.

        No score is produced, the error text is recorded, and the case is
        eligible for a retry.
        """
        self._claim(seq)
        if not isinstance(artifact_digest, str) or not _DIGEST_RE.match(
                artifact_digest):
            raise BadCaseError(f"bad artifact digest pin: {artifact_digest!r}")
        if not isinstance(error, str) or not error.strip():
            raise BadCaseError("an errored booking needs an error text")
        with self._lock:
            existing = self._bookings.get(case_id)
        attempt = (existing.attempts + 1) if existing is not None else 1
        outcome = CaseOutcome(
            case_id=case_id,
            outcome=OUTCOME_ERRORED,
            error=error,
            attempt=attempt,
        )
        return self._book(case_id, artifact_digest, outcome, attempt, seq)

    def retryable_cases(self) -> Tuple[str, ...]:
        """The case ids that may be scored again (the errored ones)."""
        with self._lock:
            return tuple(
                k for k in sorted(self._bookings)
                if self._bookings[k].outcome.retryable)


# ---------------------------------------------------------------------------
# driving one case end to end
# ---------------------------------------------------------------------------

#: Sentinel a solver returns when it reached no verdict at all.  A solver
#: returning this is booked ``unscored`` -- excluded from the aggregates
#: and not retried.
NO_VERDICT = object()


def score_case(ledger: GateScoreLedger, case_id: str, artifact_digest: str,
               gates: Sequence[Gate], solve: Callable[[], Any], seq: int, *,
               score_on_error: bool = False,
               partial: Optional[Callable[[], Any]] = None) -> CaseOutcome:
    """Solve one case and book its outcome, tri-state.

    ``solve`` is a callable that returns the case artifact, or
    :data:`NO_VERDICT` when it reached no verdict.  It may raise: a raised
    error is an infrastructure or solver error.

    - artifact returned -> the gates run and the case is booked ``scored``.
    - :data:`NO_VERDICT` returned -> booked ``unscored``: no score, out of
      the aggregates, no retry.
    - exception raised -> booked ``errored``: no score, the error text is
      recorded, the case may be scored again.

    With ``score_on_error`` and a ``partial`` accessor, a raised error is
    followed by scoring the state the solver had already reached: the
    outcome is then ``scored`` (in the denominator, possibly failed) and
    the error is still recorded.
    """
    try:
        artifact = solve()
    except Exception as error:  # noqa: BLE001 - infra, deliberately not a verdict
        text = f"{type(error).__name__}: {error}"
        if score_on_error and partial is not None:
            reached = partial()
            if reached is not None:
                outcome = ledger.score(case_id, artifact_digest, gates,
                                       reached, seq, error=text,
                                       score_on_error=True)
                return outcome
        return ledger.mark_errored(case_id, artifact_digest, text, seq)
    if artifact is NO_VERDICT:
        return ledger.mark_unscored(
            case_id, artifact_digest, "solver reached no verdict", seq)
    return ledger.score(case_id, artifact_digest, gates, artifact, seq)
