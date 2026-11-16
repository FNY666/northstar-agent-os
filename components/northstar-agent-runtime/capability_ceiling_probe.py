"""Capability-ceiling probe: fail-first admission, calibration error, ceiling
routing.

What was missing (read from the code, not assumed)
--------------------------------------------------
* ``capability_eval.py`` is a *ledger of capability claims*: it registers a
  capability, books probes, records a host-declared outcome
  (pass/fail/partial/timeout/error) and a score, and reports a profile.  It
  has **no difficulty score** (nothing says how hard a probe was) and **no
  calibration**: nothing compares a claimed confidence with what actually
  happened.
* ``confidence_gate.py`` gates *authorization* on a confidence tier.  Its
  own docstring says it outright: "Not the calibrator -- host provides
  confidence scores."  It consumes a number and never checks the number.
* ``exploit_difficulty.py`` is a one-way difficulty ratchet, but only for
  the ``exploit`` category, and it rates *a target class*, not *this
  agent's ceiling*.
* ``horizon_gate.py`` admits a task inside a **declared** verified 80%
  horizon; its registration discipline is the one this module copies: a
  number is only ever as good as the evidence behind it.

So: **nothing in the runtime measures a capability ceiling, and nothing
measures whether the agent is confidently wrong.**  A model that scores 9%
on a hard exam while reporting 95% confidence is the failure this module
is built to make visible.

The source (Humanity's Last Exam, arXiv:2501.14249) -- verbatim
----------------------------------------------------------------
* 2,500 expert-written, multi-domain, closed-book, auto-gradable questions
  (76% exact-match, 24% multiple-choice; about 14% multimodal).
* Admission is fail-first: a question is admitted only if it *stops a
  frontier model* -- roughly 70,000 candidates were filtered to 13,000,
  and 2,500 survived final review; about 500 are held out unpublished.
* Early frontier models scored in the single digits while their
  **calibration error exceeded 70%**: they were wrong *and* confident.
  HLE measures capability and calibration together.

Northstar extension (this module, not the source)
-------------------------------------------------
* HLE has a curated question bank; Northstar has no such bank, so the
  **difficulty proxy is METR human-minutes** -- an estimate of how many
  minutes a human would need for the task.  That proxy, and every threshold
  in this module, is a Northstar choice, not an HLE mechanism.
* The ceiling ledger is **one-way**: a verified ceiling is raised only by a
  measured pass, and a single failure never lowers it.  A failure says
  "this task is above the ceiling"; it does not falsify what was already
  verified.
* Routing is **bookkeeping plus a verdict**, never a dispatch: the module
  does not send anything to a human or split anything into pieces.

Honest scope
------------
* Nothing here predicts what the agent will do next.  The ledger records
  what was measured.
* The difficulty estimate is caller-supplied.  A caller that lies about it
  gets a useless ceiling.
* The module is pure and in-memory; it holds no tasks of its own beyond
  the probes, observations and verdicts it recorded.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

#: Version pin for this module's record shapes.
CAPABILITY_CEILING_PROBE_VERSION = "capability-ceiling-probe.v1"

#: Schema pin stamped on serialized records.
SCHEMA_PIN = "northstar.capability-ceiling-probe.v1"

#: The unit the difficulty proxy is expressed in.  Northstar extension:
#: METR-style estimates of *human minutes*, not an HLE difficulty score.
DIFFICULTY_UNIT = "human_minutes"

#: Name of the difficulty proxy, spelled out wherever it is reported.
DIFFICULTY_PROXY = "metr-human-minutes"

#: Default calibration-error threshold (absolute).  A bucket whose
#: calibration error exceeds it is flagged ``miscalibrated``.  Northstar
#: choice: the source reports "over 70%" for whole-model calibration error
#: on HLE, which is a different quantity on a different dataset.
DEFAULT_CALIBRATION_THRESHOLD = 0.20

#: Upper edges (human minutes) of the difficulty buckets.  Northstar
#: choice; a bucket is "difficulty <= edge".
BUCKET_EDGES: tuple[float, ...] = (30.0, 60.0, 120.0, 240.0, 480.0)

#: Above this multiple of the verified ceiling an over-ceiling task is
#: routed to a human rather than to decomposition.  Northstar choice.
DECOMPOSE_FACTOR = 2.0


class CapabilityCeilingProbeError(Exception):
    """Base class for every refusal this module raises."""


class BadProbeError(CapabilityCeilingProbeError):
    """A probe record is unusable (bad id, difficulty, confidence, outcome)."""


class DuplicateProbeError(CapabilityCeilingProbeError):
    """The same probe id was submitted twice."""


class UnknownProbeError(CapabilityCeilingProbeError):
    """A probe id was referenced that has never been submitted.

    **Reserved, never raised.**  Every operation on this ledger takes the
    probe object itself, so no call can name a probe id the ledger has
    never seen: an unknown id is refused as :class:`BadProbeError` (a
    malformed record) or :class:`DuplicateProbeError` (an id already
    submitted).  The class is kept because the name is the runtime's
    established one -- ``ai_probing``, ``capability_eval``, ``probing``
    and ``reward_hacking`` all raise it for their own id-keyed ledgers --
    and a future id-keyed operation here would need it.  It is declared,
    documented, and deliberately not raised by this module.
    """


class NotAFailureError(CapabilityCeilingProbeError):
    """Fail-first refusal: the agent already passed this task.

    A task the agent can do is not a capability-ceiling probe.  Admitting
    it would dilute the probe library with work that is already solved.
    """


class RouteTarget(str, Enum):
    """Where an over-ceiling task goes."""

    ATTEMPT = "attempt"          # inside the ceiling: take it
    DECOMPOSE = "decompose"      # over the ceiling: split it up
    HUMAN = "human"              # over the ceiling: hand it to a person

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.value


@dataclass(frozen=True)
class CeilingProbe:
    """One probe observation.

    Attributes:
        probe_id: caller-supplied identity of the probe.
        difficulty_human_minutes: difficulty **proxy** -- the METR-style
            estimate of how many minutes a human needs for this task.
            Northstar extension; not an HLE difficulty score.
        confidence: the agent's own confidence in the answer, 0-1.
        passed: whether the agent actually got it right.
    """

    probe_id: str
    difficulty_human_minutes: float
    confidence: float
    passed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.probe_id, str) or not self.probe_id:
            raise BadProbeError("probe_id must be a non-empty string")
        _check_difficulty(self.difficulty_human_minutes)
        _check_confidence(self.confidence)
        if not isinstance(self.passed, bool):
            raise BadProbeError("passed must be a bool")

    @property
    def bucket(self) -> str:
        """The difficulty bucket this probe falls in."""
        return bucket_for(self.difficulty_human_minutes)

    @property
    def error(self) -> float:
        """Per-probe calibration error: confidence - actual correctness."""
        return self.confidence - (1.0 if self.passed else 0.0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "probe_id": self.probe_id,
            "difficulty_human_minutes": self.difficulty_human_minutes,
            "difficulty_unit": DIFFICULTY_UNIT,
            "difficulty_proxy": DIFFICULTY_PROXY,
            "confidence": self.confidence,
            "passed": self.passed,
            "version": CAPABILITY_CEILING_PROBE_VERSION,
        }


@dataclass(frozen=True)
class CalibrationBucket:
    """Calibration for one difficulty bucket, as data.

    Attributes:
        bucket: bucket label.
        probes: how many observations landed in it.
        mean_confidence: mean of the agents' stated confidence.
        accuracy: fraction of observations that were correct.
        error: mean confidence minus accuracy (signed).
        miscalibrated: whether the absolute error exceeds the threshold.
        direction: ``"overconfident"``, ``"underconfident"`` or ``"none"``.
    """

    bucket: str
    probes: int
    mean_confidence: float
    accuracy: float
    error: float
    miscalibrated: bool
    direction: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "bucket": self.bucket,
            "probes": self.probes,
            "mean_confidence": self.mean_confidence,
            "accuracy": self.accuracy,
            "error": self.error,
            "miscalibrated": self.miscalibrated,
            "direction": self.direction,
            "version": CAPABILITY_CEILING_PROBE_VERSION,
        }


@dataclass(frozen=True)
class RoutingVerdict:
    """The routing verdict for one task estimate.

    Attributes:
        route: where the task goes.
        task_difficulty_human_minutes: the task's difficulty proxy.
        verified_ceiling_human_minutes: the verified ceiling in force, or
            ``None`` when no ceiling has been measured yet.
        overage_human_minutes: how far the task exceeds the ceiling, or
            ``None`` when it is inside.
        reason: why, in words.
        recommendation: what the caller should do about it.
        ceiling_source: ``"measured"``, ``"declared"`` or ``"none"``.
    """

    route: RouteTarget
    task_difficulty_human_minutes: float
    verified_ceiling_human_minutes: Optional[float]
    overage_human_minutes: Optional[float]
    reason: str
    recommendation: str
    ceiling_source: str

    @property
    def over_ceiling(self) -> bool:
        """Whether the task was kept out of the agent's own hands."""
        return self.route is not RouteTarget.ATTEMPT

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "route": self.route.value,
            "task_difficulty_human_minutes": self.task_difficulty_human_minutes,
            "verified_ceiling_human_minutes": self.verified_ceiling_human_minutes,
            "overage_human_minutes": self.overage_human_minutes,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "ceiling_source": self.ceiling_source,
            "difficulty_unit": DIFFICULTY_UNIT,
            "version": CAPABILITY_CEILING_PROBE_VERSION,
        }


@dataclass(frozen=True)
class Submission:
    """The result of submitting one probe.

    Attributes:
        probe: the observation as recorded.
        admitted: whether it entered the ceiling-probe library.
        reason: why it was admitted or refused.
        ceiling_raised_to: the new verified ceiling, when this submission
            raised it; ``None`` otherwise.
    """

    probe: CeilingProbe
    admitted: bool
    reason: str
    ceiling_raised_to: Optional[float] = None
    ceiling_source: str = "none"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "probe": self.probe.as_dict(),
            "admitted": self.admitted,
            "reason": self.reason,
            "ceiling_raised_to": self.ceiling_raised_to,
            "ceiling_source": self.ceiling_source,
            "version": CAPABILITY_CEILING_PROBE_VERSION,
        }


def _check_difficulty(value: Any) -> float:
    """Return a finite, positive difficulty estimate in human minutes."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadProbeError(
            f"difficulty_human_minutes must be a number, got {value!r}"
        )
    number = float(value)
    if not math.isfinite(number):
        raise BadProbeError(
            f"difficulty_human_minutes must be finite, got {value!r}"
        )
    if number <= 0:
        raise BadProbeError(
            f"difficulty_human_minutes must be positive, got {value!r}"
        )
    return number


def _check_confidence(value: Any) -> float:
    """Return a confidence in [0, 1]."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadProbeError(f"confidence must be a number, got {value!r}")
    number = float(value)
    if not math.isfinite(number):
        raise BadProbeError(f"confidence must be finite, got {value!r}")
    if not 0.0 <= number <= 1.0:
        raise BadProbeError(f"confidence must be in [0,1], got {value!r}")
    return number


def bucket_for(difficulty_human_minutes: float) -> str:
    """The difficulty bucket label for a difficulty estimate.

    Buckets are closed on the upper edge: a task of exactly 30 human
    minutes lands in ``"0-30"``, not in ``"30-60"``.
    """
    difficulty = _check_difficulty(difficulty_human_minutes)
    low = 0.0
    for edge in BUCKET_EDGES:
        if difficulty <= edge:
            return f"{int(low)}-{int(edge)}"
        low = edge
    return f"{int(BUCKET_EDGES[-1])}+"


class CeilingLedger:
    """The capability-ceiling ledger: probes, calibration, routing.

    Four rules, fixed:

    1. **Fail-first admission.**  Only a task the agent got *wrong* is a
       ceiling probe.  Submitting a passed task is refused with
       :class:`NotAFailureError`: a solved task is not a probe.
    2. **Calibration is measured, not asserted.**  Every probe registers
       difficulty, confidence and the actual outcome; the error
       (confidence minus accuracy) is aggregated per difficulty bucket and
       a bucket whose absolute error exceeds the threshold is flagged
       ``miscalibrated``.
    3. **The ceiling only rises on measured evidence.**  It is raised by a
       probe the agent *passed* -- nothing else.  A failure never lowers a
       verified ceiling: it says "this task is above the ceiling", not
       "the ceiling was wrong".
    4. **Over-ceiling tasks are routed, not attempted.**  A task whose
       difficulty is above the verified ceiling goes to decomposition or
       to a human.  Routing is a verdict plus a ledger entry; nothing is
       dispatched.

    The ceiling ledger therefore holds two kinds of entry: *failures*
    (the probe library -- tasks that stopped the agent) and *passes* (the
    only evidence that may raise the ceiling).
    """

    def __init__(
        self,
        *,
        calibration_threshold: float = DEFAULT_CALIBRATION_THRESHOLD,
        declared_ceiling_human_minutes: Optional[float] = None,
    ) -> None:
        if isinstance(calibration_threshold, bool) or not isinstance(
            calibration_threshold, (int, float)
        ):
            raise CapabilityCeilingProbeError(
                "calibration_threshold must be a number, got "
                f"{calibration_threshold!r}"
            )
        threshold = float(calibration_threshold)
        if not math.isfinite(threshold) or threshold < 0:
            raise CapabilityCeilingProbeError(
                "calibration_threshold must be finite and non-negative"
            )
        self.calibration_threshold = threshold
        if declared_ceiling_human_minutes is not None:
            declared = _check_difficulty(declared_ceiling_human_minutes)
            self._ceiling: Optional[float] = declared
            self._ceiling_source = "declared"
        else:
            self._ceiling = None
            self._ceiling_source = "none"
        self._probes: list[CeilingProbe] = []
        self._passed: list[CeilingProbe] = []
        self._seen_ids: set[str] = set()
        self._verdicts: list[RoutingVerdict] = []

    # -- views -------------------------------------------------------------

    @property
    def verified_ceiling_human_minutes(self) -> Optional[float]:
        """The verified ceiling in human minutes, or ``None`` if unmeasured."""
        return self._ceiling

    @property
    def ceiling_source(self) -> str:
        """``"measured"``, ``"declared"`` or ``"none"``."""
        return self._ceiling_source

    @property
    def probes(self) -> tuple[CeilingProbe, ...]:
        """Every admitted (failed) probe, in submission order."""
        return tuple(self._probes)

    @property
    def passes(self) -> tuple[CeilingProbe, ...]:
        """Every passed probe, in submission order."""
        return tuple(self._passed)

    @property
    def verdicts(self) -> tuple[RoutingVerdict, ...]:
        """Every routing verdict, in order."""
        return tuple(self._verdicts)

    # -- submission --------------------------------------------------------

    def submit(self, probe: CeilingProbe) -> Submission:
        """Submit one probe observation (deprecated alias).

        Kept as a thin alias for :meth:`observe` so the module has one
        obvious entry point for recording a measurement.
        """
        return self.observe(probe)

    def observe(self, probe: CeilingProbe) -> Submission:
        """Record one observation of the agent on one task.

        An observation always registers: difficulty, confidence and the
        actual outcome all go into the ledger, because a confident pass is
        as much a calibration fact as a confident failure.

        An observation the agent *passed* is **not** admitted to the
        ceiling-probe library -- fail-first admission -- and it is the
        only thing that may raise the verified ceiling.

        An observation the agent *failed* is admitted to the probe
        library.  It never lowers the ceiling.
        """
        if not isinstance(probe, CeilingProbe):
            raise BadProbeError(
                f"probe must be a CeilingProbe, got {type(probe).__name__}"
            )
        if probe.probe_id in self._seen_ids:
            raise DuplicateProbeError(
                f"probe_id {probe.probe_id!r} was already submitted"
            )
        self._seen_ids.add(probe.probe_id)

        if probe.passed:
            self._passed.append(probe)
            raised_to = self._raise_ceiling(probe.difficulty_human_minutes)
            return Submission(
                probe=probe,
                admitted=False,
                reason=(
                    "the agent passed this task, so it is not a capability-"
                    "ceiling probe (fail-first admission); the observation "
                    "is kept for calibration"
                    + (
                        f" and the verified ceiling rose to {raised_to:g} "
                        "human minutes"
                        if raised_to is not None
                        else ""
                    )
                ),
                ceiling_raised_to=raised_to,
                ceiling_source=self._ceiling_source,
            )

        self._probes.append(probe)
        return Submission(
            probe=probe,
            admitted=True,
            reason=(
                "the agent failed this task, so it is admitted to the "
                "capability-ceiling probe library; a failure never lowers "
                "the verified ceiling"
            ),
            ceiling_raised_to=None,
            ceiling_source=self._ceiling_source,
        )

    def admit_probe(self, probe: CeilingProbe) -> Submission:
        """Admit a task to the ceiling-probe library, fail-first.

        This is the strict door: a task the agent has already **passed**
        is refused outright with :class:`NotAFailureError` and is not
        recorded at all.  Only a task the agent got wrong is a capability
        ceiling probe.

        Use :meth:`observe` instead when the outcome is a pass that should
        still count as calibration evidence or raise the ceiling.
        """
        if not isinstance(probe, CeilingProbe):
            raise BadProbeError(
                f"probe must be a CeilingProbe, got {type(probe).__name__}"
            )
        if probe.passed:
            raise NotAFailureError(
                f"probe {probe.probe_id!r} was passed by the agent, so it "
                "is not a capability-ceiling probe: only a task that "
                "stops the agent enters the probe library"
            )
        if probe.probe_id in self._seen_ids:
            raise DuplicateProbeError(
                f"probe_id {probe.probe_id!r} was already submitted"
            )
        self._seen_ids.add(probe.probe_id)
        self._probes.append(probe)
        return Submission(
            probe=probe,
            admitted=True,
            reason=(
                "the agent failed this task, so it is admitted to the "
                "capability-ceiling probe library; a failure never lowers "
                "the verified ceiling"
            ),
            ceiling_raised_to=None,
            ceiling_source=self._ceiling_source,
        )

    def _raise_ceiling(self, difficulty: float) -> Optional[float]:
        """Raise the ceiling to ``difficulty`` if that is above it."""
        if self._ceiling is None or difficulty > self._ceiling:
            self._ceiling = difficulty
            self._ceiling_source = "measured"
            return self._ceiling
        return None

    # -- calibration -------------------------------------------------------

    def calibration(self) -> tuple[CalibrationBucket, ...]:
        """Calibration per difficulty bucket, over every observation.

        Both failures and passes are observations: a confidently correct
        answer is as much a calibration fact as a confidently wrong one.
        Buckets with no observations are omitted entirely -- an empty
        bucket has no calibration error, and reporting one would invent
        a number.
        """
        buckets: dict[str, list[CeilingProbe]] = {}
        for probe in tuple(self._probes) + tuple(self._passed):
            buckets.setdefault(probe.bucket, []).append(probe)
        out: list[CalibrationBucket] = []
        for label, items in buckets.items():
            count = len(items)
            mean_confidence = sum(p.confidence for p in items) / count
            accuracy = sum(1 for p in items if p.passed) / count
            error = round(mean_confidence - accuracy, 6)
            miscalibrated = abs(error) > self.calibration_threshold
            if error > self.calibration_threshold:
                direction = "overconfident"
            elif error < -self.calibration_threshold:
                direction = "underconfident"
            else:
                direction = "none"
            out.append(
                CalibrationBucket(
                    bucket=label,
                    probes=count,
                    mean_confidence=round(mean_confidence, 6),
                    accuracy=round(accuracy, 6),
                    error=error,
                    miscalibrated=miscalibrated,
                    direction=direction,
                )
            )
        return tuple(out)

    def miscalibrated_buckets(self) -> tuple[CalibrationBucket, ...]:
        """Only the buckets whose calibration error exceeds the threshold."""
        return tuple(b for b in self.calibration() if b.miscalibrated)

    # -- routing -----------------------------------------------------------

    def route(self, task_difficulty_human_minutes: float) -> RoutingVerdict:
        """Decide what happens to a task of the given difficulty.

        * Inside the verified ceiling -> ``attempt``: the agent may take it.
        * Over the ceiling but within ``DECOMPOSE_FACTOR`` -> ``decompose``:
          split it into pieces inside the ceiling.
        * Far over the ceiling -> ``human``: hand it to a person.

        With no ceiling measured yet there is nothing to compare against,
        so the task is *not* attempted blind: it is routed to decomposition
        and the verdict says the ceiling is unmeasured.  The ceiling is
        never invented to fill the gap.
        """
        difficulty = _check_difficulty(task_difficulty_human_minutes)
        ceiling = self._ceiling
        if ceiling is None:
            verdict = RoutingVerdict(
                route=RouteTarget.DECOMPOSE,
                task_difficulty_human_minutes=difficulty,
                verified_ceiling_human_minutes=None,
                overage_human_minutes=None,
                reason=(
                    "no verified capability ceiling has been measured yet, so "
                    f"the task ({difficulty:g} human minutes) cannot be "
                    "shown to be inside one; the ceiling is never inferred"
                ),
                recommendation=(
                    "decompose the task and probe the pieces: the ceiling "
                    "is unknown, and an unknown ceiling admits nothing"
                ),
                ceiling_source=self._ceiling_source,
            )
            self._verdicts.append(verdict)
            return verdict

        if difficulty <= ceiling:
            verdict = RoutingVerdict(
                route=RouteTarget.ATTEMPT,
                task_difficulty_human_minutes=difficulty,
                verified_ceiling_human_minutes=ceiling,
                overage_human_minutes=None,
                reason=(
                    f"task needs {difficulty:g} human minutes, within the "
                    f"verified ceiling of {ceiling:g} human minutes"
                ),
                recommendation="attempt: the task is inside the verified ceiling",
                ceiling_source=self._ceiling_source,
            )
            self._verdicts.append(verdict)
            return verdict

        overage = round(difficulty - ceiling, 6)
        factor_limit = ceiling * DECOMPOSE_FACTOR
        if difficulty <= factor_limit:
            route = RouteTarget.DECOMPOSE
            recommendation = (
                f"decompose the task into pieces within {ceiling:g} human "
                "minutes: it exceeds the verified ceiling by "
                f"{overage:g} minutes but is within the decomposition band"
            )
        else:
            route = RouteTarget.HUMAN
            recommendation = (
                "route the task to a human: it exceeds the verified ceiling "
                f"of {ceiling:g} human minutes by {overage:g} minutes, "
                f"beyond the decomposition band of {factor_limit:g} minutes"
            )
        verdict = RoutingVerdict(
            route=route,
            task_difficulty_human_minutes=difficulty,
            verified_ceiling_human_minutes=ceiling,
            overage_human_minutes=overage,
            reason=(
                f"task needs {difficulty:g} human minutes, over the verified "
                f"ceiling of {ceiling:g} human minutes by {overage:g} minutes"
            ),
            recommendation=recommendation,
            ceiling_source=self._ceiling_source,
        )
        self._verdicts.append(verdict)
        return verdict


def main() -> None:
    """Self-check: fail-first admission, calibration, routing, one-way ceiling."""
    ledger = CeilingLedger()
    # A failure enters the probe library.
    sub = ledger.submit(
        CeilingProbe("p-fail", 90.0, 0.95, passed=False)
    )
    assert sub.admitted, sub
    assert ledger.verified_ceiling_human_minutes is None, ledger
    # A pass is refused as a probe, and raises the ceiling.
    sub = ledger.submit(
        CeilingProbe("p-pass", 45.0, 0.5, passed=True)
    )
    assert not sub.admitted, sub
    assert ledger.verified_ceiling_human_minutes == 45.0, ledger
    # A failure after that does not lower the ceiling.
    ledger.submit(CeilingProbe("p-fail2", 200.0, 0.99, passed=False))
    assert ledger.verified_ceiling_human_minutes == 45.0, ledger
    # Calibration: the 60-120 bucket is confidently wrong.
    buckets = {b.bucket: b for b in ledger.calibration()}
    assert buckets["60-120"].miscalibrated, buckets
    # Routing: over the ceiling -> decompose, far over -> human.
    assert ledger.route(45.0).route is RouteTarget.ATTEMPT
    assert ledger.route(60.0).route is RouteTarget.DECOMPOSE
    assert ledger.route(400.0).route is RouteTarget.HUMAN
    print(
        "capability-ceiling-probe OK: fail-first admission, calibration "
        "buckets, ceiling routing, one-way ceiling"
    )


if __name__ == "__main__":
    main()
