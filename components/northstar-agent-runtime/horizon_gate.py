"""Admission gate: only take tasks inside the *verified 80%* time horizon.

What was missing
----------------
Northstar reports *pass counts* -- "24/24 tests pass", "18,727 tests, 4
failures".  Those are single-labouratory numbers: the Moltbook protocol-swap
discussion already flagged them as non-portable.  Nothing in the runtime
asks, *before* a task starts, "how many human minutes does this take, and
is that inside the horizon this agent has actually verified?"

Read from the code, not assumed:

* ``long_horizon.py`` is the Manager / Executor / Auditor loop that runs a
  task *while it runs*.  It has no admission gate: ``LongHorizonLoop`` is
  constructed with an objective and starts round 0.  "Horizon" in that
  module means "many rounds", not "how long the task may take".
* ``budget.py`` / ``compute_budget.py`` bound *spend* -- tokens, USD,
  device class.  Their unit is money and compute, never *human time*.  A
  budget asks "may this request be sent", not "may this task be started".
* ``evaluation_harness.py`` reports results as ``"n/m"`` pass-rate text plus
  a mean metric.  It reports *no interval* at all: a bare pass rate hides
  the uncertainty in the number.
* Nothing in the runtime stores a task's estimated human duration, and
  nothing compares one to a horizon.  So a task that needs three human
  hours is handed straight to the agent, and the failure only becomes
  visible after the hours are spent.

This module is that missing gate.  It answers one question -- "is this task
inside the horizon this agent has actually verified?" -- and it answers it
*before* the task starts.

Why the 80% horizon and not the 50% one
---------------------------------------
The headline number in the METR time-horizon work is the **50% horizon**:
the task duration at which the agent succeeds half the time.  That is a
headline figure, not a reliability line -- running a task at 50% success
rate is running a coin flip.  The **80% horizon** is the line where the
agent is expected to succeed four times in five.

Source (METR time horizons, frontier #11,
https://www.agenticsystems.ai/blog/time-horizons/, 2026-10-03, explaining
METR Time Horizon 1.1 of January 2026) -- verbatim:

* "The 80% horizon is much shorter -- in the synthetic example it is about
  a third of the 50% horizon" (METR: the 80% horizon is 4-6x shorter).
* "It takes hundreds of tasks to pin a horizon down."
* Measurements above about 16 hours "aren't reliable with the current
  tasks".
* 30 tasks -> the 90% interval for a 60-minute horizon is 27min-2.3h;
  150 tasks -> 38-74min; 1,000 tasks -> 58-73min.

Northstar extension (this module, not the source):

* The gate refuses to be constructed from a 50% horizon.  A caller that
  wants the 50% number has to say so, and the gate says no, with the
  reason.
* The gate refuses a horizon above 960 minutes (16 hours), because such a
  measurement is not reliable with the current tasks.
* The gate refuses to exist without an interval *and* a task count: a
  point estimate with no interval and no sample size is not a verified
  horizon, it is a guess.
* The gate answers with three states, never a boolean: ``ADMITTED``,
  ``FLAGGED`` (admit, but with enhanced monitoring), ``REFUSED``.  A
  boolean cannot tell "take it, but watch it" from "do not take it".

Honest scope
------------
* The horizon and its interval are **caller-supplied**.  This module does
  not measure how long a human takes; it applies a declared, verified
  horizon to a declared task estimate.  A caller that lies about either
  gets a useless gate.
* The task duration is an *estimate*.  Human-baseline conventions alone
  can shift an estimate by more than 1.25x, which is why the gate also
  reports the interval and the task count: the caller sees how much of
  the number is precision and how much is convention.
* The gate is pure and in-memory.  It holds no tasks of its own beyond the
  acceptances it has recorded, and it does not persist anything.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

#: The only unit this module measures in: minutes of *human* time.
UNIT = "human_minutes"

#: Version pin for this module's record shapes.
HORIZON_GATE_VERSION = "horizon-gate.v1"

#: Schema pin for the gate's own records.
HORIZON_GATE_SCHEMA = "northstar.horizon-gate.v1"

#: The percentile this gate admits against.  Only 80 is accepted: the 50%
#: horizon is the headline number, 80% is the reliability line for
#: autonomous operation.
REQUIRED_PERCENTILE = 80

#: 16 hours, in minutes.  A horizon longer than this is not measurable
#: with the current tasks, so it is refused rather than trusted.
MAX_RELIABLE_HORIZON_MINUTES = 960

#: Default proximity margin, in minutes, for the "close to the upper bound
#: of the interval" flag.  A task this close to (or above) the top of the
#: horizon interval is admitted only with enhanced monitoring.
DEFAULT_MARGIN_MINUTES = 10

#: Task-count thresholds for the "is this horizon pinned down" ladder.
#: From the source table (30 tasks -> 27min-2.3h, 150 -> 38-74min,
#: 1,000 -> 58-73min).
NOT_PINNED_TASK_LIMIT = 30
BASICALLY_PINNED_TASK_COUNT = 150
PINNED_TASK_COUNT = 1000


class HorizonGateError(Exception):
    """Base class for every horizon-gate refusal."""


class HorizonDeclarationError(HorizonGateError):
    """The gate could not be declared, so it does not exist.

    Raised for every fail-closed construction path: a missing interval, a
    missing task count, a 50% horizon, a horizon longer than 16 hours, an
    interval that does not contain its own point estimate.
    """


class BadTaskDuration(HorizonGateError):
    """The task duration handed to :meth:`HorizonGate.admit` is unusable."""


class AdmissionStatus(str, Enum):
    """The three admission states.

    Not a boolean: ``FLAGGED`` (admit with enhanced monitoring) and
    ``REFUSED`` (do not admit) are different decisions and must not
    collapse into one bit.
    """

    ADMITTED = "admitted"
    FLAGGED = "flagged"
    REFUSED = "refused"

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.value


@dataclass(frozen=True)
class Admission:
    """One admission decision, with the evidence behind it.

    Attributes:
        status: the three-way decision.
        task_human_minutes: the estimated human duration of the task.
        verified_80_horizon_minutes: the horizon the decision was made
            against.
        interval_low_minutes / interval_high_minutes: the horizon's
            interval, in the same unit.
        task_count: how many tasks pinned the horizon down.
        reason: why this verdict, in words.
        recommendation: what the caller should do about it.
        overage_minutes: how far the task exceeds the 80% horizon, or
            ``None`` when the task is inside it.
        margin_minutes: the proximity margin that was in force.
    """

    status: AdmissionStatus
    task_human_minutes: float
    verified_80_horizon_minutes: float
    interval_low_minutes: float
    interval_high_minutes: float
    task_count: int
    reason: str
    recommendation: str
    overage_minutes: float | None
    margin_minutes: int

    @property
    def admitted(self) -> bool:
        """Whether the task may be taken in (admitted, or flagged in)."""
        return self.status in (AdmissionStatus.ADMITTED, AdmissionStatus.FLAGGED)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "task_human_minutes": self.task_human_minutes,
            "verified_80_horizon_minutes": self.verified_80_horizon_minutes,
            "interval_low_minutes": self.interval_low_minutes,
            "interval_high_minutes": self.interval_high_minutes,
            "task_count": self.task_count,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "overage_minutes": self.overage_minutes,
            "margin_minutes": self.margin_minutes,
            "unit": UNIT,
            "version": HORIZON_GATE_VERSION,
        }


@dataclass(frozen=True)
class HorizonReport:
    """A horizon report: the horizon, its interval, and how firm it is.

    Attributes:
        verified_80_horizon_minutes: the 80% horizon, in human minutes.
        interval_low_minutes / interval_high_minutes: the interval.
        interval_width_minutes: the width of the interval.
        task_count: how many tasks pinned the horizon down.
        percentile: always 80 -- this gate admits against no other line.
        pinned: the pinning ladder verdict -- ``"not_pinned"`` below 30
            tasks, ``"basically_pinned"`` at 150 or more, ``"pinned"`` at
            1,000 or more.
        pinning_note: the human-readable statement of that verdict, with
            the task-count table quoted.
    """

    verified_80_horizon_minutes: float
    interval_low_minutes: float
    interval_high_minutes: float
    interval_width_minutes: float
    task_count: int
    percentile: int
    pinned: str
    pinning_note: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified_80_horizon_minutes": self.verified_80_horizon_minutes,
            "interval_low_minutes": self.interval_low_minutes,
            "interval_high_minutes": self.interval_high_minutes,
            "interval_width_minutes": self.interval_width_minutes,
            "task_count": self.task_count,
            "percentile": self.percentile,
            "pinned": self.pinned,
            "pinning_note": self.pinning_note,
            "unit": UNIT,
            "version": HORIZON_GATE_VERSION,
        }


def _check_number(value: Any, name: str) -> float:
    """Return a finite, non-negative float, or raise."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HorizonDeclarationError(f"{name} must be a number, got {value!r}")
    number = float(value)
    if not math.isfinite(number):
        raise HorizonDeclarationError(f"{name} must be finite, got {value!r}")
    if number < 0:
        raise HorizonDeclarationError(f"{name} must be non-negative, got {value!r}")
    return number


def _check_task_count(value: Any) -> int:
    """Return a positive int task count, or raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise HorizonDeclarationError(f"task_count must be an int, got {value!r}")
    if value <= 0:
        raise HorizonDeclarationError(f"task_count must be positive, got {value!r}")
    return value


def _check_interval(value: Any) -> tuple[float, float]:
    """Return a validated ``(low, high)`` interval, or raise.

    The interval is mandatory and must be ordered, non-degenerate, and
    must contain the horizon's own point estimate -- an interval that
    excludes the number it is an interval of is not an interval.
    """
    if value is None:
        raise HorizonDeclarationError(
            "horizon_interval is required: a horizon without an interval is "
            "not a verified horizon"
        )
    if isinstance(value, Mapping):
        try:
            low = value["low"]
            high = value["high"]
        except KeyError as exc:
            raise HorizonDeclarationError(
                f"horizon_interval must have 'low' and 'high': missing {exc}"
            ) from exc
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        low, high = value
    else:
        raise HorizonDeclarationError(
            "horizon_interval must be a (low, high) pair of human minutes"
        )
    low_f = _check_number(low, "horizon_interval.low")
    high_f = _check_number(high, "horizon_interval.high")
    if low_f > high_f:
        raise HorizonDeclarationError(
            f"horizon_interval low {low_f} must not exceed high {high_f}"
        )
    if low_f == high_f:
        raise HorizonDeclarationError(
            "horizon_interval must have width: a zero-width interval is a "
            "point estimate, not a verified horizon"
        )
    return low_f, high_f


def pinning_verdict(task_count: int) -> tuple[str, str]:
    """The pinning ladder for a horizon pinned down by ``task_count`` tasks.

    Thresholds are taken verbatim from the source's task-count table: 30
    tasks -> the 90% interval for a 60-minute horizon is 27min-2.3h; 150
    tasks -> 38-74min; 1,000 tasks -> 58-73min.  Below 30 the interval is
    too wide to call pinned; the source's own summary is "It takes hundreds
    of tasks to pin a horizon down."
    """
    if task_count >= PINNED_TASK_COUNT:
        return (
            "pinned",
            f"pinned: {task_count} tasks (>= {PINNED_TASK_COUNT}) -- the "
            f"source's table puts the 90% interval of a 60-minute horizon "
            f"at 58-73min with 1,000 tasks",
        )
    if task_count >= BASICALLY_PINNED_TASK_COUNT:
        return (
            "basically_pinned",
            f"basically pinned: {task_count} tasks (>= "
            f"{BASICALLY_PINNED_TASK_COUNT}) -- the source's table puts the "
            f"90% interval of a 60-minute horizon at 38-74min with 150 tasks",
        )
    return (
        "not_pinned",
        f"NOT pinned: {task_count} tasks (< {NOT_PINNED_TASK_LIMIT}) -- the "
        f"source's table puts the 90% interval of a 60-minute horizon at "
        f"27min-2.3h with 30 tasks; it takes hundreds of tasks to pin a "
        f"horizon down",
    )


class HorizonGate:
    """Admits tasks only inside the verified 80% horizon.

    The gate is declared with three mandatory inputs:

    * ``verified_80_horizon_minutes`` -- the agent's verified 80% horizon,
      in human minutes.  Mandatory, no default: a gate without a horizon
      admits nothing by accident.
    * ``horizon_interval`` -- the ``(low, high)`` interval of that
      horizon.  Mandatory: a point estimate with no interval is not a
      verified horizon.
    * ``task_count`` -- how many tasks pinned the horizon down.  Mandatory:
      an interval with no sample size says nothing about how wide it
      should be.

    Missing any of the three is a refusal, not a default.  So is a 50%
    horizon (the headline number, not the reliability line) and a horizon
    longer than 960 minutes (16 hours -- such measurements "aren't
    reliable with the current tasks").

    The gate keeps a record of what it admitted, refused and flagged, so a
    caller can report on its decisions; it never holds a task of its own.
    """

    def __init__(
        self,
        *,
        verified_80_horizon_minutes: Any,
        horizon_interval: Any,
        task_count: Any,
        margin_minutes: int = DEFAULT_MARGIN_MINUTES,
        horizon_percentile: int = REQUIRED_PERCENTILE,
    ) -> None:
        if horizon_percentile != REQUIRED_PERCENTILE:
            raise HorizonDeclarationError(
                f"only the {REQUIRED_PERCENTILE}% horizon is an admission "
                f"line, got {horizon_percentile!r}: the 50% horizon is the "
                f"headline number, while the 80% horizon is the reliability "
                f"line for autonomous operation (the source puts the 80% "
                f"horizon at about a third of the 50% horizon -- 4-6x "
                f"shorter)"
            )
        horizon = _check_number(
            verified_80_horizon_minutes, "verified_80_horizon_minutes"
        )
        if horizon <= 0:
            raise HorizonDeclarationError(
                "verified_80_horizon_minutes must be positive"
            )
        if horizon > MAX_RELIABLE_HORIZON_MINUTES:
            raise HorizonDeclarationError(
                f"verified_80_horizon_minutes {horizon:g} exceeds "
                f"{MAX_RELIABLE_HORIZON_MINUTES} minutes (16 hours): "
                f"measurements above about 16 hours aren't reliable with "
                f"the current tasks"
            )
        low, high = _check_interval(horizon_interval)
        if not (low <= horizon <= high):
            raise HorizonDeclarationError(
                f"horizon_interval [{low:g}, {high:g}] must contain the "
                f"horizon point estimate {horizon:g}"
            )
        count = _check_task_count(task_count)
        if isinstance(margin_minutes, bool) or not isinstance(margin_minutes, int):
            raise HorizonDeclarationError(
                f"margin_minutes must be an int, got {margin_minutes!r}"
            )
        if margin_minutes < 0:
            raise HorizonDeclarationError(
                f"margin_minutes must be non-negative, got {margin_minutes!r}"
            )

        self.verified_80_horizon_minutes = horizon
        self.interval_low_minutes = low
        self.interval_high_minutes = high
        self.task_count = count
        self.margin_minutes = margin_minutes
        self.horizon_percentile = REQUIRED_PERCENTILE
        self.unit = UNIT
        self.version = HORIZON_GATE_VERSION
        self.schema = HORIZON_GATE_SCHEMA
        self._admitted: list[Admission] = []
        self._flagged: list[Admission] = []
        self._refused: list[Admission] = []

    # -- views -------------------------------------------------------------

    @property
    def horizon_interval(self) -> tuple[float, float]:
        """The horizon's interval, in human minutes."""
        return (self.interval_low_minutes, self.interval_high_minutes)

    @property
    def admitted_count(self) -> int:
        return len(self._admitted)

    @property
    def flagged_count(self) -> int:
        return len(self._flagged)

    @property
    def refused_count(self) -> int:
        return len(self._refused)

    def report(self) -> HorizonReport:
        """The horizon report: the horizon, its interval, and how firm it is.

        Reports the interval, not a bare point: a 60-minute horizon with a
        38-74 minute interval and 150 tasks behind it is a different claim
        from the same 60 minutes with 30 tasks behind it, and the report
        says which one it is.
        """
        pinned, note = pinning_verdict(self.task_count)
        return HorizonReport(
            verified_80_horizon_minutes=self.verified_80_horizon_minutes,
            interval_low_minutes=self.interval_low_minutes,
            interval_high_minutes=self.interval_high_minutes,
            interval_width_minutes=round(
                self.interval_high_minutes - self.interval_low_minutes, 6
            ),
            task_count=self.task_count,
            percentile=self.horizon_percentile,
            pinned=pinned,
            pinning_note=note,
        )

    def as_dict(self) -> dict[str, Any]:
        """The gate's own view of itself, for an audit row."""
        return {
            "verified_80_horizon_minutes": self.verified_80_horizon_minutes,
            "horizon_interval": list(self.horizon_interval),
            "task_count": self.task_count,
            "margin_minutes": self.margin_minutes,
            "percentile": self.horizon_percentile,
            "unit": self.unit,
            "version": self.version,
            "schema": self.schema,
            "admitted_count": self.admitted_count,
            "flagged_count": self.flagged_count,
            "refused_count": self.refused_count,
        }

    # -- admission ---------------------------------------------------------

    def admit(self, task_human_minutes: Any) -> Admission:
        """Decide whether a task may be admitted.

        The decision is three-way and explicit:

        * ``REFUSED`` -- the task is longer than the verified 80% horizon
          and is not rescued by the interval: decompose it or send it to a
          human.
        * ``FLAGGED`` -- the task sits inside the horizon's interval but
          close to its upper bound: it may be taken, but only with
          enhanced monitoring.
        * ``ADMITTED`` -- the task is inside the horizon: take it.

        Precedence is deliberate and documented: the flag is evaluated
        first, because a task that lands inside the verified interval is
        within the uncertainty band of the horizon, and the honest reading
        of a band is "watch it", not "refuse it".  A task outside the band
        that is longer than the 80% horizon is refused outright.

        The task estimate must be a positive, finite number of human
        minutes; anything else is a refusal, not a guess.
        """
        if isinstance(task_human_minutes, bool) or not isinstance(
            task_human_minutes, (int, float)
        ):
            raise BadTaskDuration(
                f"task_human_minutes must be a number, got {task_human_minutes!r}"
            )
        task = float(task_human_minutes)
        if not math.isfinite(task):
            raise BadTaskDuration(
                f"task_human_minutes must be finite, got {task_human_minutes!r}"
            )
        if task <= 0:
            raise BadTaskDuration(
                f"task_human_minutes must be positive, got {task_human_minutes!r}"
            )

        horizon = self.verified_80_horizon_minutes
        low = self.interval_low_minutes
        high = self.interval_high_minutes
        margin = self.margin_minutes
        close_to_top = high - task <= margin
        inside_interval = low <= task <= high

        if inside_interval and close_to_top:
            admission = Admission(
                status=AdmissionStatus.FLAGGED,
                task_human_minutes=task,
                verified_80_horizon_minutes=horizon,
                interval_low_minutes=low,
                interval_high_minutes=high,
                task_count=self.task_count,
                reason=(
                    f"task needs {task:g} human minutes, inside the horizon "
                    f"interval [{low:g}, {high:g}] but within {margin} "
                    f"minutes of the interval's upper bound {high:g} "
                    f"(the verified 80% horizon is {horizon:g} minutes)"
                ),
                recommendation=(
                    "admit with enhanced monitoring: the task is at the "
                    "edge of the verified range, so watch progress closely "
                    "and be ready to decompose it"
                ),
                overage_minutes=None,
                margin_minutes=margin,
            )
            self._flagged.append(admission)
            return admission

        if task > horizon:
            overage = round(task - horizon, 6)
            admission = Admission(
                status=AdmissionStatus.REFUSED,
                task_human_minutes=task,
                verified_80_horizon_minutes=horizon,
                interval_low_minutes=low,
                interval_high_minutes=high,
                task_count=self.task_count,
                reason=(
                    f"task needs {task:g} human minutes, over the verified "
                    f"80% horizon of {horizon:g} minutes by {overage:g} "
                    f"minutes (horizon interval [{low:g}, {high:g}], "
                    f"{self.task_count} tasks)"
                ),
                recommendation=(
                    f"decompose the task into pieces within {horizon:g} "
                    f"human minutes, or route it to a human -- it exceeds "
                    f"the verified 80% horizon by {overage:g} minutes"
                ),
                overage_minutes=overage,
                margin_minutes=margin,
            )
            self._refused.append(admission)
            return admission

        admission = Admission(
            status=AdmissionStatus.ADMITTED,
            task_human_minutes=task,
            verified_80_horizon_minutes=horizon,
            interval_low_minutes=low,
            interval_high_minutes=high,
            task_count=self.task_count,
            reason=(
                f"task needs {task:g} human minutes, within the verified "
                f"80% horizon of {horizon:g} minutes (horizon interval "
                f"[{low:g}, {high:g}], {self.task_count} tasks)"
            ),
            recommendation=(
                "admit: the task is within the verified 80% horizon"
            ),
            overage_minutes=None,
            margin_minutes=margin,
        )
        self._admitted.append(admission)
        return admission

    def decisions(self) -> tuple[Admission, ...]:
        """Every decision this gate has made, in order."""
        return tuple(self._admitted) + tuple(self._flagged) + tuple(self._refused)
