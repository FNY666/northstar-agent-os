"""Step reliability budget: per-step success rate to run-level failure probability.

What was missing
----------------
Northstar reports *pass counts* ("24/24 tests green").  It has no budget for
the thing long-horizon runs actually die of: a run that is 300+ tool calls
long is not safe just because every step is 95% likely to work.  Under the
independent-steps model, a run of ``n`` steps at per-step success rate
``p`` contains at least one error with probability ``1 - p**n`` -- so a
95%-reliable step still puts a 30-step run at roughly 79% risk of containing
an error, and a 318-step run at essentially 100%.

The motivating source numbers (tuput, "AI News: Agents in Production,
Independent Tests -- October 2026", 2026-10-08, read in full; the article
cites the OSWorld 2.0 paper, arXiv:2606.29537):

* OSWorld 2.0 "has 108 workflows, and a skilled person takes a median of
  about 1.6 hours per task.  A task counts as done only if it is fully
  completed within 500 steps."
* "the best was Claude Opus 4.8 with maximum thinking, which fully completed
  20.6% of tasks and reached 54.8% on a partial-credit score.  GPT-5.5
  plateaued near 13%.  Claude Opus 4.7 averaged 318 tool calls per task,
  against about 30 in the original OSWorld."

The reliability arithmetic (``1 - p**n``), the three conversions below and
the fail-closed admission rule are **Northstar extensions**, not the
source's.  The source reports the trajectory lengths; the risk arithmetic
over them is ours (see ``docs/design/step-reliability-budget.md``).

Northstar extensions (not from the source):

* **The three conversions.**  ``run_failure_probability``,
  ``required_step_rate`` and ``max_steps`` are defined here.  The source
  states the trajectory lengths and the completion rates; it does not state
  these formulas.
* **The admission rule.**  ``admit`` refuses to start a run whose measured
  per-step success rate cannot reach the target run-level success rate.
  The source says nothing about admission.
* **The independence assumption.**  Real trajectories are *correlated*: a
  step that fails often makes the next step fail too.  Every number this
  module returns is the value under the **independent-steps assumption**,
  which is a modelling assumption of this module, not a measurement.  The
  formula gives the *optimistic* side of the bound under positive
  correlation.
* **Where "measured" comes from.**  The per-step success rate is expected
  to be computed from Northstar's own tool-call success statistics.  This
  module does not collect them; it only consumes the number.

Scope: this module is a *budget and admission gate*.  It does not change
any execution loop, does not retry, and does not observe a live run.  It
is a pure, deterministic, wall-clock-free function library.

Fail-closed: every public function validates its inputs and raises
:class:`StepReliabilityError` (a ``ValueError``) on an illegal argument
rather than returning a plausible-looking number.  Admission *failure* is
not an error -- it is data (:class:`AdmissionVerdict`).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

__all__ = [
    "StepReliabilityError",
    "AdmissionVerdict",
    "run_failure_probability",
    "required_step_rate",
    "max_steps",
    "admit",
]


class StepReliabilityError(ValueError):
    """Fail-closed: an illegal argument is refused, never defaulted."""


def _check_rate(value: Any, name: str) -> float:
    """Validate a probability: a real number strictly inside ``(0, 1]``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StepReliabilityError(f"{name} must be a real number, got {value!r}")
    rate = float(value)
    if math.isnan(rate) or math.isinf(rate):
        raise StepReliabilityError(f"{name} must be finite, got {value!r}")
    if not (0.0 < rate <= 1.0):
        raise StepReliabilityError(f"{name} must be in (0, 1], got {value!r}")
    return rate


def _check_steps(value: Any, name: str) -> int:
    """Validate a step count: a non-negative integer (``bool`` is not one)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise StepReliabilityError(f"{name} must be an integer, got {value!r}")
    if value < 0:
        raise StepReliabilityError(f"{name} must be >= 0, got {value!r}")
    return value


def run_failure_probability(p_step: float, n: int) -> float:
    """Probability a run of ``n`` steps contains at least one error.

    Under the independent-steps assumption, a run succeeds as a whole with
    probability ``p_step ** n``, so it contains at least one error with
    probability ``1 - p_step ** n``.

    ``n == 0`` gives ``0.0`` (an empty run cannot contain an error) and
    ``p_step == 1.0`` gives ``0.0`` (a flawless step never fails).
    """
    rate = _check_rate(p_step, "p_step")
    steps = _check_steps(n, "n")
    if steps == 0:
        return 0.0
    return 1.0 - rate**steps


def required_step_rate(p_target: float, n: int) -> float:
    """Per-step success rate needed to reach run-level success ``p_target``.

    The run-level success rate of ``n`` independent steps each succeeding
    with probability ``p`` is ``p ** n``; solving for ``p`` gives
    ``p_target ** (1 / n)``.

    ``n == 0`` gives ``1.0``: a run with no steps cannot fail, so any
    per-step rate (including a meaningless one) is sufficient.
    """
    target = _check_rate(p_target, "p_target")
    steps = _check_steps(n, "n")
    if steps == 0:
        return 1.0
    return target ** (1.0 / steps)


def max_steps(p_meas: float, p_target: float) -> int | None:
    """Largest step count whose run-level success stays at or above target.

    Solving ``p_meas ** n >= p_target`` for ``n`` gives
    ``n <= ln(p_target) / ln(p_meas)``, so the bound is the floor of that
    ratio.  The result is the maximum *allowed* step count.

    Returns ``None`` when ``p_meas >= 1``: a flawless step cannot fail at
    any length, so the bound is unbounded (there is no integer to return).

    ``p_meas <= 0`` is refused (fail-closed) -- a zero success rate never
    reaches any target below 1.
    """
    measured = _check_rate(p_meas, "p_meas")
    target = _check_rate(p_target, "p_target")
    if measured >= 1.0:
        return None
    if target >= 1.0:
        # ln(1) == 0 -> every length qualifies (0 steps is enough).
        return math.floor(0.0 / math.log(measured)) if measured < 1.0 else None
    return math.floor(math.log(target) / math.log(measured))


@dataclass(frozen=True)
class AdmissionVerdict:
    """The admission decision, as data.

    ``admitted`` is the verdict.  A refusal is *not* an exception: it is a
    verdict carrying the numbers that justify it (``gap``,
    ``predicted_failure_probability``), so a caller can report it.
    """

    admitted: bool
    measured_step_rate: float
    required_step_rate: float
    steps: int
    gap: float
    predicted_failure_probability: float
    max_steps: int | None
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.admitted


def admit(p_meas: float, p_target: float, n: int) -> AdmissionVerdict:
    """Fail-closed admission: may this run start at the measured rate?

    The required per-step rate for ``n`` steps is ``p_req``; the run is
    admitted when ``p_meas >= p_req``.  Otherwise the verdict carries the
    shortfall ``gap = p_req - p_meas`` and the predicted probability that
    the run contains at least one error under the independent-steps
    assumption.

    A refusal is data, not an exception.
    """
    measured = _check_rate(p_meas, "p_meas")
    target = _check_rate(p_target, "p_target")
    steps = _check_steps(n, "n")
    required = required_step_rate(target, steps)
    predicted = run_failure_probability(measured, steps)
    bound = max_steps(measured, target)
    if steps == 0:
        # A run with no steps cannot fail, so the target is met whatever the
        # per-step rate is.  ``required_step_rate`` still reports 1.0 (the
        # rate a zero-step run "needs"); nothing is required of the caller.
        return AdmissionVerdict(
            admitted=True,
            measured_step_rate=measured,
            required_step_rate=required,
            steps=steps,
            gap=0.0,
            predicted_failure_probability=predicted,
            max_steps=bound,
            reason="a run with no steps cannot fail",
        )
    if measured >= required:
        return AdmissionVerdict(
            admitted=True,
            measured_step_rate=measured,
            required_step_rate=required,
            steps=steps,
            gap=0.0,
            predicted_failure_probability=predicted,
            max_steps=bound,
            reason="measured step rate meets the required step rate",
        )
    return AdmissionVerdict(
        admitted=False,
        measured_step_rate=measured,
        required_step_rate=required,
        steps=steps,
        gap=required - measured,
        predicted_failure_probability=predicted,
        max_steps=bound,
        reason=(
            f"measured step rate {measured!r} is below the required step rate "
            f"{required!r} for {steps} steps; refusing to start"
        ),
    )
