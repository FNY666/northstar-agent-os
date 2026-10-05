"""Post-release drift detection (ninetieth batch).

Absorbed from 2026 eval-methodology research (mechanism ideas only,
honestly scoped here):

* **Livenerf (2026-10-01)** — the first post-release *drift-tracking*
  benchmark: re-run the *same model name* across time windows and
  compare statistically, catching silent vendor downgrades (a model that
  quietly gets worse — or cheaper to serve — without a version bump).
  This module is that pattern as a library: baseline window vs current
  window, paired by task, with a statistical verdict.
* **The 2026 industry gap** — per the evalsig 2026-05 survey, *no*
  industry eval tooling shipped bootstrap confidence intervals or paired
  permutation tests for evals. This module ships both, deterministic and
  dependency-free.

Method (paired, binary outcomes):

* Windows are paired by ``task_id``: each task contributes one baseline
  outcome and one current outcome. Unpaired, duplicated, or empty
  windows are a fail-closed ``DriftProbeError`` — an unpaired comparison
  is not a drift measurement.
* Effect: mean(current − baseline) over pairs.
* Uncertainty: bootstrap percentile CI over the paired differences
  (resample pairs with replacement).
* Significance: two-sided paired permutation test by sign-flipping the
  paired differences (exact for the paired design; the null is "signs
  are exchangeable", i.e. no systematic drift).
* Verdict: drift is flagged only when the p-value clears ``alpha``,
  the CI excludes zero, *and* the absolute effect clears ``min_effect``
  — significance alone is not drift; a 0.1-point wobble on 10k tasks
  is not a silent downgrade.

Determinism: every resampling routine takes an explicit ``seed`` and
uses ``random.Random``. Identical inputs + seed => identical outputs,
bit for bit. There is no wall-clock, no thread-local RNG, no ambient
state anywhere in this module.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Sequence


DRIFT_PROBE_SCHEMA_VERSION = "northstar.drift-probe.v1"

_DEFAULT_SEED = 20261004
_DEFAULT_RESAMPLES = 2000
_DEFAULT_PERMUTATIONS = 5000


class DriftProbeError(ValueError):
    """The drift probe refused to compare the given windows."""


# ---------------------------------------------------------------------------
# Samples and pairing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftSample:
    """One task outcome in one time window."""

    task_id: str
    passed: bool
    window: str


def _check_sample(sample: DriftSample, *, where: str) -> None:
    if not isinstance(sample, DriftSample):
        raise DriftProbeError(f"{where}: expected DriftSample, not {type(sample).__name__}")
    if not sample.task_id or not isinstance(sample.task_id, str):
        raise DriftProbeError(f"{where}: task_id must be a non-empty string")
    if not isinstance(sample.passed, bool):
        raise DriftProbeError(f"{where}: passed must be a bool, not {type(sample.passed).__name__}")
    if not sample.window or not isinstance(sample.window, str):
        raise DriftProbeError(f"{where}: window must be a non-empty string")


def pair_windows(
    baseline: Sequence[DriftSample], current: Sequence[DriftSample]
) -> list[tuple[str, bool, bool]]:
    """Pair two windows by task_id -> ``(task_id, baseline_passed, current_passed)``.

    Fail-closed: empty windows, duplicate task_ids within a window, or
    task_ids present in one window but not the other all raise
    ``DriftProbeError``. A drift verdict over unpaired tasks would be a
    comparison of two different tests, not a measurement of drift.
    """
    baseline = list(baseline)
    current = list(current)
    if not baseline:
        raise DriftProbeError("baseline window is empty")
    if not current:
        raise DriftProbeError("current window is empty")
    for sample in baseline:
        _check_sample(sample, where="baseline")
    for sample in current:
        _check_sample(sample, where="current")

    base_ids = [s.task_id for s in baseline]
    curr_ids = [s.task_id for s in current]
    if len(set(base_ids)) != len(base_ids):
        raise DriftProbeError("baseline window has duplicate task_ids")
    if len(set(curr_ids)) != len(curr_ids):
        raise DriftProbeError("current window has duplicate task_ids")

    base_map = {s.task_id: s.passed for s in baseline}
    curr_map = {s.task_id: s.passed for s in current}
    base_only = sorted(set(base_map) - set(curr_map))
    curr_only = sorted(set(curr_map) - set(base_map))
    if base_only or curr_only:
        raise DriftProbeError(
            "windows are not paired: "
            f"baseline-only={base_only[:5]} current-only={curr_only[:5]}"
        )
    return [(tid, base_map[tid], curr_map[tid]) for tid in sorted(base_map)]


def paired_differences(pairs: Sequence[tuple[str, bool, bool]]) -> list[int]:
    """Per-task difference ``current − baseline`` in ``{-1, 0, +1}``."""
    if not pairs:
        raise DriftProbeError("no paired tasks to compare")
    return [int(curr) - int(base) for _, base, curr in pairs]


def mean_difference(pairs: Sequence[tuple[str, bool, bool]]) -> float:
    """Mean paired difference: positive = improvement, negative = degradation."""
    diffs = paired_differences(pairs)
    return sum(diffs) / len(diffs)


# ---------------------------------------------------------------------------
# Bootstrap CI (percentile, over paired differences)
# ---------------------------------------------------------------------------


def bootstrap_ci(
    pairs: Sequence[tuple[str, bool, bool]],
    *,
    n_resamples: int = _DEFAULT_RESAMPLES,
    seed: int = _DEFAULT_SEED,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap CI for the mean paired difference.

    Resamples *pairs* with replacement (the paired structure is
    preserved — resampling unpaired outcomes would break the design).
    Deterministic in ``seed``.
    """
    if n_resamples < 100:
        raise DriftProbeError("n_resamples must be >= 100 for a usable CI")
    if not 0.0 < alpha < 1.0:
        raise DriftProbeError("alpha must be in (0, 1)")
    diffs = paired_differences(pairs)
    n = len(diffs)
    rng = random.Random(seed)
    means = sorted(
        sum(diffs[rng.randrange(n)] for _ in range(n)) / n
        for _ in range(n_resamples)
    )
    lo_idx = int((alpha / 2) * n_resamples)
    hi_idx = int((1 - alpha / 2) * n_resamples) - 1
    lo_idx = max(0, min(lo_idx, n_resamples - 1))
    hi_idx = max(0, min(hi_idx, n_resamples - 1))
    return (means[lo_idx], means[hi_idx])


# ---------------------------------------------------------------------------
# Paired permutation test (sign-flipping, two-sided)
# ---------------------------------------------------------------------------


def paired_permutation_test(
    pairs: Sequence[tuple[str, bool, bool]],
    *,
    n_permutations: int = _DEFAULT_PERMUTATIONS,
    seed: int = _DEFAULT_SEED,
) -> float:
    """Two-sided p-value for "no systematic drift" via sign-flipping.

    Under the null each paired difference's sign is exchangeable, so we
    flip signs at random and compare ``|mean|`` against the observed
    ``|mean|``. Uses the ``(1 + #{extreme}) / (1 + n)`` form so the
    p-value is always in ``(0, 1]`` and a zero-variance window yields
    exactly 1.0 instead of a division-by-zero or a misleading 0.0.
    Deterministic in ``seed``.
    """
    if n_permutations < 100:
        raise DriftProbeError("n_permutations must be >= 100")
    diffs = paired_differences(pairs)
    n = len(diffs)
    observed = abs(sum(diffs) / n)
    rng = random.Random(seed)
    extreme = 0
    for _ in range(n_permutations):
        flipped = sum(d if rng.random() < 0.5 else -d for d in diffs) / n
        if abs(flipped) >= observed:
            extreme += 1
    return (1 + extreme) / (1 + n_permutations)


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftVerdict:
    """The statistical verdict for one baseline-vs-current comparison."""

    drift_detected: bool
    direction: str  # "degradation" | "improvement" | "none"
    effect: float
    ci_lo: float
    ci_hi: float
    p_value: float
    n_pairs: int
    alpha: float

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": DRIFT_PROBE_SCHEMA_VERSION,
            "drift_detected": self.drift_detected,
            "direction": self.direction,
            "effect": self.effect,
            "ci": [self.ci_lo, self.ci_hi],
            "p_value": self.p_value,
            "n_pairs": self.n_pairs,
            "alpha": self.alpha,
        }


def detect_drift(
    baseline: Sequence[DriftSample],
    current: Sequence[DriftSample],
    *,
    alpha: float = 0.05,
    min_effect: float = 0.0,
    n_resamples: int = _DEFAULT_RESAMPLES,
    n_permutations: int = _DEFAULT_PERMUTATIONS,
    seed: int = _DEFAULT_SEED,
) -> DriftVerdict:
    """Livenerf-style drift verdict for one model name across two windows.

    Flags drift only on the conjunction: ``p_value < alpha`` AND the
    bootstrap CI excludes zero AND ``|effect| >= min_effect``.
    Significance without a meaningful effect is not drift; an effect
    whose CI covers zero is not evidence.
    """
    if not 0.0 < alpha < 1.0:
        raise DriftProbeError("alpha must be in (0, 1)")
    if min_effect < 0.0:
        raise DriftProbeError("min_effect must be non-negative")
    pairs = pair_windows(baseline, current)
    effect = mean_difference(pairs)
    ci_lo, ci_hi = bootstrap_ci(
        pairs, n_resamples=n_resamples, seed=seed, alpha=alpha
    )
    p_value = paired_permutation_test(
        pairs, n_permutations=n_permutations, seed=seed
    )
    ci_excludes_zero = ci_hi < 0.0 or ci_lo > 0.0
    significant = p_value < alpha and abs(effect) >= min_effect
    drift_detected = bool(significant and ci_excludes_zero)
    if not drift_detected:
        direction = "none"
    elif effect < 0:
        direction = "degradation"
    else:
        direction = "improvement"
    return DriftVerdict(
        drift_detected=drift_detected,
        direction=direction,
        effect=effect,
        ci_lo=ci_lo,
        ci_hi=ci_hi,
        p_value=p_value,
        n_pairs=len(pairs),
        alpha=alpha,
    )


def samples_from_passed(
    task_ids: Sequence[str], passed_ids: Sequence[str], window: str
) -> list[DriftSample]:
    """Build a window: every ``task_id`` passes iff it is in ``passed_ids``."""
    task_ids = list(task_ids)
    if not task_ids:
        raise DriftProbeError("task_ids is empty")
    if len(set(task_ids)) != len(task_ids):
        raise DriftProbeError("task_ids has duplicates")
    passed_set = set(passed_ids)
    unknown = sorted(passed_set - set(task_ids))
    if unknown:
        raise DriftProbeError(f"passed_ids not in task_ids: {unknown[:5]}")
    if not window or not isinstance(window, str):
        raise DriftProbeError("window must be a non-empty string")
    return [
        DriftSample(task_id=tid, passed=(tid in passed_set), window=window)
        for tid in task_ids
    ]


__all__ = [
    "DRIFT_PROBE_SCHEMA_VERSION",
    "DriftProbeError",
    "DriftSample",
    "DriftVerdict",
    "pair_windows",
    "paired_differences",
    "mean_difference",
    "bootstrap_ci",
    "paired_permutation_test",
    "detect_drift",
    "samples_from_passed",
]
