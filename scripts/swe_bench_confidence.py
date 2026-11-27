"""Give a benchmark score an interval, not just a number.

Fifty tasks scored once carry a standard error of roughly seven points, so
a difference of a few points between two runs is noise. Reporting the point
estimate alone invites exactly that reading. The Wilson score interval is
used rather than the normal approximation because at these sample sizes the
normal interval runs past the boundaries of a proportion and understates
the uncertainty near zero or one.
"""

from __future__ import annotations

import math
from typing import Any

# Two-sided 95% critical value of the normal distribution.
Z_95 = 1.959963984540054


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """The Wilson score interval for a proportion.

    Returns ``(low, high)`` as fractions in ``[0, 1]``. With no trials there
    is no interval to give, so ``(0.0, 0.0)`` is returned.
    """
    if trials <= 0:
        return (0.0, 0.0)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = proportion + z * z / (2 * trials)
    spread = z * math.sqrt(
        (proportion * (1.0 - proportion) + z * z / (4 * trials)) / trials
    )
    low = (centre - spread) / denominator
    high = (centre + spread) / denominator
    # A floating-point remainder of the form 6e-18 is a boundary, not a
    # measurement; rounding it away keeps the reported interval readable.
    return (round(max(0.0, low), 12), round(min(1.0, high), 12))


def standard_error(successes: int, trials: int) -> float:
    """The standard error of a proportion."""
    if trials <= 0:
        return 0.0
    proportion = successes / trials
    return math.sqrt(proportion * (1.0 - proportion) / trials)


def summarise(successes: int, trials: int) -> dict[str, Any]:
    """A score with the uncertainty that belongs to it."""
    low, high = wilson_interval(successes, trials)
    return {
        "successes": successes,
        "trials": trials,
        "rate": round(successes / trials, 4) if trials else 0.0,
        "ci95_low": round(low, 4),
        "ci95_high": round(high, 4),
        "standard_error": round(standard_error(successes, trials), 4),
        "interval_method": "wilson",
    }
