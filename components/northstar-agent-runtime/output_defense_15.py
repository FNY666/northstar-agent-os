"""Output defense 15: confidence calibration (mock), Simulated.

Maps raw model confidence to calibrated probability via a mock
reliability curve (piecewise linear).  Host replaces ``RELIABILITY``
with an empirically fitted curve.  Out-of-range inputs raise.

What this IS: raw score -> calibrated probability mapping.
What this IS NOT: not fitted to any real model; mock curve only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Tuple

OUTPUT_DEFENSE_15_VERSION = "output-defense-15.v1"
SCHEMA_PIN = "northstar.output-defense-15.v1"


class CalibrationError(Exception):
    """Fail-closed."""


# Mock reliability curve: (raw, calibrated) control points, sorted.
RELIABILITY: List[Tuple[float, float]] = [
    (0.0, 0.02),
    (0.25, 0.18),
    (0.5, 0.45),
    (0.75, 0.72),
    (0.9, 0.88),
    (1.0, 0.97),
]


@dataclass(frozen=True)
class CalibrationResult:
    raw: float
    calibrated: float


def calibrate(
    raw: float,
    curve: List[Tuple[float, float]] = None,
) -> CalibrationResult:
    """Linear-interpolate raw score on the reliability curve."""
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        raise CalibrationError("raw must be numeric")
    if not 0.0 <= raw <= 1.0:
        raise CalibrationError("raw must be in [0,1]")
    pts = curve if curve is not None else RELIABILITY
    if len(pts) < 2:
        raise CalibrationError("curve needs >= 2 points")
    raw = float(raw)
    if raw <= pts[0][0]:
        cal = pts[0][1]
    elif raw >= pts[-1][0]:
        cal = pts[-1][1]
    else:
        cal = pts[-1][1]
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            if x0 <= raw <= x1:
                frac = (raw - x0) / (x1 - x0) if x1 != x0 else 0.0
                cal = y0 + frac * (y1 - y0)
                break
    return CalibrationResult(raw=raw, calibrated=round(cal, 4))


def is_overconfident(raw: float, margin: float = 0.1) -> bool:
    """True if raw exceeds calibrated by more than margin."""
    r = calibrate(raw)
    return (r.raw - r.calibrated) > margin


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    r = calibrate(0.9)
    assert r.calibrated == 0.88
    r = calibrate(0.5)
    assert r.calibrated == 0.45
    r = calibrate(0.0)
    assert r.calibrated == 0.02
    assert is_overconfident(0.9) is False  # 0.9-0.88=0.02 < 0.1
    assert is_overconfident(0.75, margin=0.01) is True  # 0.75-0.72=0.03
    try:
        calibrate(1.5)
        raise AssertionError("should raise")
    except CalibrationError:
        pass
    try:
        calibrate("high")  # type: ignore
        raise AssertionError("should raise")
    except CalibrationError:
        pass
    assert stdlib_only()
    print("output-defense-15 OK: calibration curve, fail-closed, stdlib")


if __name__ == "__main__":
    main()
