"""obs_23: Burn rate alerts (mock), Simulated.

Implements Google-SRE-style burn rate alerting on synthetic inputs.
Burn rate = actual error rate / budgeted error rate for the elapsed
portion of the window.  ``classify`` uses the classic SRE thresholds:
fast > 14.4x, slow > 6x, otherwise ok.  ``should_alert`` fires only when
the rate exceeds the fast threshold for enough consecutive evaluations.

Fail-closed: non-positive elapsed/window, invalid targets, or bad > total
raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Literal

OBS23_VERSION = "obs-23.v1"
SCHEMA_PIN = "northstar.obs-23.v1"

FAST_THRESHOLD = 14.4
SLOW_THRESHOLD = 6.0
ALERT_CONSECUTIVE = 2


class Obs23Error(Exception):
    """Fail-closed."""


def _check_inputs(bad: int, total: int, slo_target: float, window_s: float, elapsed_s: float) -> None:
    for value, label in ((bad, "bad"), (total, "total")):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Obs23Error(f"{label} must be a non-negative int")
    if total == 0:
        raise Obs23Error("total must be > 0")
    if bad > total:
        raise Obs23Error("bad cannot exceed total")
    if not isinstance(slo_target, (int, float)) or isinstance(slo_target, bool):
        raise Obs23Error("slo_target must be a number")
    if not 0.0 < float(slo_target) < 1.0:
        raise Obs23Error("slo_target must be inside (0, 1)")
    for value, label in ((window_s, "window_s"), (elapsed_s, "elapsed_s")):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise Obs23Error(f"{label} must be a number")
        if float(value) <= 0:
            raise Obs23Error(f"{label} must be positive")
    if float(elapsed_s) > float(window_s):
        raise Obs23Error("elapsed_s cannot exceed window_s")


def burn_rate(bad: int, total: int, slo_target: float, window_s: float, elapsed_s: float) -> float:
    """Burn rate: actual errors vs. budgeted errors for the elapsed window.

    Returns bad / ((1 - slo_target) * total * elapsed_s / window_s).
    """
    _check_inputs(bad, total, slo_target, window_s, elapsed_s)
    budgeted = (1.0 - float(slo_target)) * total * (float(elapsed_s) / float(window_s))
    if budgeted <= 0:
        return 0.0
    return bad / budgeted


def classify(rate: float) -> Literal["ok", "slow", "fast"]:
    """Classify a burn rate: fast > 14.4x, slow > 6x, else ok."""
    if not isinstance(rate, (int, float)) or isinstance(rate, bool):
        raise Obs23Error("rate must be a number")
    if rate < 0:
        raise Obs23Error("rate cannot be negative")
    if rate > FAST_THRESHOLD:
        return "fast"
    if rate > SLOW_THRESHOLD:
        return "slow"
    return "ok"


def should_alert(rate: float, consecutive: int) -> bool:
    """Fire only when burn rate is fast for enough consecutive evaluations."""
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate < 0:
        raise Obs23Error("rate must be a non-negative number")
    if not isinstance(consecutive, int) or isinstance(consecutive, bool) or consecutive < 0:
        raise Obs23Error("consecutive must be a non-negative int")
    return rate > FAST_THRESHOLD and consecutive >= ALERT_CONSECUTIVE


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    # 0.999 target, 1h window, 5 min elapsed: budgeted = 0.001*3600*300/3600 = 0.3
    assert abs(burn_rate(30, 3600, 0.999, 3600.0, 300.0) - 100.0) < 1e-9
    assert burn_rate(0, 3600, 0.999, 3600.0, 300.0) == 0.0
    assert classify(100.0) == "fast"
    assert classify(10.0) == "slow"
    assert classify(2.0) == "ok"
    assert should_alert(100.0, 2) is True
    assert should_alert(100.0, 1) is False
    assert should_alert(2.0, 5) is False
    try:
        burn_rate(5, 100, 0.99, 3600.0, 0.0)
        raise AssertionError("should raise")
    except Obs23Error:
        pass
    try:
        burn_rate(101, 100, 0.99, 3600.0, 300.0)
        raise AssertionError("should raise")
    except Obs23Error:
        pass
    try:
        classify(-1.0)
        raise AssertionError("should raise")
    except Obs23Error:
        pass
    assert stdlib_only()
    print("obs_23 OK")


if __name__ == "__main__":
    main()
