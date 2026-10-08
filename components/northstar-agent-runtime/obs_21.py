"""obs_21: SLO definitions, Simulated.

Models a service-level objective as an immutable record: a human-readable
SLI description, a target ratio in (0, 1), and a compliance window in days.
``evaluate`` computes the observed SLI from raw good/total event counts and
reports whether the target was met and how much slack (or deficit) remains.

Fail-closed: invalid targets, negative counts, or good > total raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict

OBS21_VERSION = "obs-21.v1"
SCHEMA_PIN = "northstar.obs-21.v1"


class Obs21Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SLO:
    """A service-level objective: target ratio over a window in days."""
    name: str
    sli_description: str
    target_ratio: float
    window_days: float

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise Obs21Error("name must be a non-empty str")
        if not isinstance(self.sli_description, str) or not self.sli_description:
            raise Obs21Error("sli_description must be a non-empty str")
        if not isinstance(self.target_ratio, (int, float)) or isinstance(self.target_ratio, bool):
            raise Obs21Error("target_ratio must be a number")
        if not 0.0 < float(self.target_ratio) < 1.0:
            raise Obs21Error("target_ratio must be inside (0, 1)")
        if not isinstance(self.window_days, (int, float)) or isinstance(self.window_days, bool):
            raise Obs21Error("window_days must be a number")
        if float(self.window_days) <= 0:
            raise Obs21Error("window_days must be positive")


def evaluate(slo: SLO, good_events: int, total_events: int) -> Dict[str, object]:
    """Evaluate an SLO against observed counts.

    Returns dict with sli ratio, target, met bool, and gap (sli - target).
    """
    if not isinstance(slo, SLO):
        raise Obs21Error("slo must be an SLO")
    for value, label in ((good_events, "good_events"), (total_events, "total_events")):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Obs21Error(f"{label} must be a non-negative int")
    if total_events == 0:
        raise Obs21Error("total_events must be > 0")
    if good_events > total_events:
        raise Obs21Error("good_events cannot exceed total_events")
    sli = good_events / total_events
    target = float(slo.target_ratio)
    gap = sli - target
    return {
        "slo_name": slo.name,
        "sli": sli,
        "target": target,
        "met": gap >= 0.0,
        "gap": gap,
        "window_days": float(slo.window_days),
    }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "dataclasses"}
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
    slo = SLO("api-availability", "fraction of successful API calls", 0.999, 30.0)
    ok = evaluate(slo, 9990, 10000)
    assert ok["sli"] == 0.999 and ok["met"] is True and abs(ok["gap"]) < 1e-12
    bad = evaluate(slo, 997, 1000)
    assert bad["met"] is False and bad["gap"] < 0.0
    try:
        SLO("x", "y", 1.0, 30.0)
        raise AssertionError("should raise")
    except Obs21Error:
        pass
    try:
        SLO("x", "y", 0.0, 30.0)
        raise AssertionError("should raise")
    except Obs21Error:
        pass
    try:
        evaluate(slo, -1, 100)
        raise AssertionError("should raise")
    except Obs21Error:
        pass
    try:
        evaluate(slo, 101, 100)
        raise AssertionError("should raise")
    except Obs21Error:
        pass
    assert stdlib_only()
    print("obs_21 OK")


if __name__ == "__main__":
    main()
