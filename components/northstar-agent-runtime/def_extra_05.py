"""Risk scoring engine, Simulated.

Combines weighted 0..1 signals into a 0..100 risk score and maps it
to a band (low/medium/high/critical).

What this IS: deterministic aggregation primitive for adaptive auth.

What this IS NOT:
* Not a trained model -- weights are host-configured.
* Unknown signal names are ignored; no signals -> score 0 (not fail
  closed by itself -- the consumer decides the default action).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
DEF_EXTRA_05_VERSION = "def-extra-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-05.v1"


class RiskScoringError(Exception):
    """Fail-closed."""


#: Band thresholds: (min_score_inclusive, band).
BANDS: List[Tuple[float, str]] = [
    (75.0, "critical"),
    (50.0, "high"),
    (25.0, "medium"),
    (0.0, "low"),
]


def band_for(score: float) -> str:
    """Map a 0..100 score to a band name."""
    if not 0.0 <= score <= 100.0:
        raise RiskScoringError("score must be 0..100")
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"  # unreachable


@dataclass(frozen=True)
class RiskEngine:
    """Weighted risk aggregation."""

    weights: Dict[str, float]

    def __post_init__(self) -> None:
        for name, weight in self.weights.items():
            if weight < 0:
                raise RiskScoringError(f"negative weight for {name}")

    def score(self, signals: Dict[str, float]) -> float:
        """Weighted average of known signals, scaled to 0..100.

        Signal values must be 0..1.  Unknown signals ignored.
        """
        total_w = 0.0
        acc = 0.0
        for name, value in signals.items():
            weight = self.weights.get(name)
            if weight is None:
                continue
            if not 0.0 <= value <= 1.0:
                raise RiskScoringError(f"signal {name} out of range 0..1")
            acc += weight * value
            total_w += weight
        if total_w == 0.0:
            return 0.0
        return round(100.0 * acc / total_w, 2)

    def assess(self, signals: Dict[str, float]) -> Tuple[float, str]:
        """Return (score, band)."""
        score = self.score(signals)
        return score, band_for(score)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    engine = RiskEngine({"geo": 0.5, "device": 0.3, "behavior": 0.2})
    score, band = engine.assess({"geo": 1.0, "device": 1.0, "behavior": 1.0})
    assert score == 100.0 and band == "critical"
    score, band = engine.assess({"geo": 0.0, "device": 0.0, "behavior": 0.0})
    assert score == 0.0 and band == "low"
    score, band = engine.assess({"geo": 0.6, "device": 0.4})
    assert band == "medium" and 25.0 <= score < 50.0
    # Unknown signals ignored.
    assert engine.score({"nope": 1.0}) == 0.0
    # Out-of-range signal rejected.
    try:
        engine.score({"geo": 2.0})
    except RiskScoringError:
        pass
    else:
        raise AssertionError("expected RiskScoringError")
    assert band_for(75.0) == "critical"
    assert stdlib_only()
    print("def-extra-05 OK: scoring, bands, validation")


if __name__ == "__main__":
    main()
