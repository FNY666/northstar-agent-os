"""Output defense 16: uncertainty quantification (mock), Simulated.

Splits uncertainty into epistemic (knowledge gaps) and aleatoric
(inherent randomness) via lexical markers.  Mock — host injects a real
estimator.  High total uncertainty can trigger escalation.

What this IS: marker-based uncertainty decomposition.
What this IS NOT: not Bayesian; cannot measure true model uncertainty.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List

OUTPUT_DEFENSE_16_VERSION = "output-defense-16.v1"
SCHEMA_PIN = "northstar.output-defense-16.v1"


class UncertaintyError(Exception):
    """Fail-closed."""


EPISTEMIC_MARKERS = [
    "i don't know", "unknown", "unclear", "not sure",
    "no data", "cannot verify",
]
ALEATORIC_MARKERS = [
    "maybe", "possibly", "might", "could be",
    "sometimes", "often", "usually",
]


@dataclass(frozen=True)
class UncertaintyEstimate:
    epistemic: float  # 0..1 knowledge-gap uncertainty
    aleatoric: float  # 0..1 inherent-randomness uncertainty
    total: float


def _density(text: str, markers: List[str]) -> float:
    low = text.lower()
    hits = sum(1 for m in markers if m in low)
    words = max(1, len(low.split()))
    return min(1.0, (hits * 8) / words + (0.15 if hits else 0.0))


def quantify(text: str) -> UncertaintyEstimate:
    """Estimate uncertainty components from markers."""
    if not isinstance(text, str):
        raise UncertaintyError("text must be str")
    epi = _density(text, EPISTEMIC_MARKERS)
    ale = _density(text, ALEATORIC_MARKERS)
    total = min(1.0, epi + ale)
    return UncertaintyEstimate(
        epistemic=round(epi, 3), aleatoric=round(ale, 3),
        total=round(total, 3),
    )


def should_escalate(
    est: UncertaintyEstimate, threshold: float = 0.5
) -> bool:
    """Escalate when total uncertainty exceeds threshold."""
    if not 0.0 <= threshold <= 1.0:
        raise UncertaintyError("threshold must be in [0,1]")
    return est.total >= threshold


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
    e = quantify("The sky is blue.")
    assert e.total < 0.5 and should_escalate(e) is False
    e = quantify("I don't know, it might possibly be unclear.")
    assert e.epistemic > 0 and e.aleatoric > 0
    assert should_escalate(e, threshold=0.3) is True
    try:
        quantify(None)  # type: ignore
        raise AssertionError("should raise")
    except UncertaintyError:
        pass
    try:
        should_escalate(e, threshold=2.0)
        raise AssertionError("should raise")
    except UncertaintyError:
        pass
    assert stdlib_only()
    print("output-defense-16 OK: uncertainty split, fail-closed, stdlib")


if __name__ == "__main__":
    main()
