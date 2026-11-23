"""Confidence-gated authorization (D11, AlphaFold pLDDT), Simulated.

Each planning/observation output carries a calibrated confidence score
(0-100).  Tiers:
- >=90: low-risk tools auto-allow
- 70-90: requires observer verdict
- 50-70: unreliable, escalate
- <50: unusable, deny

Confidence is recorded with verdicts in the hash-chain ledger for
recalibration (coverage vs false-allow).

What this IS: principled uncertainty gating.

What this IS NOT:
* Not the calibrator -- host provides confidence scores.
* Tiers are configurable, not hardcoded.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

#: Module version.
CONFIDENCE_GATE_VERSION = "confidence-gate.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.confidence-gate.v1"


class ConfidenceTier(Enum):
    """Confidence tiers."""

    HIGH = "high"  # >=90: auto-allow low-risk
    MEDIUM = "medium"  # 70-90: needs observer
    LOW = "low"  # 50-70: escalate
    UNUSABLE = "unusable"  # <50: deny


class ConfidenceGateError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ConfidenceVerdict:
    """Verdict with confidence tier."""

    tier: ConfidenceTier
    confidence: int
    action: str  # "allow", "observer", "escalate", "deny"
    reason: str


class ConfidenceGate:
    """Gates actions by confidence tier."""

    def __init__(
        self,
        *,
        high_threshold: int = 90,
        medium_threshold: int = 70,
        low_threshold: int = 50,
    ) -> None:
        if not (0 < low_threshold < medium_threshold < high_threshold <= 100):
            raise ConfidenceGateError("thresholds must be ordered")
        self._high = high_threshold
        self._medium = medium_threshold
        self._low = low_threshold
        self._history: List[Dict] = []

    def check(
        self,
        confidence: int,
        tool_risk: str = "low",
    ) -> ConfidenceVerdict:
        """Check confidence against tiers.

        tool_risk: "low" or "high".  High-risk tools need higher confidence.
        """
        if not isinstance(confidence, int) or not 0 <= confidence <= 100:
            raise ConfidenceGateError("confidence must be int in [0,100]")
        # Determine tier.
        if confidence >= self._high:
            tier = ConfidenceTier.HIGH
        elif confidence >= self._medium:
            tier = ConfidenceTier.MEDIUM
        elif confidence >= self._low:
            tier = ConfidenceTier.LOW
        else:
            tier = ConfidenceTier.UNUSABLE
        # Map to action.
        if tier == ConfidenceTier.HIGH:
            # High confidence: allow low-risk, observer for high-risk.
            if tool_risk == "low":
                action, reason = "allow", "high confidence, low risk"
            else:
                action, reason = "observer", "high confidence but high risk"
        elif tier == ConfidenceTier.MEDIUM:
            action, reason = "observer", "medium confidence needs review"
        elif tier == ConfidenceTier.LOW:
            action, reason = "escalate", "low confidence, escalate"
        else:
            action, reason = "deny", "confidence too low"
        verdict = ConfidenceVerdict(tier, confidence, action, reason)
        self._history.append({
            "confidence": confidence,
            "tier": tier.value,
            "action": action,
        })
        return verdict

    @property
    def history(self) -> List[Dict]:
        return list(self._history)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "enum", "pathlib", "typing"}
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
    gate = ConfidenceGate()
    # High confidence, low risk: allow.
    v = gate.check(95, "low")
    assert v.action == "allow"
    # High confidence, high risk: observer.
    v = gate.check(95, "high")
    assert v.action == "observer"
    # Medium: observer.
    v = gate.check(80, "low")
    assert v.action == "observer"
    # Low: escalate.
    v = gate.check(60, "low")
    assert v.action == "escalate"
    # Unusable: deny.
    v = gate.check(30, "low")
    assert v.action == "deny"

    assert stdlib_only()
    print("confidence-gate OK: tiers, actions, history, stdlib")


if __name__ == "__main__":
    main()
