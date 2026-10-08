"""Integration I-002: tripwire + confidence gate (combined gate), Simulated.

Runs the tripwire guardrail and the confidence gate together and merges
into one decision:
- tripwire HALT -> halt
- tripwire REJECT_CONTENT -> reject_content
- confidence deny -> halt
- confidence escalate -> reject_content
- confidence observer -> observer
- else -> allow

What this IS: one gate with content+confidence verdicts.
What this IS NOT: not the confidence scorer -- host provides scores.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

#: Module version.
INTEGRATION_02_VERSION = "integration-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-02.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_tripwire = _load("tripwire_guardrails")
_confidence = _load("confidence_gate")


class IntegrationError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class CombinedDecision:
    """Merged tripwire + confidence verdict."""

    decision: str  # allow | observer | reject_content | halt
    reason: str
    tripwire_outcome: str
    confidence_action: str


class CombinedGate:
    """Tripwire guard + confidence gate merged into one decision."""

    def __init__(self, tripwire_guard: Any, confidence_gate: Any) -> None:
        if tripwire_guard is None or confidence_gate is None:
            raise IntegrationError("tripwire_guard and confidence_gate required")
        self._tw = tripwire_guard
        self._cg = confidence_gate

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        confidence: int,
        tool_risk: str = "low",
    ) -> CombinedDecision:
        """Check both gates; merge verdicts.  Fail-closed."""
        tw = self._tw.check(tool_name, args)
        tw_outcome = tw.outcome.value
        try:
            cg = self._cg.check(confidence, tool_risk)
            cg_action = cg.action
        except Exception:
            return CombinedDecision(
                "halt", "confidence check failed", tw_outcome, "deny"
            )
        # Tripwire takes precedence.
        if tw_outcome == "halt":
            return CombinedDecision("halt", tw.reason, tw_outcome, cg_action)
        if tw_outcome == "reject_content":
            return CombinedDecision(
                "reject_content", tw.reason, tw_outcome, cg_action
            )
        if cg_action == "deny":
            return CombinedDecision(
                "halt", "low confidence", tw_outcome, cg_action
            )
        if cg_action == "escalate":
            return CombinedDecision(
                "reject_content", "low confidence, escalate",
                tw_outcome, cg_action,
            )
        if cg_action == "observer":
            return CombinedDecision(
                "observer", "needs review", tw_outcome, cg_action
            )
        return CombinedDecision("allow", "clean", tw_outcome, cg_action)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
    }
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
    guard = _tripwire.TripwireGuard(
        "no_evil",
        lambda t, a: t == "evil",
        on_violation=_tripwire.TripwireOutcome.HALT,
    )
    gate = CombinedGate(guard, _confidence.ConfidenceGate())

    d = gate.check("evil", {}, 95, "low")
    assert d.decision == "halt"
    assert d.tripwire_outcome == "halt"

    d = gate.check("read", {}, 95, "low")
    assert d.decision == "allow"

    d = gate.check("read", {}, 80, "low")
    assert d.decision == "observer"

    d = gate.check("read", {}, 60, "low")
    assert d.decision == "reject_content"

    d = gate.check("read", {}, 30, "low")
    assert d.decision == "halt"

    assert stdlib_only()
    print("integration-02 OK: combined tripwire+confidence, stdlib")


if __name__ == "__main__":
    main()
