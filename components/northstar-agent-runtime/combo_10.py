"""Tiered confidence execution, Integrated.

Combines: two_tier_gating + confidence_gate + deterministic_veto.
Tier-1 fast scoring, confidence gating on the action, and a deterministic veto for irreversible consequences.

What this IS: a three-layer execution decision: fast screen, confidence, veto.
What this IS NOT: a replacement for human approval on critical actions.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_10_VERSION = "combo-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-10.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


tt = _load("two_tier_gating")
cg = _load("confidence_gate")
dv = _load("deterministic_veto")


class TieredConfidenceExecution:
    """Tier score -> confidence -> veto."""

    def __init__(
        self,
        tier1_fn: Callable[[str, Dict[str, Any]], float],
        veto_consequences: List[Any] = None,
    ) -> None:
        self._two_tier = tt.TwoTierGate(tier1_fn)
        self._conf = cg.ConfidenceGate()
        self._veto = dv.DeterministicVeto()
        for consequence in veto_consequences or [dv.Consequence.IRREVERSIBLE_BROAD]:
            self._veto.add_rule(dv.VetoRule("combo10", consequence))

    def execute(
        self,
        tool_name: str,
        args: Dict[str, Any],
        confidence: int,
        tool_risk: str,
        consequence: Any,
    ) -> Dict[str, Any]:
        tier = self._two_tier.check(tool_name, args)
        if tier.decision == "deny":
            raise ComboError(f"tier denied: {tier.reason}")
        verdict = self._conf.check(confidence, tool_risk)
        if verdict.action == "deny":
            raise ComboError(f"confidence denied: {verdict.reason}")
        vetoed, reason = self._veto.check(consequence)
        if vetoed:
            raise ComboError(f"veto: {reason}")
        return {"tier": tier, "confidence": verdict, "executed": True}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "collections", "dataclasses", "hashlib",
        "importlib", "json", "pathlib", "re", "sys", "typing",
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
    ex = TieredConfidenceExecution(lambda tool, args: 0.1)
    r = ex.execute("read", {}, 95, "low", dv.Consequence.REVERSIBLE_LOW)
    assert r["executed"] is True
    try:
        ex.execute("read", {}, 5, "high", dv.Consequence.REVERSIBLE_LOW)
    except ComboError:
        pass
    else:
        raise AssertionError("low confidence should fail")
    try:
        ex.execute("rm", {}, 95, "low", dv.Consequence.IRREVERSIBLE_BROAD)
    except ComboError:
        pass
    else:
        raise AssertionError("irreversible should be vetoed")
    ex2 = TieredConfidenceExecution(lambda tool, args: 0.95)
    try:
        ex2.execute("read", {}, 95, "low", dv.Consequence.REVERSIBLE_LOW)
    except ComboError:
        pass
    else:
        raise AssertionError("high tier score should deny")
    assert stdlib_only()
    print("combo-10 OK: tier, confidence, veto")



if __name__ == "__main__":
    main()
