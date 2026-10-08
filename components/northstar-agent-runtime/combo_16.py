"""Floor-enforced execution, Integrated.

Combines: floor_settings + deterministic_veto + two_tier_gating.
Policy floors set the minimum bar, the deterministic veto blocks irreversible harm, and two-tier scoring handles the gray zone.

What this IS: execution that cannot go below the floor.
What this IS NOT: a replacement for the detectors the floor names.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_16_VERSION = "combo-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-16.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


fs = _load("floor_settings")
dv = _load("deterministic_veto")
tt = _load("two_tier_gating")


class FloorEnforcedExecution:
    """Floor -> veto -> tier score."""

    def __init__(
        self,
        floors: List[Any],
        tier1_fn: Callable[[str, Dict[str, Any]], float],
        veto_consequences: List[Any] = None,
    ) -> None:
        self._floors = fs.FloorEnforcer(floors)
        self._veto = dv.DeterministicVeto()
        for consequence in veto_consequences or [dv.Consequence.IRREVERSIBLE_BROAD]:
            self._veto.add_rule(dv.VetoRule("combo16", consequence))
        self._two_tier = tt.TwoTierGate(tier1_fn)

    def execute(
        self,
        detectors: Any,
        denies: Any,
        min_severity: int,
        consequence: Any,
        tool_name: str,
        args: Dict[str, Any],
    ) -> Dict[str, Any]:
        ok, reason = self._floors.check_policy(detectors, denies, min_severity)
        if not ok:
            raise ComboError(f"floor: {reason}")
        vetoed, reason = self._veto.check(consequence)
        if vetoed:
            raise ComboError(f"veto: {reason}")
        tier = self._two_tier.check(tool_name, args)
        if tier.decision == "deny":
            raise ComboError(f"tier: {tier.reason}")
        return {"tier": tier, "executed": True}


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
    floors = [fs.Floor("f1", min_severity=10, required_detectors=frozenset({"tw"}))]
    ex = FloorEnforcedExecution(floors, lambda tool, args: 0.1)
    r = ex.execute(
        frozenset({"tw"}), frozenset(), 50,
        dv.Consequence.REVERSIBLE_LOW, "read", {},
    )
    assert r["executed"] is True
    try:
        ex.execute(frozenset(), frozenset(), 50, dv.Consequence.REVERSIBLE_LOW, "r", {})
    except ComboError:
        pass
    else:
        raise AssertionError("floor should fail")
    try:
        ex.execute(
            frozenset({"tw"}), frozenset(), 50,
            dv.Consequence.IRREVERSIBLE_BROAD, "rm", {},
        )
    except ComboError:
        pass
    else:
        raise AssertionError("veto should fail")
    ex2 = FloorEnforcedExecution(floors, lambda tool, args: 0.95)
    try:
        ex2.execute(
            frozenset({"tw"}), frozenset(), 50,
            dv.Consequence.REVERSIBLE_LOW, "r", {},
        )
    except ComboError:
        pass
    else:
        raise AssertionError("tier should deny")
    assert stdlib_only()
    print("combo-16 OK: floor, veto, tier")



if __name__ == "__main__":
    main()
