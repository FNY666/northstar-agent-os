"""Full-stack gate, Integrated.

Combines: tripwire_guardrails + provenance_tagging + deterministic_veto + resource_defense.
One call passes four layers: tripwire screen, provenance policy, irreversible veto, and resource limits.

What this IS: the kitchen-sink gate: four independent fail-closed layers.
What this IS NOT: a performance-optimized fast path.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_20_VERSION = "combo-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-20.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


tw = _load("tripwire_guardrails")
pt = _load("provenance_tagging")
dv = _load("deterministic_veto")
rd = _load("resource_defense")


class FullStackGate:
    """Tripwire -> provenance -> veto -> resources."""

    def __init__(
        self,
        tripwire: Any,
        policy: Dict[str, Any],
        veto_consequences: List[Any] = None,
        limits: Any = None,
    ) -> None:
        self._tw = tripwire
        self._policy = policy
        self._veto = dv.DeterministicVeto()
        for consequence in veto_consequences or [dv.Consequence.IRREVERSIBLE_BROAD]:
            self._veto.add_rule(dv.VetoRule("combo20", consequence))
        self._limits = limits or rd.ResourceLimits()

    def guard(
        self, tool_name: str, args: Dict[str, Any], consequence: Any
    ) -> Dict[str, Any]:
        result = self._tw.check(tool_name, args)
        if result.outcome == tw.TripwireOutcome.HALT:
            raise ComboError("layer 1: tripwire halt")
        tagged = {
            k: pt.tag_tool_output(v, tool_name)
            for k, v in args.items()
            if isinstance(v, str)
        }
        if tagged and not pt.check_policy(tool_name, tagged, self._policy):
            raise ComboError("layer 2: provenance denied")
        vetoed, reason = self._veto.check(consequence)
        if vetoed:
            raise ComboError(f"layer 3: veto ({reason})")
        ok, reason = rd.check_resources(tool_name, args, self._limits)
        if not ok:
            raise ComboError(f"layer 4: resource ({reason})")
        return {"allowed": True, "layers_passed": 4}


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
    tripwire = tw.TripwireGuard("t", lambda tool, args: "evil" in str(args))
    policy = {"read": {"allowed_sources": {"read"}}}
    gate = FullStackGate(tripwire, policy)
    r = gate.guard("read", {"path": "/x"}, dv.Consequence.REVERSIBLE_LOW)
    assert r["layers_passed"] == 4
    for args, cons, layer in [
        ({"q": "evil"}, dv.Consequence.REVERSIBLE_LOW, "1"),
        ({"path": "/x"}, dv.Consequence.REVERSIBLE_LOW, "2"),
        ({"path": "/x"}, dv.Consequence.IRREVERSIBLE_BROAD, "3"),
        ({"x": "f(" * 60}, dv.Consequence.REVERSIBLE_LOW, "4"),
    ]:
        policies = {
            "1": policy,
            "2": {"read": {"allowed_sources": {"user"}}},
            "3": policy,
            "4": policy,
        }
        g = FullStackGate(tripwire, policies[layer])
        try:
            g.guard("read", args, cons)
        except ComboError as exc:
            assert f"layer {layer}" in str(exc), str(exc)
        else:
            raise AssertionError(f"layer {layer} should block")
    assert stdlib_only()
    print("combo-20 OK: four layers")



if __name__ == "__main__":
    main()
