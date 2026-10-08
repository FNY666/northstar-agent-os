"""Gated delegation, Integrated.

Combines: two_tier_gating + command_registry + floor_settings.
Two-tier scoring screens the action, the command registry checks authorization, and floor settings enforce the policy floor.

What this IS: a delegation pipeline with fast-path scoring and hard policy floors.
What this IS NOT: a human approval workflow.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_06_VERSION = "combo-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-06.v1"


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
cr = _load("command_registry")
fs = _load("floor_settings")


class GatedDelegation:
    """Tier score -> command auth -> policy floor."""

    def __init__(
        self, tier1_fn: Callable[[str, Dict[str, Any]], float], floors: List[Any]
    ) -> None:
        self._two_tier = tt.TwoTierGate(tier1_fn)
        self._registry = cr.CommandRegistry()
        self._floors = fs.FloorEnforcer(floors)

    def register_command(self, name: str, autonomy: Any) -> None:
        self._registry.register(cr.CommandSpec(name, autonomy, name))

    def authorize(
        self,
        command: str,
        tool_name: str,
        args: Dict[str, Any],
        detectors: Any,
        denies: Any,
        min_severity: int,
    ) -> Dict[str, Any]:
        tier = self._two_tier.check(tool_name, args)
        if tier.decision == "deny":
            raise ComboError(f"tier denied: {tier.reason}")
        ok, reason = self._registry.check(command)
        if not ok:
            raise ComboError(f"command denied: {reason}")
        ok, reason = self._floors.check_policy(detectors, denies, min_severity)
        if not ok:
            raise ComboError(f"floor violated: {reason}")
        return {"tier": tier, "authorized": True}


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
    gd = GatedDelegation(lambda tool, args: 0.1, floors)
    gd.register_command("ls", cr.AutonomyLevel.AUTOMATIC)
    r = gd.authorize("ls", "ls", {}, frozenset({"tw"}), frozenset(), 50)
    assert r["authorized"] is True
    try:
        gd.authorize("nope", "ls", {}, frozenset({"tw"}), frozenset(), 50)
    except ComboError:
        pass
    else:
        raise AssertionError("unknown command should fail")
    try:
        gd.authorize("ls", "ls", {}, frozenset(), frozenset(), 50)
    except ComboError:
        pass
    else:
        raise AssertionError("missing detector should fail floor")
    assert stdlib_only()
    print("combo-06 OK: tier, registry, floor")



if __name__ == "__main__":
    main()
