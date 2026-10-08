"""Protected execution, Integrated.

Combines: deterministic_veto + resource_defense + stateful_veto.
Resource limits screen for bombs, the deterministic veto blocks irreversible harm, and the stateful veto rate-limits repeat offenders.

What this IS: three independent fail-closed execution guards.
What this IS NOT: a sandbox or capability system.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_04_VERSION = "combo-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-04.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


dv = _load("deterministic_veto")
rd = _load("resource_defense")
sv = _load("stateful_veto")


class ProtectedExecution:
    """Resources -> veto -> session rate limit."""

    def __init__(
        self,
        veto_consequences: List[Any] = None,
        limits: Any = None,
        session_id: str = "sess-04",
    ) -> None:
        self._veto = dv.DeterministicVeto()
        for consequence in veto_consequences or [dv.Consequence.IRREVERSIBLE_BROAD]:
            self._veto.add_rule(dv.VetoRule("combo04", consequence))
        self._limits = limits or rd.ResourceLimits()
        self._stateful = sv.StatefulVeto()
        self._session = session_id

    def run(
        self, tool_name: str, args: Dict[str, Any], consequence: Any
    ) -> Dict[str, Any]:
        ok, reason = rd.check_resources(tool_name, args, self._limits)
        if not ok:
            self._stateful.record_deny(self._session, tool_name, "resource")
            raise ComboError(f"resource: {reason}")
        vetoed, reason = self._veto.check(consequence)
        if vetoed:
            self._stateful.record_deny(self._session, tool_name, str(consequence))
            raise ComboError(f"veto: {reason}")
        limited, reason = self._stateful.should_rate_limit(self._session, tool_name)
        if limited:
            raise ComboError(f"rate-limited: {reason}")
        return {"allowed": True, "risk": self._stateful.risk_score(self._session)}


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
    ex = ProtectedExecution()
    r = ex.run("read", {"path": "/x"}, dv.Consequence.REVERSIBLE_LOW)
    assert r["allowed"] is True
    try:
        ex.run("expand", {"x": "f(" * 50}, dv.Consequence.REVERSIBLE_LOW)
    except ComboError:
        pass
    else:
        raise AssertionError("resource bomb should fail")
    try:
        ex.run("rm", {"p": "/"}, dv.Consequence.IRREVERSIBLE_BROAD)
    except ComboError:
        pass
    else:
        raise AssertionError("irreversible should be vetoed")
    assert stdlib_only()
    print("combo-04 OK: resources, veto, rate limit")



if __name__ == "__main__":
    main()
