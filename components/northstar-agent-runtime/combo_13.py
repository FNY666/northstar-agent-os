"""Session immune system, Integrated.

Combines: stateful_veto + lifecycle_hooks + tripwire_guardrails.
A pre-tool hook fires the tripwire; violations are recorded by the stateful veto, which rate-limits sessions that keep offending.

What this IS: adaptive session defense that learns from violations.
What this IS NOT: a permanent ban system.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_13_VERSION = "combo-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-13.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


sv = _load("stateful_veto")
lh = _load("lifecycle_hooks")
tw = _load("tripwire_guardrails")


class SessionImmuneSystem:
    """Hook -> tripwire -> record deny -> rate limit."""

    def __init__(self, tripwire: Any, session_id: str = "sess-13") -> None:
        self._tripwire = tripwire
        self._stateful = sv.StatefulVeto()
        self._session = session_id
        self._hooks = lh.HookRegistry()
        self._hooks.register(lh.HookPoint.PRE_TOOL, self._pre_tool)

    def _pre_tool(self, context: Dict[str, Any]) -> bool:
        result = self._tripwire.check(
            context.get("tool", ""), context.get("args", {})
        )
        if result.outcome == tw.TripwireOutcome.HALT:
            self._stateful.record_deny(self._session, context.get("tool", ""))
            return False
        return True

    def attempt(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        ok, _reason = self._hooks.fire(
            lh.HookPoint.PRE_TOOL, {"tool": tool_name, "args": args}
        )
        limited, limit_reason = self._stateful.should_rate_limit(
            self._session, tool_name
        )
        return {
            "allowed": bool(ok) and not limited,
            "hook_allowed": bool(ok),
            "rate_limited": limited,
            "limit_reason": limit_reason,
            "risk": self._stateful.risk_score(self._session),
        }


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
    immune = SessionImmuneSystem(tripwire)
    r = immune.attempt("read", {"p": "/x"})
    assert r["allowed"] is True and r["risk"] == 0
    r2 = immune.attempt("run", {"cmd": "evil"})
    assert r2["allowed"] is False and r2["risk"] > 0
    for _ in range(15):
        immune.attempt("run", {"cmd": "evil"})
    r3 = immune.attempt("run", {"cmd": "evil"})
    assert r3["rate_limited"] is True
    assert stdlib_only()
    print("combo-13 OK: hook, tripwire, rate limit")



if __name__ == "__main__":
    main()
