"""Alignment-observed delegation, Integrated.

Combines: alignment_check + command_registry + lifecycle_hooks.
Delegation requires an alignment judgment, a registered command, and fires lifecycle hooks around the handoff.

What this IS: delegations that are aligned, authorized, and audited.
What this IS NOT: a guarantee the delegate behaves.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_18_VERSION = "combo-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-18.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


ac = _load("alignment_check")
cr = _load("command_registry")
lh = _load("lifecycle_hooks")


class AlignmentObservedDelegation:
    """Alignment -> command auth -> hooked handoff."""

    def __init__(self, judge_fn: Callable[[Dict[str, Any]], Any]) -> None:
        self._observer = ac.AlignmentObserver(judge_fn)
        self._registry = cr.CommandRegistry()
        self._hooks = lh.HookRegistry()
        self._events: List[str] = []

    def register_command(self, name: str, autonomy: Any) -> None:
        self._registry.register(cr.CommandSpec(name, autonomy, name))

    def on(self, point: Any, fn: Callable[[Dict[str, Any]], bool]) -> None:
        self._hooks.register(point, fn)

    def delegate(
        self, goal: str, trace: List[Any], action: str, command: str
    ) -> Dict[str, Any]:
        judgment = self._observer.check(goal, trace, action)
        if not judgment.aligned:
            raise ComboError(f"misaligned: {judgment.reason}")
        ok, reason = self._registry.check(command)
        if not ok:
            raise ComboError(f"command: {reason}")
        pre_ok, _ = self._hooks.fire(lh.HookPoint.PRE_TOOL, {"command": command})
        self._events.append("pre")
        if not pre_ok:
            raise ComboError("pre-hook blocked delegation")
        post_ok, _ = self._hooks.fire(lh.HookPoint.POST_TOOL, {"command": command})
        self._events.append("post")
        return {"judgment": judgment, "delegated": command, "events": list(self._events)}


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



def _judge(inp):
    return ac.AlignmentJudgment(True, 0.9, "ok")


def main() -> None:
    d = AlignmentObservedDelegation(_judge)
    d.register_command("fetch", cr.AutonomyLevel.AUTOMATIC)
    trace = [ac.TraceEntry("action", "x")]
    r = d.delegate("goal", trace, "fetch data", "fetch")
    assert r["delegated"] == "fetch"
    assert r["events"] == ["pre", "post"]

    def _bad(inp):
        return ac.AlignmentJudgment(False, 0.1, "off")

    d2 = AlignmentObservedDelegation(_bad)
    d2.register_command("fetch", cr.AutonomyLevel.AUTOMATIC)
    try:
        d2.delegate("goal", trace, "fetch data", "fetch")
    except ComboError:
        pass
    else:
        raise AssertionError("misaligned should fail")
    try:
        d.delegate("goal", trace, "fetch data", "ghost")
    except ComboError:
        pass
    else:
        raise AssertionError("unknown command should fail")
    assert stdlib_only()
    print("combo-18 OK: align, authorize, audit")



if __name__ == "__main__":
    main()
