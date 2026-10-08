"""Resource-aware delegation, Integrated.

Combines: resource_defense + command_registry + goal_comparator.
Delegation checks resource limits first, then command authorization, then whether the goal is already reached.

What this IS: delegation that cannot bomb resources or overshoot the goal.
What this IS NOT: a scheduler.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_12_VERSION = "combo-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-12.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


rd = _load("resource_defense")
cr = _load("command_registry")
gc = _load("goal_comparator")


class ResourceAwareDelegation:
    """Resources -> command auth -> goal check."""

    def __init__(
        self, objective: str, limits: Any = None, max_cycles: int = 50
    ) -> None:
        self._limits = limits or rd.ResourceLimits()
        self._registry = cr.CommandRegistry()
        self._goal = gc.GoalComparator(objective, max_cycles=max_cycles)

    def register_command(self, name: str, autonomy: Any) -> None:
        self._registry.register(cr.CommandSpec(name, autonomy, name))

    def grant_preauth(self, n: int) -> None:
        self._registry.grant_preauth(n)

    def delegate(
        self,
        command: str,
        tool_name: str,
        args: Dict[str, Any],
        state: Dict[str, Any],
        task_queue: List[str] = None,
    ) -> Dict[str, Any]:
        ok, reason = rd.check_resources(tool_name, args, self._limits)
        if not ok:
            raise ComboError(f"resource: {reason}")
        allowed, reason = self._registry.check(command)
        if not allowed:
            raise ComboError(f"command: {reason}")
        result = self._goal.check(state, task_queue)
        return {"delegated": True, "done": result.done, "cycles": result.cycles_used}


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
    d = ResourceAwareDelegation("finish")
    d.register_command("ls", cr.AutonomyLevel.AUTOMATIC)
    d.grant_preauth(5)
    r = d.delegate("ls", "ls", {"p": "/x"}, {}, ["t1"])
    assert r["delegated"] is True and r["done"] is False
    r2 = d.delegate("ls", "ls", {"p": "/x"}, {}, [])
    assert r2["done"] is True
    try:
        d.delegate("ls", "e", {"x": "f(" * 60}, {}, [])
    except ComboError:
        pass
    else:
        raise AssertionError("resource bomb should fail")
    try:
        d.delegate("ghost", "ls", {}, {}, [])
    except ComboError:
        pass
    else:
        raise AssertionError("unknown command should fail")
    assert stdlib_only()
    print("combo-12 OK: resources, auth, goal")



if __name__ == "__main__":
    main()
