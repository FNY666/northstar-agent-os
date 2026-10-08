"""Observed execution, Integrated.

Combines: interleaved_thinking + lifecycle_hooks + task_snapshot.
Every tool call requires interleaved reasoning, fires lifecycle hooks pre/post, and is recorded into a replayable task snapshot.

What this IS: a fully observed execution loop: reason, hook, record.
What this IS NOT: a replacement for the underlying tool implementations.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_07_VERSION = "combo-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-07.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


it = _load("interleaved_thinking")
lh = _load("lifecycle_hooks")
ts = _load("task_snapshot")


class ObservedExecution:
    """Reason -> pre-hook -> execute -> post-hook -> snapshot."""

    def __init__(
        self, executor: Callable[[str, Dict[str, Any]], Any], run_id: str = "run-07"
    ) -> None:
        self._runner = it.InterleavedRunner(executor)
        self._hooks = lh.HookRegistry()
        self._snapshot = ts.TaskSnapshot(run_id, "observed run", {})
        self._fired: List[str] = []

    def on(self, point: Any, fn: Callable[[Dict[str, Any]], bool]) -> None:
        self._hooks.register(point, fn)

    def execute(
        self, reasoning: Optional[str], tool_name: str, args: Dict[str, Any]
    ) -> Any:
        ok, reason = self._hooks.fire(
            lh.HookPoint.PRE_TOOL, {"tool": tool_name, "args": args}
        )
        if not ok:
            raise ComboError(f"pre-hook blocked: {reason}")
        self._fired.append("pre")
        result = self._runner.run(reasoning, tool_name, args)
        self._hooks.fire(
            lh.HookPoint.POST_TOOL, {"tool": tool_name, "result": str(result)}
        )
        self._fired.append("post")
        self._snapshot.add_tool_call(tool_name, args, result, "allow")
        return result

    @property
    def snapshot(self) -> Any:
        return self._snapshot

    @property
    def fired(self) -> List[str]:
        return list(self._fired)


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
    ex = ObservedExecution(lambda tool, args: f"ran {tool}")
    r = ex.execute("need to list files", "ls", {"p": "/x"})
    assert r == "ran ls"
    assert ex.fired == ["pre", "post"]
    assert len(ex.snapshot.tool_calls) == 1
    try:
        ex.execute(None, "ls", {})
    except it.InterleavedError:
        pass
    else:
        raise AssertionError("missing reasoning should fail")
    ex2 = ObservedExecution(lambda tool, args: "x")
    ex2.on(lh.HookPoint.PRE_TOOL, lambda ctx: False)
    try:
        ex2.execute("reason", "ls", {})
    except ComboError:
        pass
    else:
        raise AssertionError("hook deny should fail")
    assert stdlib_only()
    print("combo-07 OK: reason, hooks, snapshot")



if __name__ == "__main__":
    main()
