"""obs_25: Runbook automation (mock), Simulated.

A runbook is an ordered list of (label, action, rollback-or-None) steps.
``run`` executes each action against a mock context dict, recording per-step
ok/result.  If an action raises, ``run`` stops, executes the rollbacks of
the already-completed steps in reverse order, and reports a failed status
with the rollback trail.  Nothing touches the real world: actions are
caller-provided callables that only see the mock context.

Fail-closed: empty labels, non-callable actions, or non-callable
rollbacks raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

OBS25_VERSION = "obs-25.v1"
SCHEMA_PIN = "northstar.obs-25.v1"


class Obs25Error(Exception):
    """Fail-closed."""


Step = Tuple[str, Callable[[Dict[str, Any]], Any], Optional[Callable[[Dict[str, Any]], Any]]]


class Runbook:
    """Ordered, rollback-capable runbook executed against a mock context."""

    def __init__(self, name: str, steps: Sequence[Step]) -> None:
        if not isinstance(name, str) or not name:
            raise Obs25Error("name must be a non-empty str")
        if not isinstance(steps, (list, tuple)) or not steps:
            raise Obs25Error("steps must be a non-empty list")
        validated: List[Step] = []
        for item in steps:
            if not isinstance(item, (list, tuple)) or len(item) not in (2, 3):
                raise Obs25Error("each step must be (label, action[, rollback])")
            label = item[0]
            action = item[1]
            rollback = item[2] if len(item) == 3 else None
            if not isinstance(label, str) or not label:
                raise Obs25Error("step label must be a non-empty str")
            if not callable(action):
                raise Obs25Error(f"action for step '{label}' must be callable")
            if rollback is not None and not callable(rollback):
                raise Obs25Error(f"rollback for step '{label}' must be callable or None")
            validated.append((label, action, rollback))
        self.name = name
        self.steps = validated

    def run(self) -> Dict[str, Any]:
        """Execute steps in order; roll back completed steps on failure."""
        ctx: Dict[str, Any] = {"runbook": self.name, "log": []}
        step_results: List[Dict[str, Any]] = []
        completed: List[Step] = []
        rollbacks: List[Dict[str, Any]] = []
        status = "ok"
        error: Optional[str] = None
        for label, action, rollback in self.steps:
            try:
                result = action(ctx)
            except Exception as exc:  # noqa: BLE001 - record and roll back
                status = "failed"
                error = f"{type(exc).__name__}: {exc}"
                step_results.append({"label": label, "ok": False, "result": None, "error": error})
                break
            step_results.append({"label": label, "ok": True, "result": result, "error": None})
            ctx["log"].append(label)
            completed.append((label, action, rollback))
        if status == "failed":
            for label, _action, rollback in reversed(completed):
                if rollback is None:
                    rollbacks.append({"label": label, "rolled_back": False})
                    continue
                try:
                    rollback(ctx)
                    rollbacks.append({"label": label, "rolled_back": True, "error": None})
                except Exception as exc:  # noqa: BLE001
                    rollbacks.append({
                        "label": label, "rolled_back": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    })
        return {
            "runbook": self.name,
            "status": status,
            "error": error,
            "steps": step_results,
            "completed": len(completed),
            "rollbacks": rollbacks,
            "context": ctx,
        }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    calls: List[str] = []

    def step1(ctx: Dict[str, Any]) -> str:
        calls.append("s1"); ctx["a"] = 1; return "done1"

    def rb1(ctx: Dict[str, Any]) -> None:
        calls.append("rb1"); ctx.pop("a", None)

    def step2(ctx: Dict[str, Any]) -> str:
        calls.append("s2"); raise RuntimeError("boom")

    rb = Runbook("deploy", [("warm cache", step1, rb1), ("switch traffic", step2, None)])
    out = rb.run()
    assert out["status"] == "failed"
    assert out["completed"] == 1
    assert calls == ["s1", "s2", "rb1"]
    assert out["rollbacks"] == [{"label": "warm cache", "rolled_back": True, "error": None}]
    assert out["steps"][1]["ok"] is False and "boom" in out["steps"][1]["error"]

    good = Runbook("healthy", [("a", lambda c: "x"), ("b", lambda c: "y")])
    out2 = good.run()
    assert out2["status"] == "ok" and out2["completed"] == 2
    assert all(s["ok"] for s in out2["steps"])

    try:
        Runbook("bad", [("", lambda c: None)])
        raise AssertionError("should raise")
    except Obs25Error:
        pass
    try:
        Runbook("bad", [("x", "not-callable")])  # type: ignore
        raise AssertionError("should raise")
    except Obs25Error:
        pass
    assert stdlib_only()
    print("obs_25 OK")


if __name__ == "__main__":
    main()
