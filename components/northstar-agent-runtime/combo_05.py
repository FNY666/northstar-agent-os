"""Aligned termination, Integrated.

Combines: alignment_check + deliberative_spec + goal_comparator.
The observer judges goal-action alignment, the decision must cite spec clauses, and the goal comparator decides if the loop halts.

What this IS: an aligned, justified, terminating decision pipeline.
What this IS NOT: a proof that the goal itself is good.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_05_VERSION = "combo-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-05.v1"


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
ds = _load("deliberative_spec")
gc = _load("goal_comparator")


class AlignedTermination:
    """Alignment -> cited decision -> termination check."""

    def __init__(
        self,
        judge_fn: Callable[[Dict[str, Any]], Any],
        spec: Dict[str, Any],
        objective: str,
        max_cycles: int = 10,
    ) -> None:
        self._observer = ac.AlignmentObserver(judge_fn)
        self._spec = spec
        self._goal_text = objective
        self._comparator = gc.GoalComparator(objective, max_cycles=max_cycles)

    def decide(
        self,
        trace: List[Any],
        action: str,
        decision: str,
        cited_clauses: List[str],
        reasoning: str,
        state: Dict[str, Any],
        task_queue: List[str] = None,
    ) -> Dict[str, Any]:
        judgment = self._observer.check(self._goal_text, trace, action)
        if not judgment.aligned:
            raise ComboError(f"misaligned: {judgment.reason}")
        try:
            deliberated = ds.require_citation(
                decision, cited_clauses, reasoning, self._spec
            )
        except ds.DeliberativeError as exc:
            raise ComboError(f"uncited: {exc}") from exc
        result = self._comparator.check(state, task_queue)
        return {
            "judgment": judgment,
            "decision": deliberated,
            "done": result.done,
            "cycles": result.cycles_used,
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



def _judge(inp):
    return ac.AlignmentJudgment(True, 0.9, "aligned")


def main() -> None:
    spec = {"c1": ds.SpecClause("c1", "be safe")}
    term = AlignedTermination(_judge, spec, "finish task")
    trace = [ac.TraceEntry("action", "did thing")]
    r = term.decide(trace, "act", "allow", ["c1"], "because c1", {}, [])
    assert r["done"] is True
    try:
        term.decide(trace, "act", "allow", ["nope"], "because", {}, [])
    except ComboError:
        pass
    else:
        raise AssertionError("uncited should fail")

    def _bad_judge(inp):
        return ac.AlignmentJudgment(False, 0.1, "off-goal")

    term2 = AlignedTermination(_bad_judge, spec, "finish task")
    try:
        term2.decide(trace, "act", "allow", ["c1"], "r", {}, [])
    except ComboError:
        pass
    else:
        raise AssertionError("misaligned should fail")
    assert stdlib_only()
    print("combo-05 OK: align, cite, terminate")



if __name__ == "__main__":
    main()
