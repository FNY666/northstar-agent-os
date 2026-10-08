"""Integration I-007: interleaved thinking + goal comparator (terminating runner), Simulated.

Every tool call needs preceding reasoning (interleaved), and after every
call the goal comparator checks for termination.  The loop halts when
the objective is reached, the queue empties, or max cycles hit.

What this IS: a reasoned loop with an off switch.
What this IS NOT: not the planner -- the host drives the loop.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Module version.
INTEGRATION_07_VERSION = "integration-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-07.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_interleaved = _load("interleaved_thinking")
_goalcmp = _load("goal_comparator")


class IntegrationError(Exception):
    """Fail-closed."""


class TerminatingRunner:
    """Enforces reasoning per action; checks termination after each."""

    def __init__(
        self,
        executor: Any,
        comparator: Any,
        log_fn: Any = None,
    ) -> None:
        if comparator is None:
            raise IntegrationError("comparator required")
        self._runner = _interleaved.InterleavedRunner(executor, log_fn)
        self._comparator = comparator

    def run(
        self,
        reasoning: Optional[str],
        tool_name: str,
        args: Optional[Dict[str, Any]],
        state_summary: Dict[str, Any],
        task_queue: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run one reasoned step, then check termination.

        Raises InterleavedError if reasoning is missing (fail-closed).
        Returns {"result", "comparison", "done", "cycles"}.
        """
        result = self._runner.run(reasoning, tool_name, args or {})
        comparison = self._comparator.check(state_summary, task_queue)
        return {
            "result": result,
            "comparison": comparison,
            "done": comparison.done,
            "cycles": comparison.cycles_used,
        }

    @property
    def actions(self) -> List[Any]:
        return self._runner.actions


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
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
    """Self-check."""
    comp = _goalcmp.GoalComparator("count to 2", max_cycles=10)
    runner = TerminatingRunner(lambda t, a: f"ran {t}", comp)

    out = runner.run(
        "need to call", "tool", {"x": 1}, {"count": 1}, ["t1"]
    )
    assert out["result"] == "ran tool"
    assert out["done"] is False
    assert out["cycles"] == 1

    out = runner.run("again", "tool", {}, {"count": 2}, [])
    assert out["done"] is True  # empty queue

    try:
        runner.run("", "tool", {}, {})
        raise AssertionError("should raise")
    except _interleaved.InterleavedError:
        pass

    assert stdlib_only()
    print("integration-07 OK: terminating runner, reasoning, stdlib")


if __name__ == "__main__":
    main()
