"""Tool sagas: compensating actions, Simulated.

A saga is a sequence of steps, each with a forward action and a
compensating (undo) action.  If a step fails, previously completed
steps are compensated in reverse order.

What this IS: long-running transaction alternative without 2PC.

What this IS NOT:
* Compensation is best-effort; failures are recorded, not retried.
* Not durable -- in-memory.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Callable, List

#: Module version.
TOOL_SYSTEM_12_VERSION = "tool-system-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-12.v1"


class ToolSystem12Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SagaStep:
    """One saga step: action + compensation."""

    name: str
    action: Callable[[], Any]
    compensate: Callable[[], None]


@dataclass
class SagaResult:
    """Outcome of a saga run."""

    completed: bool
    results: List[Any] = field(default_factory=list)
    failed_step: int = -1
    compensated: List[str] = field(default_factory=list)
    compensation_errors: List[str] = field(default_factory=list)


def run_saga(steps: List[SagaStep]) -> SagaResult:
    """Run steps; compensate in reverse on failure."""
    if not steps:
        raise ToolSystem12Error("no steps")
    result = SagaResult(completed=False)
    done: List[SagaStep] = []
    for i, step in enumerate(steps):
        try:
            result.results.append(step.action())
            done.append(step)
        except Exception as e:
            result.failed_step = i
            # Compensate in reverse order.
            for prev in reversed(done):
                try:
                    prev.compensate()
                    result.compensated.append(prev.name)
                except Exception as ce:
                    result.compensation_errors.append(
                        f"{prev.name}: {type(ce).__name__}"
                    )
            return result
    result.completed = True
    return result


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    log: List[str] = []

    def step(name: str, fail: bool = False) -> SagaStep:
        def action():
            log.append(f"{name}:do")
            if fail:
                raise ValueError("step failed")
            return name

        def compensate():
            log.append(f"{name}:undo")

        return SagaStep(name=name, action=action, compensate=compensate)

    # All succeed.
    r = run_saga([step("a"), step("b"), step("c")])
    assert r.completed is True
    assert r.results == ["a", "b", "c"]

    # Middle fails: a and b compensated in reverse.
    log.clear()
    r = run_saga([step("a"), step("b"), step("c", fail=True)])
    assert r.completed is False
    assert r.failed_step == 2
    assert r.compensated == ["b", "a"]
    assert log == ["a:do", "b:do", "c:do", "b:undo", "a:undo"]

    # Compensation failure recorded, not raised.
    def bad_comp() -> SagaStep:
        def compensate():
            raise RuntimeError("undo failed")

        return SagaStep(
            name="x", action=lambda: log.append("x:do"),
            compensate=compensate,
        )

    log.clear()
    r = run_saga([bad_comp(), step("y", fail=True)])
    assert r.completed is False
    assert len(r.compensation_errors) == 1
    assert stdlib_only()
    print("tool_system_12 OK: saga, reverse compensation, error record")


if __name__ == "__main__":
    main()
