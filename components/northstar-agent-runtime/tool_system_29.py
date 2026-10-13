"""Tool orchestration (mock): DAG of tool tasks, Simulated.

An Orchestrator runs a DAG of tool tasks in topological order.
Cycles raise.  ``parallel_groups`` reports levels of tasks with no
inter-dependencies (safe to run concurrently).  A failed task halts
its dependents (fail-closed): they never run.

What this IS:
* Simulated DAG scheduling over injected task callables.

What this IS NOT:
* Not a real parallel executor -- groups are reported, not threaded.
* Not a retry/queue system -- one failure halts dependents.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
TOOL_SYSTEM_29_VERSION = "tool-system-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-29.v1"


class ToolSystem29Error(Exception):
    """Fail-closed."""


class CycleError(ToolSystem29Error):
    """Raised when the task graph has a cycle."""


class TaskFailed(ToolSystem29Error):
    """Raised when a task callable raises; dependents halted."""

    def __init__(
        self, task: str, cause: BaseException, halted: List[str]
    ) -> None:
        super().__init__(
            f"task '{task}' failed: {cause}; halted dependents: {halted}"
        )
        self.task = task
        self.cause = cause
        self.halted = halted


@dataclass
class Task:
    """One DAG task (mock)."""

    name: str
    fn: Callable[[], Any]
    deps: List[str] = field(default_factory=list)


class Orchestrator:
    """Mock DAG orchestrator for tool tasks."""

    def __init__(self) -> None:
        self._tasks: Dict[str, Task] = {}
        self._results: Dict[str, Any] = {}

    def add_task(
        self,
        name: str,
        fn: Callable[[], Any],
        deps: Optional[List[str]] = None,
    ) -> None:
        if not name:
            raise ToolSystem29Error("task name required")
        if name in self._tasks:
            raise ToolSystem29Error(f"duplicate task '{name}'")
        self._tasks[name] = Task(
            name=name, fn=fn, deps=list(deps or [])
        )

    def _check_deps(self) -> None:
        for task in self._tasks.values():
            for dep in task.deps:
                if dep not in self._tasks:
                    raise ToolSystem29Error(
                        f"task '{task.name}' depends on unknown '{dep}'"
                    )
                if dep == task.name:
                    raise CycleError(
                        f"task '{task.name}' depends on itself"
                    )

    def parallel_groups(self) -> List[List[str]]:
        """Levels with no inter-deps (deterministic name order)."""
        self._check_deps()
        remaining = {n: set(t.deps) for n, t in self._tasks.items()}
        groups: List[List[str]] = []
        while remaining:
            ready = sorted(
                n for n, deps in remaining.items() if not deps
            )
            if not ready:
                cycle = sorted(remaining)
                raise CycleError(f"cycle among tasks: {cycle}")
            groups.append(ready)
            for n in ready:
                del remaining[n]
            for deps in remaining.values():
                deps.difference_update(ready)
        return groups

    def run(self) -> Dict[str, Any]:
        """Topological order; failed task halts dependents (fail-closed)."""
        groups = self.parallel_groups()
        self._results = {}
        failed: Optional[str] = None
        cause: Optional[BaseException] = None
        for group in groups:
            for name in group:
                task = self._tasks[name]
                if any(d not in self._results for d in task.deps):
                    continue  # dependent of a failed task: halted
                try:
                    self._results[name] = task.fn()
                except Exception as exc:  # noqa: BLE001 - wrapped in TaskFailed
                    if failed is None:
                        failed, cause = name, exc
        if failed is not None:
            halted = sorted(self._dependents(failed) - {failed})
            raise TaskFailed(failed, cause, halted)
        return dict(self._results)

    def _dependents(self, name: str) -> set:
        """Transitive closure of tasks depending on ``name``."""
        seen = {name}
        frontier = [name]
        while frontier:
            current = frontier.pop()
            for task in self._tasks.values():
                if current in task.deps and task.name not in seen:
                    seen.add(task.name)
                    frontier.append(task.name)
        return seen

    def results(self) -> Dict[str, Any]:
        return dict(self._results)


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
    order: List[str] = []
    orch = Orchestrator()
    orch.add_task("fetch", lambda: order.append("fetch") or "f")
    orch.add_task(
        "parse", lambda: order.append("parse") or "p", deps=["fetch"]
    )
    orch.add_task(
        "summarize",
        lambda: order.append("summarize") or "s",
        deps=["parse"],
    )
    orch.add_task("notify", lambda: order.append("notify") or "n")
    res = orch.run()
    assert order.index("fetch") < order.index("parse") < order.index(
        "summarize"
    )
    assert res["summarize"] == "s"
    groups = orch.parallel_groups()
    assert groups[0] == ["fetch", "notify"]
    # Cycle raises.
    cyc = Orchestrator()
    cyc.add_task("a", lambda: 1, deps=["b"])
    cyc.add_task("b", lambda: 2, deps=["a"])
    try:
        cyc.run()
        raise AssertionError("should raise")
    except CycleError:
        pass
    # Failure halts dependents.
    ran: List[str] = []
    bad = Orchestrator()
    bad.add_task("ok", lambda: ran.append("ok") or 1)

    def _boom() -> Any:
        ran.append("boom")
        raise RuntimeError("kaput")

    bad.add_task("fail", _boom)
    bad.add_task("child", lambda: ran.append("child") or 3, deps=["fail"])
    try:
        bad.run()
        raise AssertionError("should raise")
    except TaskFailed as exc:
        assert exc.task == "fail"
        assert "child" in exc.halted
    assert "child" not in ran
    assert stdlib_only()
    print("tool_system_29 OK: topo order, groups, cycles, fail-closed")


if __name__ == "__main__":
    main()
