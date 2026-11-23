"""Parallel tool calls: mock concurrent, Simulated.

Run independent tool calls "in parallel" using threads.  Results
return in submission order.  Exceptions are captured per-call.

What this IS: thread-based fan-out for I/O-bound tools.

What this IS NOT:
* Not true async -- threads with a timeout.
* Not for CPU-bound work (GIL).
"""

from __future__ import annotations

import ast
import concurrent.futures
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

#: Module version.
TOOL_SYSTEM_06_VERSION = "tool-system-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-06.v1"

#: Default per-call timeout (seconds).
DEFAULT_TIMEOUT = 30.0


class ToolSystem06Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class CallSpec:
    """One call: tool name + args."""

    tool: str
    args: Dict[str, Any]


@dataclass
class ParallelResult:
    """Per-call outcomes in submission order."""

    # List of (ok, value_or_error).
    outcomes: List[Tuple[bool, Any]]


def run_parallel(
    calls: List[CallSpec],
    tools: Dict[str, Callable[..., Any]],
    *,
    max_workers: int = 8,
    timeout: float = DEFAULT_TIMEOUT,
) -> ParallelResult:
    """Run calls concurrently.  Returns outcomes in order."""
    if not calls:
        raise ToolSystem06Error("no calls")
    if max_workers <= 0:
        raise ToolSystem06Error("max_workers must be positive")

    def _one(spec: CallSpec) -> Tuple[bool, Any]:
        if spec.tool not in tools:
            return False, ToolSystem06Error(f"unknown tool '{spec.tool}'")
        try:
            return True, tools[spec.tool](**spec.args)
        except Exception as e:
            return False, e

    outcomes: List[Tuple[bool, Any]] = [None] * len(calls)  # type: ignore
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as pool:
        future_map = {
            pool.submit(_one, spec): i for i, spec in enumerate(calls)
        }
        for fut in concurrent.futures.as_completed(future_map, timeout=timeout):
            i = future_map[fut]
            try:
                outcomes[i] = fut.result()
            except Exception as e:
                outcomes[i] = (False, e)
    return ParallelResult(outcomes=outcomes)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "concurrent", "dataclasses",
        "pathlib", "typing",
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
    tools = {
        "double": lambda x: x * 2,
        "boom": lambda: 1 / 0,
    }
    calls = [
        CallSpec("double", {"x": 1}),
        CallSpec("double", {"x": 2}),
        CallSpec("boom", {}),
        CallSpec("nope", {}),
    ]
    r = run_parallel(calls, tools)
    assert len(r.outcomes) == 4
    assert r.outcomes[0] == (True, 2)
    assert r.outcomes[1] == (True, 4)
    assert r.outcomes[2][0] is False  # ZeroDivisionError captured
    assert r.outcomes[3][0] is False  # unknown tool
    assert stdlib_only()
    print("tool_system_06 OK: parallel, order, error capture")


if __name__ == "__main__":
    main()
