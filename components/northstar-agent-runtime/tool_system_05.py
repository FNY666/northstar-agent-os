"""Tool chaining: sequential execution, Simulated.

Execute a named sequence of tool calls.  Each step names a tool and
provides args.  Results accumulate; a step can reference prior results
via {step_N} placeholders.

What this IS: ordered multi-tool execution with result passing.

What this IS NOT:
* Not conditional -- steps always run in order (use sagas for branches).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

#: Module version.
TOOL_SYSTEM_05_VERSION = "tool-system-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-05.v1"


class ToolSystem05Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ChainStep:
    """One step: tool name + args (may contain {step_N} refs)."""

    tool: str
    args: Dict[str, Any]


@dataclass
class ChainResult:
    """Results of a chain run."""

    results: List[Any] = field(default_factory=list)
    failed_step: int = -1
    error: str = ""


def _resolve(value: Any, results: List[Any]) -> Any:
    """Resolve {step_N} placeholders against prior results."""
    if isinstance(value, str) and value.startswith("{step_") and value.endswith("}"):
        try:
            idx = int(value[6:-1])
        except ValueError:
            raise ToolSystem05Error(f"bad placeholder '{value}'")
        if idx < 0 or idx >= len(results):
            raise ToolSystem05Error(f"placeholder '{value}' out of range")
        return results[idx]
    if isinstance(value, dict):
        return {k: _resolve(v, results) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, results) for v in value]
    return value


def run_chain(
    steps: List[ChainStep],
    tools: Dict[str, Callable[..., Any]],
    *,
    stop_on_error: bool = True,
) -> ChainResult:
    """Run steps in order.  Tools map names to callables."""
    if not steps:
        raise ToolSystem05Error("no steps")
    result = ChainResult()
    for i, step in enumerate(steps):
        if step.tool not in tools:
            result.failed_step = i
            result.error = f"unknown tool '{step.tool}'"
            if stop_on_error:
                break
            result.results.append(None)
            continue
        try:
            resolved = _resolve(step.args, result.results)
            if not isinstance(resolved, dict):
                raise ToolSystem05Error("args must resolve to dict")
            result.results.append(tools[step.tool](**resolved))
        except Exception as e:
            result.failed_step = i
            result.error = f"step {i} ({step.tool}): {type(e).__name__}"
            if stop_on_error:
                break
            result.results.append(None)
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
    tools = {
        "double": lambda x: x * 2,
        "add": lambda x, y: x + y,
    }
    steps = [
        ChainStep("double", {"x": 5}),
        ChainStep("add", {"x": "{step_0}", "y": 3}),
    ]
    r = run_chain(steps, tools)
    assert r.results == [10, 13], r.results
    assert r.failed_step == -1
    # Unknown tool.
    r2 = run_chain([ChainStep("nope", {})], tools)
    assert r2.failed_step == 0
    # Bad placeholder.
    r3 = run_chain([ChainStep("double", {"x": "{step_9}"})], tools)
    assert r3.failed_step == 0
    assert stdlib_only()
    print("tool_system_05 OK: chaining, placeholders, error handling")


if __name__ == "__main__":
    main()
