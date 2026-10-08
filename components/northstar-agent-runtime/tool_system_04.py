"""Tool composition: chain tools, Simulated.

Compose tools into pipelines: output of one feeds input of the next.
Pure function composition over tool callables.

What this IS: f(g(x)) for tools.

What this IS NOT:
* Not async -- synchronous composition.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
TOOL_SYSTEM_04_VERSION = "tool-system-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-04.v1"


class ToolSystem04Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ComposedTool:
    """A pipeline of tool functions."""

    name: str
    steps: tuple  # tuple of callables


def compose(name: str, *fns: Callable[[Any], Any]) -> ComposedTool:
    """Compose fns into a pipeline.  compose('p', f, g) = g(f(x))."""
    if not name:
        raise ToolSystem04Error("name required")
    if len(fns) < 2:
        raise ToolSystem04Error("compose needs >= 2 functions")
    for fn in fns:
        if not callable(fn):
            raise ToolSystem04Error("all steps must be callable")
    return ComposedTool(name=name, steps=tuple(fns))


def run_pipeline(tool: ComposedTool, initial: Any) -> Any:
    """Run the pipeline on initial input."""
    value = initial
    for fn in tool.steps:
        try:
            value = fn(value)
        except Exception as e:
            raise ToolSystem04Error(
                f"pipeline '{tool.name}' failed at {getattr(fn, '__name__', '?')}: "
                f"{type(e).__name__}"
            ) from e
    return value


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
    p = compose("upper_len", str.upper, len)
    assert run_pipeline(p, "hello") == 5
    p2 = compose("add_mul", lambda x: x + 1, lambda x: x * 10)
    assert run_pipeline(p2, 5) == 60
    try:
        compose("bad", str.upper)
        raise AssertionError("should raise")
    except ToolSystem04Error:
        pass
    # Failure propagates with context.
    def boom(x):
        raise ValueError("oops")

    try:
        run_pipeline(compose("p", str, boom), 1)
        raise AssertionError("should raise")
    except ToolSystem04Error as e:
        assert "boom" in str(e)
    assert stdlib_only()
    print("tool_system_04 OK: compose, pipeline, error context")


if __name__ == "__main__":
    main()
