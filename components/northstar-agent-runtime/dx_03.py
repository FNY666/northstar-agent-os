"""DX-03: Debugger integration (mock), Simulated.

Mock debugger for a toy program model: a list of (line_no, source)
statements plus a variables dict.  Supports breakpoints, step,
continue-to-breakpoint, and variable inspection.

Fail-closed: setting a breakpoint on a nonexistent line raises;
stepping past the end halts cleanly instead of crashing.

What this IS: the breakpoint/step/inspect control surface.
What this IS NOT: not a real debugger (no ptrace, no real frames).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

#: Module version.
DX03_DEBUGGER_VERSION = "dx-debugger.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-debugger.v1"


class DebuggerError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Frame:
    """Current execution state."""

    line_no: int
    source: str
    variables: Dict[str, Any]
    halted: bool = False


class MockDebugger:
    """Deterministic mock debugger over a statement list."""

    def __init__(self, program: List[tuple], variables: Optional[Dict[str, Any]] = None) -> None:
        if not program:
            raise DebuggerError("program must be non-empty")
        lines = [ln for ln, _ in program]
        if sorted(lines) != lines or len(set(lines)) != len(lines):
            raise DebuggerError("line numbers must be unique and ascending")
        self._program: Dict[int, str] = {ln: src for ln, src in program}
        self._ordered: List[int] = sorted(self._program)
        self._variables: Dict[str, Any] = dict(variables or {})
        self._breakpoints: Set[int] = set()
        self._pc: int = 0  # index into _ordered
        self._hits: List[int] = []

    def set_breakpoint(self, line_no: int) -> None:
        if line_no not in self._program:
            raise DebuggerError(f"no such line {line_no}")
        self._breakpoints.add(line_no)

    def clear_breakpoint(self, line_no: int) -> None:
        self._breakpoints.discard(line_no)

    def step(self) -> Frame:
        """Execute one statement, return the frame after it."""
        if self._pc >= len(self._ordered):
            return Frame(line_no=-1, source="", variables=dict(self._variables), halted=True)
        line_no = self._ordered[self._pc]
        self._pc += 1
        return Frame(line_no=line_no, source=self._program[line_no],
                     variables=dict(self._variables), halted=False)

    def continue_(self) -> Frame:
        """Run until next breakpoint or end."""
        while self._pc < len(self._ordered):
            line_no = self._ordered[self._pc]
            if line_no in self._breakpoints:
                self._hits.append(line_no)
                return Frame(line_no=line_no, source=self._program[line_no],
                             variables=dict(self._variables), halted=False)
            self.step()
        return Frame(line_no=-1, source="", variables=dict(self._variables), halted=True)

    def inspect(self, name: str) -> Any:
        if name not in self._variables:
            raise DebuggerError(f"no variable '{name}'")
        return self._variables[name]

    def set_variable(self, name: str, value: Any) -> None:
        self._variables[name] = value

    @property
    def breakpoints(self) -> List[int]:
        return sorted(self._breakpoints)

    @property
    def breakpoint_hits(self) -> List[int]:
        return list(self._hits)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    dbg = MockDebugger([(1, "x = 1"), (2, "y = 2"), (3, "z = x + y")], {"x": 1})
    dbg.set_breakpoint(2)
    f = dbg.continue_()
    assert f.line_no == 2 and not f.halted
    f = dbg.step()
    assert f.line_no == 2
    assert dbg.inspect("x") == 1
    dbg.set_variable("w", 9)
    assert dbg.inspect("w") == 9
    f = dbg.continue_()
    assert f.halted
    try:
        dbg.set_breakpoint(99)
        raise AssertionError("should raise")
    except DebuggerError:
        pass
    assert stdlib_only()
    print("dx_03 OK: breakpoints, step, continue, inspect, fail-closed")


if __name__ == "__main__":
    main()
