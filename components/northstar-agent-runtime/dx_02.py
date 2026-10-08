"""DX-02: REPL (mock interactive), Simulated.

A non-interactive simulated REPL: feed it a list of input lines and it
runs the read-eval-print loop deterministically, returning the output
lines.  Builtins: help, echo, history, clear, exit.  Custom commands
can be registered.

Fail-closed: unknown commands produce an error result and are recorded
in history; the loop never crashes on bad input.

What this IS: a deterministic stand-in for an interactive shell.
What this IS NOT: not a real terminal REPL (no readline, no tty).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

#: Module version.
DX02_REPL_VERSION = "dx-repl.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-repl.v1"


class REPLError(Exception):
    """Fail-closed."""


@dataclass
class REPLResult:
    """Result of one evaluated line."""

    line: str
    output: str
    ok: bool


class MockREPL:
    """Deterministic simulated REPL."""

    def __init__(self, prompt: str = "ns> ") -> None:
        self._prompt = prompt
        self._commands: Dict[str, Callable[[List[str]], str]] = {}
        self._history: List[str] = []
        self._register_builtins()

    def _register_builtins(self) -> None:
        self._commands["help"] = lambda argv: "commands: " + ", ".join(sorted(self._commands))
        self._commands["echo"] = lambda argv: " ".join(argv[1:])
        self._commands["history"] = lambda argv: "\n".join(
            f"{i}: {h}" for i, h in enumerate(self._history)
        )
        self._commands["clear"] = lambda argv: self._clear() or ""

    def _clear(self) -> None:
        self._history.clear()

    def register(self, name: str, fn: Callable[[List[str]], str]) -> None:
        if not name or not name.strip():
            raise REPLError("command name required")
        if not callable(fn):
            raise REPLError("handler must be callable")
        self._commands[name] = fn

    def eval_line(self, line: str) -> REPLResult:
        """Evaluate one line.  Never raises on bad input."""
        stripped = line.strip()
        if not stripped:
            return REPLResult(line=line, output="", ok=True)
        self._history.append(stripped)
        parts = stripped.split()
        cmd, argv = parts[0], parts
        fn = self._commands.get(cmd)
        if fn is None:
            return REPLResult(line=line, output=f"error: unknown command '{cmd}'", ok=False)
        try:
            out = fn(argv)
        except Exception as e:
            return REPLResult(line=line, output=f"error: {type(e).__name__}", ok=False)
        return REPLResult(line=line, output=str(out), ok=True)

    def run_script(self, lines: List[str]) -> List[REPLResult]:
        """Run a script of lines; stops after 'exit'."""
        results: List[REPLResult] = []
        for line in lines:
            if line.strip() == "exit":
                results.append(REPLResult(line=line, output="bye", ok=True))
                break
            results.append(self.eval_line(line))
        return results

    @property
    def history(self) -> List[str]:
        return list(self._history)


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
    repl = MockREPL()
    repl.register("add", lambda argv: str(sum(int(x) for x in argv[1:])))
    out = repl.run_script(["echo hello world", "add 2 3", "bogus", "history", "exit", "echo late"])
    assert out[0].output == "hello world" and out[0].ok
    assert out[1].output == "5"
    assert out[2].ok is False and "unknown command" in out[2].output
    assert "echo hello world" in out[3].output
    assert out[4].output == "bye"
    assert len(out) == 5  # stopped at exit
    assert stdlib_only()
    print("dx_02 OK: eval, builtins, history, fail-closed")


if __name__ == "__main__":
    main()
