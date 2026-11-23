"""Per-tool rate limiting (input defense), Simulated

What this IS: Sliding-window rate limiter keyed by tool name. Prevents a single tool from being hammered (cost amplification, exfil loops).

What this IS NOT:
* In-memory only.
* Window is fixed; host chooses window/count policy.
"""

from __future__ import annotations

import time

#: Module version.
MODULE_VERSION = "input-defense-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-23.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'time', 'ast', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


class ToolRateLimiter:
    """Sliding-window limiter keyed by tool name."""

    def __init__(self, max_calls=20, window_sec=60.0, time_fn=None):
        if max_calls <= 0:
            raise InputDefenseError("max_calls must be positive")
        if window_sec <= 0:
            raise InputDefenseError("window_sec must be positive")
        self.max_calls = max_calls
        self.window_sec = float(window_sec)
        self._time = time_fn or __import__("time").time
        self._calls = {}

    def allow(self, tool_name):
        """Record a call. Returns True if within limit."""
        if not tool_name:
            raise InputDefenseError("tool_name required")
        now = self._time()
        calls = [t for t in self._calls.get(tool_name, []) if now - t < self.window_sec]
        if len(calls) >= self.max_calls:
            self._calls[tool_name] = calls
            return False
        calls.append(now)
        self._calls[tool_name] = calls
        return True

    def count(self, tool_name):
        """Calls in current window."""
        now = self._time()
        return sum(1 for t in self._calls.get(tool_name, []) if now - t < self.window_sec)



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    clock = [0.0]
    l = ToolRateLimiter(max_calls=2, window_sec=10.0, time_fn=lambda: clock[0])
    assert l.allow("t") is True
    assert l.allow("t") is True
    assert l.allow("t") is False
    clock[0] = 11.0  # window slides
    assert l.allow("t") is True
    try:
        l.allow("")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-23.v1 OK")


if __name__ == "__main__":
    main()
