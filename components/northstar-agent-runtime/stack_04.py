"""Daily Temperatures: monotonic stack waiting days. IS: a decreasing monotonic stack that records days until a warmer day. IS NOT: a brute-force O(n^2) scan."""

from __future__ import annotations

import ast

VERSION = "stack-04.v1"

def _req_temps(temperatures: object) -> list[int | float]:
    if not isinstance(temperatures, list):
        raise ValueError("temperatures must be a list")
    for t in temperatures:
        if isinstance(t, bool) or not isinstance(t, (int, float)):
            raise ValueError("temperatures must contain only numbers")
    return list(temperatures)


def daily_temperatures(temperatures: list[int | float]) -> list[int]:
    """Days to wait for a warmer temperature (0 when none comes).

    Fail-closed: input must be a list of numbers.
    """
    temps = _req_temps(temperatures)
    n = len(temps)
    answer = [0] * n
    stack: list[int] = []
    for i, t in enumerate(temps):
        while stack and temps[stack[-1]] < t:
            j = stack.pop()
            answer[j] = i - j
        stack.append(i)
    return answer

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert daily_temperatures([73, 74, 75, 71, 69, 72, 76, 73]) == [1, 1, 4, 2, 1, 1, 0, 0]
    assert daily_temperatures([30, 40, 50, 60]) == [1, 1, 1, 0]
    assert daily_temperatures([30, 60, 90]) == [1, 1, 0]
    assert daily_temperatures([]) == []
    assert daily_temperatures([90, 80, 70]) == [0, 0, 0]
    try:
        daily_temperatures(["hot"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-number temp must raise ValueError")
    assert stdlib_only()
    print("stack_04 OK")


if __name__ == "__main__":
    main()
