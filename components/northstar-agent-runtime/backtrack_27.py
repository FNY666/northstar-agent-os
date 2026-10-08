"""Backtracking: add +, -, * between digits to hit a target value.

IS: given a digit string, inserts binary operators (+, -, *) between the
digits (concatenation allowed) and returns every expression evaluating to
the target, tracking the last operand so multiplication binds tighter;
numbers with leading zeros are rejected. IS NOT: a general expression
solver - no division, no parentheses, no unary minus, and no claim the
returned expressions are "simplest".
"""

import ast
from typing import List, Optional

VERSION = "backtrack_27.v1"


def add_operators(num: str, target: int) -> List[str]:
    """All expressions from num's digits evaluating to target."""
    results: List[str] = []
    n = len(num)

    def dfs(i: int, expr: str, value: int, last: int) -> None:
        if i == n:
            if value == target:
                results.append(expr)
            return
        for j in range(i + 1, n + 1):
            part = num[i:j]
            if len(part) > 1 and part[0] == "0":
                break
            v = int(part)
            if i == 0:
                dfs(j, part, v, v)
            else:
                dfs(j, expr + "+" + part, value + v, v)
                dfs(j, expr + "-" + part, value - v, -v)
                dfs(j, expr + "*" + part, value - last + last * v, last * v)

    if num:
        dfs(0, "", 0, 0)
    return results


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert set(add_operators("123", 6)) == {"1+2+3", "1*2*3"}
    assert set(add_operators("232", 8)) == {"2+3*2", "2*3+2"}
    assert set(add_operators("105", 5)) == {"1*0+5", "10-5"}
    assert set(add_operators("00", 0)) == {"0+0", "0-0", "0*0"}
    assert add_operators("3456237490", 9191) == []
    print("backtrack_27 OK")


if __name__ == "__main__":
    main()
