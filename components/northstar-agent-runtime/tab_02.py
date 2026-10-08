"""Climbing stairs (tab-02), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-climb.v1"

def climb(n: int) -> int:
    if n < 0: raise ValueError("n must be >= 0")
    if n <= 1: return 1
    a, b = 1, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert climb(0) == 1
    assert climb(2) == 2
    assert climb(3) == 3
    assert climb(5) == 8
    assert stdlib_only()
    print("tab-climb OK")

if __name__ == "__main__": main()
