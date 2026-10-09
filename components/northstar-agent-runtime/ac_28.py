"""Collatz Steps Util (D-AC-028), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_28.v1"
def collatz_steps(n: int) -> int:
    s = 0
    while n != 1: n = n // 2 if n % 2 == 0 else 3 * n + 1; s += 1
    return s
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert collatz_steps(1) == 0
    assert collatz_steps(6) == 8
    assert collatz_steps(3) == 7
    assert stdlib_only()
    print("ac_28 OK")
if __name__ == "__main__": main()
