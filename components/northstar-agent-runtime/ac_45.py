"""Fact Zeros Util (D-AC-045), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_45.v1"
def fact_zeros(n: int) -> int:
    c, p = 0, 5
    while p <= n: c += n // p; p *= 5
    return c
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
    assert fact_zeros(5) == 1
    assert fact_zeros(25) == 6
    assert fact_zeros(4) == 0
    assert stdlib_only()
    print("ac_45 OK")
if __name__ == "__main__": main()
