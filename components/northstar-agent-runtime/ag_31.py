"""Partition, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_31.v1"
def partition(xs: list, pred) -> tuple:
    t, f = [], []
    for x in xs: (t if pred(x) else f).append(x)
    return t, f
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert partition([1,2,3,4], lambda x: x % 2 == 0) == ([2,4],[1,3])
    assert partition([], bool) == ([],[])
    assert partition([1], lambda x: True) == ([1],[])
    assert stdlib_only()
    print("ag_31 OK")
if __name__ == "__main__": main()
