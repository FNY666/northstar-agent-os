"""Euclidean Distance, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_19.v1"
def euclid(a: list, b: list) -> float:
    if len(a) != len(b): raise ValueError("dim")
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))
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
    assert euclid([0,0],[3,4]) == 5.0
    assert euclid([1],[1]) == 0.0
    assert abs(euclid([1,1],[2,2]) - math.sqrt(2)) < 1e-9
    assert stdlib_only()
    print("ag_19 OK")
if __name__ == "__main__": main()
