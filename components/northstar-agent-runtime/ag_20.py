"""Unit Vector, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_20.v1"
def unit(v: list) -> list:
    n = math.sqrt(sum(x*x for x in v))
    if n == 0: raise ValueError("zero vec")
    return [x / n for x in v]
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
    assert unit([3,4]) == [0.6, 0.8]
    assert abs(sum(x*x for x in unit([1,2,3])) - 1.0) < 1e-9
    assert unit([5]) == [1.0]
    assert stdlib_only()
    print("ag_20 OK")
if __name__ == "__main__": main()
