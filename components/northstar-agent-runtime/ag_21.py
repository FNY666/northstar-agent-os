"""Softmax, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_21.v1"
def softmax(xs: list) -> list:
    if not xs: raise ValueError("empty")
    m = max(xs)
    ex = [math.exp(x - m) for x in xs]
    s = sum(ex)
    return [e / s for e in ex]
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
    assert abs(sum(softmax([1,2,3])) - 1.0) < 1e-9
    assert softmax([0,0]) == [0.5, 0.5]
    assert softmax([5]) == [1.0]
    assert stdlib_only()
    print("ag_21 OK")
if __name__ == "__main__": main()
