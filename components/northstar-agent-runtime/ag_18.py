"""Cosine Similarity, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_18.v1"
def cosine(a: list, b: list) -> float:
    if len(a) != len(b) or not a: raise ValueError("bad vec")
    dot = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(y*y for y in b))
    if na == 0 or nb == 0: raise ValueError("zero vec")
    return dot / (na * nb)
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
    assert abs(cosine([1,0],[0,1])) < 1e-9
    assert abs(cosine([1,1],[1,1]) - 1.0) < 1e-9
    assert abs(cosine([1,0],[2,0]) - 1.0) < 1e-9
    assert stdlib_only()
    print("ag_18 OK")
if __name__ == "__main__": main()
