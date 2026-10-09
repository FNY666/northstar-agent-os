"""Jaccard Similarity, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_17.v1"
def jaccard(a: set, b: set) -> float:
    u = a | b
    if not u: return 1.0
    return len(a & b) / len(u)
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
    assert jaccard({1,2},{2,3}) == 1/3
    assert jaccard(set(), set()) == 1.0
    assert jaccard({1},{2}) == 0.0
    assert stdlib_only()
    print("ag_17 OK")
if __name__ == "__main__": main()
