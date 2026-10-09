"""Top-K, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_24.v1"
def topk(xs: list, k: int) -> list:
    if k <= 0: raise ValueError("k>0")
    return sorted(xs, reverse=True)[:k]
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
    assert topk([3,1,2], 2) == [3,2]
    assert topk([1], 5) == [1]
    assert topk([5,4,3], 1) == [5]
    assert stdlib_only()
    print("ag_24 OK")
if __name__ == "__main__": main()
