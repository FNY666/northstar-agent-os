"""Bisect Index, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_46.v1"
def bisect_idx(xs: list, x: float) -> int:
    lo, hi = 0, len(xs)
    while lo < hi:
        m = (lo + hi) // 2
        if xs[m] < x: lo = m + 1
        else: hi = m
    return lo
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
    assert bisect_idx([1,3,5], 4) == 2
    assert bisect_idx([1,3,5], 0) == 0
    assert bisect_idx([], 1) == 0
    assert stdlib_only()
    print("ag_46 OK")
if __name__ == "__main__": main()
