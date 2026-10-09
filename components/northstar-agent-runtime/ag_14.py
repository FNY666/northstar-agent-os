"""Median, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_14.v1"
def median(xs: list) -> float:
    s = sorted(xs)
    if not s: raise ValueError("empty")
    n = len(s)
    return float(s[n//2]) if n % 2 else (s[n//2-1] + s[n//2]) / 2
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
    assert median([3,1,2]) == 2.0
    assert median([1,2,3,4]) == 2.5
    assert median([7]) == 7.0
    assert stdlib_only()
    print("ag_14 OK")
if __name__ == "__main__": main()
