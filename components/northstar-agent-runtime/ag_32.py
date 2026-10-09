"""Zip Pad, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_32.v1"
def zpad(a: list, b: list, fill: object = None) -> list:
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]
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
    assert zpad([1,2],[3]) == [(1,3),(2,None)]
    assert zpad([],[]) == []
    assert zpad([1],[2,3],0) == [(1,2),(0,3)]
    assert stdlib_only()
    print("ag_32 OK")
if __name__ == "__main__": main()
