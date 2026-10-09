"""Chunk List, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_12.v1"
def chunk(xs: list, n: int) -> list:
    if n <= 0: raise ValueError("n>0")
    return [xs[i:i+n] for i in range(0, len(xs), n)]
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
    assert chunk([1,2,3,4], 2) == [[1,2],[3,4]]
    assert chunk([1,2,3], 2) == [[1,2],[3]]
    assert chunk([], 3) == []
    assert stdlib_only()
    print("ag_12 OK")
if __name__ == "__main__": main()
