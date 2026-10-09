"""Capped Factorial, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_45.v1"
def cfact(n: int, cap: int = 10**18) -> int:
    if n < 0: raise ValueError("n>=0")
    r, i = 1, 2
    while i <= n and r <= cap: r, i = r * i, i + 1
    if r > cap: raise OverflowError("cap")
    return r
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
    assert cfact(5) == 120 and cfact(0) == 1
    try:
        cfact(100); assert False
    except OverflowError: pass
    assert stdlib_only()
    print("ag_45 OK")
if __name__ == "__main__": main()
