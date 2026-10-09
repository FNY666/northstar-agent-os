"""Fibonacci, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_44.v1"
def fib(n: int) -> int:
    if n < 0: raise ValueError("n>=0")
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a
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
    assert fib(0) == 0
    assert fib(10) == 55
    assert fib(1) == 1
    assert stdlib_only()
    print("ag_44 OK")
if __name__ == "__main__": main()
